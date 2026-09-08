// Copyright 2024-2026 Netcracker Technology Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// authz-agent is the authorization agent as one service: the HTTP surface the
// clients call, the embedded policy engine, and, in later steps, the loops
// that feed it. This step carries the engine, the public surface with the
// legacy check routes, and the slice of OPA's REST API the other containers
// of the Pod still use, so the same binary can stand in for the OPA
// container until the chart switches.
package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	fiberserver "github.com/netcracker/qubership-core-lib-go-fiber-server-utils/v2"
	"github.com/netcracker/qubership-core-lib-go-fiber-server-utils/v2/security"
	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	// memlimit sets the Go memory limit from the container's cgroup limit in
	// its init function; importing it is the whole configuration.
	_ "github.com/netcracker/qubership-core-lib-go/v3/memlimit"
	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"

	"authz-agent/components/authz-agent/internal/decisionlog"
	"authz-agent/components/authz-agent/internal/engine"
	"authz-agent/components/authz-agent/internal/server"
	"authz-agent/policies"
)

var logger logging.Logger

func init() {
	// The environment is the only property source: the image ships no
	// application.yaml, and the chart configures the service through
	// AUTHZ_* variables.
	configloader.Init(configloader.EnvPropertySource())
	serviceloader.Register(1, &security.DummyFiberServerSecurityMiddleware{})
	logger = logging.GetLogger("authz-agent")
}

func main() {
	cfg, err := loadConfig(os.Args[1:], configloader.GetOrDefaultString)
	if err != nil {
		logger.Errorf("configuration: %v", err)
		os.Exit(2)
	}
	modules, err := policies.Modules()
	if err != nil {
		logger.Errorf("policies: %v", err)
		os.Exit(1)
	}
	eng, err := engine.New(engine.Options{Modules: modules, DataDirs: cfg.DataDirs, Ignore: cfg.Ignore})
	if err != nil {
		logger.Errorf("policy engine: %v", err)
		os.Exit(1)
	}
	logs := decisionlog.New(cfg.DecisionLogs, logger.Warnf)

	// Immutable: strings handed out by the request context, such as a path
	// segment that becomes a store key or a header that goes into a decision
	// log event, must not alias the buffer the server reuses for the next
	// request.
	internal, err := fiberserver.New(fiber.Config{
		Immutable:             true,
		BodyLimit:             32 << 20,
		DisableStartupMessage: true,
	}).WithPrometheus("/prometheus").Process()
	if err != nil {
		logger.Errorf("fiber: %v", err)
		os.Exit(1)
	}
	// The public routes match the way Envoy's path matches did: exact,
	// case-sensitive, and without a trailing slash.
	public, err := fiberserver.New(fiber.Config{
		Immutable:             true,
		BodyLimit:             32 << 20,
		StrictRouting:         true,
		CaseSensitive:         true,
		DisableStartupMessage: true,
	}).Process()
	if err != nil {
		logger.Errorf("fiber: %v", err)
		os.Exit(1)
	}
	srv := server.Register(internal, eng, logs, server.Options{
		Authorization: cfg.Authorization,
		PapClientURL:  cfg.PapClientURL,
		CollectorURL:  cfg.DecisionLogs.URL,
	})
	srv.RegisterPublic(public)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go logs.Run(ctx)
	logger.Infof("authz-agent: %d policy modules, data from %v, decision logs to %q, public surface on %s, data API on %s",
		len(modules), cfg.DataDirs, cfg.DecisionLogs.URL, cfg.PublicAddr, cfg.Addr)

	// A listener that fails cancels the signal context, and main then shuts
	// the other listener and the decision log uploader down.
	var failed atomic.Bool
	var listeners sync.WaitGroup
	serve := func(name string, app *fiber.App, addr string) {
		listeners.Add(1)
		go func() {
			defer listeners.Done()
			if err := app.Listen(addr); err != nil {
				logger.Errorf("%s listener on %s: %v", name, addr, err)
				failed.Store(true)
				stop()
			}
		}()
	}
	serve("public", public, cfg.PublicAddr)
	serve("data API", internal, cfg.Addr)
	<-ctx.Done()
	for _, app := range []*fiber.App{public, internal} {
		if err := app.ShutdownWithTimeout(5 * time.Second); err != nil {
			logger.Warnf("shutdown: %v", err)
		}
	}
	listeners.Wait()
	logs.Wait()
	if failed.Load() {
		os.Exit(1)
	}
}
