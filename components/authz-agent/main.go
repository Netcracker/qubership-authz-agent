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

// authz-agent is the authorization agent as one service: the HTTP surface
// the clients call, the embedded policy engine, and the loops that feed it
// with the trusted providers' keys, the policies and PIPs, and the agent's
// own token. Started with OPA's command line, it stands in for the OPA
// container of the current chart instead, leaving the loops to the Pod's
// other containers and relaying to them.
package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
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

	"authz-agent/components/authz-agent/internal/authn"
	"authz-agent/components/authz-agent/internal/decisionlog"
	"authz-agent/components/authz-agent/internal/engine"
	"authz-agent/components/authz-agent/internal/m2m"
	"authz-agent/components/authz-agent/internal/pull"
	"authz-agent/components/authz-agent/internal/server"
	"authz-agent/internal/pips"
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
	cfg, err := loadConfig(os.Args[1:], get)
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.OPAAuthTokenFile != "" {
		if err := loadAuthSecret(ctx, eng, cfg.OPAAuthTokenFile); err != nil {
			logger.Warnf("data API secret: %v", err)
		}
	}
	if cfg.DecisionLogFile != "" {
		cfg.DecisionLogs.Store = decisionlog.NewStore(cfg.DecisionLogFile)
	}
	logs := decisionlog.New(cfg.DecisionLogs, logger.Warnf)

	// The trusted providers' keys are fetched before the service listens:
	// a token cannot be verified without them, and the outcome, whatever
	// it is, goes into the health report.
	var providers *authn.Manager
	if cfg.Authn.File != "" {
		providers = authn.New(cfg.Authn, eng, logger)
		providers.Bootstrap(ctx)
	}
	var tokens *m2m.Source
	if cfg.M2M.TokenURL != "" || cfg.M2M.TokenFile != "" {
		tokens = m2m.New(cfg.M2M, eng, logger)
	}
	var puller *pull.Puller
	if !cfg.StandIn {
		cfg.Pull.Entitlements = pips.LoadEntitlementsConfigFromEnv()
		var source pull.Tokens
		if tokens != nil {
			source = tokens
		}
		puller = pull.New(cfg.Pull, eng, source, logger)
	}
	opts := server.Options{
		Authorization: cfg.Authorization,
		PapClientURL:  cfg.PapClientURL,
		CollectorURL:  cfg.DecisionLogs.URL,
	}
	if !cfg.StandIn {
		opts.Health = func() server.Report { return report(providers, puller) }
	}

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
	srv := server.Register(internal, eng, logs, opts)
	srv.RegisterPublic(public)

	go logs.Run(ctx)
	if tokens != nil {
		go tokens.Run(ctx)
	}
	if puller != nil {
		go puller.Run(ctx)
	}
	if providers != nil {
		go providers.Run(ctx)
	}
	logger.Infof("authz-agent: %d policy modules, data from %v, decision logs to %q, public surface on %s, data API on %s",
		len(modules), cfg.DataDirs, decisionLogTarget(cfg), cfg.PublicAddr, cfg.Addr)

	// A listener that fails cancels the signal context, and main then shuts
	// the other listener and the loops down.
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

// get reads one key through configloader, except that an environment
// variable set to the empty string is returned as the empty string:
// configloader falls back to the default there, and the chart sets a URL to
// "" to switch it off.
func get(key, fallback string) string {
	if value, ok := os.LookupEnv(strings.ToUpper(strings.ReplaceAll(key, ".", "_"))); ok && value == "" {
		return ""
	}
	return configloader.GetOrDefaultString(key, fallback)
}

// loadAuthSecret stores the token of file as data.opa_auth_secret, the
// identity the data API guard lets write. An empty file loads nothing, so
// every write stays refused.
func loadAuthSecret(ctx context.Context, eng *engine.Engine, file string) error {
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return nil
	}
	return eng.Put(ctx, []string{"opa_auth_secret"}, token)
}

// report composes the state of the loops: the trusted providers' outcome
// under the bootstrap rules decides Healthy, and the policies' first load
// decides Loaded. providers may be nil; puller may not.
func report(providers *authn.Manager, puller *pull.Puller) server.Report {
	r := server.Report{Healthy: true}
	if providers != nil {
		healthy, message, configError, details := authn.Evaluate(providers.Status())
		if !healthy {
			r.Healthy, r.Message, r.ConfigError, r.Bootstrap = false, message, configError, details
		}
	}
	status := puller.Status()
	r.Conversion = status.Conversion
	r.Loaded = status.PoliciesLoaded
	return r
}

func decisionLogTarget(cfg config) string {
	if cfg.DecisionLogFile != "" {
		return cfg.DecisionLogFile
	}
	return cfg.DecisionLogs.URL
}
