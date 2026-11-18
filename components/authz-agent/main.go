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
// own token.
package main

import (
	"context"
	"net"
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
	"authz-agent/components/authz-agent/internal/engine"
	"authz-agent/components/authz-agent/internal/m2m"
	"authz-agent/components/authz-agent/internal/pull"
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
	cfg, err := loadConfig(get)
	refused := otherRootLevelNames(os.Environ())
	if err != nil {
		refused = append([]string{err.Error()}, refused...)
	}
	if len(refused) > 0 {
		logStop("configuration: %s", strings.Join(refused, "; "))
		os.Exit(1)
	}
	modules, err := policies.Modules()
	if err != nil {
		logStop("policies: %v", err)
		os.Exit(1)
	}
	eng, err := engine.New(engine.Options{Modules: modules})
	if err != nil {
		logStop("policy engine: %v", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The trusted providers' keys are fetched before the service listens:
	// a token cannot be verified without them, and the outcome, whatever
	// it is, goes into the health report.
	var providers *authn.Manager
	if cfg.Authn.File != "" {
		providers = authn.New(cfg.Authn, eng, logger)
		providers.Bootstrap(ctx)
	}
	tokens := m2m.New(cfg.M2M, eng, logger)
	puller := pull.New(cfg.Pull, eng, tokens, logger)
	opts := server.Options{
		Log:     logger,
		Health:  func() server.Report { return report(providers, puller) },
		PullNow: puller.PullNow,
	}

	// Immutable: strings handed out by the request context must not alias the
	// buffer the server reuses for the next request.
	internal, err := fiberserver.New(fiber.Config{
		Immutable:             true,
		BodyLimit:             32 << 20,
		DisableStartupMessage: true,
	}).WithPrometheus("/prometheus").Process()
	if err != nil {
		logStop("fiber: %v", err)
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
		logStop("fiber: %v", err)
		os.Exit(1)
	}
	srv := server.Register(internal, eng, opts)
	srv.RegisterPublic(public)

	go tokens.Run(ctx)
	if puller != nil {
		go puller.Run(ctx)
	}
	if providers != nil {
		go providers.Run(ctx)
	}
	if serve(ctx, stop, cfg, len(modules), public, internal) {
		os.Exit(1)
	}
}

// serve binds the sockets of the public and the internal surface, logs the
// startup line with the number of policy modules, and runs both surfaces
// through [serveUntilShutdown]. It reports whether the service failed: a
// socket that could not be bound, or a surface that ended on its own.
//
// Both sockets are bound before either surface serves, so an address
// already in use fails the start rather than leaving one surface up; the
// public socket is closed again when the internal one cannot be bound.
func serve(ctx context.Context, stop func(), cfg config, modules int, public, internal *fiber.App) bool {
	publicSocket, err := net.Listen("tcp", cfg.PublicAddr)
	if err != nil {
		logStop("public listener on AUTHZ_PUBLIC_ADDR=%q: %v", cfg.PublicAddr, err)
		return true
	}
	internalSocket, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		_ = publicSocket.Close()
		logStop("internal listener on AUTHZ_HTTP_ADDR=%q: %v", cfg.Addr, err)
		return true
	}
	logger.Infof("authz-agent: %d policy modules, public surface on %s, internal surface on %s",
		modules, cfg.PublicAddr, cfg.Addr)
	return serveUntilShutdown(ctx, stop, []surface{
		{"public", public, publicSocket},
		{"internal", internal, internalSocket},
	})
}

// surface is one of the service's two HTTP surfaces: the app, the socket it
// serves, and the name the logs call it.
type surface struct {
	name   string
	app    *fiber.App
	socket net.Listener
}

// serveUntilShutdown runs the surfaces until ctx ends and shuts them down,
// giving each five seconds to finish the requests still in its handlers. It
// reports whether a surface ended on its own, which is a failed start rather
// than a shutdown; stop ends ctx for the rest of the process when one does.
func serveUntilShutdown(ctx context.Context, stop func(), surfaces []surface) bool {
	// A surface that ends on its own cancels the signal context, and the
	// caller then ends the other one and the loops; one that ends because
	// the shutdown closed its socket is not that failure.
	var failed atomic.Bool
	var servers sync.WaitGroup
	for _, s := range surfaces {
		servers.Add(1)
		go func() {
			defer servers.Done()
			if err := s.app.Listener(s.socket); err != nil && ctx.Err() == nil {
				logStop("%s server on %s: %v", s.name, s.socket.Addr(), err)
				failed.Store(true)
				stop()
			}
		}()
	}
	<-ctx.Done()
	for _, s := range surfaces {
		if err := s.app.ShutdownWithTimeout(5 * time.Second); err != nil {
			logger.Warnf("shutdown: %v", err)
		}
	}
	// The shutdown above does nothing for a server still on its way to
	// Serve, so the sockets are closed as well; one already closed by its
	// own shutdown returns the error this ignores.
	for _, s := range surfaces {
		_ = s.socket.Close()
	}
	servers.Wait()
	return failed.Load()
}

// get returns the value of the environment variable that [variable] names
// for key, the empty string included, or fallback where that variable is
// unset. The caller decides what an empty value means: an empty
// AUTHZ_TRUSTED_PROVIDERS_FILE runs the service without trusted providers.
// get reads the variable itself rather than through configloader, which
// nests a name that adds an underscore and a suffix to another, such as
// LOG_LEVEL_PACKAGE_AUTHZ-AGENT, under the key of the shorter one, LOG_LEVEL,
// and then returns no value for LOG_LEVEL.
func get(key, fallback string) string {
	if value, ok := os.LookupEnv(variable(key)); ok {
		return value
	}
	return fallback
}

// logStop logs an error after which the agent exits with status 1. Where the
// agent's logger is at the level fatal, which drops error lines, logStop first
// raises the level to error, so that the line that says why the agent stops
// is logged. Fatal is the only level the logger numbers below
// [logging.LvlError], so every other level stays as it is, and a surface that
// fails at run time keeps the warnings of the shutdown that follows, where
// the level logs them.
func logStop(format string, args ...any) {
	if logger.GetLevel() < logging.LvlError {
		logger.SetLevel(logging.LvlError)
	}
	logger.Errorf(format, args...)
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
