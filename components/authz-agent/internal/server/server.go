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

// Package server registers the HTTP routes of the agent on Fiber apps: the
// public surface the clients call, which [Server.RegisterPublic] adds, and
// the internal surface the probes read, which [Register] adds.
package server

import (
	"context"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/gofiber/fiber/v2"

	"authz-agent/components/authz-agent/internal/authn"
	"authz-agent/components/authz-agent/internal/engine"
	"authz-agent/components/authz-agent/internal/snapshot"
)

// LegacyAPIVersion is the body of GET /api-version: the specification
// versions the legacy service announces, kept byte for byte.
const LegacyAPIVersion = `{"specs":[{"specRootUrl":"/access","major":3,"minor":0,"supportedMajors":[1,2,3]},{"specRootUrl":"/api","major":1,"minor":1,"supportedMajors":[1]},{"specRootUrl":"/template","major":1,"minor":0,"supportedMajors":[1]},{"specRootUrl":"/preview","major":2,"minor":0,"supportedMajors":[1,2]}]}`

// Logger receives what the request path has to report. Every method takes
// the request's context, which carries the id the platform log format prints
// as request_id, so a line here can be matched with the caller's own line for
// the same request.
//
// The decision itself is not written here, because its input carries the
// caller's token and claims.
type Logger interface {
	DebugC(ctx context.Context, format string, args ...any)
	ErrorC(ctx context.Context, format string, args ...any)
}

// discardLogger is the logger a caller that passes none gets.
type discardLogger struct{}

func (discardLogger) DebugC(context.Context, string, ...any) {
	// Deliberately empty: a caller that passes no logger wants no line.
}
func (discardLogger) ErrorC(context.Context, string, ...any) {
	// Deliberately empty: a caller that passes no logger wants no line.
}

// Options tune the routes.
type Options struct {
	// Health reports the state of the loops the service runs; nil means
	// the service is healthy and ready as long as it answers.
	Health func() Report
	// Log receives the diagnostics of the request path; nil discards them.
	Log Logger
	// PullNow loads the policies from their source and returns once they
	// are stored. Only a build with the paritytest tag routes a request to
	// it.
	PullNow func(ctx context.Context) error
	// Snapshots answers check/resource and its bulk routes with the
	// generated policies of the request's tenant; nil answers them, like
	// check/filter, with the embedded policies.
	Snapshots *snapshot.Registry
	// DefaultTenant is the tenant of a request that names none by the
	// query parameter tenant_id or the header Tenant.
	DefaultTenant func() string
	// DefaultTenantResolved reports whether DefaultTenant gives the tenant's
	// ID rather than its display name; nil means it always does. Until it
	// does, a caller is never matched with the default tenant, and a
	// request in the default tenant is denied as in a tenant without
	// policies.
	DefaultTenantResolved func() bool
}

// Server owns the handlers.
type Server struct {
	engine *engine.Engine
	opts   Options
}

// Register adds the routes of the internal surface to app: /health,
// /ready, and /api-version, and in a build with the paritytest tag
// POST /internal/v1/pull when [Options.PullNow] is set.
func Register(app *fiber.App, eng *engine.Engine, opts Options) *Server {
	if opts.Log == nil {
		opts.Log = discardLogger{}
	}
	s := &Server{engine: eng, opts: opts}
	app.Use(s.recoverPanic)
	app.Get("/health", s.health)
	app.Get("/ready", s.ready)
	app.Get("/api-version", apiVersion)
	registerTestRoutes(app, s)
	return s
}

// Report is the state of the service as its loops see it. Healthy is the
// liveness verdict, which the trusted providers decide; Loaded is the
// readiness one, set once the policies have loaded and never cleared.
type Report struct {
	Healthy bool
	// Message names the reason when the service is unhealthy or not ready.
	Message string
	// ConfigError is the trusted providers file's error, when that is the
	// reason.
	ConfigError string
	// Bootstrap carries the counts when a bootstrap threshold is not met or
	// a required provider is missing.
	Bootstrap *authn.Details
	Loaded    bool
	// Waiting names the tenants whose policies keep Loaded unset, because
	// the source names them and no snapshot of theirs was accepted.
	Waiting []string
	// UnresolvedTenant is the display name of the default tenant while
	// tenant-manager has not resolved it, and keeps the service not ready;
	// "" when it is resolved or the lookup is off.
	UnresolvedTenant string
	// Snapshots is the state of every tenant's generated policies, nil
	// without a registry.
	Snapshots *snapshot.Health
}

// HealthResponse is the body of a healthy GET /health.
type HealthResponse struct {
	Status    string           `json:"status"`
	Snapshots *snapshot.Health `json:"snapshots,omitempty"`
}

// HealthErrorResponse is the body of a 503 GET /health or GET /ready.
type HealthErrorResponse struct {
	Message string              `json:"message"`
	Details *HealthErrorDetails `json:"details,omitempty"`
}

// HealthErrorDetails carries the diagnostics of an unhealthy verdict.
// OPAReady is always true: the service holds the engine, so there is no
// separate engine to wait for. The field stays because the body's shape is
// what the platform's probes and dashboards already read.
type HealthErrorDetails struct {
	OPAReady    *bool            `json:"opaReady,omitempty"`
	ConfigError string           `json:"configError,omitempty"`
	Bootstrap   *authn.Details   `json:"bootstrap,omitempty"`
	Snapshots   *snapshot.Health `json:"snapshots,omitempty"`
}

// health answers 200 with the state of every
// tenant's generated policies when healthy, 503 with the reason and its
// details otherwise. A tenant whose candidate was refused leaves the
// service healthy: the tenant names the refusal, and the other tenants
// are served. The policies' first load is not part of it, so a liveness
// probe does not restart a service that is still waiting for its source;
// /ready carries that.
func (s *Server) health(c *fiber.Ctx) error {
	if s.opts.Health == nil {
		return c.JSON(HealthResponse{Status: "healthy"})
	}
	report := s.opts.Health()
	if report.Healthy {
		return c.JSON(HealthResponse{Status: "healthy", Snapshots: report.Snapshots})
	}
	return unavailable(c, report)
}

// ready is the readiness answer: 200 {"status":"ready"} once the service
// is healthy, the policies have loaded, and the default tenant is resolved,
// 503 otherwise. The 503 reason is the health reason when unhealthy, and
// otherwise names each unmet condition, separated by "; ": the tenants of
// [Report.Waiting] and [Report.UnresolvedTenant].
func (s *Server) ready(c *fiber.Ctx) error {
	if s.opts.Health == nil {
		return c.JSON(fiber.Map{"status": "ready"})
	}
	report := s.opts.Health()
	if !report.Healthy {
		return unavailable(c, report)
	}
	var reasons []string
	if !report.Loaded {
		reason := "policies not loaded yet"
		if len(report.Waiting) > 0 {
			reason = "no snapshot accepted yet for tenants " + strings.Join(report.Waiting, ", ")
		}
		reasons = append(reasons, reason)
	}
	if report.UnresolvedTenant != "" {
		reasons = append(reasons, fmt.Sprintf("default tenant %q not resolved via tenant-manager yet",
			report.UnresolvedTenant))
	}
	if len(reasons) > 0 {
		report.Message = strings.Join(reasons, "; ")
		return unavailable(c, report)
	}
	return c.JSON(fiber.Map{"status": "ready"})
}

// unavailable writes the 503 body of /health and /ready.
func unavailable(c *fiber.Ctx, report Report) error {
	ready := true
	return c.Status(http.StatusServiceUnavailable).JSON(HealthErrorResponse{
		Message: report.Message,
		Details: &HealthErrorDetails{
			OPAReady:    &ready,
			ConfigError: report.ConfigError,
			Bootstrap:   report.Bootstrap,
			Snapshots:   report.Snapshots,
		},
	})
}

func apiVersion(c *fiber.Ctx) error {
	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	return c.SendString(LegacyAPIVersion)
}

// recoverPanic answers 500 to a request whose handler panicked and reports
// the panic with its stack, so that one request cannot stop the process and
// the checks of every tenant with it.
func (s *Server) recoverPanic(c *fiber.Ctx) (err error) {
	defer func() {
		if r := recover(); r != nil {
			s.opts.Log.ErrorC(c.UserContext(), "%s %s panicked, answered 500: %v\n%s", c.Method(), c.Path(), r, debug.Stack())
			err = opaError(c, http.StatusInternalServerError, "internal_error", "internal error")
		}
	}()
	return c.Next()
}

// opaError writes an error body in the shape of OPA's REST API.
func opaError(c *fiber.Ctx, status int, code, message string) error {
	return c.Status(status).JSON(fiber.Map{"code": code, "message": message})
}
