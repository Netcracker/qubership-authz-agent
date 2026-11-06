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

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"authz-agent/components/authz-agent/internal/authn"
	"authz-agent/components/authz-agent/internal/engine"
)

// newApp builds the internal surface over the admission stub, with
// data.users.admin set to root.
func newApp(t *testing.T, health func() Report) (*fiber.App, *engine.Engine) {
	t.Helper()
	eng, err := engine.New(engine.Options{Modules: map[string]string{"internals.rego": admissionStub}})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if err := eng.Put(context.Background(), []string{"users"}, map[string]any{"admin": "root"}); err != nil {
		t.Fatal(err)
	}
	app := fiber.New(fiber.Config{Immutable: true, DisableStartupMessage: true})
	Register(app, eng, Options{Health: health})
	return app, eng
}

// pullServer registers both surfaces with pullNow as [Options.PullNow] and
// returns the internal one and the public one.
func pullServer(t *testing.T, pullNow func(context.Context) error) (internal, public *fiber.App) {
	t.Helper()
	internal = fiber.New(fiber.Config{Immutable: true, DisableStartupMessage: true})
	public = fiber.New(fiber.Config{Immutable: true, DisableStartupMessage: true})
	Register(internal, nil, Options{PullNow: pullNow}).RegisterPublic(public)
	return internal, public
}

// checkAs sends one READ of an ORDER to /access/v1/check/resource with an
// admission token and the subject token "Bearer <subject>", plus headers.
func checkAs(t *testing.T, app *fiber.App, subject string, headers map[string]string) (int, map[string]any, string) {
	t.Helper()
	all := map[string]string{"Authorization": "Bearer m2m", "Incoming-Token": "Bearer " + subject}
	for k, v := range headers {
		all[k] = v
	}
	return do(t, app, http.MethodPost, "/access/v1/check/resource", `{"type":"ORDER","operation":"READ"}`, all)
}

func do(t *testing.T, app *fiber.App, method, path, body string, headers map[string]string) (int, map[string]any, string) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &parsed)
	}
	return resp.StatusCode, parsed, string(raw)
}

// TestReady_WaitsForThePolicies: /ready is 503 with the health reason
// while the report is unhealthy, 503 "policies not loaded yet" while it is
// healthy but the policies have not loaded, 200 once they have, and 200
// when there is no report.
func TestReady_WaitsForThePolicies(t *testing.T) {
	report := Report{Healthy: false, Message: "bootstrap threshold not met"}
	app, _ := newApp(t, func() Report { return report })
	if code, body, _ := do(t, app, http.MethodGet, "/ready", "", nil); code != 503 || body["message"] != "bootstrap threshold not met" {
		t.Errorf("GET /ready unhealthy = %d %v, want 503 with the health reason", code, body)
	}
	report = Report{Healthy: true}
	if code, body, _ := do(t, app, http.MethodGet, "/ready", "", nil); code != 503 || body["message"] != "policies not loaded yet" {
		t.Errorf("GET /ready before the policies = %d %v, want 503 policies not loaded yet", code, body)
	}
	if code, _, raw := do(t, app, http.MethodGet, "/health", "", nil); code != 200 {
		t.Errorf("GET /health before the policies = %d %s, want 200: the policies are not a liveness matter", code, raw)
	}
	report = Report{Healthy: true, Loaded: true}
	if code, _, raw := do(t, app, http.MethodGet, "/ready", "", nil); code != 200 || raw != `{"status":"ready"}` {
		t.Errorf("GET /ready loaded = %d %s, want 200 {\"status\":\"ready\"}", code, raw)
	}
	plain, _ := newApp(t, nil)
	if code, _, raw := do(t, plain, http.MethodGet, "/ready", "", nil); code != 200 || raw != `{"status":"ready"}` {
		t.Errorf("GET /ready without a report = %d %s, want 200", code, raw)
	}
}

func TestReady_NamesTheTenantsWithoutASnapshot(t *testing.T) {
	app, _ := newApp(t, func() Report { return Report{Healthy: true, Waiting: []string{"a", "b"}} })

	code, body, _ := do(t, app, http.MethodGet, "/ready", "", nil)

	if want := "no snapshot accepted yet for tenants a, b"; code != 503 || body["message"] != want {
		t.Errorf("GET /ready = %d %v, want 503 %q", code, body, want)
	}
}

// TestHealth_ReportsTheLoops: /health is 200 when the report is healthy, 503 with the reason and its details when it
// is not, and 200 without details when there is no report.
func TestHealth_ReportsTheLoops(t *testing.T) {
	report := Report{Healthy: false, Message: "bootstrap threshold not met", Bootstrap: &authn.Details{Mode: "strict", SuccessCount: 0, RequiredCount: 1}}
	app, _ := newApp(t, func() Report { return report })
	code, body, raw := do(t, app, http.MethodGet, "/health", "", nil)
	if code != 503 || body["message"] != "bootstrap threshold not met" {
		t.Fatalf("GET /health unhealthy = %d %s, want 503 with the message", code, raw)
	}
	details := body["details"].(map[string]any)
	if details["opaReady"] != true || details["bootstrap"].(map[string]any)["requiredCount"] != float64(1) {
		t.Errorf("details = %v, want opaReady true and the bootstrap counts", details)
	}
	report = Report{Healthy: true}
	if code, _, raw := do(t, app, http.MethodGet, "/health", "", nil); code != 200 || raw != `{"status":"healthy"}` {
		t.Fatalf("GET /health healthy = %d %s, want 200 {\"status\":\"healthy\"}", code, raw)
	}
	plain, _ := newApp(t, nil)
	if code, _, raw := do(t, plain, http.MethodGet, "/health", "", nil); code != 200 || raw != `{"status":"healthy"}` {
		t.Fatalf("GET /health without a report = %d %s, want 200 {\"status\":\"healthy\"}", code, raw)
	}
}

// TestAPIVersion_LegacyBody: the body is the legacy JSON, byte for byte,
// with integer versions.
func TestAPIVersion_LegacyBody(t *testing.T) {
	app, _ := newApp(t, nil)
	code, body, raw := do(t, app, http.MethodGet, "/api-version", "", nil)
	if code != 200 || raw != LegacyAPIVersion {
		t.Fatalf("api-version: %d %s", code, raw)
	}
	specs := body["specs"].([]any)
	if first := specs[0].(map[string]any); first["specRootUrl"] != "/access" || first["major"] != float64(3) {
		t.Fatalf("first spec = %v", first)
	}
}

// TestRegister_TheStoreIsNotWritableOverHTTP: the internal surface serves no
// route that writes a document, so a PUT or a PATCH under /v1/data is 404 and
// the store holds what it held before.
func TestRegister_TheStoreIsNotWritableOverHTTP(t *testing.T) {
	app, eng := newApp(t, nil)
	writes := map[string]string{
		http.MethodPut:   `{"admin": "mallory"}`,
		http.MethodPatch: `[{"op": "replace", "path": "/admin", "value": "mallory"}]`,
	}
	for method, body := range writes {
		if code, _, raw := do(t, app, method, "/v1/data/users", body, nil); code != 404 {
			t.Errorf("%s /v1/data/users = %d %s, want 404", method, code, raw)
		}
	}
	admin, _, err := eng.Eval(context.Background(), []string{"users", "admin"}, nil)
	if err != nil || admin != "root" {
		t.Errorf("data.users.admin after the writes = %v (%v), want root", admin, err)
	}
}

// TestRegister_ServesNoDecision: the internal surface has no decision route,
// so a decision request there is 404 like any path it does not serve.
func TestRegister_ServesNoDecision(t *testing.T) {
	app, _ := newApp(t, nil)
	for _, path := range []string{"/access/v1/authorize", "/access/v1/check/resource", "/v1/data/authorize"} {
		if code, _, raw := do(t, app, http.MethodPost, path, `{"input": {}}`, nil); code != 404 {
			t.Errorf("POST %s on the internal surface = %d %s, want 404", path, code, raw)
		}
	}
}

// levels keeps the level of every line, for a test whose subject is what the
// request path reports rather than what it answers.
type levels struct{ lines []string }

func (l *levels) record(level, format string, args ...any) {
	l.lines = append(l.lines, level+": "+fmt.Sprintf(format, args...))
}

func (l *levels) DebugC(_ context.Context, format string, args ...any) {
	l.record("debug", format, args...)
}
func (l *levels) ErrorC(_ context.Context, format string, args ...any) {
	l.record("error", format, args...)
}

// at returns the lines reported at one level.
func (l *levels) at(level string) []string {
	var out []string
	for _, line := range l.lines {
		if strings.HasPrefix(line, level+": ") {
			out = append(out, line)
		}
	}
	return out
}

// TestDecide_ReportsTheDecisionAtDebug: the decision is the line a policy
// author asks for, and it names the document and the tenant. It is debug
// because every request writes one, and it carries neither the input nor
// the result, because those hold the caller's token and claims.
func TestDecide_ReportsTheDecisionAtDebug(t *testing.T) {
	reported := &levels{}
	app := newPublicAppWithLog(t, reported)

	if code, _, raw := checkAs(t, app, "alice", nil); code != 200 {
		t.Fatalf("POST /access/v1/check/resource = %d %s, want 200", code, raw)
	}
	debug := reported.at("debug")
	if len(debug) != 1 {
		t.Fatalf("one decision reported %v, want one debug line", reported.lines)
	}
	if !strings.Contains(debug[0], "path=authorize") || !strings.Contains(debug[0], "tenant=default") {
		t.Errorf("the decision reported %q, want the path authorize and tenant=default", debug[0])
	}
	if strings.Contains(debug[0], "alice") {
		t.Errorf("the decision reported %q, which carries the input", debug[0])
	}
}

// conflictingAdmission makes the checks of the caller fail at evaluation
// rather than deciding: two complete definitions of admission produce
// different values for the same request, which OPA reports as a conflict.
const conflictingAdmission = `package authorize_internals

import rego.v1

admission := {"tokenPayload": {}} if input.subject != ""

admission := {"subjectError": "x"} if input.subject != ""
`

// TestDecide_ReportsAnAdmissionThatCouldNotBeEvaluated: checks of the caller
// that fail to evaluate answer 500, and the error line is the only account
// of it. A caller that passes no logger gets no line and the same answer.
func TestDecide_ReportsAnAdmissionThatCouldNotBeEvaluated(t *testing.T) {
	reported := &levels{}
	for name, log := range map[string]Logger{"a logger was passed": reported, "no logger was passed": nil} {
		t.Run(name, func(t *testing.T) {
			app := newPublicAppOver(t, map[string]string{"internals.rego": conflictingAdmission}, Options{Log: log})

			code, body, _ := checkAs(t, app, "alice", nil)
			if code != 500 || body["code"] != "internal_error" {
				t.Fatalf("POST /access/v1/check/resource under failing checks = %d %v, want 500 internal_error", code, body)
			}
		})
	}
	errors := reported.at("error")
	if len(errors) != 1 || !strings.Contains(errors[0], "admission failed") {
		t.Fatalf("an admission that could not be evaluated reported %v, want one admission error", reported.lines)
	}
}

// TestRegister_APanicAnswers500: a handler that panics answers its request
// with 500 and an error line that names the panic, on the internal and the
// public surface, and the next request is answered.
func TestRegister_APanicAnswers500(t *testing.T) {
	eng, err := engine.New(engine.Options{Modules: map[string]string{"internals.rego": admissionStub}})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	reported := &levels{}
	internal := fiber.New(fiber.Config{DisableStartupMessage: true})
	srv := Register(internal, eng, Options{Log: reported, Health: func() Report { panic("health exploded") }})
	public := fiber.New(fiber.Config{DisableStartupMessage: true})
	srv.RegisterPublic(public)

	for _, app := range []struct {
		name string
		app  *fiber.App
	}{{"internal", internal}, {"public", public}} {
		t.Run(app.name, func(t *testing.T) {
			reported.lines = nil
			for i := range 2 {
				code, body, _ := call(t, app.app, http.MethodGet, "/health", "", nil)
				if code != http.StatusInternalServerError || body != `{"code":"internal_error","message":"internal error"}` {
					t.Errorf("GET /health %d = %d %s, want 500 internal_error", i+1, code, body)
				}
			}
			errs := reported.at("error")
			if len(errs) != 2 || !strings.Contains(errs[0], "GET /health panicked, answered 500: health exploded") {
				t.Errorf("error lines %q, want one per request naming the panic", errs)
			}
		})
	}
}
