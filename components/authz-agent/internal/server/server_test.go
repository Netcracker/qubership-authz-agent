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
	"time"

	"github.com/gofiber/fiber/v2"

	"authz-agent/components/authz-agent/internal/authn"
	"authz-agent/components/authz-agent/internal/decisionlog"
	"authz-agent/components/authz-agent/internal/engine"
	"authz-agent/components/authz-agent/internal/pull"
)

// testPolicies mirror the shape of the product policies: a decision
// document that reads its input and the store, and a non-deterministic
// builtin for the decision log to record.
const testPolicies = `package authorize

import rego.v1

allowed := input.user == data.users.admin

now := time.now_ns()
`

func newApp(t *testing.T, logs *decisionlog.Logger, health func() Report) (*fiber.App, *engine.Engine) {
	t.Helper()
	return newAppWithLog(t, logs, health, nil)
}

// newAppWithLog is newApp with the diagnostics of the request path sent to
// log, for a test whose subject is what the surface reports.
func newAppWithLog(t *testing.T, logs *decisionlog.Logger, health func() Report, log Logger) (*fiber.App, *engine.Engine) {
	t.Helper()
	return newAppWithModules(t, map[string]string{"authorize.rego": testPolicies}, logs, health, log)
}

// newAppWithModules is newAppWithLog over policies the test chooses.
func newAppWithModules(t *testing.T, modules map[string]string, logs *decisionlog.Logger, health func() Report, log Logger) (*fiber.App, *engine.Engine) {
	t.Helper()
	eng, err := engine.New(engine.Options{Modules: modules})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if err := eng.Put(context.Background(), []string{"users"}, map[string]any{"admin": "root"}); err != nil {
		t.Fatal(err)
	}
	app := fiber.New(fiber.Config{Immutable: true, DisableStartupMessage: true})
	Register(app, eng, logs, Options{Health: health, NDBuiltinCache: true, Log: log})
	return app, eng
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
	app, _ := newApp(t, nil, func() Report { return report })
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
	plain, _ := newApp(t, nil, nil)
	if code, _, raw := do(t, plain, http.MethodGet, "/ready", "", nil); code != 200 || raw != `{"status":"ready"}` {
		t.Errorf("GET /ready without a report = %d %s, want 200", code, raw)
	}
}

// TestHealth_ReportsTheLoops: /health is 200 with the conversion counts
// when the report is healthy, 503 with the reason and its details when it
// is not, and 200 without details when there is no report.
func TestHealth_ReportsTheLoops(t *testing.T) {
	report := Report{Healthy: false, Message: "bootstrap threshold not met", Bootstrap: &authn.Details{Mode: "strict", SuccessCount: 0, RequiredCount: 1}}
	app, _ := newApp(t, nil, func() Report { return report })
	code, body, raw := do(t, app, http.MethodGet, "/health", "", nil)
	if code != 503 || body["message"] != "bootstrap threshold not met" {
		t.Fatalf("GET /health unhealthy = %d %s, want 503 with the message", code, raw)
	}
	details := body["details"].(map[string]any)
	if details["opaReady"] != true || details["bootstrap"].(map[string]any)["requiredCount"] != float64(1) {
		t.Errorf("details = %v, want opaReady true and the bootstrap counts", details)
	}
	report = Report{Healthy: true, Conversion: &pull.Conversion{PolicySets: 2, Policies: 3}}
	code, body, raw = do(t, app, http.MethodGet, "/health", "", nil)
	if code != 200 || body["status"] != "healthy" || body["policyConversion"].(map[string]any)["policies"] != float64(3) {
		t.Fatalf("GET /health healthy = %d %s, want 200 with the conversion counts", code, raw)
	}
	plain, _ := newApp(t, nil, nil)
	if code, _, raw := do(t, plain, http.MethodGet, "/health", "", nil); code != 200 || raw != `{"status":"healthy"}` {
		t.Fatalf("GET /health without a report = %d %s, want 200 {\"status\":\"healthy\"}", code, raw)
	}
}

// TestAPIVersion_LegacyBody: the body is the legacy JSON, byte for byte,
// with integer versions.
func TestAPIVersion_LegacyBody(t *testing.T) {
	app, _ := newApp(t, nil, nil)
	code, body, raw := do(t, app, http.MethodGet, "/api-version", "", nil)
	if code != 200 || raw != LegacyAPIVersion {
		t.Fatalf("api-version: %d %s", code, raw)
	}
	specs := body["specs"].([]any)
	if first := specs[0].(map[string]any); first["specRootUrl"] != "/access" || first["major"] != float64(3) {
		t.Fatalf("first spec = %v", first)
	}
}

// TestAuthorize_CanonicalRouteDecides: POST /access/v1/authorize evaluates
// the authorize document with the body's input and answers the decision
// envelope, without a decision id when the decisions are not logged.
func TestAuthorize_CanonicalRouteDecides(t *testing.T) {
	app, _ := newApp(t, nil, nil)
	code, body, raw := do(t, app, http.MethodPost, "/access/v1/authorize", `{"input": {"user": "root"}}`, nil)
	if code != 200 {
		t.Fatalf("POST /access/v1/authorize = %d %s, want 200", code, raw)
	}
	if result, _ := body["result"].(map[string]any); result["allowed"] != true {
		t.Errorf("POST /access/v1/authorize = %s, want result.allowed true", raw)
	}
	if _, hasID := body["decision_id"]; hasID {
		t.Errorf("POST /access/v1/authorize = %s, want no decision_id when decisions are not logged", raw)
	}
}

// TestDecide_BadBodyAndUndefined: a malformed body is a 400 in OPA's error
// shape, and an undefined authorize document answers 200 with an empty
// object.
func TestDecide_BadBodyAndUndefined(t *testing.T) {
	app, _ := newApp(t, nil, nil)
	if code, body, _ := do(t, app, http.MethodPost, "/access/v1/authorize", `{"input": `, nil); code != 400 || body["code"] != "invalid_parameter" {
		t.Errorf("bad body: %d %v, want 400 invalid_parameter", code, body)
	}
	// No module declares package authorize, so the document is undefined.
	other, _ := newAppWithModules(t, map[string]string{"other.rego": "package other\n"}, nil, nil, nil)
	if code, _, raw := do(t, other, http.MethodPost, "/access/v1/authorize", `{}`, nil); code != 200 || raw != "{}" {
		t.Errorf("undefined document: %d %s, want 200 {}", code, raw)
	}
}

// TestRegister_TheStoreIsNotWritableOverHTTP: the internal surface serves no
// route that writes a document, so a PUT or a PATCH under /v1/data is 404 and
// the next decision reads the store as it was.
func TestRegister_TheStoreIsNotWritableOverHTTP(t *testing.T) {
	app, _ := newApp(t, nil, nil)
	writes := map[string]string{
		http.MethodPut:   `{"admin": "mallory"}`,
		http.MethodPatch: `[{"op": "replace", "path": "/admin", "value": "mallory"}]`,
	}
	for method, body := range writes {
		if code, _, raw := do(t, app, method, "/v1/data/users", body, nil); code != 404 {
			t.Errorf("%s /v1/data/users = %d %s, want 404", method, code, raw)
		}
	}
	for user, want := range map[string]bool{"root": true, "mallory": false} {
		_, body, raw := do(t, app, http.MethodPost, "/access/v1/authorize", `{"input": {"user": "`+user+`"}}`, nil)
		if result, _ := body["result"].(map[string]any); result["allowed"] != want {
			t.Errorf("decision for %s after the writes = %s, want result.allowed %t", user, raw, want)
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
func (l *levels) WarnC(_ context.Context, format string, args ...any) {
	l.record("warn", format, args...)
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
// author asks for, and it names the document and whether it was defined. It
// is debug because every request writes one, and it carries neither the
// input nor the result: those hold the caller's token and claims, and the
// decision log is where they are recorded.
func TestDecide_ReportsTheDecisionAtDebug(t *testing.T) {
	reported := &levels{}
	app, _ := newAppWithLog(t, nil, nil, reported)

	if code, _, _ := do(t, app, http.MethodPost, "/access/v1/authorize", `{"input": {"user": "alice"}}`, nil); code != 200 {
		t.Fatalf("POST /access/v1/authorize = %d, want 200", code)
	}
	debug := reported.at("debug")
	if len(debug) != 1 {
		t.Fatalf("one decision reported %v, want one debug line", reported.lines)
	}
	if !strings.Contains(debug[0], "path=authorize") || !strings.Contains(debug[0], "defined=true") {
		t.Errorf("the decision reported %q, want the path authorize and defined=true", debug[0])
	}
	if strings.Contains(debug[0], "alice") {
		t.Errorf("the decision reported %q, which carries the input; the decision log records that", debug[0])
	}
}

// conflictingPolicies makes the decision fail at evaluation rather than
// deciding: two complete definitions of allowed produce different values for
// the same request, which OPA reports as a conflict.
const conflictingPolicies = `package authorize

import rego.v1

allowed := true if input.user != ""

allowed := false if input.user != ""
`

// TestDecide_ReportsADecisionThatCouldNotBeEvaluated: a policy that fails to
// evaluate answers 500, and the decision log records nothing for a decision
// that was never made, so the error line is the only account of it. A caller
// that passes no logger gets no line and the same answer.
func TestDecide_ReportsADecisionThatCouldNotBeEvaluated(t *testing.T) {
	reported := &levels{}
	for name, log := range map[string]Logger{"a logger was passed": reported, "no logger was passed": nil} {
		t.Run(name, func(t *testing.T) {
			app, _ := newAppWithModules(t, map[string]string{"authorize.rego": conflictingPolicies}, nil, nil, log)

			code, body, _ := do(t, app, http.MethodPost, "/access/v1/authorize", `{"input": {"user": "alice"}}`, nil)
			if code != 500 || body["code"] != "internal_error" {
				t.Fatalf("POST /access/v1/authorize under a failing policy = %d %v, want 500 internal_error", code, body)
			}
		})
	}
	errors := reported.at("error")
	if len(errors) != 1 {
		t.Fatalf("a decision that could not be evaluated reported %v, want one error", reported.lines)
	}
	if !strings.Contains(errors[0], "path=authorize") {
		t.Errorf("the failure reported %q, want the path authorize", errors[0])
	}
}

// TestDecide_LogsTheDecision: with logging on, the response carries a
// decision_id and the event holds the input, the result, the recorded
// header, and the non-deterministic builtin cache.
func TestDecide_LogsTheDecision(t *testing.T) {
	received := make(chan []decisionlog.Event, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gz, err := gzipReader(r.Body)
		if err != nil {
			t.Errorf("gzip: %v", err)
			return
		}
		var batch []decisionlog.Event
		if err := json.NewDecoder(gz).Decode(&batch); err != nil {
			t.Errorf("decode: %v", err)
		}
		received <- batch
	}))
	defer srv.Close()
	logs := decisionlog.New(decisionlog.Config{URL: srv.URL, Headers: []string{"x-request-id"}, FlushInterval: 20 * time.Millisecond}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go logs.Run(ctx)
	app, _ := newApp(t, logs, nil)
	code, body, _ := do(t, app, http.MethodPost, "/access/v1/authorize", `{"input": {"user": "root"}}`, map[string]string{"X-Request-Id": "req-1"})
	if code != 200 || body["decision_id"] == nil {
		t.Fatalf("logged decision: %d %v", code, body)
	}
	select {
	case batch := <-received:
		cancel()
		logs.Wait()
		if len(batch) != 1 {
			t.Fatalf("batch size %d", len(batch))
		}
		ev := batch[0]
		if ev.DecisionID != body["decision_id"] || ev.Path != "authorize" {
			t.Errorf("event %+v", ev)
		}
		if ev.Input.(map[string]any)["user"] != "root" || ev.Result.(map[string]any)["allowed"] != true {
			t.Errorf("input/result not recorded: %+v", ev)
		}
		if ev.RequestContext == nil || ev.RequestContext.HTTP.Headers["x-request-id"][0] != "req-1" {
			t.Errorf("request header not recorded: %+v", ev.RequestContext)
		}
		if ev.NDBuiltinCache == nil {
			t.Errorf("nd_builtin_cache missing (time.now_ns was called)")
		}
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("no decision log upload within 3s")
	}
}

// TestDecide_WithoutLogging: a decision is answered as usual when the
// decisions are not logged, and carries no decision id. The builtin cache is
// not built on that path either, which the decision cannot show; the
// condition is shared with the id, so this is where it would break.
func TestDecide_WithoutLogging(t *testing.T) {
	eng, err := engine.New(engine.Options{Modules: map[string]string{"authorize.rego": testPolicies}})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if err := eng.Put(context.Background(), []string{"users"}, map[string]any{"admin": "root"}); err != nil {
		t.Fatal(err)
	}
	app := fiber.New(fiber.Config{Immutable: true, DisableStartupMessage: true})
	// A logger with neither a collector nor a store is off, as the service
	// runs without AUTHZ_DECISION_LOG_URL and AUTHZ_DECISION_LOG_FILE.
	logs := decisionlog.New(decisionlog.Config{}, nil)
	Register(app, eng, logs, Options{NDBuiltinCache: true})

	code, body, raw := do(t, app, http.MethodPost, "/access/v1/authorize", `{"input": {"user": "root"}}`, nil)
	if code != 200 || body["result"].(map[string]any)["allowed"] != true {
		t.Fatalf("POST /access/v1/authorize = %d %s, want the decision", code, raw)
	}
	if _, logged := body["decision_id"]; logged {
		t.Errorf("body = %s, want no decision id when the decisions are not logged", raw)
	}
}

// TestDecide_WithoutTheBuiltinCache: with the cache off the decision is
// answered and logged as before, and the event carries no
// nd_builtin_cache, so the PIP requests and responses are not recorded.
func TestDecide_WithoutTheBuiltinCache(t *testing.T) {
	received := make(chan []decisionlog.Event, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gz, err := gzipReader(r.Body)
		if err != nil {
			t.Errorf("gzip: %v", err)
			return
		}
		var batch []decisionlog.Event
		if err := json.NewDecoder(gz).Decode(&batch); err != nil {
			t.Errorf("decode: %v", err)
		}
		received <- batch
	}))
	defer srv.Close()
	logs := decisionlog.New(decisionlog.Config{URL: srv.URL, FlushInterval: 20 * time.Millisecond}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go logs.Run(ctx)
	eng, err := engine.New(engine.Options{Modules: map[string]string{"authorize.rego": testPolicies}})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	app := fiber.New(fiber.Config{Immutable: true, DisableStartupMessage: true})
	Register(app, eng, logs, Options{NDBuiltinCache: false})

	if code, body, raw := do(t, app, http.MethodPost, "/access/v1/authorize", `{"input": {"user": "root"}}`, nil); code != 200 || body["decision_id"] == nil {
		t.Fatalf("POST /access/v1/authorize = %d %s, want 200 with a decision id", code, raw)
	}
	select {
	case batch := <-received:
		if len(batch) != 1 || batch[0].Result == nil {
			t.Fatalf("batch = %+v, want one event with its result", batch)
		}
		if batch[0].NDBuiltinCache != nil {
			t.Errorf("nd_builtin_cache = %v, want none with the cache off", batch[0].NDBuiltinCache)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no decision log upload within 3s")
	}
}
