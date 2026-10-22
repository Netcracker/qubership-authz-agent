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

// testPolicies mirror the shape of the product policies: a decision that
// allows each resource when the subject token names data.users.admin, and a
// non-deterministic builtin for the decision log to record.
const testPolicies = `package authorize

import rego.v1

rlsIgnored := false

results := [{"isAllowed": input.subject == concat(" ", ["Bearer", data.users.admin])} | some _ in input.resources]

now := time.now_ns()
`

// newApp builds the internal surface over testPolicies, with
// data.users.admin set to root.
func newApp(t *testing.T, logs *decisionlog.Logger, health func() Report) (*fiber.App, *engine.Engine) {
	t.Helper()
	eng, err := engine.New(engine.Options{Modules: map[string]string{"authorize.rego": testPolicies}})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if err := eng.Put(context.Background(), []string{"users"}, map[string]any{"admin": "root"}); err != nil {
		t.Fatal(err)
	}
	app := fiber.New(fiber.Config{Immutable: true, DisableStartupMessage: true})
	Register(app, eng, logs, Options{Health: health, NDBuiltinCache: true})
	return app, eng
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

// TestRegister_TheStoreIsNotWritableOverHTTP: the internal surface serves no
// route that writes a document, so a PUT or a PATCH under /v1/data is 404 and
// the store holds what it held before.
func TestRegister_TheStoreIsNotWritableOverHTTP(t *testing.T) {
	app, eng := newApp(t, nil, nil)
	writes := map[string]string{
		http.MethodPut:   `{"admin": "mallory"}`,
		http.MethodPatch: `[{"op": "replace", "path": "/admin", "value": "mallory"}]`,
	}
	for method, body := range writes {
		if code, _, raw := do(t, app, method, "/v1/data/users", body, nil); code != 404 {
			t.Errorf("%s /v1/data/users = %d %s, want 404", method, code, raw)
		}
	}
	admin, _, err := eng.Eval(context.Background(), []string{"users", "admin"}, nil, nil)
	if err != nil || admin != "root" {
		t.Errorf("data.users.admin after the writes = %v (%v), want root", admin, err)
	}
}

// TestRegister_ServesNoDecision: the internal surface has no decision route,
// so a decision request there is 404 like any path it does not serve.
func TestRegister_ServesNoDecision(t *testing.T) {
	app, _ := newApp(t, nil, nil)
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
	app := newPublicAppOver(t, map[string]string{"authorize.rego": testPolicies}, nil, Options{Log: reported})

	if code, _, raw := checkAs(t, app, "alice", nil); code != 200 {
		t.Fatalf("POST /access/v1/check/resource = %d %s, want 200", code, raw)
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

allowed := true if input.subject != ""

allowed := false if input.subject != ""

results := [{"isAllowed": allowed} | some _ in input.resources]
`

// TestDecide_ReportsADecisionThatCouldNotBeEvaluated: a policy that fails to
// evaluate answers 500, and the decision log records nothing for a decision
// that was never made, so the error line is the only account of it. A caller
// that passes no logger gets no line and the same answer.
func TestDecide_ReportsADecisionThatCouldNotBeEvaluated(t *testing.T) {
	reported := &levels{}
	for name, log := range map[string]Logger{"a logger was passed": reported, "no logger was passed": nil} {
		t.Run(name, func(t *testing.T) {
			app := newPublicAppOver(t, map[string]string{"authorize.rego": conflictingPolicies}, nil, Options{Log: log})

			code, body, _ := checkAs(t, app, "alice", nil)
			if code != 500 || body["code"] != "internal_error" {
				t.Fatalf("POST /access/v1/check/resource under a failing policy = %d %v, want 500 internal_error", code, body)
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

// TestDecide_LogsTheDecision: with logging on, the event of a check request
// holds a decision id, the input, the result, the recorded header, and the
// non-deterministic builtin cache.
func TestDecide_LogsTheDecision(t *testing.T) {
	logs, events, stop := collector(t)
	defer stop()
	app := newPublicAppOver(t, map[string]string{"authorize.rego": testPolicies}, logs, Options{NDBuiltinCache: true})

	if code, _, raw := checkAs(t, app, "root", map[string]string{"X-Request-Id": "req-1"}); code != 200 || raw != "true" {
		t.Fatalf("POST /access/v1/check/resource = %d %s, want 200 true", code, raw)
	}
	ev := nextEvent(t, events)
	if ev.DecisionID == "" || ev.Path != "authorize" {
		t.Errorf("event %+v, want a decision id and the path authorize", ev)
	}
	if ev.Input.(map[string]any)["subject"] != "Bearer root" {
		t.Errorf("input = %v, want the subject token", ev.Input)
	}
	if results, _ := ev.Result.(map[string]any)["results"].([]any); len(results) != 1 || results[0].(map[string]any)["isAllowed"] != true {
		t.Errorf("result = %v, want one allowed resource", ev.Result)
	}
	if ev.RequestContext == nil || ev.RequestContext.HTTP.Headers["x-request-id"][0] != "req-1" {
		t.Errorf("request header not recorded: %+v", ev.RequestContext)
	}
	if ev.NDBuiltinCache == nil {
		t.Errorf("nd_builtin_cache missing (time.now_ns was called)")
	}
	select {
	case extra := <-events:
		t.Errorf("a second event %+v for one request, want one", extra)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestDecide_AnUndefinedDecisionCarriesItsIDOnlyWhenLogged: a check request
// whose decision is undefined is answered with the bare envelope, which
// holds the id of the logged decision when the decisions are logged and
// nothing when they are not. The builtin cache is built on the logged path alone, which the
// answer cannot show; the condition is shared with the id, so this is where
// it would break.
func TestDecide_AnUndefinedDecisionCarriesItsIDOnlyWhenLogged(t *testing.T) {
	undefined := map[string]string{"other.rego": "package other\n"}
	// A logger with neither a collector nor a store is off, as the service
	// runs without AUTHZ_DECISION_LOG_URL and AUTHZ_DECISION_LOG_FILE.
	off := newPublicAppOver(t, undefined, decisionlog.New(decisionlog.Config{}, nil), Options{NDBuiltinCache: true})
	if code, _, raw := checkAs(t, off, "root", nil); code != 200 || raw != "{}" {
		t.Errorf("undefined decision, not logged = %d %s, want 200 {}", code, raw)
	}
	logs, events, stop := collector(t)
	defer stop()
	on := newPublicAppOver(t, undefined, logs, Options{NDBuiltinCache: true})
	code, body, raw := checkAs(t, on, "root", nil)
	if code != 200 || len(body) != 1 || body["decision_id"] == nil {
		t.Errorf("undefined decision, logged = %d %s, want 200 with the decision id alone", code, raw)
	}
	if ev := nextEvent(t, events); ev.DecisionID != body["decision_id"] {
		t.Errorf("logged decision id %q, want the id of the answer, %v", ev.DecisionID, body["decision_id"])
	}
}

// TestDecide_WithoutTheBuiltinCache: with the cache off the decision is
// answered and logged as before, and the event carries no
// nd_builtin_cache, so the PIP requests and responses are not recorded.
func TestDecide_WithoutTheBuiltinCache(t *testing.T) {
	logs, events, stop := collector(t)
	defer stop()
	app := newPublicAppOver(t, map[string]string{"authorize.rego": testPolicies}, logs, Options{NDBuiltinCache: false})

	if code, _, raw := checkAs(t, app, "root", nil); code != 200 || raw != "true" {
		t.Fatalf("POST /access/v1/check/resource = %d %s, want 200 true", code, raw)
	}
	ev := nextEvent(t, events)
	if ev.Result == nil {
		t.Fatalf("event = %+v, want one with its result", ev)
	}
	if ev.NDBuiltinCache != nil {
		t.Errorf("nd_builtin_cache = %v, want none with the cache off", ev.NDBuiltinCache)
	}
}
