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
// document and a system.authz guard that opens POST authorize, guards writes
// with the secret, and refuses explain on the decision endpoint.
const testPolicies = `package authorize

import rego.v1

allowed := input.user == data.users.admin

now := time.now_ns()
`

const testAuthz = `package system.authz

import rego.v1

default allow := false

allow if {
	input.method == "POST"
	input.path == ["v1", "data", "authorize"]
	not input.params.explain
}

allow if {
	input.method == "PUT"
	input.path[0] == "v1"
	input.identity == data.opa_auth_secret
}

allow if {
	input.method == "GET"
	input.path == ["v1", "data", "users"]
	input.identity == data.opa_auth_secret
}
`

func newApp(t *testing.T, authorization bool, logs *decisionlog.Logger, health func() Report) (*fiber.App, *engine.Engine) {
	t.Helper()
	eng, err := engine.New(engine.Options{Modules: map[string]string{"authorize.rego": testPolicies, "authz.rego": testAuthz}})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if err := eng.Put(context.Background(), []string{"opa_auth_secret"}, "s3cr3t"); err != nil {
		t.Fatal(err)
	}
	if err := eng.Put(context.Background(), []string{"users"}, map[string]any{"admin": "root"}); err != nil {
		t.Fatal(err)
	}
	app := fiber.New(fiber.Config{Immutable: true, DisableStartupMessage: true})
	Register(app, eng, logs, Options{Authorization: authorization, Health: health, NDBuiltinCache: true})
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
	app, _ := newApp(t, false, nil, func() Report { return report })
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
	plain, _ := newApp(t, false, nil, nil)
	if code, _, raw := do(t, plain, http.MethodGet, "/ready", "", nil); code != 200 || raw != `{"status":"ready"}` {
		t.Errorf("GET /ready without a report = %d %s, want 200", code, raw)
	}
}

// TestHealth_ReportsTheLoops: /health is 200 with the conversion counts
// when the report is healthy, 503 with the reason and its details when it
// is not, and 200 without details when there is no report.
func TestHealth_ReportsTheLoops(t *testing.T) {
	report := Report{Healthy: false, Message: "bootstrap threshold not met", Bootstrap: &authn.Details{Mode: "strict", SuccessCount: 0, RequiredCount: 1}}
	app, _ := newApp(t, false, nil, func() Report { return report })
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
	plain, _ := newApp(t, false, nil, nil)
	if code, _, raw := do(t, plain, http.MethodGet, "/health", "", nil); code != 200 || raw != `{"status":"healthy"}` {
		t.Fatalf("GET /health without a report = %d %s, want 200 {\"status\":\"healthy\"}", code, raw)
	}
}

// TestAPIVersion_LegacyBody: the body is the legacy JSON, byte for byte,
// with integer versions.
func TestAPIVersion_LegacyBody(t *testing.T) {
	app, _ := newApp(t, false, nil, nil)
	code, body, raw := do(t, app, http.MethodGet, "/api-version", "", nil)
	if code != 200 || raw != LegacyAPIVersion {
		t.Fatalf("api-version: %d %s", code, raw)
	}
	specs := body["specs"].([]any)
	if first := specs[0].(map[string]any); first["specRootUrl"] != "/access" || first["major"] != float64(3) {
		t.Fatalf("first spec = %v", first)
	}
}

// TestAuthorize_CanonicalRouteAndDataAPIAgree: the native /access/v1/authorize
// and the data API path return the same decision envelope.
func TestAuthorize_CanonicalRouteAndDataAPIAgree(t *testing.T) {
	app, _ := newApp(t, true, nil, nil)
	body := `{"input": {"user": "root"}}`
	code1, r1, _ := do(t, app, http.MethodPost, "/access/v1/authorize", body, nil)
	code2, r2, _ := do(t, app, http.MethodPost, "/v1/data/authorize", body, nil)
	if code1 != 200 || code2 != 200 {
		t.Fatalf("statuses %d %d", code1, code2)
	}
	res1 := r1["result"].(map[string]any)
	res2 := r2["result"].(map[string]any)
	if res1["allowed"] != true || res2["allowed"] != true {
		t.Fatalf("allowed: %v %v", res1, res2)
	}
	if _, hasID := r1["decision_id"]; hasID {
		t.Fatal("decision_id must be absent when decisions are not logged")
	}
}

// TestDecide_BadBodyAndUndefined: a malformed body is a 400 in OPA's error
// shape, and an undefined document answers 200 with an empty object.
func TestDecide_BadBodyAndUndefined(t *testing.T) {
	app, _ := newApp(t, false, nil, nil)
	if code, body, _ := do(t, app, http.MethodPost, "/v1/data/authorize", `{"input": `, nil); code != 400 || body["code"] != "invalid_parameter" {
		t.Fatalf("bad body: %d %v", code, body)
	}
	if code, _, raw := do(t, app, http.MethodPost, "/v1/data/nothing", `{}`, nil); code != 200 || raw != "{}" {
		t.Fatalf("undefined document: %d %s", code, raw)
	}
}

// TestDataAPI_GuardedByPolicy: without the secret a write and a read are
// refused with 401 in OPA's shape; with it, PUT stores, GET reads, and the
// next decision sees the new document. PATCH is what the test policy does
// not open, so it stays refused even with the secret.
func TestDataAPI_GuardedByPolicy(t *testing.T) {
	app, _ := newApp(t, true, nil, nil)
	if code, body, _ := do(t, app, http.MethodPut, "/v1/data/users", `{"admin": "x"}`, nil); code != 401 || body["code"] != "unauthorized" {
		t.Fatalf("PUT without secret: %d %v", code, body)
	}
	if code, _, _ := do(t, app, http.MethodGet, "/v1/data/users", "", nil); code != 401 {
		t.Fatalf("GET without secret: %d", code)
	}
	auth := map[string]string{"Authorization": "Bearer s3cr3t"}
	if code, _, _ := do(t, app, http.MethodPut, "/v1/data/users", `{"admin": "alice"}`, auth); code != 204 {
		t.Fatalf("PUT with secret: %d", code)
	}
	if code, body, _ := do(t, app, http.MethodGet, "/v1/data/users", "", auth); code != 200 || body["result"].(map[string]any)["admin"] != "alice" {
		t.Fatalf("GET after PUT: %d %v", code, body)
	}
	if code, body, _ := do(t, app, http.MethodPost, "/v1/data/authorize", `{"input": {"user": "alice"}}`, nil); code != 200 || body["result"].(map[string]any)["allowed"] != true {
		t.Fatalf("decision after PUT: %d %v", code, body)
	}
	if code, _, _ := do(t, app, http.MethodPatch, "/v1/data/authn", `[{"op":"add","path":"/k","value":1}]`, auth); code != 401 {
		t.Fatalf("PATCH is not allowed by the test policy: %d", code)
	}
}

// TestDataAPI_WriteSemantics: with the guard off, PATCH on a missing
// document is 404 so a writer can fall back to PUT, PATCH on an existing one
// updates it, an unsupported op and a bad body are 400, the root cannot be
// replaced, and a missing document reads as an empty object.
func TestDataAPI_WriteSemantics(t *testing.T) {
	app, _ := newApp(t, false, nil, nil)
	cases := []struct {
		name, method, path, body string
		status                   int
		code                     string
	}{
		{"patch missing document", http.MethodPatch, "/v1/data/authn", `[{"op":"add","path":"/k","value":1}]`, 404, "resource_not_found"},
		{"patch existing document", http.MethodPatch, "/v1/data/users", `[{"op":"add","path":"/admin","value":"bob"}]`, 204, ""},
		{"patch with an unsupported op", http.MethodPatch, "/v1/data/users", `[{"op":"move","path":"/admin"}]`, 400, "invalid_parameter"},
		{"put on the root", http.MethodPut, "/v1/data/", `{}`, 400, "invalid_parameter"},
		{"put with a bad body", http.MethodPut, "/v1/data/users", `{`, 400, "invalid_parameter"},
	}
	for _, tc := range cases {
		code, body, _ := do(t, app, tc.method, tc.path, tc.body, nil)
		if code != tc.status || (tc.code != "" && body["code"] != tc.code) {
			t.Errorf("%s: %d %v, want %d %s", tc.name, code, body, tc.status, tc.code)
		}
	}
	if code, _, raw := do(t, app, http.MethodGet, "/v1/data/missing", "", nil); code != 200 || raw != "{}" {
		t.Fatalf("GET missing: %d %s", code, raw)
	}
}

// TestAuthorize_ExplainIsRefused: query parameters reach the policy as
// input.params, so ?explain=full on the decision endpoint is refused, on
// the canonical route as on the data API.
func TestAuthorize_ExplainIsRefused(t *testing.T) {
	app, _ := newApp(t, true, nil, nil)
	for _, path := range []string{"/v1/data/authorize", "/access/v1/authorize"} {
		if code, _, _ := do(t, app, http.MethodPost, path+"?explain=full", `{"input": {}}`, nil); code != 401 {
			t.Errorf("POST %s?explain=full = %d, want 401", path, code)
		}
		if code, _, _ := do(t, app, http.MethodPost, path+"?metrics=true", `{"input": {}}`, nil); code != 200 {
			t.Errorf("POST %s?metrics=true = %d, want 200", path, code)
		}
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
	app, _ := newApp(t, false, logs, nil)
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
	eng, err := engine.New(engine.Options{Modules: map[string]string{"authorize.rego": testPolicies, "authz.rego": testAuthz}})
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
