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

	"authz-agent/components/authz-agent/internal/decisionlog"
	"authz-agent/components/authz-agent/internal/engine"
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

func newApp(t *testing.T, authorization bool, logs *decisionlog.Logger, ready func() bool) (*fiber.App, *engine.Engine) {
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
	Register(app, eng, logs, Options{Authorization: authorization, Ready: ready})
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

// TestHealth_ReflectsReadiness: /health answers the agent's contract, 200
// with status healthy, and 503 while the engine is not ready.
func TestHealth_ReflectsReadiness(t *testing.T) {
	ready := false
	app, _ := newApp(t, false, nil, func() bool { return ready })
	if code, body, _ := do(t, app, http.MethodGet, "/health", "", nil); code != 503 || body["status"] != "unhealthy" {
		t.Fatalf("not ready: %d %v", code, body)
	}
	ready = true
	if code, body, _ := do(t, app, http.MethodGet, "/health", "", nil); code != 200 || body["status"] != "healthy" {
		t.Fatalf("ready: %d %v", code, body)
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
// input.params, so ?explain=full on the decision endpoint is refused.
func TestAuthorize_ExplainIsRefused(t *testing.T) {
	app, _ := newApp(t, true, nil, nil)
	if code, _, _ := do(t, app, http.MethodPost, "/v1/data/authorize?explain=full", `{"input": {}}`, nil); code != 401 {
		t.Fatalf("explain: %d", code)
	}
	if code, _, _ := do(t, app, http.MethodPost, "/v1/data/authorize?metrics=true", `{"input": {}}`, nil); code != 200 {
		t.Fatalf("metrics param must not be refused: %d", code)
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
