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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"authz-agent/components/authz-agent/internal/decisionlog"
	"authz-agent/components/authz-agent/internal/engine"
)

// publicPolicy stands in for the product policies on the public routes: a
// request without a subject is refused with an authError, a READ is
// allowed and any other operation denied, and each result carries an rsql
// predicate naming the resource type, so a test can tell from the response
// which resources reached the policy.
const publicPolicy = `package authorize

import rego.v1

authError := {"status": 403, "message": "no subject"} if input.subject == ""

rlsIgnored := false

results := [r |
	some res in input.resources
	r := {
		"isAllowed": res.operation == "READ",
		"predicates": [{"predicateType": "rsql", "predicate": sprintf("type==%v", [res.resourceType])}],
	}
]
`

// newPublicApp builds the public surface over publicPolicy and the guard of
// testAuthz, with the routing options main uses. papClient and collector
// are the base URLs the relays target, "" for none.
func newPublicApp(t *testing.T, authorization bool, logs *decisionlog.Logger, papClient, collector string) *fiber.App {
	t.Helper()
	eng, err := engine.New(engine.Options{Modules: map[string]string{"authorize.rego": publicPolicy, "authz.rego": testAuthz}})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	srv := Register(fiber.New(fiber.Config{Immutable: true, DisableStartupMessage: true}), eng, logs,
		Options{Authorization: authorization, PapClientURL: papClient, CollectorURL: collector, NDBuiltinCache: true})
	app := fiber.New(fiber.Config{Immutable: true, StrictRouting: true, CaseSensitive: true, DisableStartupMessage: true})
	srv.RegisterPublic(app)
	return app
}

// call sends one request and returns the status, the body, and the
// Content-Type of the response.
func call(t *testing.T, app *fiber.App, method, path, body string, headers map[string]string) (int, string, string) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw), resp.Header.Get(fiber.HeaderContentType)
}

var admin = map[string]string{"Authorization": "Bearer m2m", "Incoming-Token": "Bearer admin"}

// TestPublic_CheckResource: the v1 route answers a bare boolean and the v2
// route {"decision": bool}, both as JSON, from the first result.
func TestPublic_CheckResource(t *testing.T) {
	app := newPublicApp(t, false, nil, "", "")
	cases := []struct {
		name, path, body, want string
	}{
		{"v1 allowed", "/access/v1/check/resource?tenant_id=default", `{"type":"ORDER","operation":"READ","resource":{}}`, `true`},
		{"v1 denied", "/access/v1/check/resource", `{"type":"ORDER","operation":"DELETE"}`, `false`},
		{"v2 allowed", "/access/v2/check/resource?obligations=false", `{"type":"ORDER","operation":"READ"}`, `{"decision":true}`},
		{"v2 denied", "/access/v2/check/resource", `{"type":"ORDER","operation":"DELETE"}`, `{"decision":false}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body, contentType := call(t, app, http.MethodPost, tc.path, tc.body, admin)
			if code != 200 || body != tc.want || contentType != fiber.MIMEApplicationJSON {
				t.Errorf("POST %s = %d %s (%s), want 200 %s (%s)", tc.path, code, body, contentType, tc.want, fiber.MIMEApplicationJSON)
			}
		})
	}
}

// TestPublic_CheckResource_Refusals: a request the legacy API rejects is a
// 400 with the legacy message before any policy runs; a request the policy
// refuses carries the authError's status and message; and a GET reaches
// the handler like a POST, so its empty body is what is rejected.
func TestPublic_CheckResource_Refusals(t *testing.T) {
	app := newPublicApp(t, false, nil, "", "")
	cases := []struct {
		name, method, body string
		headers            map[string]string
		status             int
		want               string
	}{
		{"an empty body", http.MethodPost, ``, admin, 400, `{"message":"bad request"}`},
		{"a missing type", http.MethodPost, `{"resource":{"id":"1"}}`, admin, 400, `{"message":"Missing required parameter: type"}`},
		{"no subject", http.MethodPost, `{"type":"ORDER","operation":"READ"}`, nil, 403, `{"message":"no subject"}`},
		{"a GET without a body", http.MethodGet, ``, admin, 400, `{"message":"bad request"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body, _ := call(t, app, tc.method, "/access/v1/check/resource", tc.body, tc.headers)
			if code != tc.status || body != tc.want {
				t.Errorf("%s /access/v1/check/resource = %d %s, want %d %s", tc.method, code, body, tc.status, tc.want)
			}
		})
	}
}

// TestPublic_Bulk: the bulk route lists the allowed ids and the
// bulk/operations routes group them by operation; a bulk/operations request
// without a single operation is answered without the policy, so it needs no
// token.
func TestPublic_Bulk(t *testing.T) {
	app := newPublicApp(t, false, nil, "", "")
	cases := []struct {
		name, path, body string
		headers          map[string]string
		status           int
		want             string
	}{
		{"bulk lists the allowed ids", "/access/v1/check/resource/bulk?tenant_id=default",
			`[{"id":"a","type":"ORDER","operation":"READ"},{"id":"b","type":"ORDER","operation":"DELETE"},{"type":"ORDER","operation":"READ"}]`,
			admin, 200, `["a"]`},
		{"bulk refuses duplicate ids", "/access/v1/check/resource/bulk",
			`[{"id":"a","type":"ORDER","operation":"READ"},{"id":"a","type":"ORDER","operation":"READ"}]`,
			admin, 400, `{"message":"Duplicate resource id in bulk request: resource ids must be unique"}`},
		{"v1 bulk/operations groups by operation", "/access/v1/check/resource/bulk/operations",
			`[{"id":"a","type":"ORDER","operations":["READ","DELETE"]},{"id":"b","type":"ORDER","operations":["READ"]}]`,
			admin, 200, `{"DELETE":[],"READ":["a","b"]}`},
		{"v1 preview is the same route", "/preview/v1/check/resource/bulk/operations",
			`[{"id":"a","type":"ORDER","operations":["READ"]}]`, admin, 200, `{"READ":["a"]}`},
		{"v2 bulk/operations wraps the map", "/access/v2/check/resource/bulk/operations",
			`{"type":"ORDER","entries":[{"id":"a","operations":["READ","DELETE"]}]}`, admin, 200, `{"decision":{"DELETE":[],"READ":["a"]}}`},
		{"v2 preview is the same route", "/preview/v2/check/resource/bulk/operations",
			`{"type":"ORDER","entries":[{"id":"a","operations":["DELETE"]}]}`, admin, 200, `{"decision":{"DELETE":[]}}`},
		{"v1 without an operation needs no token", "/access/v1/check/resource/bulk/operations",
			`[{"id":"a","type":"ORDER","operations":[""]}]`, nil, 200, `{}`},
		{"v2 without an operation needs no token", "/access/v2/check/resource/bulk/operations",
			`{"type":"ORDER","entries":[{"id":"a","operations":[""]}]}`, nil, 200, `{"decision":{}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body, _ := call(t, app, http.MethodPost, tc.path, tc.body, tc.headers)
			if code != tc.status || body != tc.want {
				t.Errorf("POST %s = %d %s, want %d %s", tc.path, code, body, tc.status, tc.want)
			}
		})
	}
}

// TestPublic_Filter: the filter routes read the query, not the body, and
// answer the legacy filter shape with the policy's predicates.
func TestPublic_Filter(t *testing.T) {
	app := newPublicApp(t, false, nil, "", "")
	const useFilter = `{"calculationResult":"USE_FILTER_CONDITION","filterCondition":"","mongodbFilterCondition":"","rsqlFilterCondition":"type==ORDER","sqlFilterCondition":"","customFilterCondition":null}`
	const denied = `{"calculationResult":"DENY","filterCondition":"","mongodbFilterCondition":"","rsqlFilterCondition":"","sqlFilterCondition":"","customFilterCondition":null}`
	cases := []struct {
		name, path, body string
		status           int
		want             string
	}{
		{"v1 with an operation", "/access/v1/check/filter?resourceType=ORDER&operation=READ&tenant_id=default", "", 200, useFilter},
		{"v2 is the same shape", "/access/v2/check/filter?resourceType=ORDER&operation=READ", "", 200, useFilter},
		{"a denied operation", "/access/v1/check/filter?resourceType=ORDER&operation=DELETE", "", 200, denied},
		{"the last resourceType wins", "/access/v1/check/filter?resourceType=DOC&resourceType=ORDER&operation=READ", "", 200, useFilter},
		{"a body is ignored", "/access/v1/check/filter?resourceType=ORDER&operation=READ", `{"type":"DOC","operation":"DELETE"}`, 200, useFilter},
		{"no resourceType", "/access/v1/check/filter?operation=READ", "", 400, `{"message":"bad request"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body, _ := call(t, app, http.MethodPost, tc.path, tc.body, admin)
			if code != tc.status || body != tc.want {
				t.Errorf("POST %s = %d %s, want %d %s", tc.path, code, body, tc.status, tc.want)
			}
		})
	}
}

// TestPublic_Surface: the routes Envoy exposed answer as they did, and
// everything else, the data API included, is 404 {"message":"not found"}.
// The canonical route runs the data API guard, so ?explain=full is refused.
func TestPublic_Surface(t *testing.T) {
	app := newPublicApp(t, true, nil, "", "")
	authorize := `{"input":{"subject":"Bearer admin","resources":[{"resourceType":"ORDER","operation":"READ"}]}}`
	cases := []struct {
		name, method, path, body string
		status                   int
		want                     string
	}{
		{"the canonical route is the data API decision", http.MethodPost, "/access/v1/authorize", authorize, 200,
			`{"result":{"results":[{"isAllowed":true,"predicates":[{"predicate":"type==ORDER","predicateType":"rsql"}]}],"rlsIgnored":false}}`},
		{"explain is refused on the canonical route", http.MethodPost, "/access/v1/authorize?explain=full", authorize, 401,
			`{"code":"unauthorized","message":"unauthorized resource access"}`},
		{"the data API is hidden", http.MethodPost, "/v1/data/authorize", authorize, 404, `{"message":"not found"}`},
		{"an unknown path", http.MethodGet, "/unknown/endpoint", "", 404, `{"message":"not found"}`},
		{"a check route with a trailing slash", http.MethodPost, "/access/v1/check/resource/", `{"type":"ORDER","operation":"READ"}`, 404, `{"message":"not found"}`},
		{"a mistyped check route", http.MethodPost, "/access/v1/check/resourc", `{"type":"ORDER","operation":"READ"}`, 404, `{"message":"not found"}`},
		{"api-version by GET", http.MethodGet, "/api-version", "", 200, LegacyAPIVersion},
		{"api-version by POST", http.MethodPost, "/api-version", "", 200, LegacyAPIVersion},
		{"the decision-log download without a pap-client", http.MethodGet, "/internal/v1/decision-logs", "", 404, `{"message":"not found"}`},
		{"health by GET without a pap-client", http.MethodGet, "/health", "", 200, `{"status":"healthy"}`},
		{"health by POST without a pap-client", http.MethodPost, "/health", "", 405, `{"message":"method not allowed"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body, _ := call(t, app, tc.method, tc.path, tc.body, nil)
			if code != tc.status || body != tc.want {
				t.Errorf("%s %s = %d %s, want %d %s", tc.method, tc.path, code, body, tc.status, tc.want)
			}
		})
	}
}

// TestPublic_CanonicalRouteUnderOtherMethods: a method other than POST on
// the canonical route is 405 once the guard has let it through, and the
// guard sees the method itself, so a GET the policy does not open is 401.
func TestPublic_CanonicalRouteUnderOtherMethods(t *testing.T) {
	open := newPublicApp(t, false, nil, "", "")
	if code, body, _ := call(t, open, http.MethodGet, "/access/v1/authorize", "", nil); code != 405 || !strings.Contains(body, "Method Not Allowed") {
		t.Errorf("GET /access/v1/authorize without the guard = %d %s, want 405 Method Not Allowed", code, body)
	}
	guarded := newPublicApp(t, true, nil, "", "")
	if code, body, _ := call(t, guarded, http.MethodGet, "/access/v1/authorize", "", nil); code != 401 || !strings.Contains(body, `"code":"unauthorized"`) {
		t.Errorf("GET /access/v1/authorize with the guard = %d %s, want 401 unauthorized", code, body)
	}
}

// TestPublic_CheckRoutesRunTheGuard: a check route runs the guard as
// POST /v1/data/authorize with its own query parameters, whatever the
// request's method, as the Lua rewrite did, so plain parameters pass and
// ?explain=full is refused in OPA's shape.
func TestPublic_CheckRoutesRunTheGuard(t *testing.T) {
	app := newPublicApp(t, true, nil, "", "")
	body := `{"type":"ORDER","operation":"READ"}`
	if code, got, _ := call(t, app, http.MethodPost, "/access/v1/check/resource?tenant_id=default", body, admin); code != 200 || got != "true" {
		t.Errorf("POST /access/v1/check/resource?tenant_id=default = %d %s, want 200 true", code, got)
	}
	code, got, _ := call(t, app, http.MethodPost, "/access/v1/check/resource?explain=full", body, admin)
	if code != 401 || got != `{"code":"unauthorized","message":"unauthorized resource access"}` {
		t.Errorf("POST /access/v1/check/resource?explain=full = %d %s, want 401 in OPA's shape", code, got)
	}
	// The test policy opens only POST /v1/data/authorize, so a GET on a
	// filter route passes the guard only through the POST rewrite.
	const useFilter = `{"calculationResult":"USE_FILTER_CONDITION","filterCondition":"","mongodbFilterCondition":"","rsqlFilterCondition":"type==ORDER","sqlFilterCondition":"","customFilterCondition":null}`
	if code, got, _ := call(t, app, http.MethodGet, "/access/v1/check/filter?resourceType=ORDER&operation=READ", "", admin); code != 200 || got != useFilter {
		t.Errorf("GET /access/v1/check/filter with the guard = %d %s, want 200 %s", code, got, useFilter)
	}
}

// recorder is an upstream stub that records the requests it saw as
// "METHOD /path?query" and answers with a fixed status, content type, and
// body.
func recorder(status int, contentType, body string) (*httptest.Server, *[]string) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	return srv, &seen
}

// TestPublic_RelaysHealthToThePapClient: /health goes to the pap-client
// with its method and path, and the pap-client's answer comes back as it
// is, status included.
func TestPublic_RelaysHealthToThePapClient(t *testing.T) {
	papClient, seen := recorder(http.StatusServiceUnavailable, "application/json", `{"status":"unhealthy"}`)
	defer papClient.Close()
	collector, collectorSaw := recorder(http.StatusOK, "application/x-ndjson", "")
	defer collector.Close()
	app := newPublicApp(t, false, nil, papClient.URL, collector.URL)

	code, body, contentType := call(t, app, http.MethodPost, "/health", "", nil)
	if code != 503 || body != `{"status":"unhealthy"}` || contentType != "application/json" {
		t.Errorf("POST /health = %d %s (%s), want the pap-client's 503 {\"status\":\"unhealthy\"} (application/json)", code, body, contentType)
	}
	if strings.Join(*seen, ", ") != "POST /health" || len(*collectorSaw) != 0 {
		t.Errorf("pap-client saw %q and the collector %q, want only the pap-client to see POST /health", *seen, *collectorSaw)
	}
}

// TestPublic_RelaysTheDownloadToTheCollector: the decision-log download
// goes to the collector that receives the decisions, query included, and
// a body larger than one network read comes back whole.
func TestPublic_RelaysTheDownloadToTheCollector(t *testing.T) {
	lines := strings.Repeat("{\"decision_id\":\"1\"}\n", 40000)
	collector, seen := recorder(http.StatusOK, "application/x-ndjson", lines)
	defer collector.Close()
	papClient, papClientSaw := recorder(http.StatusOK, "application/json", `{"status":"healthy"}`)
	defer papClient.Close()
	app := newPublicApp(t, false, nil, papClient.URL, collector.URL)

	code, body, contentType := call(t, app, http.MethodGet, "/internal/v1/decision-logs?since=1", "", nil)
	if code != 200 || contentType != "application/x-ndjson" || len(body) != len(lines) {
		t.Errorf("GET /internal/v1/decision-logs = %d (%s) with %d bytes, want 200 (application/x-ndjson) with %d bytes", code, contentType, len(body), len(lines))
	}
	if strings.Join(*seen, ", ") != "GET /internal/v1/decision-logs?since=1" || len(*papClientSaw) != 0 {
		t.Errorf("collector saw %q and the pap-client %q, want only the collector to see the download", *seen, *papClientSaw)
	}
}

// TestPublic_ServesTheStoredDecisions: with the decisions stored in the
// service, the download serves the store as NDJSON for GET, answers 405 to
// any other method, and relays nothing to a collector.
func TestPublic_ServesTheStoredDecisions(t *testing.T) {
	collector, collectorSaw := recorder(http.StatusOK, "application/x-ndjson", "")
	defer collector.Close()
	store := decisionlog.NewStore(filepath.Join(t.TempDir(), "decision-logs.jsonl"))
	if _, err := store.Append([]decisionlog.Event{{DecisionID: "d-1", Path: "authorize"}}); err != nil {
		t.Fatal(err)
	}
	logs := decisionlog.New(decisionlog.Config{Store: store}, nil)
	app := newPublicApp(t, false, logs, "", collector.URL)

	code, body, contentType := call(t, app, http.MethodGet, "/internal/v1/decision-logs", "", nil)
	if code != 200 || contentType != "application/x-ndjson" || !strings.Contains(body, `"decision_id":"d-1"`) {
		t.Errorf("GET /internal/v1/decision-logs = %d %q (%s), want 200 NDJSON with the stored decision", code, body, contentType)
	}
	if code, body, _ := call(t, app, http.MethodPost, "/internal/v1/decision-logs", "", nil); code != 405 || body != `{"message":"method not allowed"}` {
		t.Errorf("POST /internal/v1/decision-logs = %d %s, want 405", code, body)
	}
	if len(*collectorSaw) != 0 {
		t.Errorf("collector saw %q, want nothing", *collectorSaw)
	}
}

// TestPublic_RelayWithoutPapClient: a pap-client that does not answer is
// reported as 503 naming it, so a probe distinguishes it from a healthy
// answer.
func TestPublic_RelayWithoutPapClient(t *testing.T) {
	app := newPublicApp(t, false, nil, "http://127.0.0.1:1", "")
	code, body, _ := call(t, app, http.MethodGet, "/health", "", nil)
	if code != 503 || !strings.Contains(body, "pap-client unavailable") {
		t.Errorf("GET /health with no pap-client = %d %s, want 503 with a message naming the pap-client", code, body)
	}
}

// collector runs a decision-log uploader against a collector that forwards
// every event to the returned channel.
func collector(t *testing.T) (*decisionlog.Logger, <-chan decisionlog.Event, func()) {
	t.Helper()
	events := make(chan decisionlog.Event, 16)
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
		for _, ev := range batch {
			events <- ev
		}
	}))
	logs := decisionlog.New(decisionlog.Config{URL: srv.URL, Headers: []string{"x-request-id", "x-authz-original-path"}, FlushInterval: 20 * time.Millisecond}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go logs.Run(ctx)
	return logs, events, func() {
		cancel()
		logs.Wait()
		srv.Close()
	}
}

func nextEvent(t *testing.T, events <-chan decisionlog.Event) decisionlog.Event {
	t.Helper()
	select {
	case ev := <-events:
		return ev
	case <-time.After(3 * time.Second):
		t.Fatal("no decision log upload within 3s")
		return decisionlog.Event{}
	}
}

// TestPublic_LogsTheLegacyDecision: a legacy request is logged as the
// canonical decision at authorize, with the route as x-authz-original-path,
// a generated x-request-id when the caller sent none, and the input the
// translation built: the tokens in their fields and the other headers
// under requestHeaders.
func TestPublic_LogsTheLegacyDecision(t *testing.T) {
	logs, events, stop := collector(t)
	defer stop()
	app := newPublicApp(t, false, logs, "", "")
	headers := map[string]string{"Authorization": "Bearer m2m", "Incoming-Token": "Bearer admin", "X-Tenant": "acme"}

	code, body, _ := call(t, app, http.MethodPost, "/access/v1/check/resource?tenant_id=default", `{"type":"ORDER","operation":"READ"}`, headers)
	if code != 200 || body != `true` {
		t.Fatalf("POST /access/v1/check/resource = %d %s, want 200 true", code, body)
	}
	ev := nextEvent(t, events)
	if ev.Path != "authorize" || ev.DecisionID == "" {
		t.Errorf("event path %q decision id %q, want authorize and an id", ev.Path, ev.DecisionID)
	}
	recorded := ev.RequestContext.HTTP.Headers
	if got := recorded["x-authz-original-path"]; len(got) != 1 || got[0] != "/access/v1/check/resource" {
		t.Errorf("x-authz-original-path = %q, want [/access/v1/check/resource]", got)
	}
	requestID := recorded["x-request-id"]
	if len(requestID) != 1 || len(requestID[0]) != 36 {
		t.Fatalf("x-request-id = %q, want one generated UUID", requestID)
	}
	input := ev.Input.(map[string]any)
	if input["requestId"] != requestID[0] || input["authorizationToken"] != "Bearer m2m" || input["subject"] != "Bearer admin" {
		t.Errorf("input = %v, want the generated request id and the tokens from the headers", input)
	}
	requestHeaders := input["requestHeaders"].(map[string]any)
	if requestHeaders["x-tenant"] != "acme" || requestHeaders["authorization"] != nil || requestHeaders["incoming-token"] != nil {
		t.Errorf("requestHeaders = %v, want x-tenant and neither token", requestHeaders)
	}
	if ev.Result.(map[string]any)["rlsIgnored"] != false {
		t.Errorf("result = %v, want the canonical decision", ev.Result)
	}
}

// TestPublic_LogsTheRouteAsOriginalPath: every legacy route records its
// route as x-authz-original-path. The bulk/operations routes record their
// own path and query, so the access and preview routes stay apart; the
// others record the route's path alone. The caller's request id is kept.
func TestPublic_LogsTheRouteAsOriginalPath(t *testing.T) {
	logs, events, stop := collector(t)
	defer stop()
	app := newPublicApp(t, false, logs, "", "")
	single := `{"type":"ORDER","operation":"READ"}`
	bulk := `[{"id":"a","type":"ORDER","operation":"READ"}]`
	operations := `[{"id":"a","type":"ORDER","operations":["READ"]}]`
	operationsV2 := `{"type":"ORDER","entries":[{"id":"a","operations":["READ"]}]}`
	cases := []struct {
		path, body, want string
	}{
		{"/access/v1/check/resource?tenant_id=default", single, "/access/v1/check/resource"},
		{"/access/v2/check/resource?tenant_id=default", single, "/access/v2/check/resource"},
		{"/access/v1/check/resource/bulk?tenant_id=default", bulk, "/access/v1/check/resource/bulk"},
		{"/access/v1/check/resource/bulk/operations?tenant_id=default", operations, "/access/v1/check/resource/bulk/operations?tenant_id=default"},
		{"/preview/v1/check/resource/bulk/operations?tenant_id=default", operations, "/preview/v1/check/resource/bulk/operations?tenant_id=default"},
		{"/access/v2/check/resource/bulk/operations?tenant_id=default", operationsV2, "/access/v2/check/resource/bulk/operations?tenant_id=default"},
		{"/preview/v2/check/resource/bulk/operations?tenant_id=default", operationsV2, "/preview/v2/check/resource/bulk/operations?tenant_id=default"},
		{"/access/v1/check/filter?resourceType=ORDER", "", "/access/v1/check/filter"},
		{"/access/v2/check/filter?resourceType=ORDER", "", "/access/v2/check/filter"},
	}
	for i, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			requestID := fmt.Sprintf("req-%d", i)
			headers := map[string]string{"Authorization": "Bearer m2m", "X-Request-Id": requestID}
			if code, body, _ := call(t, app, http.MethodPost, tc.path, tc.body, headers); code != 200 {
				t.Fatalf("POST %s = %d %s, want 200", tc.path, code, body)
			}
			recorded := nextEvent(t, events).RequestContext.HTTP.Headers
			if got := recorded["x-authz-original-path"]; len(got) != 1 || got[0] != tc.want {
				t.Errorf("x-authz-original-path for POST %s = %q, want [%s]", tc.path, got, tc.want)
			}
			if got := recorded["x-request-id"]; len(got) != 1 || got[0] != requestID {
				t.Errorf("x-request-id for POST %s = %q, want [%s]", tc.path, got, requestID)
			}
		})
	}
}
