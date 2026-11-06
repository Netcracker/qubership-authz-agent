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

	"github.com/gofiber/fiber/v2"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xrequestid"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxhelper"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"

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

// newPublicApp builds the public surface over publicPolicy, with the routing
// options main uses.
func newPublicApp(t *testing.T) *fiber.App {
	t.Helper()
	return newPublicAppOver(t, map[string]string{"authorize.rego": publicPolicy}, Options{})
}

// newPublicAppOver builds the public surface over modules, with
// data.users.admin set to root and the platform's context middleware ahead
// of the routes, as the platform's Fiber builder installs it in main.
func newPublicAppOver(t *testing.T, modules map[string]string, opts Options) *fiber.App {
	t.Helper()
	eng, err := engine.New(engine.Options{Modules: modules})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if err := eng.Put(context.Background(), []string{"users"}, map[string]any{"admin": "root"}); err != nil {
		t.Fatal(err)
	}
	srv := Register(fiber.New(fiber.Config{Immutable: true, DisableStartupMessage: true}), eng, opts)
	app := fiber.New(fiber.Config{Immutable: true, StrictRouting: true, CaseSensitive: true, DisableStartupMessage: true})
	app.Use(platformContext)
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

// contextIDs keeps the request id of the context every line was written
// under, which is the id the platform log format prints as request_id.
type contextIDs struct{ seen []string }

func (r *contextIDs) record(ctx context.Context) {
	if id, err := xrequestid.Of(ctx); err == nil {
		r.seen = append(r.seen, id.GetRequestId())
	}
}

func (r *contextIDs) DebugC(ctx context.Context, _ string, _ ...any) { r.record(ctx) }
func (r *contextIDs) ErrorC(ctx context.Context, _ string, _ ...any) { r.record(ctx) }

// platformContext is the middleware the platform's Fiber builder installs
// ahead of the routes: it builds the propagated context from the headers as
// they arrived, and copies what is propagated back into the response.
func platformContext(c *fiber.Ctx) error {
	headers := map[string]any{}
	for key, value := range c.Request().Header.All() {
		headers[string(key)] = string(value)
	}
	c.SetUserContext(ctxmanager.InitContext(context.Background(), headers))
	if err := ctxhelper.AddResponsePropagatableContextData(c.UserContext(), c.Response().Header.Add); err != nil {
		return err
	}
	return c.Next()
}

// requestIDPolicy refuses every request with the id the policy read from
// the input as its message, so a test can read input.requestId from the
// response.
const requestIDPolicy = `package authorize

import rego.v1

authError := {"status": 403, "message": input.requestId}
`

// TestPublic_TheRequestIdNamesTheRequestEverywhere: a policy reads the input
// and a log line reads the propagated context, so support holding one of two
// ids finds nothing under the other. A request that arrives without an
// X-Request-Id is given one, and the context built from that same absent
// header holds an id of its own, which the generated one replaces; a request
// that brings an id keeps it in all three places.
func TestPublic_TheRequestIdNamesTheRequestEverywhere(t *testing.T) {
	ctxmanager.Register(baseproviders.Get())
	for _, tc := range []struct{ name, given string }{
		{"no request id was sent", ""},
		{"the caller sent a request id", "id-from-the-caller"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := &contextIDs{}
			app := newPublicAppOver(t, map[string]string{"authorize.rego": requestIDPolicy}, Options{Log: lines})

			resp := checkResourceWithID(t, app, tc.given)
			defer func() { _ = resp.Body.Close() }()

			read := idThePolicyRead(t, resp, tc.given)
			if got := resp.Header.Get(fiber.HeaderXRequestID); got != read {
				t.Errorf("the response carries request id %q, want %q, the one the policy read", got, read)
			}
			assertLinesCarry(t, lines, read)
		})
	}
}

// checkResourceWithID sends one legacy check, under the given request id when
// it is not empty, and fails the test unless requestIDPolicy refuses it.
func checkResourceWithID(t *testing.T, app *fiber.App, given string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/access/v1/check/resource",
		strings.NewReader(`{"type":"ORDER","operation":"READ"}`))
	req.Header.Set("Incoming-Token", "Bearer admin")
	if given != "" {
		req.Header.Set(fiber.HeaderXRequestID, given)
	}
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("POST /access/v1/check/resource: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /access/v1/check/resource = %d, want 403", resp.StatusCode)
	}
	return resp
}

// idThePolicyRead is the input.requestId the refusal carries: the id the
// caller gave, or a generated UUID when it gave none.
func idThePolicyRead(t *testing.T, resp *http.Response, given string) string {
	t.Helper()
	var refusal struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&refusal); err != nil {
		t.Fatalf("the refusal is not JSON: %v", err)
	}
	if given != "" && refusal.Message != given {
		t.Fatalf("the policy read request id %q, want %q, the one the caller sent", refusal.Message, given)
	}
	if given == "" && len(refusal.Message) != 36 {
		t.Fatalf("the policy read request id %q, want a generated UUID", refusal.Message)
	}
	return refusal.Message
}

// assertLinesCarry fails unless every line the request produced was written
// under want, and unless it produced any.
func assertLinesCarry(t *testing.T, lines *contextIDs, want string) {
	t.Helper()
	if len(lines.seen) == 0 {
		t.Fatal("no line was written under the request's context, so the id it carries cannot be checked")
	}
	for i, got := range lines.seen {
		if got != want {
			t.Errorf("line %d was written under request id %q, want %q, the one the policy read", i+1, got, want)
		}
	}
}

// TestPublic_CheckResource: the v1 route answers a bare boolean and the v2
// route {"decision": bool}, both as JSON, from the first result.
func TestPublic_CheckResource(t *testing.T) {
	app := newPublicApp(t)
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
	app := newPublicApp(t)
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
	app := newPublicApp(t)
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
		{"a body the v1 route cannot parse", "/access/v1/check/resource/bulk/operations",
			`{"type":"ORDER"}`, admin, 400, `{"message":"bad request"}`},
		{"a body the v2 route cannot parse", "/access/v2/check/resource/bulk/operations",
			`[{"id":"a","type":"ORDER","operations":["READ"]}]`, admin, 400, `{"message":"bad request"}`},
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
	app := newPublicApp(t)
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

// TestPublic_Surface: the check routes, /api-version, and /health answer as
// Envoy answered them, and every other path, /access/v1/authorize and
// /internal/v1/decision-logs included, is 404 {"message":"not found"}.
func TestPublic_Surface(t *testing.T) {
	app := newPublicApp(t)
	authorize := `{"input":{"subject":"Bearer admin","resources":[{"resourceType":"ORDER","operation":"READ"}]}}`
	cases := []struct {
		name, method, path, body string
		status                   int
		want                     string
	}{
		{"an unknown path", http.MethodGet, "/unknown/endpoint", "", 404, `{"message":"not found"}`},
		{"POST /access/v1/authorize", http.MethodPost, "/access/v1/authorize", authorize, 404, `{"message":"not found"}`},
		{"a check route with a trailing slash", http.MethodPost, "/access/v1/check/resource/", `{"type":"ORDER","operation":"READ"}`, 404, `{"message":"not found"}`},
		{"a mistyped check route", http.MethodPost, "/access/v1/check/resourc", `{"type":"ORDER","operation":"READ"}`, 404, `{"message":"not found"}`},
		{"api-version by GET", http.MethodGet, "/api-version", "", 200, LegacyAPIVersion},
		{"api-version by POST", http.MethodPost, "/api-version", "", 200, LegacyAPIVersion},
		{"GET /internal/v1/decision-logs", http.MethodGet, "/internal/v1/decision-logs", "", 404, `{"message":"not found"}`},
		{"POST /internal/v1/decision-logs", http.MethodPost, "/internal/v1/decision-logs", "", 404, `{"message":"not found"}`},
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

// TestPublic_CheckRoutesIgnoreExplain: a check route reads no query
// parameter beyond the ones its request shape names, so ?explain=full gets
// the same answer as the plain request.
func TestPublic_CheckRoutesIgnoreExplain(t *testing.T) {
	app := newPublicApp(t)
	body := `{"type":"ORDER","operation":"READ"}`
	for _, path := range []string{"/access/v1/check/resource", "/access/v1/check/resource?explain=full"} {
		if code, got, _ := call(t, app, http.MethodPost, path, body, admin); code != 200 || got != "true" {
			t.Errorf("POST %s = %d %s, want 200 true", path, code, got)
		}
	}
}
