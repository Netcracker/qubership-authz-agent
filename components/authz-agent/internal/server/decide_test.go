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
	"fmt"
	"maps"
	"net/http"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// admissionStub stands in for the caller and token checks of the embedded
// policies: a request without a subject is refused with an authError, and
// a subject token Bearer expired is refused, and any other one is admitted
// with the claims of the user u1.
const admissionStub = `package authorize_internals

import rego.v1

admission := {"authError": {"status": 403, "message": "no subject"}} if input.subject == ""

admission := {"subjectError": "token expired"} if input.subject == "Bearer expired"

admission := {"tokenPayload": {"sub": "u1"}} if not input.subject in {"", "Bearer expired"}
`

type quietLoader struct{}

func (quietLoader) Infof(string, ...any) {}
func (quietLoader) Warnf(string, ...any) {}

// tenantSet is a set of tenant that allows the operation read on a doc
// where condition holds.
func tenantSet(tenant, condition string) string {
	return fmt.Sprintf(`{"policySetId": "s-%[1]s", "name": "s", "status": "ACTIVE", "tenantId": %[1]q,
		"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
		"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"tenantId": %[1]q, "rules": [{"ruleId": "r", "target": "operation == 'read'",
				"condition": %[2]q, "effect": "ALLOW", "tenantId": %[1]q}]}]}`, tenant, condition)
}

// newDecideApp builds the public surface over a registry in which tenant a
// allows every read of a doc and tenant b none, with b the default tenant.
func newDecideApp(t *testing.T) *fiber.App {
	t.Helper()
	reg := registry(t, `{"policySets": [`+tenantSet("a", "true")+`,`+tenantSet("b", "false")+`]}`)
	return newPublicAppOver(t, map[string]string{"internals.rego": admissionStub},
		Options{Snapshots: reg, DefaultTenant: func() string { return "b" }})
}

func TestDecide_TheTenantComesFromTheQueryThenTheHeaderThenTheDefault(t *testing.T) {
	app := newDecideApp(t)
	const body = `{"type":"doc","operation":"read","resource":{}}`
	for _, tc := range []struct {
		name, query, header, want string
	}{
		{"the query parameter", "?tenant_id=a", "", "true"},
		{"the query parameter over the header", "?tenant_id=b", "a", "false"},
		{"the header", "", "a", "true"},
		{"an empty query parameter falls through to the header", "?tenant_id=", "a", "true"},
		{"a query parameter of spaces is a tenant of its own", "?tenant_id=%20", "a", "false"},
		{"a leading space names another tenant", "?tenant_id=%20a", "a", "false"},
		{"a trailing space names another tenant", "?tenant_id=a%20", "a", "false"},
		{"a header arrives without the spaces around it", "", " a ", "true"},
		{"the default tenant", "", "", "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{}
			for k, v := range admin {
				headers[k] = v
			}
			if tc.header != "" {
				headers["Tenant"] = tc.header
			}
			path := "/access/v1/check/resource" + tc.query
			code, got, _ := call(t, app, http.MethodPost, path, body, headers)
			if code != 200 || got != tc.want {
				t.Errorf("POST %s with Tenant %q = %d %s, want 200 %s", path, tc.header, code, got, tc.want)
			}
		})
	}
}

// callerStub admits every request and gives as callerClaims the claims of
// the token in Authorization, by the token's text.
const callerStub = `package authorize_internals

import rego.v1

callers := {
	"Bearer PARITY_A": {"tenant-id": "a"},
	"Bearer PARITY_UNKNOWN": {"tenant-id": "PARITY_UNKNOWN"},
	"Bearer PARITY_NONE": {},
	"Bearer PARITY_EMPTY": {"tenant-id": ""},
	"Bearer PARITY_NUMBER": {"tenant-id": 1},
	"Bearer PARITY_NULL": {"tenant-id": null},
	"Bearer PARITY_ROLE_M2M": {"tenant-id": "a", "realm_access": {"roles": ["ROLE_M2M"]}},
	"Bearer PARITY_ROLE_LOWER": {"tenant-id": "a", "realm_access": {"roles": ["role_m2m"]}},
	"Bearer PARITY_LEVEL_M2M": {"level": "M2M"},
	"Bearer PARITY_LEVEL_KEY_MANAGER": {"level": "Key-Manager"},
}

admission := {"tokenPayload": {"sub": "u1"}, "callerClaims": callers[input.authorizationToken]}
`

func TestDecide_ACallerThatIsNotM2MReachesOnlyItsOwnTenant(t *testing.T) {
	reg := registry(t, `{"policySets": [`+tenantSet("a", "true")+`,`+tenantSet("b", "true")+`]}`)
	app := newPublicAppOver(t, map[string]string{"internals.rego": callerStub},
		Options{Snapshots: reg, DefaultTenant: func() string { return "a" }})
	const body = `{"type":"doc","operation":"read","resource":{}}`
	for _, tc := range []struct {
		name, token, query, header string
		status                     int
		want                       string
	}{
		{"a claim reaches its tenant", "PARITY_A", "?tenant_id=a", "", 200, "true"},
		{"a claim of a tenant without data is refused in the default tenant", "PARITY_UNKNOWN", "?tenant_id=a", "", 403, ""},
		{"a claim is refused in another tenant", "PARITY_A", "?tenant_id=b", "", 403, ""},
		{"a claim is refused in another tenant named by the header", "PARITY_A", "", "b", 403, ""},
		{"a claim is refused in its tenant spelled with a trailing space", "PARITY_A", "?tenant_id=a%20", "", 403, ""},
		{"no claim reaches the default tenant", "PARITY_NONE", "?tenant_id=a", "", 200, "true"},
		{"no claim is refused outside the default tenant", "PARITY_NONE", "?tenant_id=b", "", 403, ""},
		{"an empty claim reaches the default tenant", "PARITY_EMPTY", "?tenant_id=a", "", 200, "true"},
		{"an empty claim is refused outside the default tenant", "PARITY_EMPTY", "?tenant_id=b", "", 403, ""},
		{"a claim that is not a string is refused", "PARITY_NUMBER", "?tenant_id=a", "", 403, ""},
		{"a null claim reaches the default tenant", "PARITY_NULL", "?tenant_id=a", "", 200, "true"},
		{"ROLE_M2M reaches another tenant than its claim", "PARITY_ROLE_M2M", "?tenant_id=b", "", 200, "true"},
		{"role_m2m in lowercase is refused in another tenant than its claim", "PARITY_ROLE_LOWER", "?tenant_id=b", "", 403, ""},
		{"the level m2m in any case reaches a tenant outside the default", "PARITY_LEVEL_M2M", "?tenant_id=b", "", 200, "true"},
		{"the level key-manager in any case reaches a tenant outside the default", "PARITY_LEVEL_KEY_MANAGER", "?tenant_id=b", "", 200, "true"},
		{"a claim reaches the default tenant the request does not name", "PARITY_A", "", "", 200, "true"},
		{"a claim of another tenant is refused in the default tenant the request does not name", "PARITY_UNKNOWN", "", "", 403, ""},
		{"a claim that differs from the tenant only in case is refused", "PARITY_A", "?tenant_id=A", "", 403, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{"Authorization": "Bearer " + tc.token}
			if tc.header != "" {
				headers["Tenant"] = tc.header
			}
			path := "/access/v1/check/resource" + tc.query
			code, got, _ := call(t, app, http.MethodPost, path, body, headers)
			if code != tc.status || got != tc.want {
				t.Errorf("POST %s with Tenant %q as %s = %d %q, want %d %q", path, tc.header, tc.token, code, got, tc.status, tc.want)
			}
		})
	}
}

// A caller whose token is not M2M and has no tenant-id claim may ask only
// about the default tenant, so until tenant-manager resolves its name such a
// caller cannot be compared with any tenant, whichever the request names. A
// caller with a claim gets the 503 only for a request that names no tenant.
func TestDecide_ACallerWithoutATenantClaimGets503UntilTheDefaultTenantIsResolved(t *testing.T) {
	reg := registry(t, `{"policySets": [`+tenantSet("a", "true")+`,`+tenantSet("b", "true")+`]}`)
	resolved := false
	app := newPublicAppOver(t, map[string]string{"internals.rego": callerStub}, Options{Snapshots: reg,
		DefaultTenant: func() string { return "a" }, DefaultTenantResolved: func() bool { return resolved }})
	const body = `{"type":"doc","operation":"read","resource":{}}`
	for _, tc := range []struct {
		name, token, tenant string
		resolved            bool
		status              int
		want, retryAfter    string
	}{
		{"no claim, unresolved, another tenant", "PARITY_NONE", "b", false, 503, "", "60"},
		{"no claim, unresolved, the default tenant by name", "PARITY_NONE", "a", false, 503, "", "60"},
		{"an empty claim, unresolved", "PARITY_EMPTY", "b", false, 503, "", "60"},
		{"a null claim, unresolved", "PARITY_NULL", "b", false, 503, "", "60"},
		{"a claim of another tenant, unresolved, no tenant named", "PARITY_UNKNOWN", "", false, 503, "", "60"},
		{"a claim, unresolved, its tenant", "PARITY_A", "a", false, 200, "true", ""},
		{"a claim, unresolved, another tenant", "PARITY_A", "b", false, 403, "", ""},
		{"a claim that is not a string, unresolved", "PARITY_NUMBER", "a", false, 403, "", ""},
		{"M2M without a claim, unresolved, another tenant", "PARITY_LEVEL_M2M", "b", false, 200, "true", ""},
		{"no claim, resolved, the default tenant", "PARITY_NONE", "a", true, 200, "true", ""},
		{"no claim, resolved, another tenant", "PARITY_NONE", "b", true, 403, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolved = tc.resolved
			path := "/access/v1/check/resource"
			if tc.tenant != "" {
				path += "?tenant_id=" + tc.tenant
			}
			code, got, header := callForHeaders(t, app, http.MethodPost, path, body,
				map[string]string{"Authorization": "Bearer " + tc.token})
			if code != tc.status || got != tc.want || header.Get("Retry-After") != tc.retryAfter {
				t.Errorf("POST %s as %s = %d %q Retry-After %q, want %d %q Retry-After %q",
					path, tc.token, code, got, header.Get("Retry-After"), tc.status, tc.want, tc.retryAfter)
			}
		})
	}
}

func TestDecide_ARefusedAdmissionAnswersWithItsAuthError(t *testing.T) {
	app := newDecideApp(t)
	for _, tc := range []struct{ name, path, body string }{
		{"check/resource", "/access/v1/check/resource?tenant_id=a", `{"type":"doc","operation":"read"}`},
		{"check/filter", "/access/v1/check/filter?tenant_id=a&resourceType=doc&operation=read", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, got, _ := call(t, app, http.MethodPost, tc.path, tc.body, nil)
			if code != 403 || got != `{"message":"no subject"}` {
				t.Errorf("POST %s without a subject = %d %s, want 403 {\"message\":\"no subject\"}", tc.path, code, got)
			}
		})
	}
}

// PARITY_A carries a tenant-id claim and none of the claims an M2M token is
// recognized by, so it stays a caller of tenant a alone however those
// rules change.
func TestDecide_ACallerOutsideItsTenantIsRefusedOnEveryRoute(t *testing.T) {
	reg := registry(t, `{"policySets": [`+tenantSet("a", "true")+`,`+tenantSet("b", "true")+`]}`)
	app := newPublicAppOver(t, map[string]string{"internals.rego": callerStub},
		Options{Snapshots: reg, DefaultTenant: func() string { return "a" }})
	headers := map[string]string{"Authorization": "Bearer PARITY_A"}
	for _, route := range []struct{ name, path, query, body string }{
		{"check/resource", "/access/v1/check/resource", "", `{"type":"doc","operation":"read","resource":{}}`},
		{"check/filter", "/access/v1/check/filter", "&resourceType=doc&operation=read", ""},
	} {
		t.Run(route.name+", another tenant", func(t *testing.T) {
			path := route.path + "?tenant_id=b" + route.query
			if code, got, _ := call(t, app, http.MethodPost, path, route.body, headers); code != 403 || got != "" {
				t.Errorf("POST %s as PARITY_A = %d %q, want 403 \"\"", path, code, got)
			}
		})
		t.Run(route.name+", its own tenant", func(t *testing.T) {
			path := route.path + "?tenant_id=a" + route.query
			if code, got, _ := call(t, app, http.MethodPost, path, route.body, headers); code != 200 {
				t.Errorf("POST %s as PARITY_A = %d %q, want 200", path, code, got)
			}
		})
	}
}

func TestDecide_BulkRoutesAnswerEachItem(t *testing.T) {
	app := newDecideApp(t)
	for _, tc := range []struct {
		name, path, body, want string
	}{
		{"bulk lists the allowed ids", "/access/v1/check/resource/bulk?tenant_id=a",
			`[{"id":"x","type":"doc","operation":"read"},{"id":"y","type":"doc","operation":"write"}]`, `["x"]`},
		{"bulk/operations groups the allowed ids by operation", "/access/v1/check/resource/bulk/operations?tenant_id=a",
			`[{"id":"x","type":"doc","operations":["read","write"]},{"id":"y","type":"doc","operations":["read"]}]`,
			`{"read":["x","y"],"write":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, got, _ := call(t, app, http.MethodPost, tc.path, tc.body, admin)
			if code != 200 || got != tc.want {
				t.Errorf("POST %s = %d %s, want 200 %s", tc.path, code, got, tc.want)
			}
		})
	}
}

// A refused subject token denies every item, and no policy is asked: tenant
// a would allow the read.
func TestDecide_ARefusedSubjectTokenDeniesEveryItem(t *testing.T) {
	app := newDecideApp(t)
	headers := map[string]string{"Authorization": "Bearer m2m", "Incoming-Token": "Bearer expired"}
	for _, tc := range []struct{ path, body, want string }{
		{"/access/v1/check/resource?tenant_id=a", `{"type":"doc","operation":"read"}`, "false"},
		{"/access/v1/check/resource/bulk/operations?tenant_id=a", `[{"id":"x","type":"doc","operations":["read"]}]`, `{"read":[]}`},
		{"/access/v1/check/filter?tenant_id=a&resourceType=doc&operation=read", "",
			`{"calculationResult":"DENY","filterCondition":null,"mongodbFilterCondition":null,"rsqlFilterCondition":null,"sqlFilterCondition":null,"customFilterCondition":null}`},
	} {
		code, got, _ := call(t, app, http.MethodPost, tc.path, tc.body, headers)
		if code != 200 || got != tc.want {
			t.Errorf("POST %s with an expired subject token = %d %s, want 200 %s", tc.path, code, got, tc.want)
		}
	}
}

// While the name of the default tenant is not resolved, the policy data
// held under that name may be another tenant's, so a request that names no
// tenant is refused on every decision route, even from an M2M caller and
// although tenant default allows the read.
func TestDecide_TheDefaultTenantIsRefusedUntilItsNameIsResolved(t *testing.T) {
	reg := registry(t, `{"policySets": [`+tenantSet("default", "true")+`]}`)
	resolved := false
	app := newPublicAppOver(t, map[string]string{"internals.rego": callerStub}, Options{Snapshots: reg,
		DefaultTenant: func() string { return "default" }, DefaultTenantResolved: func() bool { return resolved }})
	m2m := map[string]string{"Authorization": "Bearer PARITY_ROLE_M2M"}
	const (
		read       = `{"type":"doc","operation":"read"}`
		bulk       = `[{"id":"x","type":"doc","operation":"read"}]`
		operations = `[{"id":"x","type":"doc","operations":["read"]}]`
		entries    = `{"type":"doc","entries":[{"id":"x","operations":["read"]}]}`
		filter     = "?resourceType=doc&operation=read"
	)
	for _, r := range []struct{ path, body string }{
		{"/access/v1/check/resource", read},
		{"/access/v1/check/resource/bulk", bulk},
		{"/access/v1/check/resource/bulk/operations", operations},
		{"/preview/v1/check/resource/bulk/operations", operations},
		{"/access/v1/check/filter" + filter, ""},
		{"/access/v2/check/resource", read},
		{"/access/v2/check/resource/bulk/operations", entries},
		{"/preview/v2/check/resource/bulk/operations", entries},
		{"/access/v2/check/filter" + filter, ""},
	} {
		t.Run(r.path, func(t *testing.T) {
			code, got, header := callForHeaders(t, app, http.MethodPost, r.path, r.body, m2m)
			if code != 503 || got != "" || header.Get("Retry-After") != "60" {
				t.Errorf("unresolved: POST %s = %d %q Retry-After %q, want 503 \"\" Retry-After \"60\"",
					r.path, code, got, header.Get("Retry-After"))
			}
		})
	}
	for _, tc := range []struct {
		name, query string
		header      map[string]string
		resolved    bool
	}{
		{"unresolved, the query parameter names the tenant", "?tenant_id=default", nil, false},
		{"unresolved, the header names the tenant", "", map[string]string{"Tenant": "default"}, false},
		{"resolved, no tenant named", "", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolved = tc.resolved
			headers := maps.Clone(m2m)
			maps.Copy(headers, tc.header)
			path := "/access/v1/check/resource" + tc.query
			if code, got, _ := call(t, app, http.MethodPost, path, read, headers); code != 200 || got != "true" {
				t.Errorf("POST %s with %v = %d %q, want 200 \"true\"", path, tc.header, code, got)
			}
		})
	}
}

// tenant-manager resolves the name while the request reads the default
// tenant: the request was admitted as unresolved, so it is refused rather
// than decided in the policy data held under the display name.
func TestDecide_ARequestThatSawTheNameUnresolvedIsRefusedWhenItResolvesMidway(t *testing.T) {
	reg := registry(t, `{"policySets": [`+tenantSet("default", "true")+`]}`)
	resolved := false
	app := newPublicAppOver(t, map[string]string{"internals.rego": callerStub}, Options{Snapshots: reg,
		DefaultTenant: func() string {
			resolved = true
			return "default"
		},
		DefaultTenantResolved: func() bool { return resolved }})
	const path = "/access/v1/check/resource"
	code, got, header := callForHeaders(t, app, http.MethodPost, path, `{"type":"doc","operation":"read"}`,
		map[string]string{"Authorization": "Bearer PARITY_ROLE_M2M"})
	if code != 503 || got != "" || header.Get("Retry-After") != "60" {
		t.Errorf("POST %s = %d %q Retry-After %q, want 503 \"\" Retry-After \"60\"",
			path, code, got, header.Get("Retry-After"))
	}
}

// fourTexts is a list of n lists of four strings of numbers, of one shape,
// each spelling 0 its own way: a lookup among 16 of them is over the limit,
// and among 15 it is not.
func fourTexts(n int) string {
	elems := make([]string, n)
	for i := range elems {
		elems[i] = fmt.Sprintf(`["1", "2", "3", "0e%d"]`, i)
	}
	return "[" + strings.Join(elems, ",") + "]"
}

// A value that a comparison reads and that would need a lookup of more than
// 16 groups is the caller's error, whether it comes in the body or in a claim
// of the subject's token: the route answers 400 and logs no error. One such
// item refuses a whole bulk request.
func TestDecide_AValueTooBigToLookUpIsRefusedAsABadRequest(t *testing.T) {
	const (
		inBody    = "resource.a CONTAINS ANY resource.b"
		inClaims  = "subject.a CONTAINS ANY subject.b"
		claimPIPs = `{"pips": [{"tenantId": "a", "name": "subject.a", "pipType": "TOKEN", "claim": "a"},
			{"tenantId": "a", "name": "subject.b", "pipType": "TOKEN", "claim": "b"}]}`
	)
	for _, tc := range []struct {
		name, condition, path string
		// value is the operand whose value is too big
		value string
		// body is the request body with b of n lists
		body func(b string) string
	}{
		{"check/resource, a value of the resource", inBody, "/access/v1/check/resource?tenant_id=a", "resource.b",
			func(b string) string {
				return `{"type":"doc","operation":"read","resource":{"a":[["z"]],"b":` + b + `}}`
			}},
		{"check/resource v2, a value of the resource", inBody, "/access/v2/check/resource?tenant_id=a", "resource.b",
			func(b string) string {
				return `{"type":"doc","operation":"read","resource":{"a":[["z"]],"b":` + b + `}}`
			}},
		{"bulk, the second of two items", inBody, "/access/v1/check/resource/bulk?tenant_id=a", "resource.b",
			func(b string) string {
				return `[{"id":"x","type":"doc","operation":"read","resource":{"a":[["z"]],"b":[["z"]]}},` +
					`{"id":"y","type":"doc","operation":"read","resource":{"a":[["z"]],"b":` + b + `}}]`
			}},
		{"bulk/operations, a value of the resource", inBody,
			"/access/v1/check/resource/bulk/operations?tenant_id=a", "resource.b",
			func(b string) string {
				return `[{"id":"x","type":"doc","operations":["read"],"resource":{"a":[["z"]],"b":` + b + `}}]`
			}},
		{"check/resource, a claim of the token", inClaims, "/access/v1/check/resource?tenant_id=a", "subject.b",
			func(string) string { return `{"type":"doc","operation":"read","resource":{}}` }},
		{"check/filter, a claim of the token", inClaims,
			"/access/v1/check/filter?tenant_id=a&resourceType=doc&operation=read", "subject.b",
			func(string) string { return "" }},
	} {
		// app is the public surface over tenant a, which allows a read of
		// a doc where tc.condition holds, for a subject whose claim b is b and
		// whose claims a and b the TOKEN PIPs subject.a and subject.b read.
		app := func(b string) (*fiber.App, *levels) {
			reported := &levels{}
			stub := `package authorize_internals

import rego.v1

admission := {"tokenPayload": {"sub": "u1", "a": [["z"]], "b": ` + b + `}}
`
			return newPublicAppOver(t, map[string]string{"internals.rego": stub},
				Options{Log: reported, Snapshots: registryWithPIPs(t, `{"policySets": [`+tenantSet("a", tc.condition)+`]}`,
					claimPIPs), DefaultTenant: func() string { return "a" }}), reported
		}
		t.Run(tc.name+", 16 lists", func(t *testing.T) {
			a, reported := app(fourTexts(16))
			code, got, _ := call(t, a, http.MethodPost, tc.path, tc.body(fourTexts(16)), admin)
			prefix := `{"message":"the value of ` + tc.value + `: `
			const limit = "a lookup among them would read more than 16 groups and scanned elements"
			if code != http.StatusBadRequest || !strings.HasPrefix(got, prefix) || !strings.Contains(got, limit) {
				t.Errorf("POST %s = %d %s, want 400 with a message that starts with %q and holds %q", tc.path, code,
					got, prefix, limit)
			}
			if lines := reported.at("error"); len(lines) != 0 {
				t.Errorf("POST %s logged at error: %q, want no line", tc.path, lines)
			}
			var refused []string
			for _, line := range reported.at("debug") {
				if strings.Contains(line, "rejected") && strings.Contains(line, limit) {
					refused = append(refused, line)
				}
			}
			if len(refused) != 1 {
				t.Errorf("POST %s logged at debug %q, want one line that the request was rejected for %q",
					tc.path, reported.at("debug"), limit)
			}
		})
		t.Run(tc.name+", 15 lists", func(t *testing.T) {
			a, _ := app(fourTexts(15))
			if code, got, _ := call(t, a, http.MethodPost, tc.path, tc.body(fourTexts(15)), admin); code != http.StatusOK {
				t.Errorf("POST %s = %d %s, want 200", tc.path, code, got)
			}
		})
	}
}

// A permission too big to compare that the tenant's mapping tables grant is
// not the caller's error: the request sent only a role. The route answers
// 500 internal_error and logs an error, so that an operator fixes the
// mapping.
func TestDecide_AMappedPermissionTooBigToLookUpFailsTheAgent(t *testing.T) {
	const path = "/access/v1/check/resource?tenant_id=a"
	const body = `{"type":"doc","operation":"read","resource":{"a":[["z"]]}}`
	// app is the public surface over tenant a, whose mapping table grants
	// the role r of every subject the permissions perms.
	app := func(perms string) (*fiber.App, *levels) {
		reported := &levels{}
		const stub = `package authorize_internals

import rego.v1

admission := {"tokenPayload": {"sub": "u1", "realm_access": {"roles": ["r"]}}}
`
		pips := `{"pips": [{"tenantId": "a", "name": "subject.permissions", "pipType": "MAPPING",
			"customMapping": {"subject.roles": {"r": ` + perms + `}}}]}`
		reg := registryWithPIPs(t, `{"policySets": [`+tenantSet("a", "resource.a CONTAINS ANY subject.permissions")+`]}`,
			pips)
		return newPublicAppOver(t, map[string]string{"internals.rego": stub},
			Options{Log: reported, Snapshots: reg, DefaultTenant: func() string { return "a" }}), reported
	}
	t.Run("16 lists", func(t *testing.T) {
		a, reported := app(fourTexts(16))
		code, got, _ := call(t, a, http.MethodPost, path, body, admin)
		const limit = "a lookup among them would read more than 16 groups and scanned elements"
		if code != http.StatusInternalServerError || !strings.Contains(got, `"code":"internal_error"`) ||
			!strings.Contains(got, limit) {
			t.Errorf("POST %s = %d %s, want 500 internal_error with a message that holds %q", path, code, got, limit)
		}
		if lines := reported.at("error"); len(lines) != 1 {
			t.Errorf("POST %s logged at error: %q, want one line", path, lines)
		}
	})
	t.Run("15 lists", func(t *testing.T) {
		a, _ := app(fourTexts(15))
		if code, got, _ := call(t, a, http.MethodPost, path, body, admin); code != http.StatusOK {
			t.Errorf("POST %s = %d %s, want 200", path, code, got)
		}
	})
}
