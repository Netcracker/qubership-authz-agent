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
	"testing"

	"github.com/gofiber/fiber/v2"

	"authz-agent/components/authz-agent/internal/legacy"
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

func TestDecide_ARefusedAdmissionAnswersWithItsAuthError(t *testing.T) {
	app := newDecideApp(t)
	code, got, _ := call(t, app, http.MethodPost, "/access/v1/check/resource?tenant_id=a",
		`{"type":"doc","operation":"read"}`, nil)
	if code != 403 || got != `{"message":"no subject"}` {
		t.Errorf("POST without a subject = %d %s, want 403 {\"message\":\"no subject\"}", code, got)
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

// TestDecide_ThePIPsGetNoTokenOfTheCaller: the headers a PIP may forward, or
// a HEADER PIP may read into a url or a body, leave out the caller's tokens,
// as input.requestHeaders does; the other headers stay.
func TestDecide_ThePIPsGetNoTokenOfTheCaller(t *testing.T) {
	headers := map[string][]string{"Authorization": {"Bearer m2m"}, "Incoming-Token": {"eyJ.user.jwt"},
		"X-Corr": {"c0", "c1"}}
	input := legacy.Input(headers, nil)
	want := map[string]string{"x-corr": "c1"}
	req, err := snapshotRequest("a", input, nil, headers, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(req.Headers, want) {
		t.Errorf("snapshotRequest headers = %v, want %v", req.Headers, want)
	}
	freq, err := filterRequest("a", input, nil, headers, legacy.Resource{ResourceType: "doc"})
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(freq.Headers, want) {
		t.Errorf("filterRequest headers = %v, want %v", freq.Headers, want)
	}
}
