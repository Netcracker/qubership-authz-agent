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

package snapshot

import (
	"fmt"
	"net/http"
	"testing"

	"authz-agent/internal/jsonvalue"
)

// denyBesideAllow is a set of tenant a whose policy, under algorithm alg,
// holds an ALLOW rule without a condition and a DENY rule over condition.
func denyBesideAllow(alg, condition string) string {
	return fmt.Sprintf(`{"policySetId": "s", "name": "s", "status": "ACTIVE", "tenantId": "a",
		"target": "resourceType == 'doc'", "combiningAlgorithm": %[1]q,
		"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": %[1]q, "tenantId": "a",
			"rules": [{"ruleId": "allow", "target": "true", "effect": "ALLOW", "tenantId": "a"},
				{"ruleId": "deny", "target": "true", "condition": %[2]q, "effect": "DENY", "tenantId": "a"}]}]}`,
		alg, condition)
}

// A DENY rule over a comparison that the PIP's answer leaves without an
// outcome (ERR in the specification's table, such as CONTAINS over a list
// with a null element) denies the resource whole, as a failed PIP does, on
// check/resource and check/filter alike. Under PERMIT_OVERRIDES the ALLOW
// rule beside it decides wherever the comparison has an outcome.
func TestADenyOverAComparisonThePIPValueLeavesWithoutAnOutcomeDenies(t *testing.T) {
	unknown := Result{Reason: ReasonUnknown}
	for _, tc := range []struct {
		name, alg, condition, body string
		want                       Result
		wantFilter                 string
	}{
		{"CONTAINS over [null] under PERMIT_OVERRIDES", "PERMIT_OVERRIDES", "subject.g CONTAINS 'x'", `[null]`,
			unknown, deny},
		{"CONTAINS over [null] under DENY_OVERRIDES", "DENY_OVERRIDES", "subject.g CONTAINS 'x'", `[null]`,
			unknown, deny},
		{"NOT CONTAINS over [null]", "PERMIT_OVERRIDES", "subject.g NOT CONTAINS 'x'", `[null]`, unknown, deny},
		{"CONTAINS over a list of two with a null element", "PERMIT_OVERRIDES", "subject.g CONTAINS 'x'",
			`["y", null]`, unknown, deny},
		{"IN a list with a null element", "PERMIT_OVERRIDES", "'x' IN subject.g", `["y", null]`, unknown, deny},
		{"IN [null]", "PERMIT_OVERRIDES", "'x' IN subject.g", `[null]`, unknown, deny},
		{"CONTAINS ANY over [null]", "PERMIT_OVERRIDES", "subject.g CONTAINS ANY 'x'", `[null]`, unknown, deny},
		{"CONTAINS over a list without null under PERMIT_OVERRIDES", "PERMIT_OVERRIDES", "subject.g CONTAINS 'x'",
			`["x"]`, Result{Allowed: true}, allow},
		{"CONTAINS over a list without null under DENY_OVERRIDES", "DENY_OVERRIDES", "subject.g CONTAINS 'x'",
			`["x"]`, Result{Reason: ReasonDenied}, deny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := pipServer(t, http.StatusOK, tc.body)
			r := pipRegistry(t)
			load(t, r, generalPIP(srv.URL, ""), denyBesideAllow(tc.alg, tc.condition))
			if got := decide(t, r, readDoc(t, "a", "y", 1)); got[0] != tc.want {
				t.Errorf("Decide(%s, PIP answers %s) = %+v, want %+v", tc.condition, tc.body, got[0], tc.want)
			}
			if got := filterOf(t, r, "a", "read"); got != tc.wantFilter {
				t.Errorf("Filter(%s, PIP answers %s) = %s, want %s", tc.condition, tc.body, got, tc.wantFilter)
			}
		})
	}
}

// scopeDenyBesideAllowAll is the policy sets of tenant a: set it iterates
// over the permission scope under algorithm alg, its target and its rule's
// effect and condition given, and set all allows every resource.
func scopeDenyBesideAllowAll(alg, target, effect, condition string) string {
	return fmt.Sprintf(`{"policySetId": "it", "name": "it", "status": "ACTIVE", "tenantId": "a",
		"target": %[2]q, "combiningAlgorithm": %[1]q,
		"iterate": {"foreach": "subject.permissionScope", "combiningAlgorithm": %[1]q},
		"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": %[1]q, "tenantId": "a",
			"rules": [{"ruleId": "r", "target": "true", "condition": %[4]q, "effect": %[3]q, "tenantId": "a"}]}]},
		{"policySetId": "all", "name": "all", "status": "ACTIVE", "tenantId": "a",
		"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
		"policies": [{"policyId": "q", "target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "a",
			"rules": [{"ruleId": "r", "target": "true", "effect": "ALLOW", "tenantId": "a"}]}]}`,
		alg, target, effect, condition)
}

// A permission scope that cannot be read makes an iterate under a target
// that holds a failed source: check/resource denies the resource and names
// the scope, and check/filter denies, though a set beside it allows every
// resource. Neither the effect of the rules inside the iterate nor whether
// their conditions read the scope matters.
func TestAFailedPermissionScopeDeniesThroughAnIterate(t *testing.T) {
	const (
		inScope = "subject.permissionScope.domain CONTAINS resource.a"
		doc     = "resourceType == 'doc'"
	)
	failed := Result{Reason: ReasonUnknown + ": subject.permissionScope"}
	scopeOfZ := `{"permissionScope": [{"policies": [{"scopeItems": [{"key": "domain", "values": [{"id": "z"}]}]}]}]}`
	for _, tc := range []struct {
		name, alg, target, effect, condition string
		status                               int
		body                                 string
		want                                 Result
		wantFilter                           string
	}{
		{"a DENY under PERMIT_UNLESS_DENY, the scope answering 500", "PERMIT_UNLESS_DENY", doc, "DENY", inScope,
			http.StatusInternalServerError, `oops`, failed, deny},
		{"a DENY under DENY_OVERRIDES, the scope answering 500", "DENY_OVERRIDES", doc, "DENY", inScope,
			http.StatusInternalServerError, `oops`, failed, deny},
		{"a DENY under PERMIT_UNLESS_DENY, the scope answering 200 with a body that is not JSON",
			"PERMIT_UNLESS_DENY", doc, "DENY", inScope, http.StatusOK, `<html>down</html>`, failed, deny},
		{"a DENY under DENY_OVERRIDES, the scope answering 200 with a body that is not JSON",
			"DENY_OVERRIDES", doc, "DENY", inScope, http.StatusOK, `<html>down</html>`, failed, deny},
		{"a DENY, the scope answering 404", "PERMIT_UNLESS_DENY", doc, "DENY", inScope, http.StatusNotFound, ``,
			failed, deny},
		{"a DENY, the scope answering 302", "PERMIT_UNLESS_DENY", doc, "DENY", inScope, http.StatusFound, ``,
			failed, deny},
		{"an ALLOW under DENY_UNLESS_PERMIT, the scope answering 500", "DENY_UNLESS_PERMIT", doc, "ALLOW", inScope,
			http.StatusInternalServerError, `oops`, failed, deny},
		{"a DENY whose condition is true, the scope answering 500", "PERMIT_UNLESS_DENY", doc, "DENY", "true",
			http.StatusInternalServerError, `oops`, failed, deny},
		{"a DENY over the resource alone, the scope answering 500", "PERMIT_UNLESS_DENY", doc, "DENY",
			"resource.a == 'zz'", http.StatusInternalServerError, `oops`, failed, deny},
		{"a DENY under a target that does not hold, the scope answering 500", "PERMIT_UNLESS_DENY",
			"resourceType == 'other'", "DENY", inScope, http.StatusInternalServerError, `oops`, Result{Allowed: true},
			allow},
		{"a DENY whose condition no pass meets", "PERMIT_UNLESS_DENY", doc, "DENY", inScope, http.StatusOK, scopeOfZ,
			Result{Allowed: true}, allow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := pipServer(t, tc.status, tc.body)
			r := pipRegistry(t)
			load(t, r, `{"tenantId": "a", "name": "subject.permissionScope", "pipType": "PERMISSION_SCOPE",
				"url": "`+srv.URL+`"}`, scopeDenyBesideAllowAll(tc.alg, tc.target, tc.effect, tc.condition))
			if got := decide(t, r, readDoc(t, "a", "y", 1)); got[0] != tc.want {
				t.Errorf("Decide(%s, scope answers %d %q) = %+v, want %+v", tc.condition, tc.status, tc.body, got[0],
					tc.want)
			}
			claims, err := jsonvalue.Decode([]byte(`{"sub": "u1", "realm_access": {"roles": ["R"]}}`))
			if err != nil {
				t.Fatal(err)
			}
			if got := filterOfClaims(t, r, claims.(*jsonvalue.Object), "a", "read"); got != tc.wantFilter {
				t.Errorf("Filter(%s, scope answers %d %q) = %s, want %s", tc.condition, tc.status, tc.body, got,
					tc.wantFilter)
			}
		})
	}
}

// A DENY over a comparison of two PIP answers denies the resource whole
// where a list of one null element leaves the comparison without an outcome,
// as in TestADenyOverAComparisonThePIPValueLeavesWithoutAnOutcomeDenies. On
// the left of CONTAINS ANY a null element ends the rule only against a right
// list without one; with a null on both sides the values are compared.
func TestADenyOverAComparisonOfTwoPIPListsWithANullElement(t *testing.T) {
	unknown := Result{Reason: ReasonUnknown}
	for _, tc := range []struct {
		name, condition, left, right string
		want                         Result
		wantFilter                   string
	}{
		{"CONTAINS ANY of [null] and [null]", "subject.g CONTAINS ANY subject.h", `[null]`, `[null]`, unknown, deny},
		{"CONTAINS ANY of [null] and a list holding null", "subject.g CONTAINS ANY subject.h", `[null]`,
			`["y", null]`, unknown, deny},
		{"CONTAINS ANY of a list holding null and [null]", "subject.g CONTAINS ANY subject.h", `["y", null]`,
			`[null]`, Result{Allowed: true}, allow},
		{"CONTAINS of [null] and a list of two", "subject.g CONTAINS subject.h", `[null]`, `["a", "b"]`, unknown,
			deny},
		{"CONTAINS of [null] and a list of one", "subject.g CONTAINS subject.h", `[null]`, `["x"]`, unknown, deny},
		{"CONTAINS of a list without null and a list of two", "subject.g CONTAINS subject.h", `["x"]`, `["a", "b"]`,
			Result{Allowed: true}, allow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := pipServer(t, http.StatusOK, tc.left)
			h, _ := pipServer(t, http.StatusOK, tc.right)
			r := pipRegistry(t)
			load(t, r, generalPIP(g.URL, "")+`, {"tenantId": "a", "name": "subject.h", "pipType": "GENERAL",
				"url": "`+h.URL+`", "httpMethod": "GET"}`, denyBesideAllow("PERMIT_OVERRIDES", tc.condition))
			if got := decide(t, r, readDoc(t, "a", "y", 1)); got[0] != tc.want {
				t.Errorf("Decide(%s, g = %s, h = %s) = %+v, want %+v", tc.condition, tc.left, tc.right, got[0], tc.want)
			}
			if got := filterOf(t, r, "a", "read"); got != tc.wantFilter {
				t.Errorf("Filter(%s, g = %s, h = %s) = %s, want %s", tc.condition, tc.left, tc.right, got,
					tc.wantFilter)
			}
		})
	}
}
