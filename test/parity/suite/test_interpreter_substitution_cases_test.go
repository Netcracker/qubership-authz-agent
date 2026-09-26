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

//go:build integration

package paritysuite

import (
	"context"
	"encoding/json"
	"net/http"
)

// substitutionHeader is the header the HEADER PIP of the substitution cases
// reads; it is not one the thin client strips (prohibitedHeaders).
const substitutionHeader = "x-parity-sub-header"

// substitutionSource is one source a placeholder can name, with the PIP that
// declares it and the pip-mock answer the PIP reads, where it is a GENERAL PIP.
type substitutionSource struct {
	key string
	// placeholder is the attribute the five predicates name.
	placeholder string
	// pip is the declaration uploaded with the case, nil for a source that
	// needs none (subject.roles).
	pip map[string]any
	// route and response pin pip-mock for a GENERAL PIP; route is empty for the
	// others.
	route    string
	response PipStubResponse
	// headers go with the filter request, for the HEADER PIP.
	headers map[string]string
}

// substitutionGeneralPIP declares a GENERAL PIP named subject.paritySub<key>
// answering at pip-mock path /sub-<key>, in the shape of the recorded
// declarations (suite-pips.json); jsonPath is set when non-empty.
func substitutionGeneralPIP(key, jsonPath string) map[string]any {
	pip := map[string]any{
		"name":              "subject.paritySub" + key,
		"url":               parityPipMockBase + "/sub-" + key,
		"httpMethod":        "POST",
		"pipType":           "GENERAL",
		"requestAttributes": map[string]string{"resourceType": "PARITY_SUITE_SUB"},
		"cacheable":         false,
	}
	if jsonPath != "" {
		pip["type"] = "JSON"
		pip["jsonPath"] = jsonPath
	}
	return pip
}

// substitutionSources are the sources of the matrix, one case each. Every
// GENERAL source answers at its own pip-mock path, so the call log after the
// run says which of them access-control read.
func substitutionSources() []substitutionSource {
	general := func(key, name, jsonPath string, response PipStubResponse) substitutionSource {
		return substitutionSource{
			key:         key,
			placeholder: "subject.paritySub" + name,
			pip:         substitutionGeneralPIP(name, jsonPath),
			route:       "/api/v1/pip/sub-" + name,
			response:    response,
		}
	}
	ok := func(body any) PipStubResponse { return PipStubResponse{StatusCode: http.StatusOK, Body: body} }
	return []substitutionSource{
		{key: "subject-roles", placeholder: "subject.roles"},
		{key: "token-scalar", placeholder: "subject.paritySubToken", pip: map[string]any{
			"name": "subject.paritySubToken", "type": "UUID", "pipType": "TOKEN", "claim": "department", "defaultValue": "none", "cacheable": false,
		}},
		{key: "header-scalar", placeholder: "subject.paritySubHeader", pip: map[string]any{
			"name": "subject.paritySubHeader", "type": "UUID", "pipType": "HEADER", "header": substitutionHeader, "defaultValue": "none", "cacheable": false,
		}, headers: map[string]string{substitutionHeader: "parity-header-value"}},
		general("general-string", "String", "$.value", ok(map[string]any{"value": "v"})),
		general("general-number", "Number", "$.value", ok(map[string]any{"value": json.Number("1000")})),
		general("general-boolean", "Boolean", "$.value", ok(map[string]any{"value": true})),
		general("general-list", "List", "", ok([]string{"a", "b"})),
		general("general-single-element-list", "SingleElementList", "", ok([]string{"a"})),
		general("general-empty-list", "EmptyList", "", ok([]string{})),
		// A body that is the JSON literal null, spelled out as the recorded
		// null-body case does; the stub writes null for a nil Body as well.
		general("general-null", "Null", "", PipStubResponse{StatusCode: http.StatusOK, BodyRaw: "null"}),
		general("general-object", "Object", "", ok(map[string]any{"k": "v"})),
		general("general-special-chars", "SpecialChars", "$.value", ok(map[string]any{"value": "red,blue;green('q')\"x\""})),
		general("general-failed", "Failed", "", PipStubResponse{StatusCode: http.StatusInternalServerError, Body: map[string]string{"error": "parity substitution case"}}),
	}
}

// How each source of a placeholder is rendered by each predicate dialect of
// check/filter. The recorded filter cases cover a few of the cells: subject.id
// in four dialects (full-use-filter), a PIP string, number, boolean and object
// in rsql (general-scalar-substitution, general-scalar-number-substitution,
// general-scalar-boolean-substitution, general-pip-dict), a PIP scalar in sql
// (token-scalar-into-sql), a PIP collection in sql (general-array-into-sql) and
// in rsql (general-pip-list), a HEADER scalar in mongodb
// (header-scalar-into-mongodb), and a scalar with characters rsql gives meaning
// to, in rsql alone (general-scalar-special-chars). No cell records the custom
// dialect at all, the querydsl dialect with a PIP, a collection in mongodb, or
// what a number, a boolean, an empty collection, a null body, or an object
// becomes outside rsql.
//
// Each case uploads one regular set whose LIST rule carries the same placeholder
// in all five predicate fields, so one filter request records the five
// renderings at once: rsql, sql, mongodb, querydsl (the predicate field) and
// custom (customPredicate, whose parameter names the same source). A GENERAL
// source answers at a pip-mock path of its own, and the call log is read after
// the case, since a rendering that shows the placeholder unreplaced is
// explained by a PIP access-control never called as much as by one it does not
// substitute. general-string is the control: a scalar every recorded dialect
// renders.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case.
func (s *ParitySuite) TestInterpreterSubstitutionCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("regular policy sets are evaluated by access-control only; authz-agent loads simplified policies")
	}
	ctx := context.Background()
	for _, source := range substitutionSources() {
		if source.route == "" {
			continue
		}
		s.Require().NoError(s.pipMock.PinRoute(ctx, source.route, source.response), "pin %s", source.route)
	}
	for _, tc := range substitutionCases() {
		s.Require().NoError(s.pipMock.ResetCalls(ctx))
		s.runRegularCases([]regularCase{tc.regularCase})
		if tc.route == "" {
			continue
		}
		s.Run(tc.id+"/the-pip-was-read", func() {
			calls, err := s.pipMock.GetCalls(ctx)
			s.Require().NoError(err)
			read := 0
			for _, call := range calls {
				if call.Path == tc.route {
					read++
				}
			}
			s.Assert().Positive(read, "pip-mock calls to %s over the requests of %s", tc.route, tc.id)
		})
	}
}

// substitutionCase pairs a regular case with the pip-mock route its source
// answers at.
type substitutionCase struct {
	regularCase
	route string
}

func substitutionCases() []substitutionCase {
	var cases []substitutionCase
	for _, source := range substitutionSources() {
		id := "substitution-" + source.key
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		rule := substitutionRule(b, source.placeholder)
		var pips []any
		if source.pip != nil {
			pips = []any{source.pip}
		}
		cases = append(cases, substitutionCase{route: source.route, regularCase: regularCase{
			id:           id,
			resourceType: rt,
			pips:         pips,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT", rule),
				}, nil),
			}}},
			requests: []isolatedRequest{{name: "filter", filter: true, headers: source.headers}},
		}})
	}
	return cases
}

// substitutionRule builds the LIST rule of a substitution case: an ALLOW rule
// that names placeholder in all five predicate fields.
func substitutionRule(b regularBuilder, placeholder string) map[string]any {
	rule := b.rule("list", "operation == 'LIST'", "true", "ALLOW", map[string]string{
		"rsqlPredicate":    "a==${" + placeholder + "}",
		"sqlPredicate":     "a=${" + placeholder + "}",
		"mongodbPredicate": `{ "a": ${` + placeholder + `} }`,
		"predicate":        "${resourceType}.a.eq(${" + placeholder + "})",
	})
	rule["customPredicate"] = map[string]any{
		"predicate": "a:${p}",
		"params":    map[string]any{"p": placeholder},
	}
	return rule
}

// substitutionRegularCases lists the regular cases of the substitution matrix
// for TestRegularCaseIDsAreUnique.
func substitutionRegularCases() []regularCase {
	var cases []regularCase
	for _, tc := range substitutionCases() {
		cases = append(cases, tc.regularCase)
	}
	return cases
}

// permissionListMapping declares a MAPPING PIP under the name suffix that grants
// permissions to role.
func permissionListMapping(suffix, role string, permissions []string) map[string]any {
	return map[string]any{
		"name":      "subject.permissions." + suffix,
		"type":      "UUID",
		"pipType":   "MAPPING",
		"cacheable": false,
		"customMapping": map[string]any{
			"subject.roles": map[string]any{
				role: permissions,
			},
		},
	}
}

// What subject.permissions holds, read through a placeholder of check/filter.
// u10-subject-permissions-is-empty and u11-subject-permissions-contains record
// false for IS EMPTY and for CONTAINS with no MAPPING PIP declared, and false
// under IS EMPTY is what a non-empty list, a null, and an absent attribute all
// produce. A predicate that names the list as a placeholder renders it in the
// response, the way general-pip-list renders a PIP collection, and the
// rendering tells the three apart. Each case here is one regular set whose LIST
// rule carries ${subject.permissions} in its rsql and sql predicates, and one
// filter request.
//
// The cases partition the MAPPING PIPs declared beside the set: none; one for
// a role the reader does not hold; one for the reader's role, the control that
// the placeholder renders a granted permission (pm1-mapping-pip-merged-list
// records the grant itself); two that grant different permissions, which says
// whether two declarations are merged into one list; two that grant the same
// permission, which says whether the merged list holds it once; and one that
// grants an empty list. permission-list-scopes-and-roles renders
// ${subject.scopes} and ${subject.roles}, the two other list-valued subject
// keys, with no MAPPING PIP declared.
//
// runRegularCases replaces the domain's PIPs only for a case that declares
// some, so the two cases with no declaration run first, on the domain the
// previous test's cleanup emptied, and every case after them declares its own.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case.
func (s *ParitySuite) TestInterpreterPermissionListCases() {
	s.runRegularCases(permissionListCases())
}

func permissionListCases() []regularCase {
	var cases []regularCase
	for _, form := range []struct {
		key  string
		pips []any
		// rsql and sql are the predicates; the default renders the permissions.
		rsql, sql string
	}{
		{key: "no-mapping"},
		{key: "scopes-and-roles", rsql: "scopes=in=(${subject.scopes})", sql: "roles IN (${subject.roles})"},
		{key: "mapping-for-another-role", pips: []any{permissionListMapping("PARITY_OTHER", "ROLE_PARITY_OTHER", []string{"parity_other_permission"})}},
		{key: "mapping-for-the-role", pips: []any{permissionListMapping("PARITY_LIST", "ROLE_PARITY_READER", []string{"parity_permission"})}},
		{key: "two-mappings-with-different-permissions", pips: []any{
			permissionListMapping("PARITY_LIST_ONE", "ROLE_PARITY_READER", []string{"parity_permission"}),
			permissionListMapping("PARITY_LIST_TWO", "ROLE_PARITY_READER", []string{"parity_other_permission"}),
		}},
		{key: "two-mappings-with-the-same-permission", pips: []any{
			permissionListMapping("PARITY_LIST_ONE", "ROLE_PARITY_READER", []string{"parity_permission"}),
			permissionListMapping("PARITY_LIST_TWO", "ROLE_PARITY_READER", []string{"parity_permission"}),
		}},
		{key: "mapping-with-an-empty-list", pips: []any{permissionListMapping("PARITY_LIST_EMPTY", "ROLE_PARITY_READER", []string{})}},
	} {
		id := "permission-list-" + form.key
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		predicates := map[string]string{
			"rsqlPredicate": valueOr(form.rsql, "perms=in=(${subject.permissions})"),
			"sqlPredicate":  valueOr(form.sql, "perms IN (${subject.permissions})"),
		}
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			pips:         form.pips,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("list", "operation == 'LIST'", "true", "ALLOW", predicates)),
				}, nil),
			}}},
			requests: []isolatedRequest{{name: "filter", filter: true}},
		})
	}
	return cases
}
