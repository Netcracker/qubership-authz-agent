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

	"authz-agent/test/parity/suite/model"
)

// isolatedCaseDomain receives one case's PIPs and policy at a time. On the legacy
// profile a declaration the PAP refuses never reaches the seeded domain and cannot
// fail its upload. On the authz-agent profile authz-policy-admin serves the union
// of all domains, so a policy the agent cannot parse fails the agent's load until
// the next case replaces it; the requests of that case then see stale policies.
const isolatedCaseDomain = "PARITY_ISOLATED"

// isolatedCase is one policy uploaded alone, with the PIPs it references, and the
// requests sent against it once the upload is accepted. A PIP it references has to
// be declared in pips, since PIPs belong to a domain; X19 and X20 reference an
// undeclared one on purpose.
type isolatedCase struct {
	id           string
	resourceType string
	operation    string
	roles        []string
	condition    string
	rsql         string
	pips         []any
	requests     []isolatedRequest
}

// isolatedRequest is a check/resource request, or a check/filter request when
// filter is set, against the case's policy.
type isolatedRequest struct {
	name      string
	operation string
	typ       string
	resource  any
	headers   map[string]string
	filter    bool
	// omitOperation sends a filter request with no operation parameter at all,
	// where an empty operation would fall back to LIST.
	omitOperation bool
	// m2mOnly sends the service's M2M token alone, with no end-user token, so
	// the subject is the service account rather than parity-reader.
	m2mOnly bool
}

// requestTokens returns the tokens req is sent with: parity-reader's bundle, or the
// M2M token alone for an m2mOnly request.
func (s *ParitySuite) requestTokens(req isolatedRequest) TokenBundle {
	if req.m2mOnly {
		return TokenBundle{M2M: s.mustM2MToken()}
	}
	return s.mustTokenBundle(UserProfileReader)
}

// parityNoHeaderPIP is a HEADER PIP with no defaultValue, a declaration no seeded
// fixture has made the PAP accept.
var parityNoHeaderPIP = map[string]any{
	"name":      "subject.parityNoHeader",
	"type":      "UUID",
	"pipType":   "HEADER",
	"header":    "x-parity-no-such-header",
	"cacheable": false,
}

// Operator forms, attribute paths, subject attributes, literals, whitespace,
// declarations, and policy shapes whose acceptance by the PAP is not established.
func (s *ParitySuite) TestIsolatedPolicyCases() {
	cases := []isolatedCase{
		{id: "j1-nested-path-neq", resourceType: "PARITY_SUITE_ISO_J1", condition: "resource.o.x != 'v'", requests: []isolatedRequest{
			{name: "parent-absent", resource: map[string]any{"id": "iso-j1"}},
			{name: "parent-empty-object", resource: map[string]any{"id": "iso-j1", "o": map[string]any{}}},
			{name: "parent-null", resource: map[string]any{"id": "iso-j1", "o": nil}},
			{name: "leaf-differs", resource: map[string]any{"id": "iso-j1", "o": map[string]any{"x": "w"}}},
		}},
		{id: "j5-array-index", resourceType: "PARITY_SUITE_ISO_J5", condition: "resource.list[0] == 'a'", requests: []isolatedRequest{
			{name: "first-element-matches", resource: map[string]any{"id": "iso-j5", "list": []string{"a", "b"}}},
			{name: "array-absent", resource: map[string]any{"id": "iso-j5"}},
		}},
		{id: "j6-array-wildcard-path", resourceType: "PARITY_SUITE_ISO_J6", condition: "resource.items[*].id CONTAINS 'a'", requests: []isolatedRequest{
			{name: "an-item-has-the-id", resource: map[string]any{"id": "iso-j6", "items": []any{map[string]any{"id": "a"}, map[string]any{"id": "b"}}}},
		}},
		{id: "j7-bracket-path", resourceType: "PARITY_SUITE_ISO_J7", condition: "resource['x'] == 'v'", requests: []isolatedRequest{
			{name: "attribute-matches", resource: map[string]any{"id": "iso-j7", "x": "v"}},
		}},
		{id: "j8-hyphen-in-key", resourceType: "PARITY_SUITE_ISO_J8", condition: "resource.a-b == 'v'", requests: []isolatedRequest{
			{name: "hyphenated-key-matches", resource: map[string]any{"id": "iso-j8", "a-b": "v"}},
		}},
		{id: "c1-number-literal", resourceType: "PARITY_SUITE_ISO_C1", condition: "resource.n == 5", requests: []isolatedRequest{
			{name: "integer", resource: map[string]any{"id": "iso-c1", "n": 5}},
			{name: "string", resource: map[string]any{"id": "iso-c1", "n": "5"}},
			{name: "float", resource: map[string]any{"id": "iso-c1", "n": json.Number("5.0")}},
		}},
		{id: "c2-number-precision", resourceType: "PARITY_SUITE_ISO_C2", condition: "resource.n == 9007199254740993", requests: []isolatedRequest{
			{name: "neighbour-below", resource: map[string]any{"id": "iso-c2", "n": json.Number("9007199254740992")}},
			{name: "exact", resource: map[string]any{"id": "iso-c2", "n": json.Number("9007199254740993")}},
		}},
		{id: "c7-equals-empty-string", resourceType: "PARITY_SUITE_ISO_C7", condition: "resource.x == ''", requests: []isolatedRequest{
			{name: "attribute-empty", resource: map[string]any{"id": "iso-c7", "x": ""}},
			{name: "attribute-absent", resource: map[string]any{"id": "iso-c7"}},
		}},
		{id: "l3-in-resource-collection", resourceType: "PARITY_SUITE_ISO_L3", condition: "resource.x IN resource.list", requests: []isolatedRequest{
			{name: "value-in-collection", resource: map[string]any{"id": "iso-l3", "x": "a", "list": []string{"a"}}},
			{name: "collection-absent", resource: map[string]any{"id": "iso-l3", "x": "a"}},
		}},
		{id: "l4-subset-of-literal-list", resourceType: "PARITY_SUITE_ISO_L4", condition: "resource.list IS SUBSET 'a', 'b'", requests: []isolatedRequest{
			{name: "empty-collection", resource: map[string]any{"id": "iso-l4", "list": []string{}}},
			{name: "foreign-element", resource: map[string]any{"id": "iso-l4", "list": []string{"c"}}},
		}},
		{id: "l5-contains-literal", resourceType: "PARITY_SUITE_ISO_L5", condition: "resource.tags CONTAINS 'red'", requests: []isolatedRequest{
			{name: "collection-with-value", resource: map[string]any{"id": "iso-l5", "tags": []string{"red"}}},
			{name: "scalar-equal-to-value", resource: map[string]any{"id": "iso-l5", "tags": "red"}},
			{name: "string-containing-value", resource: map[string]any{"id": "iso-l5", "tags": "bred"}},
		}},
		{id: "l8-number-list-in", resourceType: "PARITY_SUITE_ISO_L8", condition: "resource.n IN 1, 2", requests: []isolatedRequest{
			{name: "number", resource: map[string]any{"id": "iso-l8", "n": 1}},
			{name: "string-number", resource: map[string]any{"id": "iso-l8", "n": "1"}},
		}},
		{id: "l9-is-not-empty", resourceType: "PARITY_SUITE_ISO_L9", condition: "resource.x IS NOT EMPTY", requests: []isolatedRequest{
			{name: "attribute-absent", resource: map[string]any{"id": "iso-l9"}},
			{name: "empty-string", resource: map[string]any{"id": "iso-l9", "x": ""}},
			{name: "empty-collection", resource: map[string]any{"id": "iso-l9", "x": []string{}}},
		}},
		{id: "a1-attribute-equals-attribute", resourceType: "PARITY_SUITE_ISO_A1", condition: "resource.x == resource.y", requests: []isolatedRequest{
			{name: "both-equal", resource: map[string]any{"id": "iso-a1", "x": "v", "y": "v"}},
			{name: "right-absent", resource: map[string]any{"id": "iso-a1", "x": "v"}},
		}},
		{id: "a2-match-attribute-pattern", resourceType: "PARITY_SUITE_ISO_A2", condition: "resource.x MATCH resource.p", requests: []isolatedRequest{
			{name: "pattern-matches", resource: map[string]any{"id": "iso-a2", "x": "abc", "p": "ab*"}},
		}},
		{id: "h1-header-pip-no-value-neq", resourceType: "PARITY_SUITE_ISO_H1", condition: "subject.parityNoHeader != 'x'", pips: []any{parityNoHeaderPIP}, requests: []isolatedRequest{
			{name: "header-absent", resource: map[string]any{"id": "iso-h1"}},
			{name: "header-other-value", resource: map[string]any{"id": "iso-h1"}, headers: map[string]string{"x-parity-no-such-header": "y"}},
			{name: "header-equal-value", resource: map[string]any{"id": "iso-h1"}, headers: map[string]string{"x-parity-no-such-header": "x"}},
		}},
		{id: "h2-header-pip-no-value-is-null", resourceType: "PARITY_SUITE_ISO_H2", condition: "subject.parityNoHeader IS NULL", pips: []any{parityNoHeaderPIP}, requests: []isolatedRequest{
			{name: "header-absent", resource: map[string]any{"id": "iso-h2"}},
			{name: "header-sent", resource: map[string]any{"id": "iso-h2"}, headers: map[string]string{"x-parity-no-such-header": "y"}},
		}},
		{id: "u1-subject-roles-contains", resourceType: "PARITY_SUITE_ISO_U1", condition: "subject.roles CONTAINS 'ROLE_PARITY_READER'", requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-u1"}},
		}},
		{id: "u2-subject-roles-other-case", resourceType: "PARITY_SUITE_ISO_U2", condition: "subject.roles CONTAINS 'role_parity_reader'", requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-u2"}},
		}},
		{id: "u3-subject-service-account-is-null", resourceType: "PARITY_SUITE_ISO_U3", condition: "subject.serviceAccount IS NULL", requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-u3"}},
		}},
		{id: "u4-subject-type", resourceType: "PARITY_SUITE_ISO_U4", condition: "subject.type == 'USER'", requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-u4"}},
		}},
		{id: "u5-subject-name", resourceType: "PARITY_SUITE_ISO_U5", condition: "subject.name == 'parity-reader'", requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-u5"}},
		}},
		{id: "u6-subject-id-is-not-null", resourceType: "PARITY_SUITE_ISO_U6", condition: "subject.id IS NOT NULL", requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-u6"}},
		}},
		{id: "u7-has-access", resourceType: "PARITY_SUITE_ISO_U7", condition: "subject allowed 'READ' on resource", requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-u7"}},
		}},
		{id: "o1-operation-operand", resourceType: "PARITY_SUITE_ISO_O1", condition: "operation == 'READ'", requests: []isolatedRequest{
			{name: "read", resource: map[string]any{"id": "iso-o1"}},
		}},
		{id: "o2-resource-type-operand", resourceType: "PARITY_SUITE_ISO_O2", condition: "resourceType == 'PARITY_SUITE_ISO_O2'", requests: []isolatedRequest{
			{name: "own-type", resource: map[string]any{"id": "iso-o2"}},
		}},
		{id: "r5-bare-resource-operand", resourceType: "PARITY_SUITE_ISO_R5", condition: "resource == 'abc'", requests: []isolatedRequest{
			{name: "resource-string", resource: "abc"},
		}},
		{id: "x1-literal-on-the-left", resourceType: "PARITY_SUITE_ISO_X1", condition: "'v' == resource.x", requests: []isolatedRequest{
			{name: "attribute-matches", resource: map[string]any{"id": "iso-x1", "x": "v"}},
		}},
		{id: "x2-equals-keyword", resourceType: "PARITY_SUITE_ISO_X2", condition: "resource.x EQUALS 'v'", requests: []isolatedRequest{
			{name: "attribute-matches", resource: map[string]any{"id": "iso-x2", "x": "v"}},
		}},
		{id: "x3-not-equals-keyword", resourceType: "PARITY_SUITE_ISO_X3", condition: "resource.x NOT EQUALS 'v'", requests: []isolatedRequest{
			{name: "attribute-differs", resource: map[string]any{"id": "iso-x3", "x": "w"}},
		}},
		{id: "x4-greater-or-equal-words", resourceType: "PARITY_SUITE_ISO_X4", condition: "resource.n GREATER THAN OR EQUAL TO 5", requests: []isolatedRequest{
			{name: "boundary", resource: map[string]any{"id": "iso-x4", "n": 5}},
		}},
		{id: "x5-match-unquoted-wildcard", resourceType: "PARITY_SUITE_ISO_X5", condition: "resource.x MATCH ab*", requests: []isolatedRequest{
			{name: "prefix-matches", resource: map[string]any{"id": "iso-x5", "x": "abc"}},
			{name: "match-inside", resource: map[string]any{"id": "iso-x5", "x": "xabc"}},
			{name: "prefix-other-case", resource: map[string]any{"id": "iso-x5", "x": "ABC"}},
		}},
		{id: "x6-match-quoted-wildcard", resourceType: "PARITY_SUITE_ISO_X6", condition: "resource.x MATCH 'ab*'", requests: []isolatedRequest{
			{name: "prefix-matches", resource: map[string]any{"id": "iso-x6", "x": "abc"}},
		}},
		{id: "x9-boolean-literal-uppercase", resourceType: "PARITY_SUITE_ISO_X9", condition: "resource.b == TRUE", requests: []isolatedRequest{
			{name: "attribute-true", resource: map[string]any{"id": "iso-x9", "b": true}},
		}},
		{id: "x10-condition-literal-true", resourceType: "PARITY_SUITE_ISO_X10", condition: "TRUE", requests: []isolatedRequest{
			{name: "any-resource", resource: map[string]any{"id": "iso-x10"}},
		}},
		{id: "x11-keyword-inside-string", resourceType: "PARITY_SUITE_ISO_X11", condition: "resource.x == 'a AND b'", requests: []isolatedRequest{
			{name: "attribute-matches", resource: map[string]any{"id": "iso-x11", "x": "a AND b"}},
		}},
		{id: "x12-list-without-spaces", resourceType: "PARITY_SUITE_ISO_X12", condition: "resource.x IN 'a','b'", requests: []isolatedRequest{
			{name: "second-element", resource: map[string]any{"id": "iso-x12", "x": "b"}},
		}},
		{id: "x13-comma-inside-list-string", resourceType: "PARITY_SUITE_ISO_X13", condition: "resource.x IN 'a,b'", requests: []isolatedRequest{
			{name: "part-before-comma", resource: map[string]any{"id": "iso-x13", "x": "a"}},
			{name: "whole-string", resource: map[string]any{"id": "iso-x13", "x": "a,b"}},
		}},
		{id: "x14-leading-space", resourceType: "PARITY_SUITE_ISO_X14", condition: " resource.x == 'v'", requests: []isolatedRequest{
			{name: "attribute-matches", resource: map[string]any{"id": "iso-x14", "x": "v"}},
		}},
		{id: "x15-trailing-space", resourceType: "PARITY_SUITE_ISO_X15", condition: "resource.x == 'v' ", requests: []isolatedRequest{
			{name: "attribute-matches", resource: map[string]any{"id": "iso-x15", "x": "v"}},
		}},
		{id: "x16-tab-between-tokens", resourceType: "PARITY_SUITE_ISO_X16", condition: "resource.x ==\t'v'", requests: []isolatedRequest{
			{name: "attribute-matches", resource: map[string]any{"id": "iso-x16", "x": "v"}},
		}},
		{id: "x17-number-leading-zero", resourceType: "PARITY_SUITE_ISO_X17", condition: "resource.n == 05", requests: []isolatedRequest{
			{name: "number-five", resource: map[string]any{"id": "iso-x17", "n": 5}},
		}},
		{id: "x19-undeclared-subject-attribute", resourceType: "PARITY_SUITE_ISO_X19", condition: "subject.parityUndeclared == 'x'", requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-x19"}},
		}},
		{id: "x20-undeclared-placeholder", resourceType: "PARITY_SUITE_ISO_X20", operation: "LIST", rsql: "owner==${subject.parityUndeclared}", requests: []isolatedRequest{
			{name: "filter", operation: "LIST", filter: true},
		}},
		{id: "x24-lowercase-is-null", resourceType: "PARITY_SUITE_ISO_X24", condition: "resource.x is null", requests: []isolatedRequest{
			{name: "attribute-absent", resource: map[string]any{"id": "iso-x24"}},
		}},
		{id: "x25-double-quoted-string", resourceType: "PARITY_SUITE_ISO_X25", condition: `resource.x == "v"`, requests: []isolatedRequest{
			{name: "attribute-matches", resource: map[string]any{"id": "iso-x25", "x": "v"}},
		}},
		{id: "x26-null-literal", resourceType: "PARITY_SUITE_ISO_X26", condition: "resource.x != null", requests: []isolatedRequest{
			{name: "attribute-present", resource: map[string]any{"id": "iso-x26", "x": "w"}},
			{name: "attribute-absent", resource: map[string]any{"id": "iso-x26"}},
		}},
		{id: "x28-policy-resource-type-lowercase", resourceType: "parity_suite_iso_x28", requests: []isolatedRequest{
			{name: "request-uppercase", typ: "PARITY_SUITE_ISO_X28", resource: map[string]any{"id": "iso-x28"}},
			{name: "request-lowercase", typ: "parity_suite_iso_x28", resource: map[string]any{"id": "iso-x28"}},
		}},
		{id: "x29-policy-role-lowercase", resourceType: "PARITY_SUITE_ISO_X29", roles: []string{"role_parity_reader"}, requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-x29"}},
		}},
		{id: "x30-policy-operation-all", resourceType: "PARITY_SUITE_ISO_X30", operation: "ALL", requests: []isolatedRequest{
			{name: "read", operation: "READ", resource: map[string]any{"id": "iso-x30"}},
			{name: "delete", operation: "DELETE", resource: map[string]any{"id": "iso-x30"}},
		}},
		{id: "x31-policy-without-roles", resourceType: "PARITY_SUITE_ISO_X31", roles: []string{}, requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-x31"}},
		}},
	}

	s.runIsolatedCases(cases)
}

// runIsolatedCases uploads each case alone into isolatedCaseDomain and records the
// upload status and, when the PAP accepts the case, the status and the answer of
// every request. The upload status is a golden of its own, so a form the PAP
// refuses is a recorded result rather than a failed case. On the authz-agent
// profile the upload status is not compared (authz-policy-admin accepts anything)
// and the requests are.
func (s *ParitySuite) runIsolatedCases(cases []isolatedCase) {
	reader := []string{"ROLE_PARITY_READER"}

	ctx := context.Background()
	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s: %v", isolatedCaseDomain, err)
		}
	})
	for _, tc := range cases {
		s.Run(tc.id, func() {
			policy := map[string]any{
				"component":             "PARITY",
				"reason":                tc.id,
				"resourceType":          tc.resourceType,
				"operation":             valueOr(tc.operation, "READ"),
				"roles":                 reader,
				"applicableForFrontend": false,
				"id":                    "00000000-0000-0000-0000-0000000f0001",
			}
			if tc.roles != nil {
				policy["roles"] = tc.roles
			}
			if tc.condition != "" {
				policy["condition"] = tc.condition
			}
			if tc.rsql != "" {
				policy["rsqlPredicate"] = tc.rsql
			}
			status, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, tc.pips, []any{policy})
			s.Require().NoError(err)

			if !isAuthzAgentProfile(s.cfg.Profile) {
				s.Run("upload", func() {
					s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "isolated/"+tc.id, &model.PolicyLoadOutcome{Status: status})
				})
				if status < http.StatusOK || status >= http.StatusMultipleChoices {
					return
				}
			}
			for _, req := range tc.requests {
				s.Run(req.name, func() {
					subCase := "isolated/" + tc.id + "/" + req.name
					resourceType := valueOr(req.typ, tc.resourceType)
					opts := PerCallOptions{CustomHeaders: req.headers}
					if req.filter {
						s.runPendingFilterV1OutcomeCase(subCase, resourceType, req.filterOperation(), s.requestTokens(req), opts)
						return
					}
					s.runPendingCheckResourceV1OutcomeCase(
						subCase,
						model.CheckAccessRequest{Operation: valueOr(req.operation, "READ"), Type: resourceType, Resource: req.resource},
						s.requestTokens(req),
						opts,
					)
				})
			}
		})
	}
}

// filterOperation is the operation parameter of a filter request: LIST unless the
// request names one, and none at all when omitOperation is set.
func (r isolatedRequest) filterOperation() string {
	if r.omitOperation {
		return ""
	}
	return valueOr(r.operation, "LIST")
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
