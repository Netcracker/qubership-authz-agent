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

// parityPipMockBase is the pip-mock address as access-control resolves it, the
// same one every PIP fixture under testdata/fixtures spells out. The suite
// reaches the same service through Config.PipMockControlURL, which is a
// different address on a different network.
const parityPipMockBase = "http://pip-mock:8090/api/v1/pip"

// parityFilteredPIP declares a FILTERED PIP with the fields of an accepted
// GENERAL one, so that a refusal is about the pipType rather than about a field
// the declaration left out. No fixture has made the PAP accept this pipType and
// the field set it requires is unknown, so the case records the upload status.
var parityFilteredPIP = map[string]any{
	"name":              "subject.parityFilteredList",
	"url":               parityPipMockBase + "/iso-filtered",
	"httpMethod":        "POST",
	"pipType":           "FILTERED",
	"requestAttributes": map[string]string{"resourceType": "PARITY_SUITE_ISO_H3"},
	"cacheable":         false,
}

// parityListPIP is a GENERAL PIP returning a collection, shaped like the accepted
// declarations under testdata/fixtures, so that h5 measures the FILTERED condition
// form against a pipType the PAP is known to take.
var parityListPIP = map[string]any{
	"name":              "subject.parityList",
	"url":               parityPipMockBase + "/iso-list",
	"httpMethod":        "POST",
	"pipType":           "GENERAL",
	"requestAttributes": map[string]string{"resourceType": "PARITY_SUITE_ISO_H5"},
	"cacheable":         false,
}

// parityPermissionsPIP grants parity_permission to ROLE_PARITY_READER. A PIP of
// this shape is how access-control assigns permissions to a role outside the
// simplified policies: it declares the mapping inline, and every
// subject.permissions.<suffix> PIP the tenant holds is merged into one
// subject.permissions list on the subject. The real export carries
// "cacheable": true; this declaration keeps the false every accepted fixture
// under testdata/fixtures uses, so that pm3 cannot be answered by a cache.
var parityPermissionsPIP = map[string]any{
	"name":      "subject.permissions.PARITY",
	"type":      "UUID",
	"pipType":   "MAPPING",
	"cacheable": false,
	"customMapping": map[string]any{
		"subject.roles": map[string]any{
			"ROLE_PARITY_READER": []string{"parity_permission"},
		},
	},
}

// TestIsolatedConditionFormCases covers forms the agent's own condition parser
// accepts and no golden records: the negated operators NOT MATCH, IS NOT SUBSET
// and NOT CONTAINS ANY, the denied form of the access operator, the word forms
// GREATER THAN, LESS THAN and the two spellings of LESS THAN OR EQUAL TO, the
// single equals sign, the /…/ regex literal, and FALSE as a whole condition, all
// of them in internal/simplifiedpolicies/parser.go. It adds what no case sends at
// all: subject.scopes, subject.permissions in a condition and the MAPPING PIP
// that grants one, the FILTERED pipType, signed and fractional literals, and
// JSON Path beyond the plain and bracketed paths of TestIsolatedPolicyCases.
//
// Each case asks two things: whether the PAP accepts the form, and what
// access-control decides once it has. A refusal settles the first and leaves the
// second open. Where the second question is reachable, the case sends two requests
// that a working operator tells apart, because a form the PAP accepts and the
// evaluator ignores answers false to both. resource['x'] and MATCH against an
// attribute are already recorded as behaving that way (j7, a2).
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestIsolatedConditionFormCases() {
	// Both routes return a collection holding the value the H cases compare
	// against, so a false decision there means the form was ignored rather than
	// that the PIP returned nothing.
	for _, route := range []string{"/api/v1/pip/iso-filtered", "/api/v1/pip/iso-list"} {
		err := s.pipMock.PinRoute(context.Background(), route, PipStubResponse{
			StatusCode: http.StatusOK,
			Body:       []string{"red", "blue"},
		})
		s.Require().NoError(err, "pin %s", route)
	}

	cases := []isolatedCase{
		// Negation. CONTAINS, MATCH and IS SUBSET are recorded; their negated
		// forms are not. Each case therefore sends the null value that already
		// separates NOT IN from NOT CONTAINS in the round 2 semantics cases,
		// where n1 is true and n2 is false.
		{id: "m1-not-match", resourceType: "PARITY_SUITE_ISO_M1", condition: "resource.x NOT MATCH ab*", requests: []isolatedRequest{
			{name: "pattern-matches", resource: map[string]any{"id": "iso-m1", "x": "abc"}},
			{name: "pattern-does-not-match", resource: map[string]any{"id": "iso-m1", "x": "zzz"}},
			{name: "attribute-null", resource: map[string]any{"id": "iso-m1", "x": nil}},
		}},
		{id: "m2-not-contains-any", resourceType: "PARITY_SUITE_ISO_M2", condition: "resource.tags NOT CONTAINS ANY 'red', 'blue'", requests: []isolatedRequest{
			{name: "one-element-shared", resource: map[string]any{"id": "iso-m2", "tags": []string{"red"}}},
			{name: "no-element-shared", resource: map[string]any{"id": "iso-m2", "tags": []string{"green"}}},
			{name: "attribute-null", resource: map[string]any{"id": "iso-m2", "tags": nil}},
		}},
		// IS SUBSET is false for an empty collection (l4), where set theory
		// makes it true, so the empty case decides whether the two operators
		// are complements.
		{id: "m3-is-not-subset", resourceType: "PARITY_SUITE_ISO_M3", condition: "resource.list IS NOT SUBSET 'a', 'b'", requests: []isolatedRequest{
			{name: "every-element-listed", resource: map[string]any{"id": "iso-m3", "list": []string{"a"}}},
			{name: "foreign-element", resource: map[string]any{"id": "iso-m3", "list": []string{"c"}}},
			{name: "empty-collection", resource: map[string]any{"id": "iso-m3", "list": []string{}}},
			{name: "attribute-null", resource: map[string]any{"id": "iso-m3", "list": nil}},
		}},

		// Subject attributes. subject.isM2M and subject.permissionScope are
		// recorded as refused (g8a, g8b). subject.scopes appears nowhere at all;
		// subject.permissions only as the target of a regular policy set, which
		// the PAP accepts and which is false for a reader with no permission
		// assigned. IS EMPTY shows whether the attribute resolves in a condition
		// at all; CONTAINS shows what it holds on this stand.
		{id: "u8-subject-scopes-is-empty", resourceType: "PARITY_SUITE_ISO_U8", condition: "subject.scopes IS EMPTY", requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-u8"}},
		}},
		{id: "u9-subject-scopes-contains", resourceType: "PARITY_SUITE_ISO_U9", condition: "subject.scopes CONTAINS 'profile'", requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-u9"}},
		}},
		// The parity users carry no assigned permission, so u10 and u11 record
		// the negative answers; pm1 is u11's positive half.
		{id: "u10-subject-permissions-is-empty", resourceType: "PARITY_SUITE_ISO_U10", condition: "subject.permissions IS EMPTY", requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-u10"}},
		}},
		{id: "u11-subject-permissions-contains", resourceType: "PARITY_SUITE_ISO_U11", condition: "subject.permissions CONTAINS 'parity_permission'", requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-u11"}},
		}},

		// Permission mapping. pm1 is u11 with the permission granted, and its
		// upload status also answers whether the PAP takes a MAPPING PIP at all.
		{id: "pm1-mapping-pip-merged-list", resourceType: "PARITY_SUITE_ISO_PM1", condition: "subject.permissions CONTAINS 'parity_permission'", pips: []any{parityPermissionsPIP}, requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-pm1"}},
		}},
		// Whether a policy can read one mapping PIP by its own name, or only
		// the merged list pm1 reads.
		{id: "pm2-mapping-pip-suffixed-reference", resourceType: "PARITY_SUITE_ISO_PM2", condition: "subject.permissions.PARITY CONTAINS 'parity_permission'", pips: []any{parityPermissionsPIP}, requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-pm2"}},
		}},
		// pm3 asks pm1's question with the declaration withdrawn: the upload of
		// each case replaces the domain's PIPs, so by now PARITY_ISOLATED holds
		// none. A false answer scopes the mapping to the declaration that
		// carried it; a true one means it outlived that declaration, and the
		// permission granted here is visible to every case of the tenant that
		// reads subject.permissions. permission-policy-target records false for
		// the same permission and the same role, so a true answer here is worth
		// checking against that golden after the run.
		//
		// This case reads what pm1 uploaded and has to run after it, which the
		// order of this slice gives it.
		{id: "pm3-mapping-pip-after-declaration-removed", resourceType: "PARITY_SUITE_ISO_PM3", condition: "subject.permissions CONTAINS 'parity_permission'", requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-pm3"}},
		}},
		// The access operator has a denied form as well as the allowed form
		// recorded in u7, which the PAP accepts and which is false on this
		// stand because no entitlement source backs it.
		{id: "u12-subject-denied", resourceType: "PARITY_SUITE_ISO_U12", condition: "subject denied 'READ' on resource", requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-u12"}},
		}},

		// Word forms of the comparisons. Only GREATER THAN OR EQUAL TO is
		// recorded (x4), and the parser takes OR EQUALS TO as well as OR EQUAL
		// TO. Each case sends the boundary and its neighbor, so a form the
		// evaluator maps to a different operator is visible.
		{id: "w1-greater-than-words", resourceType: "PARITY_SUITE_ISO_W1", condition: "resource.n GREATER THAN 5", requests: []isolatedRequest{
			{name: "boundary", resource: map[string]any{"id": "iso-w1", "n": 5}},
			{name: "above-boundary", resource: map[string]any{"id": "iso-w1", "n": 6}},
		}},
		{id: "w2-less-than-words", resourceType: "PARITY_SUITE_ISO_W2", condition: "resource.n LESS THAN 5", requests: []isolatedRequest{
			{name: "boundary", resource: map[string]any{"id": "iso-w2", "n": 5}},
			{name: "below-boundary", resource: map[string]any{"id": "iso-w2", "n": 4}},
		}},
		{id: "w3-less-than-or-equal-words", resourceType: "PARITY_SUITE_ISO_W3", condition: "resource.n LESS THAN OR EQUAL TO 5", requests: []isolatedRequest{
			{name: "boundary", resource: map[string]any{"id": "iso-w3", "n": 5}},
			{name: "above-boundary", resource: map[string]any{"id": "iso-w3", "n": 6}},
		}},
		{id: "w4-greater-than-or-equals-to-words", resourceType: "PARITY_SUITE_ISO_W4", condition: "resource.n GREATER THAN OR EQUALS TO 5", requests: []isolatedRequest{
			{name: "boundary", resource: map[string]any{"id": "iso-w4", "n": 5}},
			{name: "below-boundary", resource: map[string]any{"id": "iso-w4", "n": 4}},
		}},
		{id: "w5-less-than-or-equals-to-words", resourceType: "PARITY_SUITE_ISO_W5", condition: "resource.n LESS THAN OR EQUALS TO 5", requests: []isolatedRequest{
			{name: "boundary", resource: map[string]any{"id": "iso-w5", "n": 5}},
			{name: "above-boundary", resource: map[string]any{"id": "iso-w5", "n": 6}},
		}},

		// Literals and whole-expression forms. EQUALS and == are recorded
		// (x2, x1) and the single equals sign the parser also accepts is not;
		// TRUE as a whole condition is recorded (x10) and FALSE is not.
		{id: "x32-single-equal-sign", resourceType: "PARITY_SUITE_ISO_X32", condition: "resource.x = 'v'", requests: []isolatedRequest{
			{name: "attribute-matches", resource: map[string]any{"id": "iso-x32", "x": "v"}},
			{name: "attribute-differs", resource: map[string]any{"id": "iso-x32", "x": "w"}},
		}},
		{id: "x33-condition-literal-false", resourceType: "PARITY_SUITE_ISO_X33", condition: "FALSE", requests: []isolatedRequest{
			{name: "any-resource", resource: map[string]any{"id": "iso-x33"}},
		}},
		// The parser reads /…/ as a regex literal and hands it on as a plain
		// string. MATCH with an unquoted wildcard is recorded (x5) and with a
		// quoted one is refused (x6), so this is the third spelling.
		{id: "x34-regex-literal", resourceType: "PARITY_SUITE_ISO_X34", condition: "resource.x MATCH /ab.*/", requests: []isolatedRequest{
			{name: "pattern-matches", resource: map[string]any{"id": "iso-x34", "x": "abc"}},
			{name: "pattern-does-not-match", resource: map[string]any{"id": "iso-x34", "x": "zzz"}},
		}},

		// Numbers. Equality compares through the string form, so 5.0 does not
		// equal 5 (c1); the relational operators compare numerically, so the
		// string "10" is greater than 5 (c3, in the round 2 semantics cases,
		// where a string comparison would answer false). No recorded case puts
		// a sign or a fraction in the literal itself.
		{id: "c10-negative-number-equals", resourceType: "PARITY_SUITE_ISO_C10", condition: "resource.n == -5", requests: []isolatedRequest{
			{name: "exact", resource: map[string]any{"id": "iso-c10", "n": json.Number("-5")}},
			{name: "same-magnitude-positive", resource: map[string]any{"id": "iso-c10", "n": json.Number("5")}},
		}},
		{id: "c11-decimal-number-equals", resourceType: "PARITY_SUITE_ISO_C11", condition: "resource.n == 5.5", requests: []isolatedRequest{
			{name: "exact", resource: map[string]any{"id": "iso-c11", "n": json.Number("5.5")}},
			{name: "string", resource: map[string]any{"id": "iso-c11", "n": "5.5"}},
			{name: "trailing-zero", resource: map[string]any{"id": "iso-c11", "n": json.Number("5.50")}},
		}},
		{id: "c12-greater-than-negative", resourceType: "PARITY_SUITE_ISO_C12", condition: "resource.n > -5", requests: []isolatedRequest{
			{name: "above-boundary", resource: map[string]any{"id": "iso-c12", "n": json.Number("-4")}},
			{name: "below-boundary", resource: map[string]any{"id": "iso-c12", "n": json.Number("-10")}},
		}},

		// JSON Path. resource.list[0] and resource.items[*].id both work (j5,
		// j6), while resource['x'] is accepted and answers false (j7).
		// Each case pairs a resource the path selects with one it does not, so
		// that an accepted path nobody evaluates reads as two false answers.
		{id: "j9-jsonpath-filter-expression", resourceType: "PARITY_SUITE_ISO_J9", condition: "resource.items[?(@.type=='a')].id CONTAINS 'x'", requests: []isolatedRequest{
			{name: "selected-item-has-the-id", resource: map[string]any{"id": "iso-j9", "items": []any{map[string]any{"type": "a", "id": "x"}, map[string]any{"type": "b", "id": "y"}}}},
			{name: "the-id-is-on-the-other-item", resource: map[string]any{"id": "iso-j9", "items": []any{map[string]any{"type": "a", "id": "y"}, map[string]any{"type": "b", "id": "x"}}}},
		}},
		{id: "j10-jsonpath-recursive-descent", resourceType: "PARITY_SUITE_ISO_J10", condition: "resource..code CONTAINS 'x'", requests: []isolatedRequest{
			{name: "nested-code", resource: map[string]any{"id": "iso-j10", "o": map[string]any{"code": "x"}}},
			{name: "no-code-anywhere", resource: map[string]any{"id": "iso-j10", "o": map[string]any{"other": "x"}}},
		}},

		// The FILTERED PIP. The agent drops the pipType on the pull path
		// (internal/acconfig/convert.go) and refuses it on the mount path
		// (internal/pips/validate.go), and neither the type nor the condition
		// form that passes it an argument appears in any fixture. The three
		// cases separate the two: whether the declaration is accepted, whether
		// the form is accepted on a PIP that has the type, and whether the form
		// is accepted on one that does not.
		{id: "h3-filtered-pip-plain-reference", resourceType: "PARITY_SUITE_ISO_H3", condition: "subject.parityFilteredList CONTAINS 'red'", pips: []any{parityFilteredPIP}, requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-h3"}},
		}},
		{id: "h4-filtered-pip-filtered-form", resourceType: "PARITY_SUITE_ISO_H4", condition: "subject.parityFilteredList FILTERED 'red' CONTAINS 'red'", pips: []any{parityFilteredPIP}, requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-h4"}},
		}},
		{id: "h5-filtered-form-on-general-pip", resourceType: "PARITY_SUITE_ISO_H5", condition: "subject.parityList FILTERED 'red' CONTAINS 'red'", pips: []any{parityListPIP}, requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "iso-h5"}},
		}},
	}

	s.runIsolatedCases(cases)
}
