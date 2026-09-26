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
	"net/http"
	"strings"
)

// round11ResourceType is the resource type of the isolated case keyed key.
func round11ResourceType(key string) string {
	return "PARITY_SUITE_R11_" + strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
}

// round11Probes puts every operand of forms through orProbePair, each case
// sending requests.
func round11Probes(forms []struct{ key, operand string }, requests ...isolatedRequest) []isolatedCase {
	var cases []isolatedCase
	for _, form := range forms {
		cases = append(cases, orProbePair(form.key, round11ResourceType(form.key), form.operand, requests...)...)
	}
	return cases
}

// Whether !=, NOT IN, NOT CONTAINS and > over an absent resource key end the rule
// or are false. Each is recorded alone (s2b, s3, s4, s5), where a false operand
// and an ended rule both answer false; on the left of an OR the absent key is
// recorded for ==, IS NOT NULL, IS EMPTY, IS NOT EMPTY, NOT MATCH, NOT CONTAINS
// ANY and IS NOT SUBSET only (s10, s12a, nn1-nn5).
//
// Each operator goes through orProbePair against a resource without x and with
// a = y: true means the operand is false and OR went on, false means it ended the
// rule.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound11AbsentKeyProbeCases() {
	s.runIsolatedCases(round11Probes([]struct{ key, operand string }{
		{"ak-not-equals", "resource.x != 'v'"},
		{"ak-not-in", "resource.x NOT IN 'v', 'w'"},
		{"ak-not-contains", "resource.x NOT CONTAINS 'v'"},
		{"ak-greater-than", "resource.x > 5"},
	}, isolatedRequest{name: "x-absent", resource: map[string]any{"id": "r11-absent", "a": "y"}}))
}

// Whether ==, <, <=, >=, IS EMPTY, NOT CONTAINS, NOT CONTAINS ANY and NOT MATCH
// over a resource attribute that is null are false or end the rule. Each is
// recorded alone (s1c, nl1, nl6, nl2, n4, n2, m2, m1), where both answer false.
// Of the relational operators only > is recorded on the left of an OR (n3).
// CONTAINS, CONTAINS ANY and MATCH end the rule over null on the left of an OR
// (nc-*), so their negations may too.
//
// Each operator goes through orProbePair against a resource whose x is null and
// whose a is y.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound11NullProbeCases() {
	s.runIsolatedCases(round11Probes([]struct{ key, operand string }{
		{"nx-equals", "resource.x == 'v'"},
		{"nx-less-than", "resource.x < 5"},
		{"nx-less-or-equal", "resource.x <= 5"},
		{"nx-greater-or-equal", "resource.x >= 5"},
		{"nx-is-empty", "resource.x IS EMPTY"},
		{"nx-not-contains", "resource.x NOT CONTAINS 'v'"},
		{"nx-not-contains-any", "resource.x NOT CONTAINS ANY 'v', 'w'"},
		{"nx-not-match", "resource.x NOT MATCH v*"},
	}, isolatedRequest{name: "x-null", resource: map[string]any{"id": "r11-null", "x": nil, "a": "y"}}))
}

// What ==, !=, IS NOT EMPTY and IS SUBSET answer over an empty resource array,
// what NOT CONTAINS answers over a JSON Path that selects nothing, and whether IS
// EMPTY over an index past the end is false or ends the rule. Over an array of
// one value == is false and != true (pa-*), and over an empty one they are
// recorded nowhere; IS NOT EMPTY and IS SUBSET over [] are recorded alone (l9,
// l4). NOT CONTAINS over an empty selection is recorded on the left of an OR
// only (np1), which tells a value from an ended rule but not true from false.
// IS EMPTY over resource.list[5] is recorded alone (np3).
//
// == and != are asked alone and through orProbePair, the others through one of
// the two, each against a resource with a = y. The empty selection reads
// items[?(@.type=='zzz')].id from items holding one element of another type.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound11EmptyCollectionCases() {
	emptyArray := isolatedRequest{name: "x-empty-array", resource: map[string]any{"id": "r11-empty", "x": []string{}, "a": "y"}}
	var cases []isolatedCase
	for _, form := range []struct{ key, operand string }{
		{"ea-equals", "resource.x == 'v'"},
		{"ea-not-equals", "resource.x != 'v'"},
	} {
		cases = append(cases, isolatedCase{id: form.key + "-alone", resourceType: round11ResourceType(form.key + "-alone"), condition: form.operand, requests: []isolatedRequest{emptyArray}})
	}
	cases = append(cases, round11Probes([]struct{ key, operand string }{
		{"ea-equals", "resource.x == 'v'"},
		{"ea-not-equals", "resource.x != 'v'"},
		{"ea-is-not-empty", "resource.x IS NOT EMPTY"},
		{"ea-is-subset", "resource.x IS SUBSET 'v', 'w'"},
	}, emptyArray)...)
	cases = append(cases,
		isolatedCase{id: "sel-not-contains-alone", resourceType: round11ResourceType("sel-not-contains-alone"),
			condition: "resource.items[?(@.type=='zzz')].id NOT CONTAINS 'v'",
			requests: []isolatedRequest{{name: "nothing-selected", resource: map[string]any{
				"id": "r11-selection", "items": []any{map[string]any{"type": "a", "id": "x"}},
			}}}},
	)
	cases = append(cases, round11Probes([]struct{ key, operand string }{
		{"oob-is-empty", "resource.list[5] IS EMPTY"},
	}, isolatedRequest{name: "index-past-the-end", resource: map[string]any{"id": "r11-index", "list": []string{"a"}, "a": "y"}})...)
	s.runIsolatedCases(cases)
}

// Whether IS EMPTY over a GENERAL PIP whose body is the JSON literal null is false
// or ends the rule. nb-null-body-is-empty records it alone, false.
//
// The PIP answers null at a route of its own, as in nb-null-body-*, and the
// condition goes through orProbePair with resource.a y.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound11NullBodyProbeCases() {
	const route = "/api/v1/pip/r11-null-body"
	s.Require().NoError(s.pipMock.PinRoute(context.Background(), route, PipStubResponse{StatusCode: http.StatusOK, BodyRaw: "null"}))
	nullBody := map[string]any{
		"name": "subject.parityR11NullBody", "url": "http://pip-mock:8090" + route, "httpMethod": "POST", "pipType": "GENERAL",
		"requestAttributes": map[string]string{"case": "r11-null-body"}, "cacheable": false,
	}
	cases := orProbePair("pn-null-body-is-empty", round11ResourceType("pn-null-body-is-empty"), "subject.parityR11NullBody IS EMPTY",
		isolatedRequest{name: "reader", resource: map[string]any{"id": "r11-null-body", "a": "y"}})
	for i := range cases {
		cases[i].pips = []any{nullBody}
	}
	s.runIsolatedCases(cases)
}

// Whether the literal null on the left of == is a null value or ends the rule,
// and whether an absent resource key on the right of == is a false operand or
// ends the rule. null IS NULL and null IS NOT NULL are recorded (dn-*), and
// neither tells the two readings apart, since a null value and an absent key
// answer those two operators alike. The literal null on the right of != ends the
// rule (df2). a1/right-absent records the absent key on the right alone.
//
// Each goes through orProbePair against a resource with v = v, no x, and a = y.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound11NullLiteralAndRightOperandCases() {
	s.runIsolatedCases(round11Probes([]struct{ key, operand string }{
		{"lr-null-literal-equals", "null == 'v'"},
		{"lr-absent-key-on-the-right", "resource.v == resource.x"},
	}, isolatedRequest{name: "x-absent", resource: map[string]any{"id": "r11-right", "v": "v", "a": "y"}}))
}
