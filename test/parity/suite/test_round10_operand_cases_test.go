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

import "strings"

// round10ResourceType is the resource type of the isolated case keyed key.
func round10ResourceType(key string) string {
	return "PARITY_SUITE_R10_" + strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
}

// round10AloneAndProbe builds, for one condition operand, the case that asks it
// alone and the orProbePair that puts it on the left of an OR whose right
// operand is true, all three sent requests.
func round10AloneAndProbe(key, operand string, requests []isolatedRequest) []isolatedCase {
	cases := []isolatedCase{{id: key + "-alone", resourceType: round10ResourceType(key + "-alone"), condition: operand, requests: requests}}
	return append(cases, orProbePair(key, round10ResourceType(key), operand, requests...)...)
}

// What IS NOT NULL answers over resource['x'] and over the literal null. The PAP
// accepts both forms, and IS NULL over either is true whether x is there or not
// (dn-is-null-over-a-bracket-path, dn-is-null-over-the-null-literal), while ==
// over resource['x'] ends the rule (df1). IS NOT NULL over them is recorded
// nowhere, so neither is whether it is a value or ends the rule. The agent's
// condition parser accepts both conditions.
//
// Each form is asked alone and through orProbePair, with x present and absent;
// resource.a is y in every request, so the probe's right operand holds.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound10DeadFormNotNullCases() {
	requests := []isolatedRequest{
		{name: "x-present", resource: map[string]any{"id": "r10-dead", "x": "v", "a": "y"}},
		{name: "x-absent", resource: map[string]any{"id": "r10-dead", "a": "y"}},
	}
	var cases []isolatedCase
	cases = append(cases, round10AloneAndProbe("dn-is-not-null-over-a-bracket-path", "resource['x'] IS NOT NULL", requests)...)
	cases = append(cases, round10AloneAndProbe("dn-is-not-null-over-the-null-literal", "null IS NOT NULL", requests)...)
	s.runIsolatedCases(cases)
}

// What IS NOT NULL answers over a resource attribute that is an empty array. IS
// NULL over it is true (es-empty-collection-is-null), which leaves IS NOT NULL
// either its negation or false, as over an empty header; neither is recorded.
// The agent's condition parser accepts the condition.
//
// The attribute is asked alone and through orProbePair, empty and holding one
// value; the one value is the control that IS NOT NULL holds over a collection.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound10EmptyCollectionNotNullCases() {
	s.runIsolatedCases(round10AloneAndProbe("ec-is-not-null-over-an-empty-array", "resource.list IS NOT NULL", []isolatedRequest{
		{name: "list-empty", resource: map[string]any{"id": "r10-empty", "list": []string{}, "a": "y"}},
		{name: "list-of-one", resource: map[string]any{"id": "r10-empty", "list": []string{"v"}, "a": "y"}},
	}))
}

// What check/resource answers for a simplified policy whose only predicate names
// an undeclared placeholder. x20-undeclared-placeholder records the filter,
// which denies; the decision on the same policy is recorded nowhere. A filter
// that denies where check/resource allows is the one shape in which the agent
// would need to mark such a policy. The agent's converter accepts the policy.
//
// The filter is asked again beside check/resource, the control that the policy
// is the one x20 records.
//
// The case lives in its own test function so that a recording run can be
// filtered to it and leave every golden already committed alone.
func (s *ParitySuite) TestRound10UndeclaredPlaceholderCheckCases() {
	s.runIsolatedCases([]isolatedCase{{
		id: "x20-undeclared-placeholder-check", resourceType: round10ResourceType("x20-check"), operation: "LIST",
		rsql: "owner==${subject.parityUndeclared}",
		requests: []isolatedRequest{
			{name: "check-list", operation: "LIST", resource: map[string]any{"id": "r10-x20"}},
			{name: "filter", operation: "LIST", filter: true},
		},
	}})
}

// What IN, CONTAINS, CONTAINS ANY, IS SUBSET and MATCH answer over a resource
// attribute that is null. Over null, NOT IN is true (n1), and NOT CONTAINS and NOT
// MATCH are false (n2, m1) alone, where a false operand and an ended rule look the
// same; the plain operators are recorded over null nowhere. The agent's
// condition parser accepts every condition here.
//
// Each operator is asked alone, which records its value if it has one, and
// through orProbePair, which tells a value from an ended rule; resource.a is y.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound10NullOperandCases() {
	requests := []isolatedRequest{{name: "x-null", resource: map[string]any{"id": "r10-null", "x": nil, "a": "y"}}}
	var cases []isolatedCase
	for _, form := range []struct{ key, operand string }{
		{"nc-in", "resource.x IN 'a', 'z'"},
		{"nc-contains", "resource.x CONTAINS 'a'"},
		{"nc-contains-any", "resource.x CONTAINS ANY 'a', 'z'"},
		{"nc-is-subset", "resource.x IS SUBSET 'a', 'z'"},
		{"nc-match", "resource.x MATCH a*"},
	} {
		cases = append(cases, round10AloneAndProbe(form.key, form.operand, requests)...)
	}
	s.runIsolatedCases(cases)
}

// What NOT IN, MATCH, CONTAINS ANY and IS SUBSET answer over a HEADER PIP whose
// header holds one value, and what a header sent empty resolves to. ==, !=, IN
// and CONTAINS over one value are recorded (sl-header-*); the other operators
// are recorded over a header split into a list (hl1-hl3) or absent (es-*), and
// an empty header is recorded nowhere: it may be an empty list, a list of one
// empty string, or an absent header. The agent's condition parser accepts every
// condition here.
//
// The single-value cases are sent the header a and the header b, alone and
// through orProbePair with the header a. The empty-header cases ask IS EMPTY, IS
// NULL, equality with the empty string, and resource.id IN the header, each with
// the header sent empty and not sent at all; the absent header is the control, recorded as an empty list
// (es-absent-header-*).
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound10SingleValueHeaderCases() {
	headerA := map[string]string{round9OneHeader: "a"}
	var cases []isolatedCase
	for _, form := range []struct{ key, operator string }{
		{"not-in", "NOT IN 'a', 'z'"},
		{"match", "MATCH a"},
		{"contains-any", "CONTAINS ANY 'a', 'z'"},
		{"is-subset", "IS SUBSET 'a', 'z'"},
	} {
		key := "sv-header-" + form.key
		cases = append(cases, isolatedCase{
			id: key, resourceType: round10ResourceType(key), condition: "subject.parityR9OneHeader " + form.operator,
			pips: []any{round9OneHeaderPIP},
			requests: []isolatedRequest{
				{name: "header-a", resource: map[string]any{"id": "r10-sv"}, headers: headerA},
				{name: "header-b", resource: map[string]any{"id": "r10-sv"}, headers: map[string]string{round9OneHeader: "b"}},
			},
		})
		for _, pair := range orProbePair(key+"-or-true", round10ResourceType(key+"-or-true"), "subject.parityR9OneHeader "+form.operator,
			isolatedRequest{name: "header-a", resource: map[string]any{"id": "r10-sv", "a": "y"}, headers: headerA}) {
			pair.pips = []any{round9OneHeaderPIP}
			cases = append(cases, pair)
		}
	}
	for _, form := range []struct{ key, condition string }{
		{"is-empty", "subject.parityR9OneHeader IS EMPTY"},
		{"is-null", "subject.parityR9OneHeader IS NULL"},
		{"equals-empty-string", "subject.parityR9OneHeader == ''"},
		{"resource-in", "resource.id IN subject.parityR9OneHeader"},
	} {
		key := "eh-header-" + form.key
		cases = append(cases, isolatedCase{
			id: key, resourceType: round10ResourceType(key), condition: form.condition, pips: []any{round9OneHeaderPIP},
			requests: []isolatedRequest{
				{name: "header-empty", resource: map[string]any{"id": ""}, headers: map[string]string{round9OneHeader: ""}},
				{name: "header-absent", resource: map[string]any{"id": ""}},
			},
		})
	}
	s.runIsolatedCases(cases)
}
