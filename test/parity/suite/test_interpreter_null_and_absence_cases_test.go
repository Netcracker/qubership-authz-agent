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

import "encoding/json"

// orProbePair builds the two isolated cases that tell a false leaf from an aborted
// rule. The recorded goldens fix the reading: a leaf that evaluates to false lets
// OR go on to the next operand (s11-false-or-absent against s9-true-or-absent),
// and an operand that cannot be evaluated ends the rule whatever OR would have
// done next (s10-absent-or-true is false although its right operand is true).
//
// The probe case puts the operand under question on the left of an OR whose right
// operand, resource.a == 'y', is true for every request: a true answer means the
// operand evaluated to a value and OR went on, a false answer means the operand
// ended the rule. The control case swaps the operands. It is true under both
// readings, because OR stops at a true left operand, so a false control means the
// fixture is broken and the probe's answer means nothing.
func orProbePair(id, resourceType, operand string, requests ...isolatedRequest) []isolatedCase {
	return []isolatedCase{
		{id: id, resourceType: resourceType, condition: operand + " OR resource.a == 'y'", requests: requests},
		{id: id + "-control", resourceType: resourceType + "_CTL", condition: "resource.a == 'y' OR " + operand, requests: requests},
	}
}

// What a condition answers over a null value and over an absent key, in the
// operators no golden records. The agent's own condition parser accepts every
// condition below.
//
// Over a null value the recorded answers are per operator: > does not end the
// rule (n3-greater-than-null-or-true is true) and its value alone is not
// recorded, IS EMPTY is false (n4), NOT IN is true and NOT CONTAINS is false (n1,
// n2). The four relational operators, IS NOT NULL and IS NOT EMPTY are not
// recorded alone over null, and IS NOT NULL is recorded over an absent key only
// inside a guarded chain (s12a). The nl cases record each of them alone, so the
// operator-by-state table has a value in every relational cell rather than in
// two.
//
// Over an absent key the recorded answers split the operators into two groups:
// IS NULL is true (s6a), == and != and > end the rule (s1b, s2b, s5), and so do
// NOT IN and NOT CONTAINS (s3, s4). IS EMPTY and IS NOT EMPTY are recorded as false
// (s7, l9) but only alone, where a false leaf and an aborted rule look the same;
// NOT MATCH, NOT CONTAINS ANY and IS NOT SUBSET are recorded over null (m1, m2,
// m3) and not over absence at all. The nn cases put each of them through
// orProbePair.
//
// The np cases do the same for a JSON Path that selects nothing. A plain path to an
// absent key ends the rule (s2b-neq-attribute-absent with s10); a filter expression
// with no match and a recursive descent that finds nothing are recorded only under
// CONTAINS, where an empty selection and an aborted rule both answer false (j9,
// j10), and an index past the end and a wildcard to a key no element has are not
// recorded at all. What a JSON Path selects is a collection, and j5-array-index
// records == over one as false for a value it holds, so the probes use the
// collection operators: each path is sent through orProbePair with NOT CONTAINS
// and alone with IS EMPTY, so an empty selection (IS EMPTY true, probe true) is
// told from an aborted rule (probe false).
//
// The relational operators compare numerically once the attribute is a number
// (c3-greater-than-string-number), while == compares the string forms and is false
// for 5.0 against the literal 5 (c1-number-literal/float). nb1 and nb2 send 5.0 as
// a number and as a string against >= 5 and <= 5, with the integer 5 as the
// control: x4-greater-or-equal-words records that boundary as true.
//
// Every case carries a request a working operator answers true, because a
// condition access-control accepts and never evaluates answers false to every
// request. The cases live in their own test function so that a recording run can
// be filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestInterpreterNullAndAbsenceCases() {
	// Every probe resource carries a = y; items and list are there for the np paths
	// to select nothing from.
	probe := func(name string, extra map[string]any) isolatedRequest {
		resource := map[string]any{"id": "nul-" + name, "a": "y"}
		for key, value := range extra {
			resource[key] = value
		}
		return isolatedRequest{name: name, resource: resource}
	}
	populated := map[string]any{
		"items": []any{map[string]any{"type": "a", "id": "x"}},
		"list":  []string{"a"},
	}

	var cases []isolatedCase

	// null under each relational operator alone; the second request of each is
	// the control that the operator answers true for a number.
	cases = append(cases,
		isolatedCase{id: "nl1-less-than-over-null", resourceType: "PARITY_SUITE_NUL_NL1", condition: "resource.n < 5", requests: []isolatedRequest{
			{name: "null", resource: map[string]any{"id": "nul-nl1", "n": nil}},
			{name: "number-below", resource: map[string]any{"id": "nul-nl1", "n": json.Number("4")}},
		}},
		isolatedCase{id: "nl2-greater-or-equal-over-null", resourceType: "PARITY_SUITE_NUL_NL2", condition: "resource.n >= 5", requests: []isolatedRequest{
			{name: "null", resource: map[string]any{"id": "nul-nl2", "n": nil}},
			{name: "number-at-the-boundary", resource: map[string]any{"id": "nul-nl2", "n": json.Number("5")}},
		}},
		isolatedCase{id: "nl5-greater-than-over-null", resourceType: "PARITY_SUITE_NUL_NL5", condition: "resource.n > 5", requests: []isolatedRequest{
			{name: "null", resource: map[string]any{"id": "nul-nl5", "n": nil}},
			{name: "number-above", resource: map[string]any{"id": "nul-nl5", "n": json.Number("6")}},
		}},
		isolatedCase{id: "nl6-less-or-equal-over-null", resourceType: "PARITY_SUITE_NUL_NL6", condition: "resource.n <= 5", requests: []isolatedRequest{
			{name: "null", resource: map[string]any{"id": "nul-nl6", "n": nil}},
			{name: "number-at-the-boundary", resource: map[string]any{"id": "nul-nl6", "n": json.Number("5")}},
		}},
		isolatedCase{id: "nl3-is-not-null-over-null", resourceType: "PARITY_SUITE_NUL_NL3", condition: "resource.x IS NOT NULL", requests: []isolatedRequest{
			{name: "null", resource: map[string]any{"id": "nul-nl3", "x": nil}},
			{name: "string", resource: map[string]any{"id": "nul-nl3", "x": "v"}},
		}},
		// IS EMPTY over null is recorded as false (n4). If IS NOT EMPTY is false as
		// well, null is neither empty nor non-empty; if it is true, the two operators
		// are complements.
		isolatedCase{id: "nl4-is-not-empty-over-null", resourceType: "PARITY_SUITE_NUL_NL4", condition: "resource.x IS NOT EMPTY", requests: []isolatedRequest{
			{name: "null", resource: map[string]any{"id": "nul-nl4", "x": nil}},
			{name: "collection-with-an-element", resource: map[string]any{"id": "nul-nl4", "x": []string{"v"}}},
		}},
	)

	// An absent key under the operators recorded only alone or only over null.
	cases = append(cases, orProbePair("nn1-is-empty-over-absence", "PARITY_SUITE_NUL_NN1", "resource.x IS EMPTY", probe("key-absent", nil))...)
	cases = append(cases, orProbePair("nn2-is-not-empty-over-absence", "PARITY_SUITE_NUL_NN2", "resource.x IS NOT EMPTY", probe("key-absent", nil))...)
	cases = append(cases, orProbePair("nn3-not-match-over-absence", "PARITY_SUITE_NUL_NN3", "resource.x NOT MATCH ab*", probe("key-absent", nil))...)
	cases = append(cases, orProbePair("nn4-not-contains-any-over-absence", "PARITY_SUITE_NUL_NN4", "resource.tags NOT CONTAINS ANY 'p', 'q'", probe("key-absent", nil))...)
	cases = append(cases, orProbePair("nn5-is-not-subset-over-absence", "PARITY_SUITE_NUL_NN5", "resource.list IS NOT SUBSET 'p', 'q'", probe("key-absent", nil))...)

	// A JSON Path that selects nothing from a resource that has the parent.
	for _, path := range []struct{ key, rt, path string }{
		{"np1-filter-expression-without-a-match", "PARITY_SUITE_NUL_NP1", "resource.items[?(@.type=='zzz')].id"},
		{"np2-recursive-descent-without-a-match", "PARITY_SUITE_NUL_NP2", "resource..nocode"},
		{"np3-index-past-the-end", "PARITY_SUITE_NUL_NP3", "resource.list[5]"},
		{"np4-wildcard-to-a-missing-key", "PARITY_SUITE_NUL_NP4", "resource.items[*].nokey"},
	} {
		cases = append(cases, orProbePair(path.key, path.rt, path.path+" NOT CONTAINS 'v'", probe("nothing-selected", populated))...)
		cases = append(cases, isolatedCase{id: path.key + "-is-empty", resourceType: path.rt + "_EMPTY", condition: path.path + " IS EMPTY", requests: []isolatedRequest{
			probe("nothing-selected", populated),
		}})
	}

	// The integer boundary of a relational operator against a fraction.
	cases = append(cases,
		isolatedCase{id: "nb1-greater-or-equal-at-a-fractional-boundary", resourceType: "PARITY_SUITE_NUL_NB1", condition: "resource.n >= 5", requests: []isolatedRequest{
			{name: "integer", resource: map[string]any{"id": "nul-nb1", "n": json.Number("5")}},
			{name: "one-decimal-place", resource: map[string]any{"id": "nul-nb1", "n": json.Number("5.0")}},
			{name: "one-decimal-place-as-a-string", resource: map[string]any{"id": "nul-nb1", "n": "5.0"}},
		}},
		isolatedCase{id: "nb2-less-or-equal-at-a-fractional-boundary", resourceType: "PARITY_SUITE_NUL_NB2", condition: "resource.n <= 5", requests: []isolatedRequest{
			{name: "integer", resource: map[string]any{"id": "nul-nb2", "n": json.Number("5")}},
			{name: "one-decimal-place", resource: map[string]any{"id": "nul-nb2", "n": json.Number("5.0")}},
			{name: "one-decimal-place-as-a-string", resource: map[string]any{"id": "nul-nb2", "n": "5.0"}},
		}},
	)

	s.runIsolatedCases(cases)
}

// parityMixedCasePermissionPIP grants the permission Parity.Read, spelled in mixed
// case, to ROLE_PARITY_READER. It is parityPermissionsPIP with another suffix and
// another permission, so that the two mappings never merge into one list.
var parityMixedCasePermissionPIP = map[string]any{
	"name":      "subject.permissions.PARITY_CASE",
	"type":      "UUID",
	"pipType":   "MAPPING",
	"cacheable": false,
	"customMapping": map[string]any{
		"subject.roles": map[string]any{
			"ROLE_PARITY_READER": []string{"Parity.Read"},
		},
	},
}

// Whether subject.permissions CONTAINS compares case-insensitively. Case is ignored
// under == (c5-string-equals-other-case), under CONTAINS over a resource
// collection (vt3 asks) and under subject.roles CONTAINS
// (u2-subject-roles-other-case), and subject.permissions CONTAINS is the leaf
// product policies are built from. pm1-mapping-pip-merged-list records the
// permission granted through a MAPPING PIP and read back in the same case, so pc3,
// which repeats that shape, is the control for the two cases that spell the
// permission in another case.
//
// pm3-mapping-pip-after-declaration-removed records that a mapping goes away with
// its declaration, so each case declares the PIP again.
func (s *ParitySuite) TestInterpreterPermissionCaseCases() {
	s.runIsolatedCases([]isolatedCase{
		{id: "pc1-permission-in-lower-case", resourceType: "PARITY_SUITE_PERM_PC1", condition: "subject.permissions CONTAINS 'parity.read'", pips: []any{parityMixedCasePermissionPIP}, requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "perm-pc1"}},
		}},
		{id: "pc2-permission-in-upper-case", resourceType: "PARITY_SUITE_PERM_PC2", condition: "subject.permissions CONTAINS 'PARITY.READ'", pips: []any{parityMixedCasePermissionPIP}, requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "perm-pc2"}},
		}},
		{id: "pc3-permission-in-the-granted-case", resourceType: "PARITY_SUITE_PERM_PC3", condition: "subject.permissions CONTAINS 'Parity.Read'", pips: []any{parityMixedCasePermissionPIP}, requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "perm-pc3"}},
		}},
	})
}
