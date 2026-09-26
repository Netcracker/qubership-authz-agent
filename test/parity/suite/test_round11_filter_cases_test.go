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

// round11NestedSetCase builds a DENY_OVERRIDES set of round9PredicatePolicy
// and the set nested builds, and sends requests.
func round11NestedSetCase(id string, nested func(b regularBuilder) map[string]any, requests []isolatedRequest) regularCase {
	b := regularBuilder{caseID: id}
	rt := regularResourceType(id)
	return regularCase{
		id:           id,
		resourceType: rt,
		uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
			b.set("outer", "resourceType == '"+rt+"'", "DENY_OVERRIDES", []any{round9PredicatePolicy(b)}, []any{nested(b)}),
		}}},
		requests: requests,
	}
}

// round11FilterCases builds the cases of TestRound11FilterNodeCases.
func round11FilterCases() []regularCase {
	var cases []regularCase

	cases = append(cases, round11NestedSetCase("fn-nested-set-target-reads-the-resource", func(b regularBuilder) map[string]any {
		return b.set("nested", "resource.x == 'a'", "DENY_UNLESS_PERMIT", []any{
			b.policy("nested-allows", readerTarget, "DENY_UNLESS_PERMIT",
				b.rule("nested-list-allow", "operation == 'LIST'", "true", "ALLOW", nil)),
		}, nil)
	}, []isolatedRequest{
		{name: "filter", filter: true},
		{name: "check-list-without-x", operation: "LIST", resource: map[string]any{"id": "r11-filter"}},
		{name: "check-list-with-x-a", operation: "LIST", resource: map[string]any{"id": "r11-filter", "x": "a"}},
	}))

	for _, algorithm := range []string{"DENY_UNLESS_PERMIT", "PERMIT_UNLESS_DENY", "DENY_OVERRIDES", "PERMIT_OVERRIDES"} {
		key := strings.ToLower(strings.ReplaceAll(algorithm, "_", "-"))
		cases = append(cases, round11NestedSetCase("fn-nested-set-without-an-applicable-policy-under-"+key, func(b regularBuilder) map[string]any {
			return b.set("nested", "true", algorithm, []any{
				b.policy("for-nobody", round9FalseSubjectCondition, "DENY_UNLESS_PERMIT",
					b.rule("for-nobody-list-allow", "operation == 'LIST'", "true", "ALLOW", nil)),
			}, nil)
		}, round9FilterRequests))
	}

	for _, algorithm := range []string{"PERMIT_OVERRIDES", "PERMIT_UNLESS_DENY"} {
		key := strings.ToLower(strings.ReplaceAll(algorithm, "_", "-"))
		cases = append(cases, round9SetCase("fn-"+key+"-set-with-a-policy-without-a-list-rule", algorithm, func(b regularBuilder) []any {
			return []any{round9PredicatePolicy(b), round9UpdateOnlyPolicy(b)}
		}))
	}
	return cases
}

// What check/filter answers for a set nested in a DENY_OVERRIDES set beside a
// policy with an ALLOW predicate, when the nested set denies or does not apply
// in a way the filter has not been asked about.
//
// fn-nested-set-target-reads-the-resource nests a set whose target reads
// resource.x. A target that reads the resource is recorded to deny a filter
// alone (set-target-reads-*/filter), where a node that denies and a node that
// does not apply give the same DENY; beside the predicate policy under
// DENY_OVERRIDES, a node that denies takes the whole answer and a node that does
// not apply leaves allowed==1. check/resource without x and with x = a are the
// controls.
//
// fn-nested-set-without-an-applicable-policy-under-* nests, under each of the
// four algorithms, a set whose one policy targets a role nobody holds. What a
// set whose policies all do not apply contributes to a filter is recorded
// nowhere; the answer is DENY, allowed==1, or ALLOW depending on whether the
// nested set denies, does not apply, or permits.
//
// fn-*-set-with-a-policy-without-a-list-rule is
// deny-overrides-set-with-a-policy-without-a-list-rule under PERMIT_OVERRIDES
// and PERMIT_UNLESS_DENY: a policy with an ALLOW predicate on LIST beside a
// DENY_UNLESS_PERMIT policy with a rule on UPDATE alone, which denies LIST.
// Under DENY_OVERRIDES that deny takes the filter (DENY); under
// DENY_UNLESS_PERMIT a deny beside a predicate is dropped
// (deny-in-one-policy-beside-a-predicate-in-another). The other two algorithms
// are recorded nowhere.
//
// Every case sends the filter on LIST and check/resource on LIST.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case.
func (s *ParitySuite) TestRound11FilterNodeCases() {
	s.runRegularCases(round11FilterCases())
}
