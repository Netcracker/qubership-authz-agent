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

// What check/filter does with a rule that has no predicate and a condition it can
// evaluate without a resource, and which operation a filter request with no
// operation parameter is answered for.
//
// filter-rule-with-a-condition-and-no-predicate records DENY for a rule whose
// condition reads resource.x, and a filter request carries no resource, so the
// recording does not separate a rule without a predicate being left out of the
// filter from a condition that could not be evaluated. The first case here gives
// the rule a condition on the subject's roles, which the filter request can
// evaluate: ALLOW means the rule takes part in the filter and lifts it when its
// condition holds, DENY means a rule without a predicate is left out whatever its
// condition. The second case is the control with the recorded resource condition,
// run on the same stand. Each sends check/resource for the same operation too.
//
// filter-without-an-operation records read==1 against rules on READ and on
// UPDATE, which fits both a default operation of READ and the first rule that
// applies. The third case has rules on UPDATE and on LIST and none on READ,
// uploaded in that order: DENY means the operation defaults to READ, list==1
// that it defaults to LIST, and update==1 that the first rule in upload order
// is taken. The request with the operation UPDATE spelled out is the control
// that the set answers a filter at all.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case.
func (s *ParitySuite) TestRound7FilterCases() {
	s.runRegularCases(round7FilterCases())
}

func round7FilterCases() []regularCase {
	var cases []regularCase

	for _, form := range []struct {
		key, condition string
		resource       map[string]any
	}{
		{"subject", readerTarget, map[string]any{"id": "reg-filter-cond"}},
		{"resource", "resource.x == 'v'", map[string]any{"id": "reg-filter-cond", "x": "v"}},
	} {
		id := "filter-rule-with-a-" + form.key + "-condition-and-no-predicate"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("list-under-a-condition", "operation == 'LIST'", form.condition, "ALLOW", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "filter", filter: true},
				{name: "check-list-condition-true", operation: "LIST", resource: form.resource},
			},
		})
	}

	{
		id := "filter-without-an-operation-and-no-rule-on-read"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("update", "operation == 'UPDATE'", "true", "ALLOW", map[string]string{"rsqlPredicate": "update==1"}),
						b.rule("list", "operation == 'LIST'", "true", "ALLOW", map[string]string{"rsqlPredicate": "list==1"})),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "filter-with-no-operation", filter: true, omitOperation: true},
				{name: "filter-with-update", filter: true, operation: "UPDATE"},
			},
		})
	}

	return cases
}
