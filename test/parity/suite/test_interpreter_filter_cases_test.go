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

// What check/filter does with a rule that carries no predicate, with more than two
// groups of predicates, with no operation, and with a target that reads the
// resource. The recorded filter cases all reach a rule with a predicate: the
// condition of such a rule is not applied (f1-false-condition-beside-predicate,
// filter-allow-rule-condition-false), a DENY rule's predicate is left out under
// DENY_UNLESS_PERMIT (filter-allow-and-deny-rules), and the predicates of a nested set and of a
// simplified policy beside a set are grouped in parentheses (filter-nested-sets,
// filter-set-beside-simplified-policy). ALLOW with no predicate is recorded for a
// simplified policy only (agg-ols-plus-rls).
//
// The rules with no predicate ask whether a rule that allows without restricting
// lifts the filter to ALLOW, or is skipped so that the predicates beside it still
// apply. Each such case also sends check/resource for the same operation, so the
// filter answer is read against a decision the same rules produce.
//
// The order in which access-control joins the predicates of one group is not
// stable between runs, so no case here asks for it; four-groups-on-one-type asks
// only how the groups are bracketed once there are more than two.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy profile
// only, like every regular case.
func (s *ParitySuite) TestInterpreterFilterCases() {
	s.runRegularCases(interpreterFilterCases())
}

func interpreterFilterCases() []regularCase {
	var cases []regularCase

	// One ALLOW rule with a condition and no predicate. ALLOW means the rule lifts
	// the filter whatever its condition; DENY means a rule without a predicate does
	// not take part in a filter. The two check requests record the same rule's
	// decision with the condition true and false.
	{
		id := "filter-rule-with-a-condition-and-no-predicate"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("list-when-x", "operation == 'LIST'", "resource.x == 'v'", "ALLOW", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "filter", filter: true},
				{name: "check-list-condition-true", operation: "LIST", resource: map[string]any{"id": "reg-filter-cond", "x": "v"}},
				{name: "check-list-condition-false", operation: "LIST", resource: map[string]any{"id": "reg-filter-cond", "x": "w"}},
			},
		})
	}

	// The same rule beside an ALLOW rule with a predicate. ALLOW means the rule
	// without a predicate wins over the predicate; USE_FILTER_CONDITION with b==2
	// means the predicate alone reaches the response.
	{
		id := "filter-condition-without-predicate-beside-a-predicate"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("list-when-x", "operation == 'LIST'", "resource.x == 'v'", "ALLOW", nil),
						b.rule("list-with-predicate", "operation == 'LIST'", "true", "ALLOW", map[string]string{"rsqlPredicate": "b==2"})),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "filter", filter: true},
				{name: "check-list", operation: "LIST", resource: map[string]any{"id": "reg-filter-beside", "x": "w"}},
			},
		})
	}

	// One ALLOW rule with neither condition nor predicate, the regular-set twin of
	// agg-ols-plus-rls.
	{
		id := "filter-rule-without-condition-or-predicate"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("list", "operation == 'LIST'", "true", "ALLOW", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "filter", filter: true},
				{name: "check-list", operation: "LIST", resource: map[string]any{"id": "reg-filter-bare"}},
			},
		})
	}

	// Four groups of predicates on one resource type: two simplified policies and
	// two sets under two externalIDs. Two groups are bracketed as (a),(b); this
	// records the bracketing of four, and whether the two simplified policies form
	// one group or two.
	{
		id := "filter-four-groups-on-one-type"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		rtTarget := "resourceType == '" + rt + "'"
		simplified := func(key, predicate string) map[string]any {
			return map[string]any{
				"component":             "PARITY",
				"reason":                id + " " + key,
				"resourceType":          rt,
				"operation":             "LIST",
				"rsqlPredicate":         predicate,
				"roles":                 []string{"ROLE_PARITY_READER"},
				"applicableForFrontend": false,
				"id":                    b.id("simplified/" + key),
			}
		}
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			simplified:   []any{simplified("first", "simplified1==1"), simplified("second", "simplified2==2")},
			uploads: []regularUpload{
				{externalID: "parity-" + id + "-first", sets: []any{
					b.set("first", rtTarget, "DENY_UNLESS_PERMIT", []any{
						b.policy("first-reader", readerTarget, "DENY_UNLESS_PERMIT",
							b.rule("first-list", "operation == 'LIST'", "true", "ALLOW", map[string]string{"rsqlPredicate": "regular1==1"})),
					}, nil),
				}},
				{externalID: "parity-" + id + "-second", sets: []any{
					b.set("second", rtTarget, "DENY_UNLESS_PERMIT", []any{
						b.policy("second-reader", readerTarget, "DENY_UNLESS_PERMIT",
							b.rule("second-list", "operation == 'LIST'", "true", "ALLOW", map[string]string{"rsqlPredicate": "regular2==2"})),
					}, nil),
				}},
			},
			requests: []isolatedRequest{{name: "filter", filter: true}},
		})
	}

	// A filter request with no operation parameter, and one with the operation ALL
	// spelled out, against rules on READ and on UPDATE with predicates of their
	// own. The READ request is the control.
	{
		id := "filter-without-an-operation"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("read", "operation == 'READ'", "true", "ALLOW", map[string]string{"rsqlPredicate": "read==1"}),
						b.rule("update", "operation == 'UPDATE'", "true", "ALLOW", map[string]string{"rsqlPredicate": "update==1"})),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "filter-with-no-operation", filter: true, omitOperation: true},
				{name: "filter-with-the-operation-all", filter: true, operation: "ALL"},
				{name: "filter-with-read", filter: true, operation: "READ"},
			},
		})
	}

	// A target that reads the resource, in the policy and in the rule, on a filter
	// request that carries no resource. missing-attribute-in-set-target records
	// that the PAP refuses such a target on a set; f3 records that a condition
	// reading the resource does not keep the predicate out. The check request
	// carries the attribute the target reads and is the control.
	for _, level := range []string{"policy", "rule"} {
		id := "filter-target-reads-the-resource-in-the-" + level
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		policyTarget := readerTarget
		ruleTarget := "operation == 'LIST'"
		if level == "policy" {
			policyTarget += " AND resource.service == 'parity-svc'"
		} else {
			ruleTarget += " AND resource.service == 'parity-svc'"
		}
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", policyTarget, "DENY_UNLESS_PERMIT",
						b.rule("list", ruleTarget, "true", "ALLOW", map[string]string{"rsqlPredicate": "svc==1"})),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "filter", filter: true},
				{name: "check-list-with-the-service", operation: "LIST", resource: map[string]any{"id": "reg-filter-target", "service": "parity-svc"}},
			},
		})
	}

	return cases
}

// What a simplified policy with operation ALL does with a condition and with a
// predicate. x30-policy-operation-all records that ALL matches READ and DELETE for
// a policy with neither. oa1 pairs a condition with ALL: true for a = y and false
// for a = n on both operations means the condition is evaluated, true for all four
// means ALL drops it, and a refused upload means the form is outside the language.
// oa2 pairs a predicate with ALL and asks two filter operations for it.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestInterpreterOperationAllCases() {
	s.runIsolatedCases([]isolatedCase{
		{id: "oa1-operation-all-with-a-condition", resourceType: "PARITY_SUITE_ALL_OA1", operation: "ALL", condition: "resource.a == 'y'", requests: []isolatedRequest{
			{name: "read-condition-true", operation: "READ", resource: map[string]any{"id": "all-oa1", "a": "y"}},
			{name: "read-condition-false", operation: "READ", resource: map[string]any{"id": "all-oa1", "a": "n"}},
			{name: "delete-condition-true", operation: "DELETE", resource: map[string]any{"id": "all-oa1", "a": "y"}},
			{name: "delete-condition-false", operation: "DELETE", resource: map[string]any{"id": "all-oa1", "a": "n"}},
		}},
		{id: "oa2-operation-all-with-a-predicate", resourceType: "PARITY_SUITE_ALL_OA2", operation: "ALL", rsql: "all==1", requests: []isolatedRequest{
			{name: "filter-list", operation: "LIST", filter: true},
			{name: "filter-read", operation: "READ", filter: true},
		}},
	})
}
