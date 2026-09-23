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

// denyPredicatePolicy is a DENY_OVERRIDES policy whose one rule on LIST is a DENY
// with a true condition and the rsql predicate blocked==1.
func denyPredicatePolicy(b regularBuilder) map[string]any {
	return b.policy("denies", readerTarget, "DENY_OVERRIDES",
		b.rule("list-deny-with-a-predicate", "operation == 'LIST'", "true", "DENY", map[string]string{"rsqlPredicate": "blocked==1"}))
}

// What the algorithm of a set does to the predicates of its policies in
// check/filter. Every recorded case of a predicate reaching a filter under a
// set puts the set under DENY_UNLESS_PERMIT (deny-predicates-under-*,
// deny-in-one-policy-beside-a-predicate-in-another), except
// deny-overrides-set-*, where the set denies through a policy with no rule on
// the operation and no predicate is left to shape. A PERMIT_UNLESS_DENY policy
// drops the ALLOW predicates of its rules (deny-predicates-under-permit-unless-deny),
// and a PERMIT_UNLESS_DENY iterate node keeps them
// (scope-filter/*/filter-custom-permit-unless-deny); what a PERMIT_UNLESS_DENY
// set does with the ALLOW predicate of a policy is recorded nowhere. The
// agent's converter accepts every set here.
//
// Under each of the four set algorithms, -over-an-allow-predicate holds one
// DENY_UNLESS_PERMIT policy with an ALLOW on LIST carrying allowed==1,
// -over-a-deny-predicate holds one DENY_OVERRIDES policy with a DENY on LIST
// carrying blocked==1, and -over-allow-and-deny-predicates holds both. The sets
// under DENY_UNLESS_PERMIT are the controls, the set algorithm every recorded
// predicate was seen under. set-algorithm-deny-overrides-over-an-allow-predicate
// repeats deny-overrides-set-with-the-predicate-policy-alone, whose filter is
// allowed==1, and has to record the same answer. check/resource on LIST records
// the decision the filter has to follow.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case.
func (s *ParitySuite) TestRound10SetAlgorithmFilterCases() {
	s.runRegularCases(round10SetAlgorithmFilterCases())
}

func round10SetAlgorithmFilterCases() []regularCase {
	var cases []regularCase
	for _, algorithm := range acceptedAlgorithms {
		cases = append(cases,
			round9SetCase("set-algorithm-"+algorithm.key+"-over-an-allow-predicate", algorithm.name, func(b regularBuilder) []any {
				return []any{b.policy("allows", readerTarget, "DENY_UNLESS_PERMIT", allowWithPredicate(b, "list-allow-with-a-predicate", "allowed==1"))}
			}),
			round9SetCase("set-algorithm-"+algorithm.key+"-over-a-deny-predicate", algorithm.name, func(b regularBuilder) []any {
				return []any{denyPredicatePolicy(b)}
			}),
			round9SetCase("set-algorithm-"+algorithm.key+"-over-allow-and-deny-predicates", algorithm.name, func(b regularBuilder) []any {
				return []any{
					b.policy("allows", readerTarget, "DENY_UNLESS_PERMIT", allowWithPredicate(b, "list-allow-with-a-predicate", "allowed==1")),
					denyPredicatePolicy(b),
				}
			}),
		)
	}
	return cases
}

// What check/filter does with a rule whose condition or target reads the
// resource and evaluates without it. A filter request carries no resource, and
// the recorded rule without a predicate whose condition is resource.x == 'a' is
// left out of the filter (filter-rule-with-a-resource-condition-and-no-predicate).
// Over an absent key IS NULL is true in check/resource (s6a), and an OR whose
// other operand is true is true there too when the resource is read second; a
// filter that evaluated these conditions the same way would lift the filter. The
// agent's converter accepts every set here.
//
// Each rule is an ALLOW on LIST with no predicate: resource.x IS NULL as the
// condition, resource.x == 'a' OR the reader's role, the same operands swapped,
// and resource.x IS NULL in the rule target with a true condition. Each is asked
// alone, where the filter answer is the rule's own, and beside an ALLOW with the
// predicate allowed==1, where an unrestricted ALLOW beside a predicate answers
// ALLOW (allow-without-predicate-true-beside-a-predicate).
// resource-equals-without-predicate-beside-a-predicate is the control, the
// recorded condition in the same pair, and is asked beside the predicate only.
// check/resource on LIST, for a resource without x, records what the rule
// decides when the resource is there.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case.
func (s *ParitySuite) TestRound10FilterResourceConditionCases() {
	s.runRegularCases(round10FilterResourceConditionCases())
}

func round10FilterResourceConditionCases() []regularCase {
	var cases []regularCase
	for _, form := range []struct {
		key, target, condition string
		alone                  bool
	}{
		{"resource-is-null", "operation == 'LIST'", "resource.x IS NULL", true},
		{"resource-or-subject", "operation == 'LIST'", "resource.x == 'a' OR " + readerTarget, true},
		{"subject-or-resource", "operation == 'LIST'", readerTarget + " OR resource.x == 'a'", true},
		{"target-resource-is-null", "operation == 'LIST' AND resource.x IS NULL", "true", true},
		{"resource-equals", "operation == 'LIST'", "resource.x == 'a'", false},
	} {
		withoutPredicate := func(b regularBuilder) map[string]any {
			return b.rule("list-reads-the-resource", form.target, form.condition, "ALLOW", nil)
		}
		if form.alone {
			cases = append(cases, round9PolicyCase(form.key+"-without-predicate-alone", "DENY_UNLESS_PERMIT", func(b regularBuilder) []any {
				return []any{withoutPredicate(b)}
			}))
		}
		cases = append(cases, round9PolicyCase(form.key+"-without-predicate-beside-a-predicate", "DENY_UNLESS_PERMIT", func(b regularBuilder) []any {
			return []any{withoutPredicate(b), allowWithPredicate(b, "list-with-a-predicate", "allowed==1")}
		}))
	}
	return cases
}

// What check/filter does with a deny list whose rules carry no predicate and
// read the resource: a PERMIT_UNLESS_DENY policy of DENY rules on
// resource.uri MATCH, the form every deny list of the product policies in reach
// takes. The recorded deny list carries predicates (filter-under-a-deny-list),
// and the recorded DENY rules without a predicate read the subject
// (deny-without-predicate-*). The agent's converter accepts every set here.
//
// deny-list-without-predicate is the deny list alone, under a
// DENY_UNLESS_PERMIT set; the filter may answer ALLOW, as the PERMIT_UNLESS_DENY
// policy permits wherever its DENY does not apply, or DENY. -beside-a-predicate
// adds a policy with an ALLOW carrying allowed==1, where the answer may be that
// predicate or ALLOW. check/resource on LIST with a uri the rule matches and with
// one it does not is the control that the deny list applies to a resource.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case.
func (s *ParitySuite) TestRound10DenyListFilterCases() {
	s.runRegularCases(round10DenyListFilterCases())
}

func round10DenyListFilterCases() []regularCase {
	denyList := func(b regularBuilder) map[string]any {
		return b.policy("deny-list", readerTarget, "PERMIT_UNLESS_DENY",
			b.rule("list-deny-a-secret-uri", "operation == 'LIST'", "resource.uri MATCH /v1/secret/**", "DENY", nil))
	}
	requests := []isolatedRequest{
		{name: "filter", filter: true},
		{name: "check-list-uri-in-the-list", operation: "LIST", resource: map[string]any{"id": "r10-deny-list", "uri": "/v1/secret/a"}},
		{name: "check-list-uri-outside-the-list", operation: "LIST", resource: map[string]any{"id": "r10-deny-list", "uri": "/v1/open/a"}},
	}
	alone := round9SetCase("deny-list-without-predicate", "DENY_UNLESS_PERMIT", func(b regularBuilder) []any {
		return []any{denyList(b)}
	})
	alone.requests = requests
	beside := round9SetCase("deny-list-without-predicate-beside-a-predicate", "DENY_UNLESS_PERMIT", func(b regularBuilder) []any {
		return []any{denyList(b), b.policy("allows", readerTarget, "DENY_UNLESS_PERMIT", allowWithPredicate(b, "list-allow-with-a-predicate", "allowed==1"))}
	})
	beside.requests = requests
	return []regularCase{alone, beside}
}
