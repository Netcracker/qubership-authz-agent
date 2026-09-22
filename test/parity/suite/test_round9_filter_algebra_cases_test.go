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

// round9FalseSubjectCondition is a condition over the subject alone that is false
// for parity-reader, so a filter request, which carries no resource, evaluates it.
const round9FalseSubjectCondition = "subject.roles CONTAINS 'ROLE_PARITY_NOBODY'"

// round9FilterRequests are the requests of every case in this file: the filter on
// LIST, and check/resource on LIST, the decision the same rules produce.
var round9FilterRequests = []isolatedRequest{
	{name: "filter", filter: true},
	{name: "check-list", operation: "LIST", resource: map[string]any{"id": "r9-filter"}},
}

// round9SetCase builds a case of one set under setAlgorithm holding policies,
// each built by the case's builder, and sends round9FilterRequests.
func round9SetCase(id, setAlgorithm string, policies func(b regularBuilder) []any) regularCase {
	b := regularBuilder{caseID: id}
	rt := regularResourceType(id)
	return regularCase{
		id:           id,
		resourceType: rt,
		uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
			b.set("set", "resourceType == '"+rt+"'", setAlgorithm, policies(b), nil),
		}}},
		requests: round9FilterRequests,
	}
}

// round9PolicyCase is round9SetCase with the set under DENY_UNLESS_PERMIT and one
// policy under policyAlgorithm holding rules.
func round9PolicyCase(id, policyAlgorithm string, rules func(b regularBuilder) []any) regularCase {
	return round9SetCase(id, "DENY_UNLESS_PERMIT", func(b regularBuilder) []any {
		return []any{b.policy("reader", readerTarget, policyAlgorithm, rules(b)...)}
	})
}

// allowWithPredicate is an ALLOW rule on LIST whose predicate is rsql.
func allowWithPredicate(b regularBuilder, key, rsql string) map[string]any {
	return b.rule(key, "operation == 'LIST'", "true", "ALLOW", map[string]string{"rsqlPredicate": rsql})
}

// What check/filter does with a DENY rule that has no predicate and a condition
// that holds, under each combining algorithm of its policy. deny-predicates-under-*
// records that a DENY rule's predicate is dropped under DENY_UNLESS_PERMIT and
// PERMIT_OVERRIDES and enters the response negated under the other two; every
// recorded DENY rule without a predicate reads the resource in its condition, so
// it never reaches a filter. The agent's converter accepts every set here.
//
// Under each algorithm the DENY rule sits beside an ALLOW rule with a predicate,
// and beside an ALLOW rule with neither predicate nor condition, which lifts the
// filter on its own (filter-rule-without-condition-or-predicate).
// false-beside-a-predicate under each algorithm is the control: the same DENY
// rule with a condition that is false for the reader, so a response that
// differs from it is the true condition's.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case.
func (s *ParitySuite) TestRound9DenyRuleWithoutPredicateCases() {
	s.runRegularCases(round9DenyRuleWithoutPredicateCases())
}

func round9DenyRuleWithoutPredicateCases() []regularCase {
	var cases []regularCase
	for _, algorithm := range acceptedAlgorithms {
		for _, form := range []struct {
			key, condition string
			allow          func(b regularBuilder) map[string]any
		}{
			{"true-beside-a-predicate", "true", func(b regularBuilder) map[string]any {
				return allowWithPredicate(b, "list-allow-with-a-predicate", "allowed==1")
			}},
			{"true-beside-an-unrestricted-allow", "true", func(b regularBuilder) map[string]any {
				return b.rule("list-allow", "operation == 'LIST'", "true", "ALLOW", nil)
			}},
			{"false-beside-a-predicate", round9FalseSubjectCondition, func(b regularBuilder) map[string]any {
				return allowWithPredicate(b, "list-allow-with-a-predicate", "allowed==1")
			}},
		} {
			cases = append(cases, round9PolicyCase("deny-without-predicate-"+form.key+"-under-"+algorithm.key, algorithm.name,
				func(b regularBuilder) []any {
					return []any{
						b.rule("list-deny", "operation == 'LIST'", form.condition, "DENY", nil),
						form.allow(b),
					}
				}))
		}
	}
	return cases
}

// What check/filter does with an ALLOW rule that has no predicate and a condition
// over the subject that is false for the reader. The recorded rule without a
// predicate lifts the filter when its subject condition holds
// (filter-rule-with-a-subject-condition-and-no-predicate) and is left out when
// its condition reads the resource (filter-rule-with-a-resource-condition-and-no-predicate);
// a subject condition that does not hold is recorded nowhere. The agent's
// converter accepts every set here.
//
// The rule is asked alone and beside an ALLOW rule with a predicate.
// allow-without-predicate-true-beside-a-predicate is the control, the same pair
// with the condition true; it is also the only case of an unrestricted ALLOW
// beside a predicate in one policy, which TestRound9FilterAlgebraCases relies on.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case.
func (s *ParitySuite) TestRound9FalseConditionWithoutPredicateCases() {
	s.runRegularCases(round9FalseConditionWithoutPredicateCases())
}

func round9FalseConditionWithoutPredicateCases() []regularCase {
	withoutPredicate := func(b regularBuilder, condition string) map[string]any {
		return b.rule("list-under-a-subject-condition", "operation == 'LIST'", condition, "ALLOW", nil)
	}
	return []regularCase{
		round9PolicyCase("allow-without-predicate-false-alone", "DENY_UNLESS_PERMIT", func(b regularBuilder) []any {
			return []any{withoutPredicate(b, round9FalseSubjectCondition)}
		}),
		round9PolicyCase("allow-without-predicate-false-beside-a-predicate", "DENY_UNLESS_PERMIT", func(b regularBuilder) []any {
			return []any{withoutPredicate(b, round9FalseSubjectCondition), allowWithPredicate(b, "list-with-a-predicate", "allowed==1")}
		}),
		round9PolicyCase("allow-without-predicate-true-beside-a-predicate", "DENY_UNLESS_PERMIT", func(b regularBuilder) []any {
			return []any{withoutPredicate(b, readerTarget), allowWithPredicate(b, "list-with-a-predicate", "allowed==1")}
		}),
	}
}

// How check/filter combines nodes whose check/resource decision is recorded and
// whose filter answer is not. Each case pairs with a control that differs in
// the one element under question. An unrestricted ALLOW beside a predicate in
// one policy is asked by allow-without-predicate-true-beside-a-predicate in
// TestRound9FalseConditionWithoutPredicateCases. The agent's converter accepts
// every set here.
//
// permit-unless-deny-with-deny-rules-elsewhere is a PERMIT_UNLESS_DENY policy
// whose one DENY rule, with a predicate, is on UPDATE: on LIST nothing applies,
// the policy permits in check/resource (only-deny-rules-*), and the filter may
// answer ALLOW or nothing. Its filter on UPDATE is the control, where the DENY
// rule applies and its predicate enters negated (deny-predicates-under-*).
//
// deny-overrides-set-with-a-policy-without-a-list-rule is a DENY_OVERRIDES set of
// a policy with an ALLOW predicate on LIST and a DENY_UNLESS_PERMIT policy with a
// rule on UPDATE alone. In check/resource the second policy denies LIST and
// overrides the first (TestInterpreterCombiningCases); whether the filter
// follows or answers the first policy's predicate is not recorded. The control
// is the set with the first policy alone.
//
// deny-in-one-policy-beside-a-predicate-in-another is a DENY_UNLESS_PERMIT set
// of a DENY_OVERRIDES policy whose DENY rule on LIST has no predicate and a true
// condition, beside a policy with an ALLOW predicate. check/resource permits,
// since the set permits when any policy does; the filter may deny the whole
// answer instead. The control gives the DENY rule a false condition.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case.
func (s *ParitySuite) TestRound9FilterAlgebraCases() {
	s.runRegularCases(round9FilterAlgebraCases())
}

func round9FilterAlgebraCases() []regularCase {
	var cases []regularCase

	pud := round9PolicyCase("permit-unless-deny-with-deny-rules-elsewhere", "PERMIT_UNLESS_DENY", func(b regularBuilder) []any {
		return []any{b.rule("update-deny", "operation == 'UPDATE'", "true", "DENY", map[string]string{"rsqlPredicate": "blocked==1"})}
	})
	pud.requests = append(append([]isolatedRequest(nil), round9FilterRequests...), isolatedRequest{name: "filter-update", filter: true, operation: "UPDATE"})
	cases = append(cases, pud)

	predicatePolicy := func(b regularBuilder) map[string]any {
		return b.policy("with-a-predicate", readerTarget, "DENY_UNLESS_PERMIT", allowWithPredicate(b, "list-with-a-predicate", "allowed==1"))
	}
	cases = append(cases,
		round9SetCase("deny-overrides-set-with-a-policy-without-a-list-rule", "DENY_OVERRIDES", func(b regularBuilder) []any {
			return []any{
				predicatePolicy(b),
				b.policy("update-only", readerTarget, "DENY_UNLESS_PERMIT",
					b.rule("update-allow", "operation == 'UPDATE'", "true", "ALLOW", nil)),
			}
		}),
		round9SetCase("deny-overrides-set-with-the-predicate-policy-alone", "DENY_OVERRIDES", func(b regularBuilder) []any {
			return []any{predicatePolicy(b)}
		}),
	)

	for _, form := range []struct{ key, condition string }{
		{"deny-in-one-policy-beside-a-predicate-in-another", "true"},
		{"false-deny-in-one-policy-beside-a-predicate-in-another", round9FalseSubjectCondition},
	} {
		cases = append(cases, round9SetCase(form.key, "DENY_UNLESS_PERMIT", func(b regularBuilder) []any {
			return []any{
				b.policy("denies", readerTarget, "DENY_OVERRIDES",
					b.rule("list-deny", "operation == 'LIST'", form.condition, "DENY", nil)),
				predicatePolicy(b),
			}
		}))
	}
	return cases
}

// What check/filter and check/resource answer when one rule's predicate names a
// placeholder that cannot be resolved and a neighbor rule of the same policy has
// a predicate that can. x20 records that an undeclared placeholder in a
// simplified policy's only predicate denies the whole filter answer, and
// permission-list-no-mapping records the same for ${subject.permissions} with no
// MAPPING PIP; neither has a neighbor. The agent's converter accepts every set
// here.
//
// Each case holds two ALLOW rules on LIST: one naming the placeholder under
// question, and one with the predicate b==2. undeclared-placeholder-alone is the
// regular-set twin of x20 and the other side of the pair: the neighbor is
// absent. declared-placeholder-beside-a-predicate is the positive control, the
// same pair with ${subject.id}, which renders (rls-happy).
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case. No case declares a PIP, so each runs
// on the domain the previous test's cleanup emptied.
func (s *ParitySuite) TestRound9UnresolvedPlaceholderCases() {
	s.runRegularCases(round9UnresolvedPlaceholderCases())
}

func round9UnresolvedPlaceholderCases() []regularCase {
	var cases []regularCase
	for _, form := range []struct {
		key, predicate string
		neighbor       bool
	}{
		{"undeclared-placeholder-beside-a-predicate", "a==${subject.parityR9Undeclared}", true},
		{"permissions-without-mapping-beside-a-predicate", "perms=in=(${subject.permissions})", true},
		{"undeclared-placeholder-alone", "a==${subject.parityR9Undeclared}", false},
		{"declared-placeholder-beside-a-predicate", "a==${subject.id}", true},
	} {
		cases = append(cases, round9PolicyCase(form.key, "DENY_UNLESS_PERMIT", func(b regularBuilder) []any {
			rules := []any{allowWithPredicate(b, "list-with-the-placeholder", form.predicate)}
			if form.neighbor {
				rules = append(rules, allowWithPredicate(b, "list-with-b", "b==2"))
			}
			return rules
		}))
	}
	return cases
}

// How ${subject.name} and ${subject.type} are rendered by each predicate dialect.
// rls-happy records ${subject.id} unquoted in rsql, and substitution-subject-roles
// records a subject list quoted; the two other scalar subject attributes are
// recorded nowhere, so an unquoted id is an observation of one attribute rather
// than a rule for canonical scalars. The agent's converter accepts every set
// here.
//
// Each case is the substitution-* shape, one placeholder in all five predicate
// fields of one LIST rule, and one filter request. substitution-subject-id is
// the control: the attribute already recorded, in the same five fields.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case.
func (s *ParitySuite) TestRound9SubjectScalarSubstitutionCases() {
	s.runRegularCases(round9SubjectScalarSubstitutionCases())
}

func round9SubjectScalarSubstitutionCases() []regularCase {
	var cases []regularCase
	for _, attribute := range []string{"name", "type", "id"} {
		id := "substitution-subject-" + attribute
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT", substitutionRule(b, "subject."+attribute)),
				}, nil),
			}}},
			requests: []isolatedRequest{{name: "filter", filter: true}},
		})
	}
	return cases
}
