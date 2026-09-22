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

// What check/filter carries for the predicates of DENY rules under each combining
// algorithm of the policy. filter-allow-and-deny-rules records, under
// DENY_UNLESS_PERMIT, a response that holds the ALLOW rule's predicate and not
// the DENY rule's. Whether the DENY predicates are left out under every
// algorithm, or enter the response in some negated form under the algorithms
// where a DENY decides, is recorded nowhere, and the answer is per dialect: an
// rsql, sql, mongodb, querydsl and custom predicate each have a negation of
// their own, or none.
//
// Each case is one regular set with one policy under one of the four accepted
// algorithms, holding two ALLOW rules and two DENY rules on LIST, every rule
// with all five predicate fields, and one filter request. The set's own
// algorithm is DENY_UNLESS_PERMIT in every case, so a difference between the
// four responses is the policy algorithm's. A fifth case repeats the
// DENY_OVERRIDES one with the four string predicates alone, since no recorded
// upload carries a customPredicate and a refusal of that shape would otherwise
// look like a refusal of the DENY rules.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case.
func (s *ParitySuite) TestInterpreterDenyPredicateCases() {
	s.runRegularCases(denyPredicateCases())
}

// denyPredicateRule builds a LIST rule with the given effect whose predicate
// fields all test the field name against value: the four string predicates, and
// the custom predicate too when withCustom is set, in the shape with params the
// other uploads of the suite use.
func denyPredicateRule(b regularBuilder, key, field, value, effect string, withCustom bool) map[string]any {
	rule := b.rule(key, "operation == 'LIST'", "true", effect, map[string]string{
		"rsqlPredicate":    field + "==" + value,
		"sqlPredicate":     field + "=" + value,
		"mongodbPredicate": `{ "` + field + `": ` + value + ` }`,
		"predicate":        "${resourceType}." + field + ".eq(" + value + ")",
	})
	if withCustom {
		rule["customPredicate"] = map[string]any{
			"predicate": field + ":" + value + ":${owner}",
			"params":    map[string]any{"owner": "subject.id"},
		}
	}
	return rule
}

// denyPredicateCases builds one case per policy algorithm with all five predicate
// fields, and one more under DENY_OVERRIDES with the four string predicates
// alone, so that a refusal of the customPredicate shape is told from a refusal
// of the DENY rules.
func denyPredicateCases() []regularCase {
	var cases []regularCase
	type form struct {
		key        string
		algorithm  string
		withCustom bool
	}
	var forms []form
	for _, algorithm := range acceptedAlgorithms {
		forms = append(forms, form{algorithm.key, algorithm.name, true})
	}
	forms = append(forms, form{"deny-overrides-without-custom-predicate", "DENY_OVERRIDES", false})
	for _, form := range forms {
		id := "deny-predicates-under-" + form.key
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, form.algorithm,
						denyPredicateRule(b, "allow-a", "a", "1", "ALLOW", form.withCustom),
						denyPredicateRule(b, "allow-b", "b", "2", "ALLOW", form.withCustom),
						denyPredicateRule(b, "deny-c", "c", "3", "DENY", form.withCustom),
						denyPredicateRule(b, "deny-d", "d", "4", "DENY", form.withCustom)),
				}, nil),
			}}},
			requests: []isolatedRequest{{name: "filter", filter: true}},
		})
	}
	return cases
}
