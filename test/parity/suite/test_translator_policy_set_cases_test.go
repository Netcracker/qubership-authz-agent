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
)

// translatorPipRoutes are the pip-mock paths the failed-PIP cases pin, and the
// status each one answers with. The healthy route is the control: a condition that
// reads it allows, so a case where every answer is false is not explained by
// pip-mock being unreachable or by the declaration being dropped.
var translatorPipRoutes = map[string]PipStubResponse{
	"/api/v1/pip/translator-broken": {StatusCode: http.StatusInternalServerError, Body: map[string]string{"error": "parity translator case"}},
	"/api/v1/pip/translator-gone":   {StatusCode: http.StatusNotFound, Body: map[string]string{"error": "parity translator case"}},
	"/api/v1/pip/translator-live":   {StatusCode: http.StatusOK, Body: map[string]string{"value": "v"}},
}

// translatorFailedPIPs declare the three GENERAL PIPs of the failed-PIP cases,
// shaped like the accepted declarations under testdata/fixtures. The live one reads
// $.value out of the body, so its condition compares a value rather than an object.
// Every fixture declaration names the consuming resource type in
// requestAttributes; these declarations are read by one case per combining
// algorithm and so name the group instead. The field is request-body content, not
// something access-control matches on.
var translatorFailedPIPs = []any{
	map[string]any{
		"name":              "subject.parityTranslatorBroken",
		"url":               parityPipMockBase + "/translator-broken",
		"httpMethod":        "POST",
		"pipType":           "GENERAL",
		"requestAttributes": map[string]string{"resourceType": "PARITY_SUITE_TRANSLATOR_PIP"},
		"cacheable":         false,
	},
	map[string]any{
		"name":              "subject.parityTranslatorGone",
		"url":               parityPipMockBase + "/translator-gone",
		"httpMethod":        "POST",
		"pipType":           "GENERAL",
		"requestAttributes": map[string]string{"resourceType": "PARITY_SUITE_TRANSLATOR_PIP"},
		"cacheable":         false,
	},
	map[string]any{
		"name":              "subject.parityTranslatorLive",
		"url":               parityPipMockBase + "/translator-live",
		"httpMethod":        "POST",
		"pipType":           "GENERAL",
		"type":              "JSON",
		"jsonPath":          "$.value",
		"requestAttributes": map[string]string{"resourceType": "PARITY_SUITE_TRANSLATOR_PIP"},
		"cacheable":         false,
	},
}

// withRuleID replaces the rule id regularBuilder derived from the case and the
// rule's key. Two rules of two different sets carry the same id only where the case
// is about that collision.
func withRuleID(rule map[string]any, id string) map[string]any {
	rule["ruleId"] = id
	return rule
}

// Answers of access-control that a translator of regular policy sets cannot be
// written without, and that no golden records: what a set decides when the only
// rules it holds are DENY rules none of which applied, what a rule whose condition
// reads a PIP that failed does to the rule beside it, what check/filter returns for
// a resource type whose policy is a deny list, and what the filter carries when two
// sets name one rule id.
//
// The other cases of the regular set format are in TestRegularPolicySetCases; these
// live in their own test function so that a recording run can be filtered to them
// and leave every golden already committed alone.
//
// Every case carries a request that allows, or a predicate that reaches the
// response, because a set the PAP accepted and never evaluated answers DENY to
// every request. A refused set upload is recorded as a golden of its own and ends
// its case before any request is sent, so a refusal and a DENY are never the same
// golden; a refused PIP declaration fails the case outright in runRegularCases and
// records nothing, which is louder still.
func (s *ParitySuite) TestTranslatorPolicySetCases() {
	ctx := context.Background()
	for path, response := range translatorPipRoutes {
		s.Require().NoError(s.pipMock.PinRoute(ctx, path, response), "pin %s", path)
	}

	s.runRegularCases(translatorPolicySetCases())

	// The failed-PIP cases run one at a time, because the call log is read after
	// each of them. A log read once after all four would pass on a case whose PIPs
	// were never called as long as another case reached the same paths, and that is
	// the reading the check exists to rule out: a run in which access-control never
	// called pip-mock records the same DENY column as a run in which it called and
	// the call failed.
	for _, tc := range translatorFailedPIPCases() {
		s.Require().NoError(s.pipMock.ResetCalls(ctx))
		s.runRegularCases([]regularCase{tc})
		s.Run(tc.id+"/the-pips-were-read", func() {
			calls, err := s.pipMock.GetCalls(ctx)
			s.Require().NoError(err)
			read := map[string]int{}
			for _, call := range calls {
				if _, pinned := translatorPipRoutes[call.Path]; pinned {
					read[call.Path]++
				}
			}
			for path := range translatorPipRoutes {
				s.Assert().Positive(read[path], "pip-mock calls to %s over the requests of %s", path, tc.id)
			}
		})
	}
}

func translatorPolicySetCases() []regularCase {
	var cases []regularCase

	// A policy whose rules are all DENY and none of which applied. The recorded
	// algorithm cases send DELETE at a lone DENY rule that does apply, and they
	// send CREATE at a policy with no applicable rule at all, but no case asks what
	// a policy answers when it holds only rules that did not fire. The two
	// requests are the pair: deny-applies is the control that the rule is live, and
	// deny-does-not-apply is the column the translator needs.
	for _, algorithm := range []struct{ key, name string }{
		{"deny-overrides", "DENY_OVERRIDES"},
		{"permit-unless-deny", "PERMIT_UNLESS_DENY"},
	} {
		id := "only-deny-rules-" + algorithm.key
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", algorithm.name, []any{
					b.policy("reader", readerTarget, algorithm.name,
						b.rule("read-deny", "operation == 'READ'", "resource.flag == 'on'", "DENY", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "deny-applies", operation: "READ", resource: map[string]any{"id": "tr-only-deny", "flag": "on"}},
				{name: "deny-does-not-apply", operation: "READ", resource: map[string]any{"id": "tr-only-deny", "flag": "off"}},
			},
		})
	}

	// The same question one level up: the policy holds a DENY rule that would
	// apply, and the policy target keeps the request from reaching it. The probe
	// policy is the control, and it is the reason a DENY on read-under-an-unmatched-
	// policy means the set answered rather than that the set was never consulted.
	{
		id := "deny-policy-target-does-not-match"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_OVERRIDES", []any{
					b.policy("other-role", "subject.roles CONTAINS 'ROLE_PARITY_NO_SUCH_ROLE'", "DENY_OVERRIDES",
						b.rule("read-deny", "operation == 'READ'", "true", "DENY", nil)),
					b.policy("probe", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("probe-allow", "operation == 'PROBE'", "true", "ALLOW", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "read-under-an-unmatched-policy", operation: "READ", resource: map[string]any{"id": "tr-policy-target"}},
				{name: "probe-under-the-matched-policy", operation: "PROBE", resource: map[string]any{"id": "tr-policy-target"}},
			},
		})
	}

	// A policy with an empty rule list, under the algorithm that permits what no
	// rule denied. The probe policy holds a DENY rule that does apply, so a DENY on
	// probe-under-a-deny-rule shows the set is evaluated and a DENY on
	// read-under-a-policy-without-rules is then the answer of the empty policy.
	{
		id := "permit-unless-deny-without-rules"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "PERMIT_UNLESS_DENY", []any{
					b.policy("without-rules", readerTarget, "PERMIT_UNLESS_DENY"),
					b.policy("probe", readerTarget, "PERMIT_UNLESS_DENY",
						b.rule("probe-deny", "operation == 'PROBE'", "true", "DENY", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "read-under-a-policy-without-rules", operation: "READ", resource: map[string]any{"id": "tr-no-rules"}},
				{name: "probe-under-a-deny-rule", operation: "PROBE", resource: map[string]any{"id": "tr-no-rules"}},
			},
		})
	}

	// check/filter for a resource type whose only policy is a deny list. The
	// recorded filter cases all reach an ALLOW rule with a predicate, and this shape
	// has none: every rule is a DENY, so either the reader is unrestricted, or the
	// denials arrive as a predicate, or the answer is DENY. The check-list request
	// records the check/resource answer for the same request, which fixes which of
	// the three the filter is consistent with.
	{
		id := "filter-under-a-deny-list"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("deny-list", readerTarget, "PERMIT_UNLESS_DENY",
						b.rule("deny-alpha", "operation == 'LIST'", "true", "DENY", map[string]string{"rsqlPredicate": "area==alpha"}),
						b.rule("deny-beta", "operation == 'LIST'", "true", "DENY", map[string]string{"rsqlPredicate": "area==beta"})),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "filter", filter: true},
				{name: "check-list", operation: "LIST", resource: map[string]any{"id": "tr-filter-deny-list"}},
			},
		})
	}

	// The control for filter-under-a-deny-list: the same deny list with an ALLOW
	// rule carrying a predicate beside it. A predicate in this response and none in
	// the other one means the deny list contributes nothing to a filter; the same
	// response in both means the ALLOW rule decided either way.
	{
		id := "filter-under-a-deny-list-beside-an-allow"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("deny-list", readerTarget, "PERMIT_UNLESS_DENY",
						b.rule("deny-alpha", "operation == 'LIST'", "true", "DENY", map[string]string{"rsqlPredicate": "area==alpha"})),
					b.policy("allow-list", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("allow-open", "operation == 'LIST'", "true", "ALLOW", map[string]string{"rsqlPredicate": "area==open"})),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "filter", filter: true},
				{name: "check-list", operation: "LIST", resource: map[string]any{"id": "tr-filter-both"}},
			},
		})
	}

	// Two sets of two externalIDs whose rules carry one id, each with a predicate of
	// its own. The translator keeps its own key per rule, and the answer says
	// whether the external id has to stay unique across sets for the response to
	// carry both predicates.
	{
		id := "repeated-rule-id-in-two-sets"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		rtTarget := "resourceType == '" + rt + "'"
		const sharedRuleID = "00000000-0000-0000-0000-0000000f0042"
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{
				{externalID: "parity-" + id + "-first", sets: []any{
					b.set("first", rtTarget, "DENY_UNLESS_PERMIT", []any{
						b.policy("first-reader", readerTarget, "DENY_UNLESS_PERMIT",
							withRuleID(b.rule("first-list", "operation == 'LIST'", "true", "ALLOW",
								map[string]string{"rsqlPredicate": "first==1"}), sharedRuleID)),
					}, nil),
				}},
				{externalID: "parity-" + id + "-second", sets: []any{
					b.set("second", rtTarget, "DENY_UNLESS_PERMIT", []any{
						b.policy("second-reader", readerTarget, "DENY_UNLESS_PERMIT",
							withRuleID(b.rule("second-list", "operation == 'LIST'", "true", "ALLOW",
								map[string]string{"rsqlPredicate": "second==2"}), sharedRuleID)),
					}, nil),
				}},
			},
			requests: []isolatedRequest{
				{name: "filter", filter: true},
				{name: "check-list", operation: "LIST", resource: map[string]any{"id": "tr-repeated-id"}},
			},
		})
	}

	// The control for repeated-rule-id-in-two-sets: the same two sets with the ids
	// regularBuilder derives, which differ. A response carrying both predicates
	// here and one predicate there is the collision; two identical responses mean
	// the repeated id costs nothing.
	{
		id := "distinct-rule-ids-in-two-sets"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		rtTarget := "resourceType == '" + rt + "'"
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{
				{externalID: "parity-" + id + "-first", sets: []any{
					b.set("first", rtTarget, "DENY_UNLESS_PERMIT", []any{
						b.policy("first-reader", readerTarget, "DENY_UNLESS_PERMIT",
							b.rule("first-list", "operation == 'LIST'", "true", "ALLOW",
								map[string]string{"rsqlPredicate": "first==1"})),
					}, nil),
				}},
				{externalID: "parity-" + id + "-second", sets: []any{
					b.set("second", rtTarget, "DENY_UNLESS_PERMIT", []any{
						b.policy("second-reader", readerTarget, "DENY_UNLESS_PERMIT",
							b.rule("second-list", "operation == 'LIST'", "true", "ALLOW",
								map[string]string{"rsqlPredicate": "second==2"})),
					}, nil),
				}},
			},
			requests: []isolatedRequest{
				{name: "filter", filter: true},
				{name: "check-list", operation: "LIST", resource: map[string]any{"id": "tr-distinct-ids"}},
			},
		})
	}

	return cases
}

// translatorFailedPIPCases are the cases of TestTranslatorPolicySetCases that read a
// PIP, kept apart from the others because the test runs them one at a time and reads
// the pip-mock call log after each.
func translatorFailedPIPCases() []regularCase {
	var cases []regularCase

	// A rule whose condition reads a GENERAL PIP that failed, beside a rule of the
	// same policy that allows. approve-failed-allow-beside-allow records this shape
	// with a missing resource key and answers true under all four algorithms, which
	// is what says an unresolvable value makes one rule inapplicable and leaves its
	// neighbor alone. A failed PIP is the other way an operand fails to resolve,
	// and whether the two are the same event decides whether a translator can drop
	// the abort altogether.
	//
	// The operations split the shapes: READ an ALLOW that reads the PIP answering
	// 500 beside an ALLOW, UPDATE the same with 404, DELETE a DENY that reads the
	// 500 beside an ALLOW, and PROBE the rule that reads the live PIP alone.
	for _, algorithm := range []struct{ key, name string }{
		{"deny-unless-permit", "DENY_UNLESS_PERMIT"},
		{"permit-unless-deny", "PERMIT_UNLESS_DENY"},
		{"deny-overrides", "DENY_OVERRIDES"},
		{"permit-overrides", "PERMIT_OVERRIDES"},
	} {
		id := "failed-pip-beside-allow-" + algorithm.key
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			pips:         translatorFailedPIPs,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", algorithm.name, []any{
					b.policy("reader", readerTarget, algorithm.name,
						b.rule("read-allow-reads-the-broken-pip", "operation == 'READ'", "subject.parityTranslatorBroken != 'x'", "ALLOW", nil),
						b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil),
						b.rule("update-allow-reads-the-gone-pip", "operation == 'UPDATE'", "subject.parityTranslatorGone != 'x'", "ALLOW", nil),
						b.rule("update-allow", "operation == 'UPDATE'", "true", "ALLOW", nil),
						b.rule("delete-deny-reads-the-broken-pip", "operation == 'DELETE'", "subject.parityTranslatorBroken != 'x'", "DENY", nil),
						b.rule("delete-allow", "operation == 'DELETE'", "true", "ALLOW", nil),
						b.rule("probe-allow-reads-the-live-pip", "operation == 'PROBE'", "subject.parityTranslatorLive == 'v'", "ALLOW", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "failed-allow-beside-allow", operation: "READ", resource: map[string]any{"id": "tr-failed-pip"}},
				{name: "missing-allow-beside-allow", operation: "UPDATE", resource: map[string]any{"id": "tr-failed-pip"}},
				{name: "failed-deny-beside-allow", operation: "DELETE", resource: map[string]any{"id": "tr-failed-pip"}},
				{name: "live-pip-alone", operation: "PROBE", resource: map[string]any{"id": "tr-failed-pip"}},
			},
		})
	}

	return cases
}
