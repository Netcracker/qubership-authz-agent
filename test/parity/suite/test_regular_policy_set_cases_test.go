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
	"fmt"
	"iter"
	"net/http"
	"slices"
	"strings"

	"authz-agent/test/parity/suite/model"
)

// readerTarget is the policy target every regular case grants to parity-reader.
const readerTarget = "subject.roles CONTAINS 'ROLE_PARITY_READER'"

// regularCase uploads regular policy sets, and optionally the PIPs they reference
// and simplified policies for the same resource type, then sends requests against
// them.
type regularCase struct {
	id           string
	resourceType string
	// pips and simplified policies go into isolatedCaseDomain before the sets are
	// uploaded. PIPs belong to a domain and policy sets do not, so a set that
	// reads one declares it here.
	pips       []any
	simplified []any
	// uploads run in order; each replaces the sets of its own externalID.
	uploads  []regularUpload
	requests []isolatedRequest
	// steps run in order after requests, and only when every upload was
	// accepted.
	steps []regularStep
	// cleanup is sent before the uploads and, in reverse order, when the case
	// ends, whatever its outcome; see customizationCleanup.
	cleanup []papCall
	// readsRoutes are the pip-mock routes that have to receive a call while
	// the case runs; see caseSpec.ReadsRoutes.
	readsRoutes []string
	// pipCalls is the pip-mock route whose calls over the whole case are
	// recorded as a pip-call golden; see caseSpec.PIPCalls.
	pipCalls string
}

// regularStep is one customization step of a case, as customizeStep
// describes it: call, whose status is recorded under golden, and the requests
// sent after it.
type regularStep struct {
	name     string
	call     papCall
	golden   ParityEndpointID
	requests []isolatedRequest
}

type regularUpload struct {
	externalID string
	sets       []any
}

func regularResourceType(caseID string) string {
	return "PARITY_SUITE_REG_" + strings.ToUpper(strings.ReplaceAll(caseID, "-", "_"))
}

// How access-control evaluates regular policy sets: the nested policy set, policy,
// and rule format with targets, combining algorithms, ALLOW and DENY effects, and
// four predicate kinds. The agent loads simplified policies only, so the cases
// record access-control's answers as the behavior an evaluator of regular sets has
// to reproduce, and run on the legacy profile only.
//
// Each case records the status of every upload and, when all were accepted, the
// status and the answer of every request. The resource types are the case's own,
// and the sets are emptied when the test ends.
func (s *ParitySuite) TestRegularPolicySetCases() {
	s.runRegularCases(regularPolicySetCases())
}

// runRegularCases uploads the sets of each case and records the upload status and,
// once every upload was accepted, the status and the answer of every request. The
// upload status is a golden of its own, so a set the PAP refuses is a recorded
// result rather than a failed case, and the requests of a refused case are skipped
// because they would record a DENY the rules never produced.
//
// A case with PIPs or simplified policies first uploads them into the isolated
// domain and records that status as regular/<case>/declare-the-domain: the first
// of the three PUTs of [UploadIsolatedPolicies] that was not accepted, or else the
// last. When the PAP refused it, the case ends after that golden, before its
// customization cleanup, its sets, and its requests, since the sets would name PIPs
// that were never declared.
//
// When the test ends, every externalID the cases uploaded under is emptied and
// then the isolated domain is, in that order, so that no set outlives the PIP
// declarations it names. A set that does poisons the stand for every group that
// runs after it: access-control refuses every check request with 400, not only
// the ones the set's target matches.
func (s *ParitySuite) runRegularCases(cases []regularCase) {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("regular policy sets are evaluated by access-control only; authz-agent loads simplified policies")
	}
	ctx := context.Background()
	m2m := s.mustM2MToken()
	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s: %v", isolatedCaseDomain, err)
		}
	})
	s.emptyPolicySetsOnCleanup(s.cfg, regularExternalIDs(cases)...)
	for _, tc := range cases {
		s.Run(tc.id, func() {
			s.resetCallsFor(append(slices.Clone(tc.readsRoutes), tc.pipCalls))
			if len(tc.pips) > 0 || len(tc.simplified) > 0 {
				status, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, tc.pips, tc.simplified)
				s.Require().NoError(err)
				s.Run("declare-the-domain", func() {
					s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "regular/"+tc.id+"/declare-the-domain", &model.PolicyLoadOutcome{Status: status})
				})
				if status < http.StatusOK || status >= http.StatusMultipleChoices {
					return
				}
			}
			s.sendCustomizationCleanup(slices.All(tc.cleanup))
			if len(tc.cleanup) > 0 {
				s.T().Cleanup(func() { s.sendCustomizationCleanup(slices.Backward(tc.cleanup)) })
			}
			accepted := true
			for i, upload := range tc.uploads {
				status, _, err := HelperPutPolicySets(ctx, s.cfg, m2m, upload.externalID, upload.sets)
				s.Require().NoError(err)
				s.Run(fmt.Sprintf("upload-%d", i+1), func() {
					s.requirePendingGolden(PSUITE_LOAD_POLICY_SETS, fmt.Sprintf("regular/%s/upload-%d", tc.id, i+1), &model.PolicyLoadOutcome{Status: status})
				})
				if status < http.StatusOK || status >= http.StatusMultipleChoices {
					accepted = false
				}
			}
			if !accepted {
				return
			}
			runRequests := func(requests []isolatedRequest) {
				for _, req := range requests {
					s.Run(req.name, func() {
						s.runRequest("regular/"+tc.id+"/"+req.name, tc.resourceType, req)
					})
				}
			}
			runRequests(tc.requests)
			for _, step := range tc.steps {
				status, _, err := HelperPAPCall(ctx, s.cfg, m2m, step.call)
				s.Require().NoError(err)
				s.Run(step.name, func() {
					s.requirePendingGolden(step.golden, "regular/"+tc.id+"/"+step.name, &model.PolicyLoadOutcome{Status: status})
				})
				runRequests(step.requests)
			}
			s.recordCasePIPCalls("regular/"+tc.id, tc.pipCalls)
			s.requireRoutesRead(tc.readsRoutes)
		})
	}
}

// resetCallsFor clears the pip-mock call log when routes names a route, so
// that requireRoutesRead and recordCasePIPCalls count the calls of one case
// alone. An empty route names none.
func (s *ParitySuite) resetCallsFor(routes []string) {
	if slices.ContainsFunc(routes, func(route string) bool { return route != "" }) {
		s.Require().NoError(s.pipMock.ResetCalls(context.Background()), "clear the pip-mock call log")
	}
}

// recordCasePIPCalls compares what route received since resetCallsFor cleared
// the log with the pip-call golden subCase. An empty route records nothing.
func (s *ParitySuite) recordCasePIPCalls(subCase, route string) {
	if route == "" {
		return
	}
	outcome := s.pipCallOutcome(route)
	s.Run("the-pip-calls", func() {
		s.requirePendingGolden(PSUITE_PIP_CALL, subCase, outcome)
	})
}

// requireRoutesRead fails the test when a route of routes received no call
// since resetCallsFor cleared the log. It records no golden. The runners call it
// after a case's requests, so a case whose upload was refused skips it.
func (s *ParitySuite) requireRoutesRead(routes []string) {
	if len(routes) == 0 {
		return
	}
	s.Run("the-pips-were-read", func() {
		calls, err := s.pipMock.GetCalls(context.Background())
		s.Require().NoError(err, "read the pip-mock call log")
		read := map[string]int{}
		for _, call := range calls {
			read[call.Path]++
		}
		for _, route := range routes {
			s.Assert().Positive(read[route], "pip-mock calls to %s", route)
		}
	})
}

// sendCustomizationCleanup sends each of calls and never fails the test. It
// logs a call that could not be sent or that the PAP answered with 5xx. A 4xx
// answer is not logged: before the upload the customization usually does not
// exist, and a refused delete of it is expected.
func (s *ParitySuite) sendCustomizationCleanup(calls iter.Seq2[int, papCall]) {
	ctx := context.Background()
	m2m := s.mustM2MToken()
	for _, call := range calls {
		status, _, err := HelperPAPCall(ctx, s.cfg, m2m, call)
		if err != nil {
			s.T().Logf("%s %s: %v", call.method, call.path, err)
		} else if status >= http.StatusInternalServerError {
			s.T().Logf("%s %s: status %d", call.method, call.path, status)
		}
	}
}

// regularExternalIDs lists the externalIDs the cases upload under, each once, in
// the order of their first upload.
func regularExternalIDs(cases []regularCase) []string {
	var ids []string
	seen := map[string]struct{}{}
	for _, tc := range cases {
		for _, upload := range tc.uploads {
			if _, dup := seen[upload.externalID]; dup {
				continue
			}
			seen[upload.externalID] = struct{}{}
			ids = append(ids, upload.externalID)
		}
	}
	return ids
}

func regularPolicySetCases() []regularCase {
	var cases []regularCase

	// One case per combining algorithm name, used at both the set and the policy
	// level. Each operation meets a different mix of rules: READ an ALLOW before a
	// DENY, UPDATE a DENY before an ALLOW, DELETE a DENY alone, CREATE no rule,
	// APPROVE an ALLOW whose condition reads a missing attribute beside an ALLOW,
	// REJECT such a DENY beside an ALLOW. The absent and unknown names record what
	// the PAP does without a valid algorithm.
	for _, algorithm := range []struct{ key, name string }{
		{"deny-unless-permit", "DENY_UNLESS_PERMIT"},
		{"permit-unless-deny", "PERMIT_UNLESS_DENY"},
		{"deny-overrides", "DENY_OVERRIDES"},
		{"permit-overrides", "PERMIT_OVERRIDES"},
		{"first-applicable", "FIRST_APPLICABLE"},
		{"only-one-applicable", "ONLY_ONE_APPLICABLE"},
		{"ordered-deny-overrides", "ORDERED_DENY_OVERRIDES"},
		{"ordered-permit-overrides", "ORDERED_PERMIT_OVERRIDES"},
		{"absent", ""},
		{"unknown", "PARITY_NO_SUCH_ALGORITHM"},
	} {
		id := "algorithm-" + algorithm.key
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", algorithm.name, []any{
					b.policy("reader", readerTarget, algorithm.name,
						b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil),
						b.rule("read-deny", "operation == 'READ'", "true", "DENY", nil),
						b.rule("update-deny", "operation == 'UPDATE'", "true", "DENY", nil),
						b.rule("update-allow", "operation == 'UPDATE'", "true", "ALLOW", nil),
						b.rule("delete-deny", "operation == 'DELETE'", "true", "DENY", nil),
						b.rule("approve-allow-missing-attribute", "operation == 'APPROVE'", "resource.x == 'v'", "ALLOW", nil),
						b.rule("approve-allow", "operation == 'APPROVE'", "true", "ALLOW", nil),
						b.rule("reject-deny-missing-attribute", "operation == 'REJECT'", "resource.x == 'v'", "DENY", nil),
						b.rule("reject-allow", "operation == 'REJECT'", "true", "ALLOW", nil),
					),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "read-allow-then-deny", operation: "READ", resource: map[string]any{"id": "reg-alg"}},
				{name: "update-deny-then-allow", operation: "UPDATE", resource: map[string]any{"id": "reg-alg"}},
				{name: "delete-deny-alone", operation: "DELETE", resource: map[string]any{"id": "reg-alg"}},
				{name: "create-no-rule", operation: "CREATE", resource: map[string]any{"id": "reg-alg"}},
				{name: "approve-failed-allow-beside-allow", operation: "APPROVE", resource: map[string]any{"id": "reg-alg"}},
				{name: "reject-failed-deny-beside-allow", operation: "REJECT", resource: map[string]any{"id": "reg-alg"}},
			},
		})
	}

	// A DENY in the outer set against an ALLOW in a nested set, under two outer
	// algorithms.
	for _, outer := range []struct{ key, name string }{
		{"permit-overrides", "PERMIT_OVERRIDES"},
		{"deny-unless-permit", "DENY_UNLESS_PERMIT"},
	} {
		id := "nested-outer-deny-inner-allow-" + outer.key
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		rtTarget := "resourceType == '" + rt + "'"
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("outer", rtTarget, outer.name,
					[]any{b.policy("outer-reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("outer-read-deny", "operation == 'READ'", "true", "DENY", nil))},
					[]any{b.set("inner", rtTarget, "DENY_UNLESS_PERMIT",
						[]any{b.policy("inner-reader", readerTarget, "DENY_UNLESS_PERMIT",
							b.rule("inner-read-allow", "operation == 'READ'", "true", "ALLOW", nil))},
						nil)}),
			}}},
			requests: []isolatedRequest{{name: "read", resource: map[string]any{"id": "reg-nested"}}},
		})
	}

	// A missing attribute in the target of a set, a policy, or a rule, beside a
	// sibling at the same level that allows when resource.s is 'y'. The set case
	// builds both policies from the key reader, so they carry one policyId, and
	// the recorded 400 is as likely the shared id as the target;
	// TestRound7SetTargetRefusalCases separates the two, and the fixture stays
	// as recorded.
	{
		id := "missing-attribute-in-set-target"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("reads-missing", "resourceType == '"+rt+"' AND resource.x == 'v'", "DENY_UNLESS_PERMIT",
					[]any{b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil))}, nil),
				b.set("sibling", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT",
					[]any{b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("read-allow-when-s", "operation == 'READ'", "resource.s == 'y'", "ALLOW", nil))}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "sibling-allows", resource: map[string]any{"id": "reg-set-target", "s": "y"}},
				{name: "both-attributes-present", resource: map[string]any{"id": "reg-set-target", "x": "v", "s": "n"}},
			},
		})
	}
	{
		id := "missing-attribute-in-policy-target"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reads-missing", readerTarget+" AND resource.x == 'v'", "DENY_UNLESS_PERMIT",
						b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil)),
					b.policy("sibling", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("read-allow-when-s", "operation == 'READ'", "resource.s == 'y'", "ALLOW", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{{name: "sibling-allows", resource: map[string]any{"id": "reg-policy-target", "s": "y"}}},
		})
	}
	{
		id := "missing-attribute-in-rule-target"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("reads-missing", "operation == 'READ' AND resource.x == 'v'", "true", "ALLOW", nil),
						b.rule("sibling", "operation == 'READ'", "resource.s == 'y'", "ALLOW", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{{name: "sibling-allows", resource: map[string]any{"id": "reg-rule-target", "s": "y"}}},
		})
	}

	// A DENY rule whose target is false against one whose condition is false, under
	// PERMIT_UNLESS_DENY: whether the two count as not applicable alike.
	{
		id := "deny-target-false-against-condition-false"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "PERMIT_UNLESS_DENY", []any{
					b.policy("reader", readerTarget, "PERMIT_UNLESS_DENY",
						b.rule("read-deny-condition", "operation == 'READ'", "resource.flag == 'on'", "DENY", nil),
						b.rule("update-deny-target", "operation == 'UPDATE' AND resource.flag == 'on'", "true", "DENY", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "read-condition-false", operation: "READ", resource: map[string]any{"id": "reg-tc", "flag": "off"}},
				{name: "update-target-false", operation: "UPDATE", resource: map[string]any{"id": "reg-tc", "flag": "off"}},
			},
		})
	}

	// Two PERMIT_UNLESS_DENY policies with deny lists of their own under one
	// DENY_UNLESS_PERMIT set. Product policies ship that shape for a service whose
	// endpoints are open except for a few, and split the exceptions over two
	// policies. Each policy permits whatever its own list does not deny, so a set
	// that takes the permit of either one lets the second policy cancel the first
	// policy's denial. The alpha and beta requests record that; shared, denied by
	// both lists, and open, denied by neither, fix the other two columns.
	{
		id := "two-deny-lists-in-one-set"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("denies-alpha", readerTarget, "PERMIT_UNLESS_DENY",
						b.rule("alpha", "operation == 'READ'", "resource.area == 'alpha'", "DENY", nil),
						b.rule("alpha-shared", "operation == 'READ'", "resource.area == 'shared'", "DENY", nil)),
					b.policy("denies-beta", readerTarget, "PERMIT_UNLESS_DENY",
						b.rule("beta", "operation == 'READ'", "resource.area == 'beta'", "DENY", nil),
						b.rule("beta-shared", "operation == 'READ'", "resource.area == 'shared'", "DENY", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "denied-by-the-alpha-list", resource: map[string]any{"id": "reg-two-lists", "area": "alpha"}},
				{name: "denied-by-the-beta-list", resource: map[string]any{"id": "reg-two-lists", "area": "beta"}},
				{name: "denied-by-both-lists", resource: map[string]any{"id": "reg-two-lists", "area": "shared"}},
				{name: "denied-by-neither-list", resource: map[string]any{"id": "reg-two-lists", "area": "open"}},
			},
		})
	}

	// The control for two-deny-lists-in-one-set: the same deny list in one policy.
	// Here alpha meets a single PERMIT_UNLESS_DENY verdict with nothing to combine
	// it with, so a request the two-policy case answers differently is answered by
	// the set level rather than by the rules.
	{
		id := "one-deny-list-in-one-set"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("denies-both", readerTarget, "PERMIT_UNLESS_DENY",
						b.rule("alpha", "operation == 'READ'", "resource.area == 'alpha'", "DENY", nil),
						b.rule("beta", "operation == 'READ'", "resource.area == 'beta'", "DENY", nil),
						b.rule("shared", "operation == 'READ'", "resource.area == 'shared'", "DENY", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "denied-by-the-single-list", resource: map[string]any{"id": "reg-one-list", "area": "alpha"}},
				{name: "denied-by-no-entry", resource: map[string]any{"id": "reg-one-list", "area": "open"}},
			},
		})
	}

	// Policy and rule styles that simplified policies do not produce.
	{
		id := "permission-policy-target"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("permission", "subject.permissions CONTAINS 'parity_permission'", "DENY_UNLESS_PERMIT",
						b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{{name: "reader-without-permission", resource: map[string]any{"id": "reg-permission"}}},
		})
	}
	{
		id := "bare-resource-condition"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("show-element", "operation == 'SHOW'", "resource == 'parity:ui:element'", "ALLOW", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "matching-element", operation: "SHOW", resource: "parity:ui:element"},
				{name: "other-element", operation: "SHOW", resource: "parity:ui:other"},
			},
		})
	}
	{
		id := "method-name-operation"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("method", "operation == 'ParityController.getThing'", "true", "ALLOW", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "same-name", operation: "ParityController.getThing", resource: map[string]any{"id": "reg-method"}},
				{name: "other-case", operation: "paritycontroller.getthing", resource: map[string]any{"id": "reg-method"}},
			},
		})
	}

	// Filters: how predicates of several rules, of a DENY rule, of a rule whose
	// condition is false, of nested sets, and of a simplified policy beside a set
	// combine.
	allKinds := func(field string) map[string]string {
		return map[string]string{
			"predicate":        "${resourceType}." + field + ".eq(\"1\")",
			"rsqlPredicate":    field + "==1",
			"sqlPredicate":     field + "=1",
			"mongodbPredicate": "{ \"" + field + "\": 1 }",
		}
	}
	{
		id := "filter-two-allow-rules"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("first", "operation == 'LIST'", "true", "ALLOW", allKinds("a")),
						b.rule("second", "operation == 'LIST'", "true", "ALLOW", allKinds("b"))),
				}, nil),
			}}},
			requests: []isolatedRequest{{name: "filter", filter: true}},
		})
	}
	{
		id := "filter-allow-and-deny-rules"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("allow", "operation == 'LIST'", "true", "ALLOW", map[string]string{"rsqlPredicate": "a==1"}),
						b.rule("deny", "operation == 'LIST'", "true", "DENY", map[string]string{"rsqlPredicate": "b==2"})),
				}, nil),
			}}},
			requests: []isolatedRequest{{name: "filter", filter: true}},
		})
	}
	{
		id := "filter-allow-rule-condition-false"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("condition-false", "operation == 'LIST'", "false", "ALLOW", map[string]string{"rsqlPredicate": "a==1"}),
						b.rule("condition-true", "operation == 'LIST'", "true", "ALLOW", map[string]string{"rsqlPredicate": "b==2"})),
				}, nil),
			}}},
			requests: []isolatedRequest{{name: "filter", filter: true}},
		})
	}
	{
		id := "filter-nested-sets"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		rtTarget := "resourceType == '" + rt + "'"
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("outer", rtTarget, "DENY_UNLESS_PERMIT",
					[]any{b.policy("outer-reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("outer-list", "operation == 'LIST'", "true", "ALLOW", map[string]string{"rsqlPredicate": "outer==1"}))},
					[]any{b.set("inner", rtTarget, "DENY_UNLESS_PERMIT",
						[]any{b.policy("inner-reader", readerTarget, "DENY_UNLESS_PERMIT",
							b.rule("inner-list", "operation == 'LIST'", "true", "ALLOW", map[string]string{"rsqlPredicate": "inner==1"}))},
						nil)}),
			}}},
			requests: []isolatedRequest{{name: "filter", filter: true}},
		})
	}
	{
		id := "filter-set-beside-simplified-policy"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			simplified: []any{map[string]any{
				"component":             "PARITY",
				"reason":                id,
				"resourceType":          rt,
				"operation":             "LIST",
				"rsqlPredicate":         "simplified==1",
				"roles":                 []string{"ROLE_PARITY_READER"},
				"applicableForFrontend": false,
				"id":                    b.id("simplified"),
			}},
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("list", "operation == 'LIST'", "true", "ALLOW", map[string]string{"rsqlPredicate": "regular==1"})),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "filter", filter: true},
				{name: "check-list", operation: "LIST", resource: map[string]any{"id": "reg-mixed"}},
			},
		})
	}

	// Lifecycle: an inactive set, a second upload under the same externalID, and two
	// externalIDs for one resource type.
	{
		id := "inactive-set"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		set := b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
			b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
				b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil)),
		}, nil)
		set["status"] = "INACTIVE"
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads:      []regularUpload{{externalID: "parity-" + id, sets: []any{set}}},
			requests:     []isolatedRequest{{name: "read", resource: map[string]any{"id": "reg-inactive"}}},
		})
	}
	{
		id := "reupload-replaces-sets"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		rtTarget := "resourceType == '" + rt + "'"
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{
				{externalID: "parity-" + id, sets: []any{
					b.set("set", rtTarget, "DENY_UNLESS_PERMIT", []any{
						b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
							b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil)),
					}, nil),
				}},
				{externalID: "parity-" + id, sets: []any{
					b.set("set", rtTarget, "DENY_UNLESS_PERMIT", []any{
						b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
							b.rule("update-allow", "operation == 'UPDATE'", "true", "ALLOW", nil)),
					}, nil),
				}},
			},
			requests: []isolatedRequest{
				{name: "read-from-first-upload", operation: "READ", resource: map[string]any{"id": "reg-reupload"}},
				{name: "update-from-second-upload", operation: "UPDATE", resource: map[string]any{"id": "reg-reupload"}},
			},
		})
	}
	{
		id := "two-external-ids-allow-and-deny"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		rtTarget := "resourceType == '" + rt + "'"
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{
				{externalID: "parity-" + id + "-allow", sets: []any{
					b.set("allow", rtTarget, "DENY_UNLESS_PERMIT", []any{
						b.policy("allow-reader", readerTarget, "DENY_UNLESS_PERMIT",
							b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil)),
					}, nil),
				}},
				{externalID: "parity-" + id + "-deny", sets: []any{
					b.set("deny", rtTarget, "DENY_UNLESS_PERMIT", []any{
						b.policy("deny-reader", readerTarget, "DENY_UNLESS_PERMIT",
							b.rule("read-deny", "operation == 'READ'", "true", "DENY", nil)),
					}, nil),
				}},
			},
			requests: []isolatedRequest{{name: "read", resource: map[string]any{"id": "reg-two-sets"}}},
		})
	}

	return cases
}
