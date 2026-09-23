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

	"authz-agent/test/parity/suite/model"
)

const (
	// failedPIPFilterBrokenRoute is the pip-mock path of the PIP that answers 500.
	failedPIPFilterBrokenRoute = "/api/v1/pip/r10-filter-broken"
	// failedPIPFilterLiveRoute is the pip-mock path of the PIP that answers v.
	failedPIPFilterLiveRoute = "/api/v1/pip/r10-filter-live"
)

// failedPIPFilterPIPs declares the two GENERAL PIPs of
// TestRound10FailedPIPFilterCases: the broken one, which the LIST rule reads,
// and the live one, which the UPDATE rule reads.
var failedPIPFilterPIPs = []any{
	map[string]any{
		"name": "subject.parityR10FilterBroken", "url": "http://pip-mock:8090" + failedPIPFilterBrokenRoute,
		"httpMethod": "POST", "pipType": "GENERAL", "requestAttributes": map[string]string{"case": "r10-filter"}, "cacheable": false,
	},
	map[string]any{
		"name": "subject.parityR10FilterLive", "url": "http://pip-mock:8090" + failedPIPFilterLiveRoute,
		"httpMethod": "POST", "pipType": "GENERAL", "requestAttributes": map[string]string{"case": "r10-filter"}, "cacheable": false,
		"type": "JSON", "jsonPath": "$.value",
	},
}

// failedPIPFilterRequests are the requests of every case of
// TestRound10FailedPIPFilterCases. The LIST requests reach the rule that reads
// the failed PIP; the UPDATE requests reach its twin, which reads the live one.
var failedPIPFilterRequests = []isolatedRequest{
	{name: "filter-list", filter: true, operation: "LIST"},
	{name: "check-list", operation: "LIST", resource: map[string]any{"id": "r10-failed-pip-filter"}},
	{name: "filter-update", filter: true, operation: "UPDATE"},
	{name: "check-update", operation: "UPDATE", resource: map[string]any{"id": "r10-failed-pip-filter"}},
}

// failedPIPFilterCase is one policy of TestRound10FailedPIPFilterCases under a
// DENY_UNLESS_PERMIT set: on LIST, a rule with the given effect and no predicate
// whose condition reads the failed PIP, beside an ALLOW with the predicate
// allowed==1; on UPDATE, the same pair with the live PIP.
func failedPIPFilterCase(id, algorithm, effect string) regularCase {
	tc := round9PolicyCase(id, algorithm, func(b regularBuilder) []any {
		return []any{
			b.rule("list-reads-the-failed-pip", "operation == 'LIST'", "subject.parityR10FilterBroken != 'x'", effect, nil),
			allowWithPredicate(b, "list-allow-with-a-predicate", "allowed==1"),
			b.rule("update-reads-the-live-pip", "operation == 'UPDATE'", "subject.parityR10FilterLive == 'v'", effect, nil),
			b.rule("update-allow-with-a-predicate", "operation == 'UPDATE'", "true", "ALLOW", map[string]string{"rsqlPredicate": "allowed==1"}),
		}
	})
	tc.requests = failedPIPFilterRequests
	return tc
}

// failedPIPFilterCases are the two policies of TestRound10FailedPIPFilterCases.
func failedPIPFilterCases() []regularCase {
	return []regularCase{
		failedPIPFilterCase("failed-pip-allow-without-predicate", "DENY_UNLESS_PERMIT", "ALLOW"),
		failedPIPFilterCase("failed-pip-deny-without-predicate", "DENY_OVERRIDES", "DENY"),
	}
}

// What check/filter answers when a rule without a predicate reads a GENERAL PIP
// that answered 500, beside a rule whose predicate is allowed==1. A failed PIP
// that the evaluation reached makes check/resource false for the whole request
// (failed-pip-scope), and a placeholder of a failed PIP in a predicate denies the
// whole filter (p8, substitution-general-failed); a failed PIP in the condition
// of a rule without a predicate is recorded in no filter. The agent's converter
// accepts every set here.
//
// failed-pip-allow-without-predicate puts an ALLOW reading the PIP in a
// DENY_UNLESS_PERMIT policy; failed-pip-deny-without-predicate puts a DENY
// reading it in a DENY_OVERRIDES policy, where the same DENY with a true
// condition denies the filter (deny-without-predicate-true-beside-a-predicate-under-deny-overrides).
// The answer may be DENY, as for a failed placeholder, or the neighbor's
// predicate, as for a rule that is left out. On UPDATE the same rule reads a PIP
// that answers v, the control that the pair gives the recorded answer when the
// PIP resolves.
//
// Whether the rule reading the PIP is evaluated can depend on the order in which
// the stand evaluates the rules of the policy, which the stand does not define,
// so every LIST request is classed by whether pip-mock saw a call to the failed
// PIP's route while it ran, and recorded under -when-the-pip-was-read or
// -when-the-pip-was-skipped. A stand keeps one order across uploads, so one run
// records one class; the other class is recorded by a stand with the other
// order. The UPDATE requests have to reach the live PIP.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case.
func (s *ParitySuite) TestRound10FailedPIPFilterCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("regular policy sets are evaluated by access-control only; authz-agent loads simplified policies")
	}
	ctx := context.Background()
	m2m := s.mustM2MToken()
	cases := failedPIPFilterCases()
	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s: %v", isolatedCaseDomain, err)
		}
	})
	status, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, failedPIPFilterPIPs, nil)
	s.Require().NoError(err)
	s.Run("declare-the-pips", func() {
		s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "failed-pip-filter/declare-the-pips", &model.PolicyLoadOutcome{Status: status})
	})
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return
	}
	s.Require().NoError(s.pipMock.PinRoute(ctx, failedPIPFilterBrokenRoute, PipStubResponse{
		StatusCode: http.StatusInternalServerError,
		Body:       map[string]string{"error": "parity failed-pip filter case"},
	}))
	s.Require().NoError(s.pipMock.PinRoute(ctx, failedPIPFilterLiveRoute, PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       map[string]string{"value": "v"},
	}))
	s.emptyPolicySetsOnCleanup(s.cfg, regularExternalIDs(cases)...)
	for _, tc := range cases {
		s.Run(tc.id, func() {
			upload := tc.uploads[0]
			uploadStatus, _, err := HelperPutPolicySets(ctx, s.cfg, m2m, upload.externalID, upload.sets)
			s.Require().NoError(err)
			s.Run("upload-1", func() {
				s.requirePendingGolden(PSUITE_LOAD_POLICY_SETS, "regular/"+tc.id+"/upload-1", &model.PolicyLoadOutcome{Status: uploadStatus})
			})
			if uploadStatus < http.StatusOK || uploadStatus >= http.StatusMultipleChoices {
				return
			}
			for _, req := range tc.requests {
				s.Run(req.name, func() {
					s.Require().NoError(s.pipMock.ResetCalls(ctx))
					id, outcome := s.sendRegularRequest(tc.resourceType, req)
					broken, live := s.pipCalls(failedPIPFilterBrokenRoute), s.pipCalls(failedPIPFilterLiveRoute)
					s.T().Logf("%s/%s: pip-mock received %d call(s) to %s and %d to %s",
						tc.id, req.name, broken, failedPIPFilterBrokenRoute, live, failedPIPFilterLiveRoute)
					subCase := "regular/" + tc.id + "/" + req.name
					if req.operation == "UPDATE" {
						s.Assert().Positive(live, "pip-mock calls to %s over %s", failedPIPFilterLiveRoute, subCase)
					} else if broken > 0 {
						subCase += "-when-the-pip-was-read"
					} else {
						subCase += "-when-the-pip-was-skipped"
					}
					s.requirePendingGolden(id, subCase, outcome)
				})
			}
		})
	}
}
