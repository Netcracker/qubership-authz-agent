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
	"net/http"

	"authz-agent/test/parity/suite/model"
)

// failedPIPScopeUploads is how many times each failed-PIP scope case uploads its
// sets and sends its request. The case assumes that the stand orders the children
// of a node afresh on every upload, as it was seen to do between stands, so that
// some uploads reach the failed PIP and some end at the allowing neighbor first;
// eight uploads leave each outcome unseen in under one run in a hundred if the
// order is even. A stand that keeps one order across uploads fills one class only,
// and the other class's skip says so.
const failedPIPScopeUploads = 8

// failedPIPScopeShapes are the two levels at which a node reading a failed PIP
// can sit beside a node that allows: two policies of one set, and two sets of
// one upload. Each shape reads a PIP of its own.
var failedPIPScopeShapes = []struct {
	key, pip, route string
	// sets builds the upload of the shape: rt is its resource type and pip the
	// name of the PIP its reading rule compares.
	sets func(b regularBuilder, rt, pip string) []any
}{
	{"policy", "subject.parityScopeBrokenPolicy", "/api/v1/pip/scope-broken-policy",
		func(b regularBuilder, rt, pip string) []any {
			return []any{b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
				failedPIPScopePolicy(b, "reads-the-pip", pip),
				failedPIPScopePolicy(b, "allows", ""),
			}, nil)}
		}},
	{"set", "subject.parityScopeBrokenSet", "/api/v1/pip/scope-broken-set",
		func(b regularBuilder, rt, pip string) []any {
			return []any{
				b.set("reads-the-pip", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT",
					[]any{failedPIPScopePolicy(b, "reads-the-pip", pip)}, nil),
				b.set("allows", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT",
					[]any{failedPIPScopePolicy(b, "allows", "")}, nil),
			}
		}},
}

// failedPIPScopePolicy is a DENY_UNLESS_PERMIT policy with one ALLOW rule on
// READ. With pip set the rule's condition reads that PIP; with pip empty the rule
// is unconditional.
func failedPIPScopePolicy(b regularBuilder, key, pip string) map[string]any {
	condition := "true"
	if pip != "" {
		condition = pip + " != 'x'"
	}
	return b.policy(key, readerTarget, "DENY_UNLESS_PERMIT",
		b.rule(key+"-read-allow", "operation == 'READ'", condition, "ALLOW", nil))
}

// How far the abort of a GENERAL PIP that answered 500 reaches when the node
// reading it has a neighbor that allows unconditionally. failed-pip-beside-allow-*
// records that inside one policy the failure decides against the request under
// PERMIT_UNLESS_DENY and DENY_OVERRIDES, so the failure is not a rule made
// inapplicable; whether it is a deny of that node, which a permitting neighbor
// under DENY_UNLESS_PERMIT outweighs, or a refusal of the whole request, only a
// neighbor at the level above can show. Both shapes put the reading node under
// DENY_UNLESS_PERMIT, where a permit is terminal: when the allowing neighbor is
// evaluated first the PIP is never read and the request is allowed, and when the
// reading node is evaluated first the PIP is read and the answer is the one the
// case is after. Which comes first is the stand's, so each case uploads its sets
// failedPIPScopeUploads times, sends its request after each, and reads the
// pip-mock call log in between; see failedPIPScopeUploads for the assumption
// behind the repetition. A PIP declared cacheable false is read on every request
// (pip-cache-cacheable-false), so a call count of zero is a skip, not a cache hit.
//
// Two goldens per case, each the answer shared by every upload of its class:
// read-when-the-pip-was-read, the uploads whose request pip-mock saw a call
// from, and read-when-the-pip-was-skipped, the control, the uploads it saw
// none from. The answers of one class have to agree before the first is
// recorded. A class no upload fell into is skipped with both counts, and the
// other class is still recorded: a stand that keeps one order across uploads
// records the half it can show and reports the half it cannot. Legacy profile
// only, like every regular case.
func (s *ParitySuite) TestRound8FailedPIPScopeCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("regular policy sets are evaluated by access-control only; authz-agent loads simplified policies")
	}
	ctx := context.Background()
	m2m := s.mustM2MToken()
	cases := failedPIPScopeCases()
	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s: %v", isolatedCaseDomain, err)
		}
	})
	var declarations []any
	for _, tc := range cases {
		declarations = append(declarations, tc.pips...)
	}
	status, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, declarations, nil)
	s.Require().NoError(err)
	s.Run("declare-the-pips", func() {
		s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "failed-pip-scope/declare-the-pips", &model.PolicyLoadOutcome{Status: status})
	})
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return
	}
	s.emptyPolicySetsOnCleanup(s.cfg, regularExternalIDs(cases)...)
	for _, shape := range failedPIPScopeShapes {
		tc := failedPIPScopeCase(shape.key, shape.pip, shape.sets)
		s.Run(tc.id, func() {
			s.Require().NoError(s.pipMock.PinRoute(ctx, shape.route, PipStubResponse{
				StatusCode: http.StatusInternalServerError,
				Body:       map[string]string{"error": "parity failed-pip scope case"},
			}))
			upload := tc.uploads[0]
			// byClass collects the outcome of every upload whose request read the PIP
			// (true) or skipped it (false).
			byClass := map[bool][]model.CheckResourceOutcome{}
			for attempt := 1; attempt <= failedPIPScopeUploads; attempt++ {
				uploadStatus, _, err := HelperPutPolicySets(ctx, s.cfg, m2m, upload.externalID, upload.sets)
				s.Require().NoError(err)
				if attempt == 1 {
					s.Run("upload-1", func() {
						s.requirePendingGolden(PSUITE_LOAD_POLICY_SETS, "regular/"+tc.id+"/upload-1", &model.PolicyLoadOutcome{Status: uploadStatus})
					})
				}
				if uploadStatus < http.StatusOK || uploadStatus >= http.StatusMultipleChoices {
					return
				}
				s.Require().NoError(s.pipMock.ResetCalls(ctx))
				checkStatus, decision, _, err := HelperCheckResourceV1(ctx, s.cfg,
					model.CheckAccessRequest{Operation: "READ", Type: tc.resourceType, Resource: tc.requests[0].resource},
					s.mustTokenBundle(UserProfileReader), PerCallOptions{})
				s.Require().NoError(err)
				calls, err := s.pipMock.GetCalls(ctx)
				s.Require().NoError(err)
				read := 0
				for _, call := range calls {
					if call.Path == shape.route {
						read++
					}
				}
				s.T().Logf("upload %d of %s: pip-mock received %d call(s) to %s, status %d, decision %t",
					attempt, tc.id, read, shape.route, checkStatus, decision)
				byClass[read > 0] = append(byClass[read > 0], model.CheckResourceOutcome{Status: checkStatus, Decision: decision})
			}
			for _, class := range []struct {
				name string
				read bool
			}{
				{"read-when-the-pip-was-read", true},
				{"read-when-the-pip-was-skipped", false},
			} {
				s.Run(class.name, func() {
					outcomes := byClass[class.read]
					if len(outcomes) == 0 {
						s.T().Skipf("pip-mock saw a call to %s from %d of the %d uploads of %s and none from %d; no upload in the class of this golden, "+
							"so the stand may keep one order across uploads: rerun the case on another stand",
							shape.route, len(byClass[true]), failedPIPScopeUploads, tc.id, len(byClass[false]))
					}
					for _, outcome := range outcomes[1:] {
						s.Require().Equal(outcomes[0], outcome, "outcomes of the %d uploads of %s whose request %s the PIP: %v",
							len(outcomes), tc.id, map[bool]string{true: "read", false: "skipped"}[class.read], outcomes)
					}
					s.requirePendingGolden(PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, "regular/"+tc.id+"/"+class.name, &outcomes[0])
				})
			}
		})
	}
}

// failedPIPScopeCases builds the regular case of every shape of
// failedPIPScopeShapes, for TestRegularCaseElementIDsAreUnique.
func failedPIPScopeCases() []regularCase {
	var cases []regularCase
	for _, shape := range failedPIPScopeShapes {
		cases = append(cases, failedPIPScopeCase(shape.key, shape.pip, shape.sets))
	}
	return cases
}

// failedPIPScopeCase builds the regular case of one shape: the declaration of
// its PIP, its one upload, and the one request TestRound8FailedPIPScopeCases
// sends after every upload, which runRegularCases would send once.
func failedPIPScopeCase(key, pip string, sets func(b regularBuilder, rt, pip string) []any) regularCase {
	id := fmt.Sprintf("failed-pip-%s-beside-an-allowing-%s", key, key)
	b := regularBuilder{caseID: id}
	rt := regularResourceType(id)
	return regularCase{
		id:           id,
		resourceType: rt,
		pips: []any{map[string]any{
			"name":              pip,
			"url":               parityPipMockBase + "/scope-broken-" + key,
			"httpMethod":        "POST",
			"pipType":           "GENERAL",
			"requestAttributes": map[string]string{"resourceType": rt},
			"cacheable":         false,
		}},
		uploads:  []regularUpload{{externalID: "parity-" + id, sets: sets(b, rt, pip)}},
		requests: []isolatedRequest{{name: "read", operation: "READ", resource: map[string]any{"id": "reg-failed-pip-scope"}}},
	}
}
