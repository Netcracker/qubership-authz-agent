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
	"time"

	"authz-agent/test/parity/suite/model"
)

// iteratePermitOverridesExternalID is the externalID the two iterating sets of
// TestRound7IteratePermitOverridesCases are uploaded under.
const iteratePermitOverridesExternalID = "parity-scope-iterate-permit-overrides"

// iteratePermitOverridesPolicies are the two policy shapes each put under a
// PERMIT_OVERRIDES iterating set, keyed by the resource type suffix of their
// set. Each is a policy whose pass over a grant of another region denies, so
// under two grants the region of either grant meets a permitting pass and a
// denying pass.
var iteratePermitOverridesPolicies = []struct {
	key string
	// policy builds the policy of the set for the case id b was built from.
	policy func(b regularBuilder) map[string]any
}{
	// A DENY_UNLESS_PERMIT policy holding one ALLOW rule, region granted: the
	// pass over the grant of another region has no rule that permits and denies
	// by default.
	{"allow-when-granted", func(b regularBuilder) map[string]any {
		return b.policy("scoped", readerTarget, "DENY_UNLESS_PERMIT",
			b.rule("region-granted", "operation == 'READ'",
				"subject.permissionScope.region CONTAINS resource.region", "ALLOW", nil))
	}},
	// The policy of scope-iterate with DENY_OVERRIDES in place of the set's own
	// algorithm: a DENY rule, region not granted, beside an ALLOW rule with no
	// condition, so the pass over the grant of another region denies through
	// the DENY rule.
	{"deny-beside-allow", func(b regularBuilder) map[string]any {
		return b.policy("scoped", readerTarget, "DENY_OVERRIDES",
			b.rule("region-not-granted", "operation == 'READ'",
				"subject.permissionScope.region NOT CONTAINS resource.region", "DENY", nil),
			b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil))
	}},
}

// iteratePermitOverridesResourceType is the resource type of the iterating set
// built for one policy shape.
func iteratePermitOverridesResourceType(key string) string {
	return regularResourceType("scope-iterate-permit-overrides-" + key)
}

// How a PERMIT_OVERRIDES iterating set combines a pass that permits with a pass
// that denies. scope-iterate records the set under PERMIT_OVERRIDES with a
// PERMIT_OVERRIDES policy holding a DENY rule beside an unconditional ALLOW, and
// there every pass permits on its own, since the policy's ALLOW overrides its
// DENY, so the recorded answers are true whatever the set does with the
// passes. Here the policy is one whose pass over a grant of another region
// denies, in the two shapes of iteratePermitOverridesPolicies, under the same
// grants and requests as scope-iterate: under two grants the region of either
// grant is true when one permitting pass permits the set and false when a
// denying pass is taken instead, region-of-no-grant is denied by every pass
// and is the control, one grant has nothing to combine, and no grant records
// what PERMIT_OVERRIDES answers over zero passes. The PIP, the wire body, and
// the cache wait are permission-scope-wire's, and the pip-mock call log is read
// after every shape.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only.
func (s *ParitySuite) TestRound7IteratePermitOverridesCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("iterate is a regular policy set field; the agent loads simplified policies")
	}
	ctx := context.Background()
	m2m := s.mustM2MToken()
	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s: %v", isolatedCaseDomain, err)
		}
	})

	var sets []any
	for _, shape := range iteratePermitOverridesPolicies {
		b := regularBuilder{caseID: "scope-iterate-permit-overrides-" + shape.key}
		rt := iteratePermitOverridesResourceType(shape.key)
		sets = append(sets, b.iteratingSet("set", "resourceType == '"+rt+"'", "PERMIT_OVERRIDES",
			"subject.permissionScope", []any{shape.policy(b)}))
	}

	pipStatus, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, []any{permissionScopeWirePIP}, nil)
	s.Require().NoError(err)
	s.Run("declare-the-pip", func() {
		s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "scope-iterate-permit-overrides/declare-the-pip", &model.PolicyLoadOutcome{Status: pipStatus})
	})
	if pipStatus < http.StatusOK || pipStatus >= http.StatusMultipleChoices {
		return
	}

	s.emptyPolicySetsOnCleanup(s.cfg, iteratePermitOverridesExternalID)
	setStatus, _, err := HelperPutPolicySets(ctx, s.cfg, m2m, iteratePermitOverridesExternalID, sets)
	s.Require().NoError(err)
	s.Run("upload-the-sets", func() {
		s.requirePendingGolden(PSUITE_LOAD_POLICY_SETS, "scope-iterate-permit-overrides/upload-the-sets", &model.PolicyLoadOutcome{Status: setStatus})
	})
	if setStatus < http.StatusOK || setStatus >= http.StatusMultipleChoices {
		return
	}

	scopePath := permissionScopeWirePath(parityReaderSubjectID)
	for _, grants := range iterateAlgorithmGrants {
		// Outlive the cachePeriod of the declaration, as permission-scope-wire does,
		// so the body pinned next is the one the next request sees.
		time.Sleep(2 * time.Second)
		s.Run(grants.name, func() {
			s.Require().NoError(s.pipMock.ResetCalls(ctx))
			s.Require().NoError(s.pipMock.PinRoute(ctx, scopePath, PipStubResponse{
				StatusCode: http.StatusOK,
				Body:       permissionScopeWireBody(parityReaderSubjectID, grants.grants),
			}))
			for _, shape := range iteratePermitOverridesPolicies {
				for _, req := range iterateAlgorithmRequests {
					s.Run(shape.key+"/"+req.name, func() {
						s.runPendingCheckResourceV1OutcomeCase(
							"scope-iterate-permit-overrides/"+grants.name+"/"+shape.key+"/"+req.name,
							model.CheckAccessRequest{
								Operation: "READ",
								Type:      iteratePermitOverridesResourceType(shape.key),
								Resource:  req.resource,
							},
							s.mustTokenBundle(UserProfileReader),
							PerCallOptions{},
						)
					})
				}
			}
			s.Run("the-pip-was-read", func() {
				calls, err := s.pipMock.GetCalls(ctx)
				s.Require().NoError(err)
				read := 0
				for _, call := range calls {
					if call.Path == scopePath {
						read++
					}
				}
				s.Assert().Positive(read, "pip-mock calls to %s over the requests with the %s body pinned", scopePath, grants.name)
			})
		})
	}
}
