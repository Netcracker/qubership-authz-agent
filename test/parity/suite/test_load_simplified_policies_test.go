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

	"authz-agent/test/parity/suite/model"
)

// loadCaseDomain receives one policy per case and is emptied after each, so a
// refused or unparsable condition never reaches the domain the other cases use.
const loadCaseDomain = "PARITY_LOAD"

// Records whether access-control accepts a condition at upload time. The
// conditions outside AbacExpression.g4 (parentheses, a standalone NOT, a doubled
// space, a lowercase keyword) sit beside subject.isM2M and a permissionScope
// reference, which the grammar allows and no seeded policy uses, and a control.
// subject.isM2M does not parse in the agent, so none of these can join the seeded
// pack: one unparsable condition fails the whole upload.
//
// The authz-agent profile uploads to authz-policy-admin, which stores what it is
// given, so the status says nothing about the agent there and the cases skip.
func (s *ParitySuite) TestLoadSimplifiedPoliciesConditionSyntax() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("upload validation belongs to the PAP; authz-policy-admin stores policies without validating the condition")
	}
	cases := []struct{ subCase, condition string }{
		{"control-single-comparison", "resource.a == 'y'"},
		{"g4-parentheses", "(resource.a == 'y' OR resource.b == 'y') AND resource.c == 'y'"},
		{"g5-standalone-not", "NOT resource.a == 'y'"},
		{"g6a-doubled-space", "resource.a == 'y'  AND resource.c == 'y'"},
		{"g6b-lowercase-and", "resource.a == 'y' and resource.c == 'y'"},
		{"g8a-subject-is-m2m", "subject.isM2M"},
		{"g8b-permission-scope-is-null", "subject.permissionScope.region IS NULL"},
	}
	ctx := context.Background()
	m2m := s.mustM2MToken()
	for _, tc := range cases {
		s.Run(tc.subCase, func() {
			policy := map[string]any{
				"component":             "PARITY",
				"reason":                tc.subCase,
				"resourceType":          "PARITY_SUITE_LOAD",
				"operation":             "READ",
				"condition":             tc.condition,
				"roles":                 []string{"ROLE_PARITY_READER"},
				"applicableForFrontend": false,
				"id":                    "00000000-0000-0000-0000-0000000e0001",
			}
			status, _, err := HelperPutSimplifiedPolicies(ctx, s.cfg, m2m, loadCaseDomain, []any{policy})
			s.Require().NoError(err)
			s.T().Cleanup(func() {
				status, raw, err := HelperPutSimplifiedPolicies(ctx, s.cfg, m2m, loadCaseDomain, []any{})
				if err != nil || status < 200 || status >= 300 {
					s.T().Logf("empty domain %s: status=%d body=%s err=%v", loadCaseDomain, status, raw, err)
				}
			})

			s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "condition-syntax/"+tc.subCase, &model.PolicyLoadOutcome{Status: status})
		})
	}
}
