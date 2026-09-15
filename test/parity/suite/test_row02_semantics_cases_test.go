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

// The semantics cases ask access-control what a condition answers when an
// attribute it reads is missing, and in which order it evaluates OR and AND.
// Their goldens are recorded on a live access-control; until then each case
// skips and prints the answer it got. The case identifier prefixes (s1a, d3, …)
// follow the golden-capture case list kept outside this repository, and every
// policy is in testdata/fixtures/policies/suite/semantics-*.json.

// semanticsCase is one request against one PARITY_SUITE_SEM_* resource type.
type semanticsCase struct {
	subCase      string
	resourceType string
	resource     map[string]any
}

func (s *ParitySuite) runSemanticsCases(cases []semanticsCase) {
	for _, tc := range cases {
		s.Run(tc.subCase, func() {
			s.runPendingCheckResourceV1Case(
				"semantics/"+tc.subCase,
				model.CheckAccessRequest{Operation: "READ", Type: tc.resourceType, Resource: tc.resource},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1MissingResourceAttribute() {
	s.runSemanticsCases([]semanticsCase{
		{"s1a-eq-attribute-matches", "PARITY_SUITE_SEM_S1", map[string]any{"id": "sem-s1a", "x": "v"}},
		{"s1b-eq-attribute-absent", "PARITY_SUITE_SEM_S1", map[string]any{"id": "sem-s1b"}},
		{"s1c-eq-attribute-null", "PARITY_SUITE_SEM_S1", map[string]any{"id": "sem-s1c", "x": nil}},
		{"s2a-neq-attribute-differs", "PARITY_SUITE_SEM_S2", map[string]any{"id": "sem-s2a", "x": "w"}},
		{"s2b-neq-attribute-absent", "PARITY_SUITE_SEM_S2", map[string]any{"id": "sem-s2b"}},
		{"s2c-neq-attribute-null", "PARITY_SUITE_SEM_S2", map[string]any{"id": "sem-s2c", "x": nil}},
		{"s3-not-in-attribute-absent", "PARITY_SUITE_SEM_S3", map[string]any{"id": "sem-s3"}},
		{"s4-not-contains-attribute-absent", "PARITY_SUITE_SEM_S4", map[string]any{"id": "sem-s4"}},
		{"s5-greater-than-attribute-absent", "PARITY_SUITE_SEM_S5", map[string]any{"id": "sem-s5"}},
		{"s6a-is-null-attribute-absent", "PARITY_SUITE_SEM_S6", map[string]any{"id": "sem-s6a"}},
		{"s6b-is-null-attribute-null", "PARITY_SUITE_SEM_S6", map[string]any{"id": "sem-s6b", "x": nil}},
		{"s7-is-empty-attribute-absent", "PARITY_SUITE_SEM_S7", map[string]any{"id": "sem-s7"}},
	})
}

func (s *ParitySuite) TestRow02CheckResourceV1MissingAttributeUnderOr() {
	s.runSemanticsCases([]semanticsCase{
		{"s9-true-or-absent", "PARITY_SUITE_SEM_S9", map[string]any{"id": "sem-s9", "a": "y"}},
		{"s10-absent-or-true", "PARITY_SUITE_SEM_S10", map[string]any{"id": "sem-s10", "a": "y"}},
		{"s11-false-or-absent", "PARITY_SUITE_SEM_S11", map[string]any{"id": "sem-s11", "a": "y"}},
		{"s12a-guarded-chain-or-true", "PARITY_SUITE_SEM_S12", map[string]any{"id": "sem-s12a", "a": "y"}},
		{"s12b-guarded-chain-or-false", "PARITY_SUITE_SEM_S12", map[string]any{"id": "sem-s12b", "a": "n"}},
	})
}

// Each resource type carries two policies on the same (resourceType, operation):
// one reads the missing attribute x, the other allows on s == 'y'. Access-control
// evaluates policies on a role in no fixed order, so each request is sent
// siblingPolicyCalls times and the answers have to agree.
func (s *ParitySuite) TestRow02CheckResourceV1MissingAttributeBesideAllowingPolicy() {
	const siblingPolicyCalls = 20
	cases := []struct {
		subCase      string
		resourceType string
		profile      UserProfile
		resource     map[string]any
	}{
		{"d1-failing-policy-first", "PARITY_SUITE_SEM_D1", UserProfileReader, map[string]any{"id": "sem-d1", "s": "y"}},
		{"d2-allowing-policy-first", "PARITY_SUITE_SEM_D2", UserProfileReader, map[string]any{"id": "sem-d2", "s": "y"}},
		{"d3-false-and-absent", "PARITY_SUITE_SEM_D3", UserProfileReader, map[string]any{"id": "sem-d3", "a": "y", "s": "y"}},
		{"d4-policies-on-different-roles", "PARITY_SUITE_SEM_D4", UserProfileMultiRole, map[string]any{"id": "sem-d4", "s": "y"}},
	}
	for _, tc := range cases {
		s.Run(tc.subCase, func() {
			s.runRepeatedPendingCheckResourceV1Case(
				"semantics/"+tc.subCase,
				model.CheckAccessRequest{Operation: "READ", Type: tc.resourceType, Resource: tc.resource},
				s.mustTokenBundle(tc.profile),
				siblingPolicyCalls,
			)
		})
	}
}

// parityNoClaim and parityNoClaimDefault read a claim no parity user carries;
// parityBroken and parityEmptyJson are GENERAL PIPs pinned per case.
func (s *ParitySuite) TestRow02CheckResourceV1MissingPIPAttribute() {
	s.runSemanticsCases([]semanticsCase{
		{"p1a-token-pip-no-value-eq", "PARITY_SUITE_SEM_P1A", map[string]any{"id": "sem-p1a"}},
		{"p1b-token-pip-no-value-neq", "PARITY_SUITE_SEM_P1B", map[string]any{"id": "sem-p1b"}},
		{"p1c-token-pip-no-value-is-null", "PARITY_SUITE_SEM_P1C", map[string]any{"id": "sem-p1c"}},
		{"p2-token-pip-default-value", "PARITY_SUITE_SEM_P2", map[string]any{"id": "sem-p2"}},
	})
}

func (s *ParitySuite) TestRow02CheckResourceV1FailedGeneralPIP() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/sem-broken", PipStubResponse{
		StatusCode: http.StatusInternalServerError,
		Body:       map[string]any{"error": "parity semantics case"},
	})
	s.Require().NoError(err)

	s.runSemanticsCases([]semanticsCase{
		{"p3a-failed-pip-neq", "PARITY_SUITE_SEM_P3A", map[string]any{"id": "sem-p3a"}},
		{"p3c-failed-pip-or-true", "PARITY_SUITE_SEM_P3C", map[string]any{"id": "sem-p3c", "a": "y"}},
	})

	// P3b's left operand already decides the OR. Whether the PIP was still called
	// is logged before the comparison, since a pending golden ends the subtest.
	s.Run("p3b-true-or-failed-pip", func() {
		ctx := context.Background()
		s.Require().NoError(s.pipMock.ResetCalls(ctx))
		status, decision, _, err := HelperCheckResourceV1(ctx, s.cfg,
			model.CheckAccessRequest{Operation: "READ", Type: "PARITY_SUITE_SEM_P3B", Resource: map[string]any{"id": "sem-p3b", "a": "y"}},
			s.mustTokenBundle(UserProfileReader), PerCallOptions{})
		s.Require().NoError(err)
		s.Require().Equal(http.StatusOK, status)
		calls, err := s.pipMock.GetCalls(ctx)
		s.Require().NoError(err)
		brokenCalls := 0
		for _, call := range calls {
			if call.Path == "/api/v1/pip/sem-broken" {
				brokenCalls++
			}
		}
		s.T().Logf("/api/v1/pip/sem-broken received %d call(s) while deciding P3b", brokenCalls)
		s.requirePendingGolden(PSUITE_ROW_2_CHECK_RESOURCE_V1, "semantics/p3b-true-or-failed-pip", &decision)
	})
}

func (s *ParitySuite) TestRow02CheckResourceV1GeneralPIPJsonPathMatchesNothing() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/sem-empty-json", PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       map[string]any{},
	})
	s.Require().NoError(err)

	s.runSemanticsCases([]semanticsCase{
		{"p4-empty-json-pip-neq", "PARITY_SUITE_SEM_P4", map[string]any{"id": "sem-p4"}},
	})
}

// The PAP refuses parentheses and a standalone NOT (see
// TestLoadSimplifiedPoliciesConditionSyntax), so every condition is an OR of ANDs. G1 and G2 put a negated operator inside that AND, which the agent's
// parser encodes as a third level of nesting.
func (s *ParitySuite) TestRow02CheckResourceV1ExpressionShape() {
	s.runSemanticsCases([]semanticsCase{
		{"g1a-or-and-is-not-null-true", "PARITY_SUITE_SEM_G1", map[string]any{"id": "sem-g1a", "a": "n", "b": "z", "c": "y"}},
		{"g1b-or-and-is-not-null-absent", "PARITY_SUITE_SEM_G1", map[string]any{"id": "sem-g1b", "a": "n", "c": "y"}},
		{"g2-or-and-not-contains-true", "PARITY_SUITE_SEM_G2", map[string]any{"id": "sem-g2", "a": "n", "c": "y", "tags": []string{"blue"}}},
		{"g3a-precedence-left-true", "PARITY_SUITE_SEM_G3", map[string]any{"id": "sem-g3a", "a": "y", "b": "n", "c": "n"}},
		{"g3b-precedence-half-and-true", "PARITY_SUITE_SEM_G3", map[string]any{"id": "sem-g3b", "a": "n", "b": "y", "c": "n"}},
		{"g7a-ten-and-last-false", "PARITY_SUITE_SEM_G7A", map[string]any{
			"id": "sem-g7a", "a1": "y", "a2": "y", "a3": "y", "a4": "y", "a5": "y",
			"a6": "y", "a7": "y", "a8": "y", "a9": "y", "a10": "n",
		}},
		{"g7b-ten-or-last-true", "PARITY_SUITE_SEM_G7B", map[string]any{
			"id": "sem-g7b", "a1": "n", "a2": "n", "a3": "n", "a4": "n", "a5": "n",
			"a6": "n", "a7": "n", "a8": "n", "a9": "n", "a10": "y",
		}},
		{"g7c-four-and-groups-last-true", "PARITY_SUITE_SEM_G7C", map[string]any{
			"id": "sem-g7c",
			"a1": "y", "a2": "y", "a3": "y", "a4": "n",
			"b1": "n", "b2": "y", "b3": "y", "b4": "y",
			"c1": "y", "c2": "n", "c3": "y", "c4": "y",
			"d1": "y", "d2": "y", "d3": "y", "d4": "y",
		}},
	})
}
