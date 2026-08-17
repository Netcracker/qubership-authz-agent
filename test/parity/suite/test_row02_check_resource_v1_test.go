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

// Row 2 drives POST /access/v1/check/resource. Every sub-case below hits
// the Step 2 bespoke smoke fixture set:
//
//	PARITY_CUSTOMER READ   → OLS allow (ols-allow.json)
//	PARITY_CUSTOMER DELETE → OLS allow (ols-deny.json; DELETE is the only
//	                         allowed op so any other op (WRITE) denies)
//	PARITY_PAYMENT EXECUTE → RLS (general-pip.json) gated on
//	                         subject.parityAllowed (pinned per test)

func (s *ParitySuite) TestRow02CheckResourceV1AllowIncoming() {
	ctx := context.Background()

	m2m, err := s.tokens.M2MToken()
	s.Require().NoError(err)
	eu, err := s.tokens.EndUserToken(UserProfileReader)
	s.Require().NoError(err)

	status, decision, _, err := HelperCheckResourceV1(
		ctx, s.cfg,
		model.CheckAccessRequest{
			Operation: "READ",
			Type:      "PARITY_CUSTOMER",
			Resource:  map[string]any{"id": "row2-allow-incoming"},
		},
		TokenBundle{M2M: m2m, EndUser: eu},
		PerCallOptions{},
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)

	if err := s.comparator.Compare(PSUITE_ROW_2_CHECK_RESOURCE_V1, "allow-incoming", &decision); err != nil {
		s.T().Errorf("%v", err)
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1DenyIncoming() {
	ctx := context.Background()

	m2m, err := s.tokens.M2MToken()
	s.Require().NoError(err)
	eu, err := s.tokens.EndUserToken(UserProfileReader)
	s.Require().NoError(err)

	// WRITE is not granted on PARITY_CUSTOMER for ROLE_PARITY_READER; only
	// READ (ols-allow.json) and DELETE (ols-deny.json) are.
	status, decision, _, err := HelperCheckResourceV1(
		ctx, s.cfg,
		model.CheckAccessRequest{
			Operation: "WRITE",
			Type:      "PARITY_CUSTOMER",
			Resource:  map[string]any{"id": "row2-deny-incoming"},
		},
		TokenBundle{M2M: m2m, EndUser: eu},
		PerCallOptions{},
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)

	if err := s.comparator.Compare(PSUITE_ROW_2_CHECK_RESOURCE_V1, "deny-incoming", &decision); err != nil {
		s.T().Errorf("%v", err)
	}
}

// TestRow02CheckResourceV1GeneralPipAllow drives the GENERAL-PIP fixture
// (seed/policies/general-pip.json). The pip-mock is pinned in SetupTest to
// return an allow set containing the resource id; the RSQL predicate
// `id=in=(${subject.parityAllowed})` matches and the decision is true.
func (s *ParitySuite) TestRow02CheckResourceV1GeneralPipAllow() {
	ctx := context.Background()

	err := s.pipMock.PinRoute(ctx, "/api/v1/pip/allowed", PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       []string{"row2-pip-allow", "row2-pip-other"},
	})
	s.Require().NoError(err)

	m2m, err := s.tokens.M2MToken()
	s.Require().NoError(err)
	eu, err := s.tokens.EndUserToken(UserProfileReader)
	s.Require().NoError(err)

	status, decision, _, err := HelperCheckResourceV1(
		ctx, s.cfg,
		model.CheckAccessRequest{
			Operation: "EXECUTE",
			Type:      "PARITY_PAYMENT",
			Resource:  map[string]any{"id": "row2-pip-allow"},
		},
		TokenBundle{M2M: m2m, EndUser: eu},
		PerCallOptions{},
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)

	if err := s.comparator.Compare(PSUITE_ROW_2_CHECK_RESOURCE_V1, "general-pip-allow", &decision); err != nil {
		s.T().Errorf("%v", err)
	}
}

// TestRow02CheckResourceV1GeneralPipDeny uses a resource id the pinned mock
// does NOT return, so the RSQL predicate rejects it and the decision is false.
func (s *ParitySuite) TestRow02CheckResourceV1GeneralPipDeny() {
	ctx := context.Background()

	err := s.pipMock.PinRoute(ctx, "/api/v1/pip/allowed", PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       []string{"row2-pip-allow", "row2-pip-other"},
	})
	s.Require().NoError(err)

	m2m, err := s.tokens.M2MToken()
	s.Require().NoError(err)
	eu, err := s.tokens.EndUserToken(UserProfileReader)
	s.Require().NoError(err)

	status, decision, _, err := HelperCheckResourceV1(
		ctx, s.cfg,
		model.CheckAccessRequest{
			Operation: "EXECUTE",
			Type:      "PARITY_PAYMENT",
			Resource:  map[string]any{"id": "row2-pip-not-allowed"},
		},
		TokenBundle{M2M: m2m, EndUser: eu},
		PerCallOptions{},
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)

	if err := s.comparator.Compare(PSUITE_ROW_2_CHECK_RESOURCE_V1, "general-pip-deny", &decision); err != nil {
		s.T().Errorf("%v", err)
	}
}

// TestRow02CheckResourceV1AnonymousBaseline drives the anonymous flow
// (Authorization-Type: anonymous, no Incoming-Token). Per the recorded finding,
// legacy AC constructs an anonymous principal with no realm roles, so
// ROLE_PARITY_READER-gated rows always deny. Expected: false.
func (s *ParitySuite) TestRow02CheckResourceV1AnonymousBaseline() {
	ctx := context.Background()

	m2m, err := s.tokens.M2MToken()
	s.Require().NoError(err)

	status, decision, _, err := HelperCheckResourceV1(
		ctx, s.cfg,
		model.CheckAccessRequest{
			Operation: "READ",
			Type:      "PARITY_CUSTOMER",
			Resource:  map[string]any{"id": "row2-anon"},
		},
		TokenBundle{M2M: m2m, Anonymous: true},
		PerCallOptions{},
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)

	if err := s.comparator.Compare(PSUITE_ROW_2_CHECK_RESOURCE_V1, "anonymous-baseline", &decision); err != nil {
		s.T().Errorf("%v", err)
	}
}
