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

// Row 3 drives POST /access/v1/check/resource/bulk. Response is a
// Set<String> of allowed ids (sort-invariant per D-M). The bulk body
// stuffs three entries against the Step 2 fixtures:
//
//	id=A: PARITY_CUSTOMER READ   → allow
//	id=B: PARITY_CUSTOMER WRITE  → deny (no policy matches)
//	id=C: PARITY_CUSTOMER DELETE → allow (ols-deny.json grants DELETE)
//
// Expected allowed set: {A, C} (order not asserted).
func (s *ParitySuite) TestRow03CheckResourceBulkV1Mixed() {
	ctx := context.Background()

	m2m, err := s.tokens.M2MToken()
	s.Require().NoError(err)
	eu, err := s.tokens.EndUserToken(UserProfileReader)
	s.Require().NoError(err)

	idA := "row3-A"
	idB := "row3-B"
	idC := "row3-C"
	body := []model.CheckAccessRequestWithID{
		{ID: &idA, Operation: "READ", Type: "PARITY_CUSTOMER", Resource: map[string]any{"id": idA}},
		{ID: &idB, Operation: "WRITE", Type: "PARITY_CUSTOMER", Resource: map[string]any{"id": idB}},
		{ID: &idC, Operation: "DELETE", Type: "PARITY_CUSTOMER", Resource: map[string]any{"id": idC}},
	}

	status, allowed, _, err := HelperCheckResourcesV1(
		ctx, s.cfg, body,
		TokenBundle{M2M: m2m, EndUser: eu},
		PerCallOptions{},
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)

	if err := s.comparator.Compare(PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1, "mixed", &allowed); err != nil {
		s.T().Errorf("%v", err)
	}
}
