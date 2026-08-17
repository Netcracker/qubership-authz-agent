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

// Row 4 drives POST /access/v1/check/resource/bulk/operations. Response is
// Map<String, Set<String>> — one entry per request id, mapping to the subset
// of operations that were granted. The bulk body issues a single entry against
// PARITY_CUSTOMER with operations {READ, WRITE, DELETE}; against the Step 2
// fixtures that yields {READ, DELETE} (WRITE is not granted).
func (s *ParitySuite) TestRow04CheckResourceBulkOperationsV1Mixed() {
	ctx := context.Background()

	m2m, err := s.tokens.M2MToken()
	s.Require().NoError(err)
	eu, err := s.tokens.EndUserToken(UserProfileReader)
	s.Require().NoError(err)

	idA := "row4-A"
	body := []model.CheckAccessBulkOperationsRequest{
		{ID: &idA, Operations: []string{"READ", "WRITE", "DELETE"}, Type: "PARITY_CUSTOMER", Resource: map[string]any{"id": idA}},
	}

	status, decoded, _, err := HelperCheckResourcesByOperationsV1(
		ctx, s.cfg, body,
		TokenBundle{M2M: m2m, EndUser: eu},
		PerCallOptions{},
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)

	if err := s.comparator.Compare(PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1, "mixed", &decoded); err != nil {
		s.T().Errorf("%v", err)
	}
}
