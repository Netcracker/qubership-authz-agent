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

// Row 5 drives POST /preview/v1/check/resource/bulk/operations. Same wire
// shape as row 4; in the absence of a separate preview policy set, preview
// evaluates the same rules and returns the same per-id operations map.
func (s *ParitySuite) TestRow05PreviewBulkOperationsV1Mixed() {
	ctx := context.Background()

	m2m, err := s.tokens.M2MToken()
	s.Require().NoError(err)
	eu, err := s.tokens.EndUserToken(UserProfileReader)
	s.Require().NoError(err)

	idA := "row5-A"
	body := []model.CheckAccessBulkOperationsRequest{
		{ID: &idA, Operations: []string{"READ", "WRITE", "DELETE"}, Type: "PARITY_CUSTOMER", Resource: map[string]any{"id": idA}},
	}

	status, decoded, _, err := HelperPreviewCheckResourcesByOperationsV1(
		ctx, s.cfg, body,
		TokenBundle{M2M: m2m, EndUser: eu},
		PerCallOptions{},
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)

	if err := s.comparator.Compare(PSUITE_ROW_5_PREVIEW_BULK_OPERATIONS_V1, "mixed", &decoded); err != nil {
		s.T().Errorf("%v", err)
	}
}
