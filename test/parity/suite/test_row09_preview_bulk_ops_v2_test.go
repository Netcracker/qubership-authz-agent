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

// Row 9 drives POST /preview/v2/check/resource/bulk/operations. Same shape
// as row 8; the helper forces v2Flags{Preview: true}.
func (s *ParitySuite) TestRow09PreviewBulkOperationsV2Mixed() {
	ctx := context.Background()

	m2m, err := s.tokens.M2MToken()
	s.Require().NoError(err)
	eu, err := s.tokens.EndUserToken(UserProfileReader)
	s.Require().NoError(err)

	idA := "row9-A"
	req := model.CheckResourcesRequest{
		Type: "PARITY_CUSTOMER",
		Entries: []model.CheckResourcesRequestEntry{
			{ID: &idA, Operations: []string{"READ", "WRITE", "DELETE"}, Resource: map[string]any{"id": idA}},
		},
	}

	status, decoded, _, err := HelperPreviewCheckResourcesV2(
		ctx, s.cfg, req,
		TokenBundle{M2M: m2m, EndUser: eu},
		PerCallOptions{},
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)

	if err := s.comparator.Compare(PSUITE_ROW_9_PREVIEW_BULK_OPERATIONS_V2, "mixed", &decoded); err != nil {
		s.T().Errorf("%v", err)
	}
}
