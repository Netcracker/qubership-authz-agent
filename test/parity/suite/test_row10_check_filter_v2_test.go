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
)

// Row 10 drives POST /access/v2/check/filter?obligations=false. Same
// underlying RLS fixture as row 6 (rls-filter.json on PARITY_ORDER/LIST).
// The v2 response schema adds an Obligations block that the comparator
// filters out at cmp.Diff time per D-E.
func (s *ParitySuite) TestRow10CheckFilterV2RlsHappy() {
	ctx := context.Background()

	m2m, err := s.tokens.M2MToken()
	s.Require().NoError(err)
	eu, err := s.tokens.EndUserToken(UserProfileReader)
	s.Require().NoError(err)

	status, decoded, _, err := HelperFilterV2(
		ctx, s.cfg,
		"PARITY_ORDER", "LIST",
		TokenBundle{M2M: m2m, EndUser: eu},
		PerCallOptions{},
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)

	if err := s.comparator.Compare(PSUITE_ROW_10_CHECK_FILTER_V2, "rls-happy", &decoded); err != nil {
		s.T().Errorf("%v", err)
	}
}
