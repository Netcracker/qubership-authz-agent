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

// Row 29 — validation of missing `resourceType` query param on
// POST /access/v1/check/filter. Jakarta @NotNull @QueryParam("resourceType")
// on CheckEndpoint.filter (CheckEndpoint.java:137-182) triggers HTTP 400
// before the policy engine is reached.
func (s *ParitySuite) TestRow29ValidationMissingResourceType() {
	ctx := context.Background()

	m2m, err := s.tokens.M2MToken()
	s.Require().NoError(err)
	eu, err := s.tokens.EndUserToken(UserProfileReader)
	s.Require().NoError(err)

	// Empty resourceType argument — the helper skips the query param entirely.
	status, _, raw, err := HelperFilterV1(
		ctx, s.cfg,
		"", "LIST",
		TokenBundle{M2M: m2m, EndUser: eu},
		PerCallOptions{},
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, status, "expected HTTP 400 for missing resourceType; body=%s", string(raw))
	s.Require().NotEmpty(raw)
}
