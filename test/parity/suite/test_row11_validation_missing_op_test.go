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
	"strings"

	"authz-agent/test/parity/suite/model"
)

// Row 11 — validation of missing `operation` field on POST /access/v1/check/resource.
// The legacy server runs CheckRequestValidator.validateInputParameters
// (CheckRequestValidator.java:31-44) which rejects an empty operation with
// HTTP 400. Per D-V item 12 + the Go pivot, this path reaches the server
// because the Go helper has no client-side pre-validator short-circuit.
// Asserted via status code + body substring — no golden.
func (s *ParitySuite) TestRow11ValidationMissingOperation() {
	ctx := context.Background()

	m2m, err := s.tokens.M2MToken()
	s.Require().NoError(err)
	eu, err := s.tokens.EndUserToken(UserProfileReader)
	s.Require().NoError(err)

	status, _, raw, err := HelperCheckResourceV1(
		ctx, s.cfg,
		model.CheckAccessRequest{
			Operation: "",
			Type:      "PARITY_CUSTOMER",
			Resource:  map[string]any{"id": "row11"},
		},
		TokenBundle{M2M: m2m, EndUser: eu},
		PerCallOptions{},
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, status, "expected HTTP 400 for missing operation; body=%s", string(raw))
	s.Require().NotEmpty(raw, "expected non-empty error body")
	// The legacy Netcracker error envelope is a JSON object — assert it at
	// least carries a recognizable marker. The exact message shape is
	// server-curated and not worth pinning literally.
	bodyLower := strings.ToLower(string(raw))
	s.Require().True(
		strings.Contains(bodyLower, "operation") || strings.Contains(bodyLower, "parameter") || strings.Contains(bodyLower, "invalid"),
		"error body should mention operation/parameter/invalid; got %s", string(raw),
	)
}
