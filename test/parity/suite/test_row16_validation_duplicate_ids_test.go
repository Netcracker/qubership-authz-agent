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

// Row 16 — validation of duplicate ids on POST /access/v1/check/resource/bulk.
// CheckRequestValidator (CheckRequestValidator.java:76-94) raises
// NotUniqueResourcesIdsException when two entries share the same id; the
// server returns HTTP 400. Again this path reaches the server because the
// Go helper has no pre-validator.
func (s *ParitySuite) TestRow16ValidationDuplicateIds() {
	ctx := context.Background()

	m2m, err := s.tokens.M2MToken()
	s.Require().NoError(err)
	eu, err := s.tokens.EndUserToken(UserProfileReader)
	s.Require().NoError(err)

	dup := "row16-dup"
	body := []model.CheckAccessRequestWithID{
		{ID: &dup, Operation: "READ", Type: "PARITY_CUSTOMER", Resource: map[string]any{"id": dup}},
		{ID: &dup, Operation: "DELETE", Type: "PARITY_CUSTOMER", Resource: map[string]any{"id": dup}},
	}

	// The helper wraps a decode error when the server returns a JSON error
	// envelope instead of the Set<String> success shape. For validation rows
	// that is the expected path — we assert on status + raw body and ignore
	// the decode failure.
	status, _, raw, _ := HelperCheckResourcesV1(
		ctx, s.cfg, body,
		TokenBundle{M2M: m2m, EndUser: eu},
		PerCallOptions{},
	)
	s.Require().Equal(http.StatusBadRequest, status, "expected HTTP 400 for duplicate ids; body=%s", string(raw))
	s.Require().NotEmpty(raw)
	bodyLower := strings.ToLower(string(raw))
	s.Require().True(
		strings.Contains(bodyLower, "unique") || strings.Contains(bodyLower, "duplicate") || strings.Contains(bodyLower, "id"),
		"error body should mention unique/duplicate/id; got %s", string(raw),
	)
}
