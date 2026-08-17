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

func (s *ParitySuite) TestRow03CheckResourceBulkV1Anonymous() {
	body := []model.CheckAccessRequestWithID{
		{ID: stringPtr("row3-anon-a"), Operation: "READ", Type: "PARITY_CUSTOMER", Resource: map[string]any{"id": "row3-anon-a"}},
		{ID: stringPtr("row3-anon-b"), Operation: "DELETE", Type: "PARITY_CUSTOMER", Resource: map[string]any{"id": "row3-anon-b"}},
	}
	s.runCheckResourceBulkV1Case("anon", body, s.mustAnonymousTokenBundle(), PerCallOptions{})
}

func (s *ParitySuite) TestRow03CheckResourceBulkV1GeneralPipList() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/allowed", PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       []string{"row3-pip-allow", "row3-pip-other"},
	})
	s.Require().NoError(err)

	body := []model.CheckAccessRequestWithID{
		{ID: stringPtr("row3-pip-allow"), Operation: "EXECUTE", Type: "PARITY_PAYMENT", Resource: map[string]any{"id": "row3-pip-allow"}},
		{ID: stringPtr("row3-pip-deny"), Operation: "EXECUTE", Type: "PARITY_PAYMENT", Resource: map[string]any{"id": "row3-pip-deny"}},
		{ID: stringPtr("row3-pip-other"), Operation: "EXECUTE", Type: "PARITY_PAYMENT", Resource: map[string]any{"id": "row3-pip-other"}},
	}
	s.runCheckResourceBulkV1Case("general-pip-list", body, s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}

func (s *ParitySuite) TestRow03CheckResourceBulkV1GeneralPipDict() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/meta", PipStubResponse{
		StatusCode: http.StatusOK,
		Body: map[string]any{
			"department": "finance",
			"maxAmount":  1000,
			"ids":        []string{"row3-dict-allow", "row3-dict-other"},
		},
	})
	s.Require().NoError(err)

	body := []model.CheckAccessRequestWithID{
		{
			ID:        stringPtr("row3-dict-allow"),
			Operation: "READ",
			Type:      "PARITY_SUITE_DICT",
			Resource:  map[string]any{"id": "row3-dict-allow", "department": "finance", "amount": 500},
		},
		{
			ID:        stringPtr("row3-dict-deny"),
			Operation: "READ",
			Type:      "PARITY_SUITE_DICT",
			Resource:  map[string]any{"id": "row3-dict-deny", "department": "finance", "amount": 1500},
		},
		{
			ID:        stringPtr("row3-dict-other"),
			Operation: "READ",
			Type:      "PARITY_SUITE_DICT",
			Resource:  map[string]any{"id": "row3-dict-other", "department": "finance", "amount": 900},
		},
	}
	s.runCheckResourceBulkV1Case("general-pip-dict", body, s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}

func (s *ParitySuite) TestRow03CheckResourceBulkV1AggConditionOr() {
	body := []model.CheckAccessRequestWithID{
		{ID: stringPtr("row3-agg-gold"), Operation: "READ", Type: "PARITY_SUITE_AGG_COND", Resource: map[string]any{"id": "row3-agg-gold", "tier": "GOLD"}},
		{ID: stringPtr("row3-agg-silver"), Operation: "READ", Type: "PARITY_SUITE_AGG_COND", Resource: map[string]any{"id": "row3-agg-silver", "tier": "SILVER"}},
		{ID: stringPtr("row3-agg-bronze"), Operation: "READ", Type: "PARITY_SUITE_AGG_COND", Resource: map[string]any{"id": "row3-agg-bronze", "tier": "BRONZE"}},
		{ID: stringPtr("row3-agg-platinum"), Operation: "READ", Type: "PARITY_SUITE_AGG_COND", Resource: map[string]any{"id": "row3-agg-platinum", "tier": "PLATINUM"}},
	}
	s.runCheckResourceBulkV1Case("agg-condition-or", body, s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}
