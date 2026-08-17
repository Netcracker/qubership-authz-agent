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

import "authz-agent/test/parity/suite/model"

func (s *ParitySuite) TestRow04CheckResourceBulkOperationsV1Anonymous() {
	body := []model.CheckAccessBulkOperationsRequest{
		{
			ID:         stringPtr("row4-anon-a"),
			Operations: []string{"READ", "WRITE", "DELETE"},
			Type:       "PARITY_CUSTOMER",
			Resource:   map[string]any{"id": "row4-anon-a"},
		},
	}
	s.runCheckResourceBulkOpsV1Case("anon", body, s.mustAnonymousTokenBundle(), PerCallOptions{})
}

func (s *ParitySuite) TestRow04CheckResourceBulkOperationsV1AggPerOperation() {
	body := []model.CheckAccessBulkOperationsRequest{
		{
			ID:         stringPtr("row4-agg-public-a"),
			Operations: []string{"READ", "WRITE"},
			Type:       "PARITY_SUITE_AGG_OPS",
			Resource:   map[string]any{"id": "row4-agg-public-a", "status": "PUBLIC"},
		},
		{
			ID:         stringPtr("row4-agg-public-b"),
			Operations: []string{"READ", "WRITE"},
			Type:       "PARITY_SUITE_AGG_OPS",
			Resource:   map[string]any{"id": "row4-agg-public-b", "status": "PUBLIC"},
		},
		{
			ID:         stringPtr("row4-agg-private"),
			Operations: []string{"READ", "WRITE"},
			Type:       "PARITY_SUITE_AGG_OPS",
			Resource:   map[string]any{"id": "row4-agg-private", "status": "PRIVATE"},
		},
	}
	s.runCheckResourceBulkOpsV1Case("agg-per-operation", body, s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}
