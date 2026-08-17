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

func (s *ParitySuite) TestRow08CheckResourceBulkOperationsV2Anonymous() {
	body := model.CheckResourcesRequest{
		Type: "PARITY_CUSTOMER",
		Entries: []model.CheckResourcesRequestEntry{
			{ID: stringPtr("row8-anon-a"), Operations: []string{"READ", "WRITE", "DELETE"}, Resource: map[string]any{"id": "row8-anon-a"}},
		},
	}
	s.runCheckResourceBulkOpsV2Case("anon", body, s.mustAnonymousTokenBundle(), PerCallOptions{})
}
