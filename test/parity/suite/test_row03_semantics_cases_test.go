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

// Whether a policy that stops on a missing attribute for one resource of a bulk
// request affects the other resource. PARITY_SUITE_SEM_S2 holds resource.x != 'v';
// the first resource has no x, the second has x = 'w'.
func (s *ParitySuite) TestRow03CheckResourceBulkV1MissingAttributeInOneResource() {
	s.runPendingCheckResourceBulkV1Case(
		"semantics/b1-missing-attribute-in-one-resource",
		[]model.CheckAccessRequestWithID{
			{ID: stringPtr("sem2-b1-absent"), Operation: "READ", Type: "PARITY_SUITE_SEM_S2", Resource: map[string]any{"id": "sem2-b1-absent"}},
			{ID: stringPtr("sem2-b1-w"), Operation: "READ", Type: "PARITY_SUITE_SEM_S2", Resource: map[string]any{"id": "sem2-b1-w", "x": "w"}},
		},
		s.mustTokenBundle(UserProfileReader),
		PerCallOptions{},
	)
}
