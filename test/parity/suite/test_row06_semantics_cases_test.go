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

// Filter counterparts of the row 2 semantics cases: which predicate survives when a
// policy reads a TOKEN PIP that has no value.
func (s *ParitySuite) TestRow06CheckFilterV1MissingPIPAttribute() {
	cases := []struct{ subCase, resourceType string }{
		{"d5-failing-policy-beside-predicate", "PARITY_SUITE_SEM_D5"},
		{"p5-placeholder-of-pip-without-value", "PARITY_SUITE_SEM_P5"},
	}
	for _, tc := range cases {
		s.Run(tc.subCase, func() {
			s.runPendingFilterV1Case("semantics/"+tc.subCase, tc.resourceType, "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
		})
	}
}
