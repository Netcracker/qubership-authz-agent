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

// Whether a filter applies a policy's condition to its predicate at all. In F1 the
// condition is false over a TOKEN PIP value parity-reader has (department is
// finance); in F2 it is true; in F3 it reads a resource attribute, and a filter
// request carries no resource. Access-control may refuse F3, so the filter cases
// record the status together with the result.
func (s *ParitySuite) TestRow06CheckFilterV1ConditionBesidePredicate() {
	cases := []struct{ subCase, resourceType string }{
		{"f1-false-condition-beside-predicate", "PARITY_SUITE_SEM2_F1"},
		{"f2-true-condition", "PARITY_SUITE_SEM2_F2"},
		{"f3-resource-condition-without-resource", "PARITY_SUITE_SEM2_F3"},
	}
	for _, tc := range cases {
		s.Run(tc.subCase, func() {
			s.runPendingFilterV1OutcomeCase("semantics/"+tc.subCase, tc.resourceType, "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
		})
	}
}

func (s *ParitySuite) TestRow06CheckFilterV1PlaceholderOfFailedGeneralPIP() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/sem-broken", PipStubResponse{
		StatusCode: http.StatusInternalServerError,
		Body:       map[string]any{"error": "parity semantics case"},
	})
	s.Require().NoError(err)

	s.runPendingFilterV1OutcomeCase("semantics/p8-placeholder-of-failed-pip", "PARITY_SUITE_SEM2_P8", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}
