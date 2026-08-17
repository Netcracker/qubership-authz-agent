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

func (s *ParitySuite) TestRow06CheckFilterV1AllowBaseline() {
	s.runFilterV1Case("allow-baseline", "PARITY_SUITE_ALLOW", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}

func (s *ParitySuite) TestRow06CheckFilterV1AggTwoPredicates() {
	s.runFilterV1Case("agg-two-predicates", "PARITY_SUITE_AGG_PRED", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}

func (s *ParitySuite) TestRow06CheckFilterV1AggOlsPlusRls() {
	s.runFilterV1Case("agg-ols-plus-rls", "PARITY_SUITE_AGG_MIXED", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}

func (s *ParitySuite) TestRow06CheckFilterV1GeneralScalarSubstitution() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/status-scalar", PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       map[string]any{"value": "OPEN"},
	})
	s.Require().NoError(err)

	s.runFilterV1Case("general-scalar-substitution", "PARITY_SUITE_SCALAR", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}
