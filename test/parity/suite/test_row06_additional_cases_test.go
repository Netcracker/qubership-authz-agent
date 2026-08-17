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

func (s *ParitySuite) TestRow06CheckFilterV1FullUseFilter() {
	s.runFilterV1Case("full-use-filter", "PARITY_SUITE_FULL_FILTER", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}

func (s *ParitySuite) TestRow06CheckFilterV1DenyIncoming() {
	s.runFilterV1Case("deny-incoming", "PARITY_SUITE_ALLOW", "LIST", s.mustTokenBundle(UserProfileOther), PerCallOptions{})
}

func (s *ParitySuite) TestRow06CheckFilterV1Anonymous() {
	s.runFilterV1Case("anon", "PARITY_SUITE_ALLOW", "LIST", s.mustAnonymousTokenBundle(), PerCallOptions{})
}

func (s *ParitySuite) TestRow06CheckFilterV1TokenPip() {
	s.runFilterV1Case("token-pip", "PARITY_SUITE_TOKEN_FILTER", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}

func (s *ParitySuite) TestRow06CheckFilterV1HeaderPip() {
	s.runFilterV1Case(
		"header-pip",
		"PARITY_SUITE_HEADER_FILTER",
		"LIST",
		s.mustTokenBundle(UserProfileReader),
		PerCallOptions{CustomHeaders: map[string]string{"x-parity-pip-attribute": "parity-allow"}},
	)
}

func (s *ParitySuite) TestRow06CheckFilterV1GeneralPipList() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/allowed", PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       []string{"row6-list-1", "row6-list-2"},
	})
	s.Require().NoError(err)

	s.runFilterV1Case("general-pip-list", "PARITY_SUITE_LIST_FILTER", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}

func (s *ParitySuite) TestRow06CheckFilterV1GeneralPipDict() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/meta", PipStubResponse{
		StatusCode: http.StatusOK,
		Body: map[string]any{
			"department": "finance",
			"maxAmount":  1000,
			"ids":        []string{"row6-dict-1", "row6-dict-2"},
		},
	})
	s.Require().NoError(err)

	s.runFilterV1Case("general-pip-dict", "PARITY_SUITE_DICT_FILTER", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}

func (s *ParitySuite) TestRow06CheckFilterV1CLANGCompoundRsql() {
	s.runFilterV1Case("clang-filter-rsql-compound", "PARITY_SUITE_CLANG_FILTER", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}
