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

func (s *ParitySuite) TestRow10CheckFilterV2FullUseFilter() {
	s.runFilterV2Case("full-use-filter", "PARITY_SUITE_FULL_FILTER", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}

func (s *ParitySuite) TestRow10CheckFilterV2AllowBaseline() {
	s.runFilterV2Case("allow-baseline", "PARITY_SUITE_ALLOW", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}

func (s *ParitySuite) TestRow10CheckFilterV2DenyIncoming() {
	s.runFilterV2Case("deny-incoming", "PARITY_SUITE_ALLOW", "LIST", s.mustTokenBundle(UserProfileOther), PerCallOptions{})
}

func (s *ParitySuite) TestRow10CheckFilterV2Anonymous() {
	s.runFilterV2Case("anon", "PARITY_SUITE_ALLOW", "LIST", s.mustAnonymousTokenBundle(), PerCallOptions{})
}

func (s *ParitySuite) TestRow10CheckFilterV2TokenPip() {
	s.runFilterV2Case("token-pip", "PARITY_SUITE_TOKEN_FILTER", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}

func (s *ParitySuite) TestRow10CheckFilterV2HeaderPip() {
	s.runFilterV2Case(
		"header-pip",
		"PARITY_SUITE_HEADER_FILTER",
		"LIST",
		s.mustTokenBundle(UserProfileReader),
		PerCallOptions{CustomHeaders: map[string]string{"x-parity-pip-attribute": "parity-allow"}},
	)
}

func (s *ParitySuite) TestRow10CheckFilterV2GeneralPipList() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/allowed", PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       []string{"row10-list-1", "row10-list-2"},
	})
	s.Require().NoError(err)

	s.runFilterV2Case("general-pip-list", "PARITY_SUITE_LIST_FILTER", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}

func (s *ParitySuite) TestRow10CheckFilterV2GeneralPipDict() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/meta", PipStubResponse{
		StatusCode: http.StatusOK,
		Body: map[string]any{
			"department": "finance",
			"maxAmount":  1000,
			"ids":        []string{"row10-dict-1", "row10-dict-2"},
		},
	})
	s.Require().NoError(err)

	s.runFilterV2Case("general-pip-dict", "PARITY_SUITE_DICT_FILTER", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}
