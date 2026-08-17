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

func (s *ParitySuite) TestRow07CheckResourceV2TokenPip() {
	cases := []struct {
		name    string
		subCase string
		profile UserProfile
	}{
		{name: "allow", subCase: "token-pip/allow", profile: UserProfileReader},
		{name: "deny", subCase: "token-pip/deny", profile: UserProfileReviewer},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV2Case(
				tc.subCase,
				model.CheckResourceRequest{
					Operation: "READ",
					Type:      "PARITY_SUITE_TOKEN",
					Resource:  map[string]any{"id": "row7-token-" + tc.name},
				},
				s.mustTokenBundle(tc.profile),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow07CheckResourceV2HeaderPip() {
	cases := []struct {
		name    string
		subCase string
		header  string
	}{
		{name: "allow", subCase: "header-pip/allow", header: "parity-allow"},
		{name: "deny", subCase: "header-pip/deny", header: "parity-deny"},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV2Case(
				tc.subCase,
				model.CheckResourceRequest{
					Operation: "READ",
					Type:      "PARITY_SUITE_HEADER",
					Resource:  map[string]any{"id": "row7-header-" + tc.name},
				},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{CustomHeaders: map[string]string{"x-parity-pip-attribute": tc.header}},
			)
		})
	}
}

func (s *ParitySuite) TestRow07CheckResourceV2GeneralPipList() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/allowed", PipStubResponse{
		StatusCode: http.StatusOK,
		// Keep the allow-set byte-identical to the existing row-2 GENERAL-PIP
		// cases. Legacy AC may retain GENERAL-PIP list values across nearby
		// evaluations, so reusing the same ids makes the v2 parity row stable
		// even when the full suite runs row 2 before row 7.
		Body: []string{"row2-pip-allow", "row2-pip-other"},
	})
	s.Require().NoError(err)

	cases := []struct {
		name       string
		subCase    string
		resourceID string
	}{
		{name: "allow", subCase: "general-pip-list/allow", resourceID: "row2-pip-allow"},
		{name: "deny", subCase: "general-pip-list/deny", resourceID: "row2-pip-not-allowed"},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV2Case(
				tc.subCase,
				model.CheckResourceRequest{
					Operation: "EXECUTE",
					Type:      "PARITY_PAYMENT",
					Resource:  map[string]any{"id": tc.resourceID},
				},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow07CheckResourceV2GeneralPipDict() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/meta", PipStubResponse{
		StatusCode: http.StatusOK,
		Body: map[string]any{
			"department": "finance",
			"maxAmount":  1000,
			"ids":        []string{"row7-dict-allow", "row7-dict-other"},
		},
	})
	s.Require().NoError(err)

	cases := []struct {
		name     string
		subCase  string
		resource map[string]any
	}{
		{
			name:    "allow",
			subCase: "general-pip-dict/allow",
			resource: map[string]any{
				"id":         "row7-dict-allow",
				"department": "finance",
				"amount":     500,
			},
		},
		{
			name:    "deny",
			subCase: "general-pip-dict/deny",
			resource: map[string]any{
				"id":         "row7-dict-deny",
				"department": "finance",
				"amount":     1500,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV2Case(
				tc.subCase,
				model.CheckResourceRequest{
					Operation: "READ",
					Type:      "PARITY_SUITE_DICT",
					Resource:  tc.resource,
				},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow07CheckResourceV2AggMultiRole() {
	cases := []struct {
		name    string
		subCase string
		profile UserProfile
	}{
		{name: "reader", subCase: "agg-multi-role/reader", profile: UserProfileReader},
		{name: "reviewer", subCase: "agg-multi-role/reviewer", profile: UserProfileReviewer},
		{name: "multi-role", subCase: "agg-multi-role/multi-role", profile: UserProfileMultiRole},
		{name: "other-deny", subCase: "agg-multi-role/other-deny", profile: UserProfileOther},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV2Case(
				tc.subCase,
				model.CheckResourceRequest{
					Operation: "READ",
					Type:      "PARITY_SUITE_MULTI",
					Resource:  map[string]any{"id": "row7-agg-" + tc.name},
				},
				s.mustTokenBundle(tc.profile),
				PerCallOptions{},
			)
		})
	}
}
