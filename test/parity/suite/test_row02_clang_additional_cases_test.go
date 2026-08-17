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

func (s *ParitySuite) TestRow02CheckResourceV1CLANGBooleanAnd() {
	cases := []struct {
		name     string
		subCase  string
		active   bool
		verified bool
	}{
		{name: "true-true", subCase: "clang-boolean-and/true-true", active: true, verified: true},
		{name: "true-false", subCase: "clang-boolean-and/true-false", active: true, verified: false},
		{name: "false-true", subCase: "clang-boolean-and/false-true", active: false, verified: true},
		{name: "false-false", subCase: "clang-boolean-and/false-false", active: false, verified: false},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{
					Operation: "READ",
					Type:      "PARITY_SUITE_CLANG_AND",
					Resource:  map[string]any{"id": "row2-clang-and-" + tc.name, "active": tc.active, "verified": tc.verified},
				},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1CLANGNot() {
	cases := []struct {
		name     string
		subCase  string
		archived bool
	}{
		{name: "archived-true", subCase: "clang-not/archived-true", archived: true},
		{name: "archived-false", subCase: "clang-not/archived-false", archived: false},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{
					Operation: "READ",
					Type:      "PARITY_SUITE_CLANG_NOT",
					Resource:  map[string]any{"id": "row2-clang-not-" + tc.name, "archived": tc.archived},
				},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1CLANGInPipCollection() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/status-allowed", PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       []string{"OPEN", "PENDING"},
	})
	s.Require().NoError(err)

	cases := []struct {
		name    string
		subCase string
		status  string
	}{
		{name: "allow", subCase: "clang-in-pip/allow", status: "OPEN"},
		{name: "deny", subCase: "clang-in-pip/deny", status: "CLOSED"},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{
					Operation: "READ",
					Type:      "PARITY_SUITE_CLANG_IN_PIP",
					Resource:  map[string]any{"id": "row2-clang-in-pip-" + tc.name, "status": tc.status},
				},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1CLANGIsSubset() {
	cases := []struct {
		name    string
		subCase string
		tags    []string
	}{
		{name: "allow", subCase: "clang-is-subset/allow", tags: []string{"red", "blue"}},
		{name: "deny", subCase: "clang-is-subset/deny", tags: []string{"red", "green"}},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{
					Operation: "READ",
					Type:      "PARITY_SUITE_CLANG_SUBSET",
					Resource:  map[string]any{"id": "row2-clang-subset-" + tc.name, "tags": tc.tags},
				},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1CLANGNestedSubjectLeaf() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/meta", PipStubResponse{
		StatusCode: http.StatusOK,
		Body: map[string]any{
			"department": "sales",
			"maxAmount":  1000,
			"ids":        []string{"row2-nested-allow"},
		},
	})
	s.Require().NoError(err)

	cases := []struct {
		name       string
		subCase    string
		department string
	}{
		{name: "allow", subCase: "clang-nested-subject/allow", department: "sales"},
		{name: "deny", subCase: "clang-nested-subject/deny", department: "engineering"},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{
					Operation: "READ",
					Type:      "PARITY_SUITE_CLANG_NESTED",
					Resource:  map[string]any{"id": "row2-clang-nested-" + tc.name, "department": tc.department},
				},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}
