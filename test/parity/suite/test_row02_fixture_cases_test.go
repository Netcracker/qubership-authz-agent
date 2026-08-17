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

func (s *ParitySuite) TestRow02CheckResourceV1TokenPip() {
	cases := []struct {
		name    string
		subCase string
		profile UserProfile
		body    model.CheckAccessRequest
	}{
		{
			name:    "allow-reader-finance",
			subCase: "token-pip/allow",
			profile: UserProfileReader,
			body: model.CheckAccessRequest{
				Operation: "READ",
				Type:      "PARITY_SUITE_TOKEN",
				Resource:  map[string]any{"id": "row2-token-allow"},
			},
		},
		{
			name:    "deny-reviewer-compliance",
			subCase: "token-pip/deny",
			profile: UserProfileReviewer,
			body: model.CheckAccessRequest{
				Operation: "READ",
				Type:      "PARITY_SUITE_TOKEN",
				Resource:  map[string]any{"id": "row2-token-deny"},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(tc.subCase, tc.body, s.mustTokenBundle(tc.profile), PerCallOptions{})
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1HeaderPip() {
	cases := []struct {
		name    string
		subCase string
		header  string
	}{
		{
			name:    "allow",
			subCase: "header-pip/allow",
			header:  "parity-allow",
		},
		{
			name:    "deny",
			subCase: "header-pip/deny",
			header:  "parity-deny",
		},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{
					Operation: "READ",
					Type:      "PARITY_SUITE_HEADER",
					Resource:  map[string]any{"id": "row2-header-" + tc.name},
				},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{CustomHeaders: map[string]string{"x-parity-pip-attribute": tc.header}},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1GeneralPipDict() {
	ctx := context.Background()
	err := s.pipMock.PinRoute(ctx, "/api/v1/pip/meta", PipStubResponse{
		StatusCode: http.StatusOK,
		Body: map[string]any{
			"department": "finance",
			"maxAmount":  1000,
			"ids":        []string{"row2-dict-allow", "row2-dict-other"},
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
				"id":         "row2-dict-allow",
				"department": "finance",
				"amount":     500,
			},
		},
		{
			name:    "deny",
			subCase: "general-pip-dict/deny",
			resource: map[string]any{
				"id":         "row2-dict-deny",
				"department": "finance",
				"amount":     1500,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{
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

func (s *ParitySuite) TestRow02CheckResourceV1AggMultiRole() {
	cases := []struct {
		name    string
		subCase string
		profile UserProfile
	}{
		{
			name:    "reader",
			subCase: "agg-multi-role/reader",
			profile: UserProfileReader,
		},
		{
			name:    "reviewer",
			subCase: "agg-multi-role/reviewer",
			profile: UserProfileReviewer,
		},
		{
			name:    "multi-role",
			subCase: "agg-multi-role/multi-role",
			profile: UserProfileMultiRole,
		},
		{
			name:    "other-deny",
			subCase: "agg-multi-role/other-deny",
			profile: UserProfileOther,
		},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{
					Operation: "READ",
					Type:      "PARITY_SUITE_MULTI",
					Resource:  map[string]any{"id": "row2-agg-" + tc.name},
				},
				s.mustTokenBundle(tc.profile),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1CLANGStringEquality() {
	cases := []struct {
		name     string
		subCase  string
		category string
	}{
		{name: "allow", subCase: "clang-string-equality/allow", category: "PARITY_GOLD"},
		{name: "deny", subCase: "clang-string-equality/deny", category: "PARITY_SILVER"},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{
					Operation: "READ",
					Type:      "PARITY_SUITE_CLANG_EQ",
					Resource:  map[string]any{"id": "row2-clang-eq-" + tc.name, "category": tc.category},
				},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1CLANGNumberRelational() {
	cases := []struct {
		name    string
		subCase string
		amount  int
	}{
		{name: "below-range", subCase: "clang-number-relational/below-range", amount: 50},
		{name: "in-range", subCase: "clang-number-relational/in-range", amount: 500},
		{name: "above-range", subCase: "clang-number-relational/above-range", amount: 1500},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{
					Operation: "READ",
					Type:      "PARITY_SUITE_CLANG_NUM",
					Resource:  map[string]any{"id": "row2-clang-num-" + tc.name, "amount": tc.amount},
				},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1CLANGBooleanOr() {
	cases := []struct {
		name      string
		subCase   string
		priority  string
		escalated bool
	}{
		{name: "high-true", subCase: "clang-boolean-or/high-true", priority: "HIGH", escalated: true},
		{name: "high-false", subCase: "clang-boolean-or/high-false", priority: "HIGH", escalated: false},
		{name: "low-true", subCase: "clang-boolean-or/low-true", priority: "LOW", escalated: true},
		{name: "low-false", subCase: "clang-boolean-or/low-false", priority: "LOW", escalated: false},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{
					Operation: "READ",
					Type:      "PARITY_SUITE_CLANG_OR",
					Resource: map[string]any{
						"id":        "row2-clang-or-" + tc.name,
						"priority":  tc.priority,
						"escalated": tc.escalated,
					},
				},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1CLANGInLiteral() {
	cases := []struct {
		name    string
		subCase string
		status  string
	}{
		{name: "open", subCase: "clang-in-literal/open", status: "OPEN"},
		{name: "pending", subCase: "clang-in-literal/pending", status: "PENDING"},
		{name: "review", subCase: "clang-in-literal/review", status: "REVIEW"},
		{name: "closed", subCase: "clang-in-literal/closed", status: "CLOSED"},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{
					Operation: "READ",
					Type:      "PARITY_SUITE_CLANG_IN",
					Resource:  map[string]any{"id": "row2-clang-in-" + tc.name, "status": tc.status},
				},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1CLANGContainsAny() {
	cases := []struct {
		name    string
		subCase string
		tags    []string
	}{
		{name: "allow", subCase: "clang-contains-any/allow", tags: []string{"red", "green"}},
		{name: "deny", subCase: "clang-contains-any/deny", tags: []string{"yellow", "purple"}},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{
					Operation: "READ",
					Type:      "PARITY_SUITE_CLANG_CANY",
					Resource:  map[string]any{"id": "row2-clang-cany-" + tc.name, "tags": tc.tags},
				},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1CLANGNull() {
	cases := []struct {
		name     string
		subCase  string
		resource map[string]any
	}{
		{
			name:    "owner-present",
			subCase: "clang-null/owner-present",
			resource: map[string]any{
				"id":      "row2-clang-null-owner-present",
				"ownerId": "owner-42",
			},
		},
		{
			name:     "owner-missing",
			subCase:  "clang-null/owner-missing",
			resource: map[string]any{"id": "row2-clang-null-owner-missing"},
		},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{
					Operation: "READ",
					Type:      "PARITY_SUITE_CLANG_NULL",
					Resource:  tc.resource,
				},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}
