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

const parityReaderSubjectID = "00000000-0000-0000-0000-000000000101"

func (s *ParitySuite) TestRow02CheckResourceV1TokenSourceSeparation() {
	cases := []struct {
		name    string
		subCase string
		profile UserProfile
	}{
		{name: "reader-allow", subCase: "token-source-separation/allow", profile: UserProfileReader},
		{name: "reviewer-deny", subCase: "token-source-separation/deny", profile: UserProfileReviewer},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{
					Operation: "READ",
					Type:      "PARITY_SUITE_TOKEN_SOURCE",
					Resource:  map[string]any{"id": "row2-token-source-" + tc.name},
				},
				s.mustTokenBundle(tc.profile),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1HeaderPipProhibited() {
	cases := []struct {
		name    string
		subCase string
		headers map[string]string
	}{
		{
			name:    "stripped",
			subCase: "header-pip-prohibited/stripped",
			headers: map[string]string{"Tenant": "parity-tenant-allow", "AUTHORIZATION": "bogus"},
		},
		{
			name:    "manual-absent",
			subCase: "header-pip-prohibited/manual-absent",
			headers: nil,
		},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{
					Operation: "READ",
					Type:      "PARITY_CUSTOMER",
					Resource:  map[string]any{"id": "row2-header-prohibited-" + tc.name},
				},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{CustomHeaders: tc.headers},
			)
		})
	}
}
