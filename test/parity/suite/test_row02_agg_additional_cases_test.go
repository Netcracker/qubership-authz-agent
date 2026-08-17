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

func (s *ParitySuite) TestRow02CheckResourceV1AggConditionOr() {
	cases := []struct {
		name    string
		subCase string
		tier    string
	}{
		{name: "gold", subCase: "agg-condition-or/gold", tier: "GOLD"},
		{name: "silver", subCase: "agg-condition-or/silver", tier: "SILVER"},
		{name: "bronze", subCase: "agg-condition-or/bronze", tier: "BRONZE"},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{
					Operation: "READ",
					Type:      "PARITY_SUITE_AGG_COND",
					Resource:  map[string]any{"id": "row2-agg-cond-" + tc.name, "tier": tc.tier},
				},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}
