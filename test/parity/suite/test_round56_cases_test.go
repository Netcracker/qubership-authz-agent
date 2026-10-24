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

// Round 56 asks three behaviors that no earlier golden shows. Each case runs
// in a tenant of its own and declares what it needs through the PAP:
// TestRound56ClaimsIsEmptyCases asks whether IS EMPTY over a null value makes
// its rule false, ends the rule, or fails the whole request, for four carriers
// of null; TestRound56ClaimsFilterGroupsCases asks how check/filter groups the
// predicates of simplified policies of two components and two operations; and
// TestRound56ClaimsPipTokenCases records whose token, and which Tenant, a call
// to a GENERAL PIP carries. Each file records the stand's version first and
// opens and closes with a control. The cases are data under
// testdata/cases/round56, and each case's about field says what it asks.

// TestRound56ClaimsIsEmptyCases runs round56/claims-is-empty.json.
func (s *ParitySuite) TestRound56ClaimsIsEmptyCases() {
	s.runCaseFile("round56/claims-is-empty.json")
}

// TestRound56ClaimsFilterGroupsCases runs round56/claims-filter-groups.json.
func (s *ParitySuite) TestRound56ClaimsFilterGroupsCases() {
	s.runCaseFile("round56/claims-filter-groups.json")
}

// TestRound56ClaimsPipTokenCases runs round56/claims-pip-token.json.
func (s *ParitySuite) TestRound56ClaimsPipTokenCases() {
	s.runCaseFile("round56/claims-pip-token.json")
}
