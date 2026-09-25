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

// Round 23 asks again, through another request, position, placement or set
// shape, the rules that exactly one earlier golden pins, so that each rests on
// two goldens. Its cases are data under testdata/cases/round23, and each
// case's about field names the rule it pins and, where one earlier case
// carried it, the golden it seconds and the variant. Each
// function runs one file, so that a recording run can be filtered to it and
// record it on a stand of its own.

// TestRound23SecondCarrierConditionsCases runs round23/second-carrier-conditions.json.
func (s *ParitySuite) TestRound23SecondCarrierConditionsCases() {
	s.runCaseFile("round23/second-carrier-conditions.json")
}

// TestRound23SecondCarrierSetsCases runs round23/second-carrier-sets.json.
func (s *ParitySuite) TestRound23SecondCarrierSetsCases() {
	s.runCaseFile("round23/second-carrier-sets.json")
}

// TestRound23SecondCarrierFilterCases runs round23/second-carrier-filter.json.
func (s *ParitySuite) TestRound23SecondCarrierFilterCases() {
	s.runCaseFile("round23/second-carrier-filter.json")
}

// TestRound23SecondCarrierPAPCases runs round23/second-carrier-pap.json.
func (s *ParitySuite) TestRound23SecondCarrierPAPCases() {
	s.runCaseFile("round23/second-carrier-pap.json")
}

// TestRound23SecondCarrierScopeNoGrantsCases runs round23/second-carrier-scope-no-grants.json.
func (s *ParitySuite) TestRound23SecondCarrierScopeNoGrantsCases() {
	s.runCaseFile("round23/second-carrier-scope-no-grants.json")
}

// TestRound23SecondCarrierScopeTwoGrantsCases runs round23/second-carrier-scope-two-grants.json.
func (s *ParitySuite) TestRound23SecondCarrierScopeTwoGrantsCases() {
	s.runCaseFile("round23/second-carrier-scope-two-grants.json")
}
