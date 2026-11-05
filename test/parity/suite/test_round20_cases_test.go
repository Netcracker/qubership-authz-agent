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

// Round 20 asks the operand contexts of round 19's context files again, with
// no empty rule condition, which made the PAP refuse most of their cases; asks
// again the two filter cases of round 15 whose 400 was the stand state; and
// asks what round 19 left open. Its cases are data under
// testdata/cases/round20, and each file's about field says what it asks. Each
// function runs one file, so that a recording run can be filtered to it and
// record it on a stand of its own.

// TestRound20QuestionsCases runs round20/questions.json.
func (s *ParitySuite) TestRound20QuestionsCases() { s.runCaseFile("round20/questions.json") }

// TestRound20ReaskRound15GroupsCases runs round20/reask-round15-groups.json.
func (s *ParitySuite) TestRound20ReaskRound15GroupsCases() {
	s.runCaseFile("round20/reask-round15-groups.json")
}

// TestRound20ContextCases runs round20/context.json.
func (s *ParitySuite) TestRound20ContextCases() { s.runCaseFile("round20/context.json") }

// TestRound20ContextOneGrantCases runs round20/context-one-grant.json.
func (s *ParitySuite) TestRound20ContextOneGrantCases() {
	s.runCaseFile("round20/context-one-grant.json")
}

// TestRound20ContextTwoGrantsCases runs round20/context-two-grants.json.
func (s *ParitySuite) TestRound20ContextTwoGrantsCases() {
	s.runCaseFile("round20/context-two-grants.json")
}

// TestRound20ContextWithoutMappingCases runs
// round20/context-without-mapping.json. Its one case reads subject.permissions
// as absent, so it runs on a stand whose declaration never held a MAPPING PIP.
func (s *ParitySuite) TestRound20ContextWithoutMappingCases() {
	s.runCaseFile("round20/context-without-mapping.json")
}
