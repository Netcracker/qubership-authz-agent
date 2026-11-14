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

// Round 18 asks whether the 400s that round 17 recorded for its residual DENY
// twins are a rule or the state of the stand, what makes a permission scope
// read fail with 400 under one grant, the rules round 17 left open, which part
// of round 16's t16-28 depends on the order of children, and what fuzzing
// still reaches after the round 17 rules. Its cases are data under
// testdata/cases/round18, and each file's about field says what it asks. Every
// file that uploads regular sets opens and closes with a control DENY rule
// that answers true while the stand is in order. Each function runs one file,
// so that a recording run can be filtered to it and record it on a stand of
// its own. The files are listed in the order that asks the most per golden
// first, except the order file, which needs several stands.

// TestRound18StandStateCases runs round18/stand-state.json. It has to run on a
// fresh stand: its controls tell a request that breaks the stand from a request
// that answers 400 on its own.
func (s *ParitySuite) TestRound18StandStateCases() { s.runCaseFile("round18/stand-state.json") }

// TestRound18StandStateRound15Cases runs round18/stand-state-round15.json,
// on a fresh stand for the same reason.
func (s *ParitySuite) TestRound18StandStateRound15Cases() {
	s.runCaseFile("round18/stand-state-round15.json")
}

// TestRound18StandStateReverseCases runs round18/stand-state-reverse.json, on a
// fresh stand for the same reason.
func (s *ParitySuite) TestRound18StandStateReverseCases() {
	s.runCaseFile("round18/stand-state-reverse.json")
}

// TestRound18ScopeOneGrantCases runs round18/scope-one-grant.json.
func (s *ParitySuite) TestRound18ScopeOneGrantCases() { s.runCaseFile("round18/scope-one-grant.json") }

// TestRound18QuestionsCases runs round18/questions.json.
func (s *ParitySuite) TestRound18QuestionsCases() { s.runCaseFile("round18/questions.json") }

// TestRound18ScopeOneGrantTwoValuesCases runs
// round18/scope-one-grant-two-values.json.
func (s *ParitySuite) TestRound18ScopeOneGrantTwoValuesCases() {
	s.runCaseFile("round18/scope-one-grant-two-values.json")
}

// TestRound18ResidualCases runs round18/residual.json.
func (s *ParitySuite) TestRound18ResidualCases() { s.runCaseFile("round18/residual.json") }

// TestRound18ValuesCases runs round18/values.json.
func (s *ParitySuite) TestRound18ValuesCases() { s.runCaseFile("round18/values.json") }

// TestRound18OrderCases runs round18/order.json. It comes last because its
// answers are worth recording only from at least five stands, as in round 17.
func (s *ParitySuite) TestRound18OrderCases() { s.runCaseFile("round18/order.json") }
