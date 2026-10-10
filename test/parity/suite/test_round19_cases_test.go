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

// Round 19 asks again the cases whose check goldens answered 400 because an
// earlier case of their file dropped a PIP that a loaded set still read, asks
// where that state reaches, and asks the rules no golden pins yet: how a
// condition is lexed and parsed, operand contexts no golden reached, and the
// questions round 18 left open. Its cases are data under
// testdata/cases/round19, and each file's about field says what it asks.
//
// A PIP upload replaces the whole declaration of the suite's domain, so in
// every file except stand-rule.json a case with sets that names PIPs also names
// one PIP of each name an earlier case with sets of the file named, and no
// loaded set reads a PIP the declaration lacks. Each function runs one file, so
// that a recording run can be filtered to it and record it on a stand of its
// own.

// TestRound19QuestionsCases runs round19/questions.json.
func (s *ParitySuite) TestRound19QuestionsCases() { s.runCaseFile("round19/questions.json") }

// TestRound19ReaskRound15PairsAnyCases runs round19/reask-round15-pairs-any.json.
func (s *ParitySuite) TestRound19ReaskRound15PairsAnyCases() {
	s.runCaseFile("round19/reask-round15-pairs-any.json")
}

// TestRound19ReaskRound15PairsContainsCases runs
// round19/reask-round15-pairs-contains.json.
func (s *ParitySuite) TestRound19ReaskRound15PairsContainsCases() {
	s.runCaseFile("round19/reask-round15-pairs-contains.json")
}

// TestRound19ReaskRound15PairsInCases runs round19/reask-round15-pairs-in.json.
func (s *ParitySuite) TestRound19ReaskRound15PairsInCases() {
	s.runCaseFile("round19/reask-round15-pairs-in.json")
}

// TestRound19ReaskRound15PairsSubsetCases runs
// round19/reask-round15-pairs-subset.json.
func (s *ParitySuite) TestRound19ReaskRound15PairsSubsetCases() {
	s.runCaseFile("round19/reask-round15-pairs-subset.json")
}

// TestRound19ReaskRound15QuestionsCases runs
// round19/reask-round15-questions.json.
func (s *ParitySuite) TestRound19ReaskRound15QuestionsCases() {
	s.runCaseFile("round19/reask-round15-questions.json")
}

// TestRound19ReaskRound17ResidualCases runs
// round19/reask-round17-residual.json.
func (s *ParitySuite) TestRound19ReaskRound17ResidualCases() {
	s.runCaseFile("round19/reask-round17-residual.json")
}

// TestRound19ReaskRound18ResidualCases runs
// round19/reask-round18-residual.json.
func (s *ParitySuite) TestRound19ReaskRound18ResidualCases() {
	s.runCaseFile("round19/reask-round18-residual.json")
}

// TestRound19LexerCases runs round19/lexer.json. Several of its uploads ask
// the PAP to refuse a text, and a refused upload leaves its check unanswered.
func (s *ParitySuite) TestRound19LexerCases() { s.runCaseFile("round19/lexer.json") }

// TestRound19CustomParamsCases runs round19/custom-params.json.
func (s *ParitySuite) TestRound19CustomParamsCases() { s.runCaseFile("round19/custom-params.json") }

// TestRound19ContextCases runs round19/context.json.
func (s *ParitySuite) TestRound19ContextCases() { s.runCaseFile("round19/context.json") }

// TestRound19ContextOneGrantCases runs round19/context-one-grant.json.
func (s *ParitySuite) TestRound19ContextOneGrantCases() {
	s.runCaseFile("round19/context-one-grant.json")
}

// TestRound19ContextTwoGrantsCases runs round19/context-two-grants.json.
func (s *ParitySuite) TestRound19ContextTwoGrantsCases() {
	s.runCaseFile("round19/context-two-grants.json")
}

// TestRound19KPathsCases runs round19/kpaths.json. Several of its uploads ask
// the PAP to refuse a text.
func (s *ParitySuite) TestRound19KPathsCases() { s.runCaseFile("round19/kpaths.json") }

// TestRound19StandRuleCases runs round19/stand-rule.json. It breaks the stand
// on purpose between s19-reads-b-only and s19-declares-both, so it has to run
// on a stand of its own.
func (s *ParitySuite) TestRound19StandRuleCases() { s.runCaseFile("round19/stand-rule.json") }
