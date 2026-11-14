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

// Round 46 asks five things no earlier golden answers. The diff2 files hold
// the smallest inputs on which the specification and two second models,
// written apart from it, answer differently. The spell files hold spellings of
// one value in a literal, around it in the condition, on the data side, and in
// the status of a set. The spellpos files hold spellings at the other places
// of a condition, split into must, should, and may files, most wanted first.
// The rawpairs files hold combinations of raw input features no golden sent
// together. The hyp files hold the cases that tell an open hypothesis from the
// specification. Each file records the stand's version first and opens and
// closes with a control. The cases are data under testdata/cases/round46, and
// each file's about field says what it asks.

// TestRound46Diff2Part01Cases runs round46/diff2-1.json.
func (s *ParitySuite) TestRound46Diff2Part01Cases() {
	s.runCaseFile("round46/diff2-1.json")
}

// TestRound46Diff2Part02Cases runs round46/diff2-2.json.
func (s *ParitySuite) TestRound46Diff2Part02Cases() {
	s.runCaseFile("round46/diff2-2.json")
}

// TestRound46Diff2Part03Cases runs round46/diff2-3.json.
func (s *ParitySuite) TestRound46Diff2Part03Cases() {
	s.runCaseFile("round46/diff2-3.json")
}

// TestRound46Diff2Part04Cases runs round46/diff2-4.json.
func (s *ParitySuite) TestRound46Diff2Part04Cases() {
	s.runCaseFile("round46/diff2-4.json")
}

// TestRound46Diff2Part05Cases runs round46/diff2-5.json.
func (s *ParitySuite) TestRound46Diff2Part05Cases() {
	s.runCaseFile("round46/diff2-5.json")
}

// TestRound46Diff2Part06Cases runs round46/diff2-6.json.
func (s *ParitySuite) TestRound46Diff2Part06Cases() {
	s.runCaseFile("round46/diff2-6.json")
}

// TestRound46Diff2Part07Cases runs round46/diff2-7.json.
func (s *ParitySuite) TestRound46Diff2Part07Cases() {
	s.runCaseFile("round46/diff2-7.json")
}

// TestRound46Diff2Part08Cases runs round46/diff2-8.json.
func (s *ParitySuite) TestRound46Diff2Part08Cases() {
	s.runCaseFile("round46/diff2-8.json")
}

// TestRound46Diff2Part09Cases runs round46/diff2-9.json.
func (s *ParitySuite) TestRound46Diff2Part09Cases() {
	s.runCaseFile("round46/diff2-9.json")
}

// TestRound46Diff2Part10Cases runs round46/diff2-10.json.
func (s *ParitySuite) TestRound46Diff2Part10Cases() {
	s.runCaseFile("round46/diff2-10.json")
}

// TestRound46Diff2Part11Cases runs round46/diff2-11.json.
func (s *ParitySuite) TestRound46Diff2Part11Cases() {
	s.runCaseFile("round46/diff2-11.json")
}

// TestRound46Diff2Part12Cases runs round46/diff2-12.json.
func (s *ParitySuite) TestRound46Diff2Part12Cases() {
	s.runCaseFile("round46/diff2-12.json")
}

// TestRound46Diff2Part13Cases runs round46/diff2-13.json.
func (s *ParitySuite) TestRound46Diff2Part13Cases() {
	s.runCaseFile("round46/diff2-13.json")
}

// TestRound46Diff2Part14Cases runs round46/diff2-14.json.
func (s *ParitySuite) TestRound46Diff2Part14Cases() {
	s.runCaseFile("round46/diff2-14.json")
}

// TestRound46Diff2Part15Cases runs round46/diff2-15.json.
func (s *ParitySuite) TestRound46Diff2Part15Cases() {
	s.runCaseFile("round46/diff2-15.json")
}

// TestRound46Diff2Part16Cases runs round46/diff2-16.json.
func (s *ParitySuite) TestRound46Diff2Part16Cases() {
	s.runCaseFile("round46/diff2-16.json")
}

// TestRound46Diff2Part17Cases runs round46/diff2-17.json.
func (s *ParitySuite) TestRound46Diff2Part17Cases() {
	s.runCaseFile("round46/diff2-17.json")
}

// TestRound46Diff2Part18Cases runs round46/diff2-18.json.
func (s *ParitySuite) TestRound46Diff2Part18Cases() {
	s.runCaseFile("round46/diff2-18.json")
}

// TestRound46Diff2Part19Cases runs round46/diff2-19.json.
func (s *ParitySuite) TestRound46Diff2Part19Cases() {
	s.runCaseFile("round46/diff2-19.json")
}

// TestRound46Diff2Part20Cases runs round46/diff2-20.json.
func (s *ParitySuite) TestRound46Diff2Part20Cases() {
	s.runCaseFile("round46/diff2-20.json")
}

// TestRound46Diff2Part21Cases runs round46/diff2-21.json.
func (s *ParitySuite) TestRound46Diff2Part21Cases() {
	s.runCaseFile("round46/diff2-21.json")
}

// TestRound46Diff2Part22Cases runs round46/diff2-22.json.
func (s *ParitySuite) TestRound46Diff2Part22Cases() {
	s.runCaseFile("round46/diff2-22.json")
}

// TestRound46Diff2Part23Cases runs round46/diff2-23.json.
func (s *ParitySuite) TestRound46Diff2Part23Cases() {
	s.runCaseFile("round46/diff2-23.json")
}

// TestRound46Diff2Part24Cases runs round46/diff2-24.json.
func (s *ParitySuite) TestRound46Diff2Part24Cases() {
	s.runCaseFile("round46/diff2-24.json")
}

// TestRound46Diff2Part25Cases runs round46/diff2-25.json.
func (s *ParitySuite) TestRound46Diff2Part25Cases() {
	s.runCaseFile("round46/diff2-25.json")
}

// TestRound46Diff2Part26Cases runs round46/diff2-26.json.
func (s *ParitySuite) TestRound46Diff2Part26Cases() {
	s.runCaseFile("round46/diff2-26.json")
}

// TestRound46Diff2Part27Cases runs round46/diff2-27.json.
func (s *ParitySuite) TestRound46Diff2Part27Cases() {
	s.runCaseFile("round46/diff2-27.json")
}

// TestRound46Diff2Part28Cases runs round46/diff2-28.json.
func (s *ParitySuite) TestRound46Diff2Part28Cases() {
	s.runCaseFile("round46/diff2-28.json")
}

// TestRound46Diff2Part29Cases runs round46/diff2-29.json.
func (s *ParitySuite) TestRound46Diff2Part29Cases() {
	s.runCaseFile("round46/diff2-29.json")
}

// TestRound46Diff2Part30Cases runs round46/diff2-30.json.
func (s *ParitySuite) TestRound46Diff2Part30Cases() {
	s.runCaseFile("round46/diff2-30.json")
}

// TestRound46Diff2Part31Cases runs round46/diff2-31.json.
func (s *ParitySuite) TestRound46Diff2Part31Cases() {
	s.runCaseFile("round46/diff2-31.json")
}

// TestRound46Diff2Part32Cases runs round46/diff2-32.json.
func (s *ParitySuite) TestRound46Diff2Part32Cases() {
	s.runCaseFile("round46/diff2-32.json")
}

// TestRound46Diff2Part33Cases runs round46/diff2-33.json.
func (s *ParitySuite) TestRound46Diff2Part33Cases() {
	s.runCaseFile("round46/diff2-33.json")
}

// TestRound46Diff2Part34Cases runs round46/diff2-34.json.
func (s *ParitySuite) TestRound46Diff2Part34Cases() {
	s.runCaseFile("round46/diff2-34.json")
}

// TestRound46Diff2Part35Cases runs round46/diff2-35.json.
func (s *ParitySuite) TestRound46Diff2Part35Cases() {
	s.runCaseFile("round46/diff2-35.json")
}

// TestRound46Diff2Part36Cases runs round46/diff2-36.json.
func (s *ParitySuite) TestRound46Diff2Part36Cases() {
	s.runCaseFile("round46/diff2-36.json")
}

// TestRound46Diff2Part37Cases runs round46/diff2-37.json.
func (s *ParitySuite) TestRound46Diff2Part37Cases() {
	s.runCaseFile("round46/diff2-37.json")
}

// TestRound46Diff2Part38Cases runs round46/diff2-38.json.
func (s *ParitySuite) TestRound46Diff2Part38Cases() {
	s.runCaseFile("round46/diff2-38.json")
}

// TestRound46Diff2Part39Cases runs round46/diff2-39.json.
func (s *ParitySuite) TestRound46Diff2Part39Cases() {
	s.runCaseFile("round46/diff2-39.json")
}

// TestRound46Diff2Part40Cases runs round46/diff2-40.json.
func (s *ParitySuite) TestRound46Diff2Part40Cases() {
	s.runCaseFile("round46/diff2-40.json")
}

// TestRound46Diff2Part41Cases runs round46/diff2-41.json.
func (s *ParitySuite) TestRound46Diff2Part41Cases() {
	s.runCaseFile("round46/diff2-41.json")
}

// TestRound46Diff2Part42Cases runs round46/diff2-42.json.
func (s *ParitySuite) TestRound46Diff2Part42Cases() {
	s.runCaseFile("round46/diff2-42.json")
}

// TestRound46Diff2Part43Cases runs round46/diff2-43.json.
func (s *ParitySuite) TestRound46Diff2Part43Cases() {
	s.runCaseFile("round46/diff2-43.json")
}

// TestRound46Diff2Part44Cases runs round46/diff2-44.json.
func (s *ParitySuite) TestRound46Diff2Part44Cases() {
	s.runCaseFile("round46/diff2-44.json")
}

// TestRound46Diff2Part45Cases runs round46/diff2-45.json.
func (s *ParitySuite) TestRound46Diff2Part45Cases() {
	s.runCaseFile("round46/diff2-45.json")
}

// TestRound46Diff2Part46Cases runs round46/diff2-46.json.
func (s *ParitySuite) TestRound46Diff2Part46Cases() {
	s.runCaseFile("round46/diff2-46.json")
}

// TestRound46SpellDataCases runs round46/spell-data.json.
func (s *ParitySuite) TestRound46SpellDataCases() {
	s.runCaseFile("round46/spell-data.json")
}

// TestRound46SpellFieldsCases runs round46/spell-fields.json.
func (s *ParitySuite) TestRound46SpellFieldsCases() {
	s.runCaseFile("round46/spell-fields.json")
}

// TestRound46SpellLiteralsCases runs round46/spell-literals.json.
func (s *ParitySuite) TestRound46SpellLiteralsCases() {
	s.runCaseFile("round46/spell-literals.json")
}

// TestRound46SpellSyntaxCases runs round46/spell-syntax.json.
func (s *ParitySuite) TestRound46SpellSyntaxCases() {
	s.runCaseFile("round46/spell-syntax.json")
}

// TestRound46SpellposMayCases runs round46/spellpos-may.json.
func (s *ParitySuite) TestRound46SpellposMayCases() {
	s.runCaseFile("round46/spellpos-may.json")
}

// TestRound46SpellposMustCases runs round46/spellpos-must.json.
func (s *ParitySuite) TestRound46SpellposMustCases() {
	s.runCaseFile("round46/spellpos-must.json")
}

// TestRound46SpellposShouldCases runs round46/spellpos-should.json.
func (s *ParitySuite) TestRound46SpellposShouldCases() {
	s.runCaseFile("round46/spellpos-should.json")
}

// TestRound46RawpairsG0Cases runs round46/rawpairs-g0.json.
func (s *ParitySuite) TestRound46RawpairsG0Cases() {
	s.runCaseFile("round46/rawpairs-g0.json")
}

// TestRound46RawpairsG1Cases runs round46/rawpairs-g1.json.
func (s *ParitySuite) TestRound46RawpairsG1Cases() {
	s.runCaseFile("round46/rawpairs-g1.json")
}

// TestRound46RawpairsG2Cases runs round46/rawpairs-g2.json.
func (s *ParitySuite) TestRound46RawpairsG2Cases() {
	s.runCaseFile("round46/rawpairs-g2.json")
}

// TestRound46RawpairsGfailCases runs round46/rawpairs-gfail.json.
func (s *ParitySuite) TestRound46RawpairsGfailCases() {
	s.runCaseFile("round46/rawpairs-gfail.json")
}

// TestRound46RawpairsGnoneCases runs round46/rawpairs-gnone.json.
func (s *ParitySuite) TestRound46RawpairsGnoneCases() {
	s.runCaseFile("round46/rawpairs-gnone.json")
}

// TestRound46RawpairsHeadsCases runs round46/rawpairs-heads.json.
func (s *ParitySuite) TestRound46RawpairsHeadsCases() {
	s.runCaseFile("round46/rawpairs-heads.json")
}

// TestRound46HypEnumsCases runs round46/hyp-enums.json.
func (s *ParitySuite) TestRound46HypEnumsCases() {
	s.runCaseFile("round46/hyp-enums.json")
}

// TestRound46HypListsCases runs round46/hyp-lists.json.
func (s *ParitySuite) TestRound46HypListsCases() {
	s.runCaseFile("round46/hyp-lists.json")
}

// TestRound46HypPIPTypeCases runs round46/hyp-pip-type.json.
func (s *ParitySuite) TestRound46HypPIPTypeCases() {
	s.runCaseFile("round46/hyp-pip-type.json")
}

// TestRound46HypPIPTypeTwinCases runs round46/hyp-pip-type-twin.json.
func (s *ParitySuite) TestRound46HypPIPTypeTwinCases() {
	s.runCaseFile("round46/hyp-pip-type-twin.json")
}

// TestRound46HypURLsCases runs round46/hyp-urls.json.
func (s *ParitySuite) TestRound46HypURLsCases() {
	s.runCaseFile("round46/hyp-urls.json")
}
