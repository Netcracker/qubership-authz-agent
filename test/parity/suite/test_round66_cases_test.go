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

// Round 66 asks the PAP questions left open after round 65 and the re-record
// of rounds 45 and 47 to 60: another tenant's set customization seen by
// decisions in both tenants, the copy of a customized set under another letter
// case, field states each under a resource type of its own, metamorphic pairs
// built from the reads the stand recorded, obligations writes no round sent,
// and the User Management stub answering a user's roles under realmRoles.
// Every step that asks for a decision is followed by raw reads of both
// exports, policy sets and PIPs. Each case runs in a tenant of its own, and
// each file opens and closes with a control. The cases are data under
// testdata/cases/round66, and each case's about field says what it asks.

// TestRound66ObligationsOnBehalfCases runs round66/obligations-on-behalf.json.
func (s *ParitySuite) TestRound66ObligationsOnBehalfCases() {
	s.runCaseFile("round66/obligations-on-behalf.json")
}

// TestRound66OpenCopyCases runs round66/open-copy.json.
func (s *ParitySuite) TestRound66OpenCopyCases() {
	s.runCaseFile("round66/open-copy.json")
}

// TestRound66OpenForeignMoveCases runs round66/open-foreign-move.json.
func (s *ParitySuite) TestRound66OpenForeignMoveCases() {
	s.runCaseFile("round66/open-foreign-move.json")
}

// TestRound66OpenGapsCases runs round66/open-gaps.json.
func (s *ParitySuite) TestRound66OpenGapsCases() {
	s.runCaseFile("round66/open-gaps.json")
}

// TestRound66OpenObligationsCases runs round66/open-obligations.json.
func (s *ParitySuite) TestRound66OpenObligationsCases() {
	s.runCaseFile("round66/open-obligations.json")
}

// TestRound66OpenPapseqCases runs round66/open-papseq.json.
func (s *ParitySuite) TestRound66OpenPapseqCases() {
	s.runCaseFile("round66/open-papseq.json")
}

// TestRound66OpenSurvivorsCases runs round66/open-survivors.json.
func (s *ParitySuite) TestRound66OpenSurvivorsCases() {
	s.runCaseFile("round66/open-survivors.json")
}

// TestRound66PapfieldsMayCases runs round66/papfields-may.json.
func (s *ParitySuite) TestRound66PapfieldsMayCases() {
	s.runCaseFile("round66/papfields-may.json")
}

// TestRound66PapfieldsShouldCases runs round66/papfields-should.json.
func (s *ParitySuite) TestRound66PapfieldsShouldCases() {
	s.runCaseFile("round66/papfields-should.json")
}

// TestRound66PapmetaMustCases runs round66/papmeta-must.json.
func (s *ParitySuite) TestRound66PapmetaMustCases() {
	s.runCaseFile("round66/papmeta-must.json")
}

// TestRound66PapmetaShouldCases runs round66/papmeta-should.json.
func (s *ParitySuite) TestRound66PapmetaShouldCases() {
	s.runCaseFile("round66/papmeta-should.json")
}
