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

// Round 54 asks what round 53 and round 50 left: the shape of a write body
// (papstate), more short sequences of PAP operations, some with a step in a
// second tenant (papseq), and more field states read back after each write
// (papfields). Each case runs in a tenant of its own; the papseq controls
// replay a round 45 case in the default tenant. Each file records the stand's
// version first and opens and closes with a control. The cases are data under
// testdata/cases/round54, and each case's about field says what it asks.

// TestRound54PapfieldsMustCases runs round54/papfields-must.json.
func (s *ParitySuite) TestRound54PapfieldsMustCases() {
	s.runCaseFile("round54/papfields-must.json")
}

// TestRound54PapfieldsShouldCases runs round54/papfields-should.json.
func (s *ParitySuite) TestRound54PapfieldsShouldCases() {
	s.runCaseFile("round54/papfields-should.json")
}

// TestRound54PapfieldsMayCases runs round54/papfields-may.json.
func (s *ParitySuite) TestRound54PapfieldsMayCases() {
	s.runCaseFile("round54/papfields-may.json")
}

// TestRound54PapseqMustCases runs round54/papseq-must.json.
func (s *ParitySuite) TestRound54PapseqMustCases() {
	s.runCaseFile("round54/papseq-must.json")
}

// TestRound54PapseqShouldCases runs round54/papseq-should.json.
func (s *ParitySuite) TestRound54PapseqShouldCases() {
	s.runCaseFile("round54/papseq-should.json")
}

// TestRound54PapseqMayCases runs round54/papseq-may.json.
func (s *ParitySuite) TestRound54PapseqMayCases() {
	s.runCaseFile("round54/papseq-may.json")
}

// TestRound54PapstateMustCases runs round54/papstate-must.json.
func (s *ParitySuite) TestRound54PapstateMustCases() {
	s.runCaseFile("round54/papstate-must.json")
}
