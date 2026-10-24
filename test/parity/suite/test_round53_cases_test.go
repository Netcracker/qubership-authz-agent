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

// Round 53 sends short sequences of PAP operations that no recorded answer
// covers: an operation after earlier steps left its target present, inactive,
// customized, deleted, emptied, or refused, on the same key, another spelling
// of it, or the key at another place. Each case runs in a tenant of its own;
// the controls replay a round 45 case in the default tenant. Each file records
// the stand's version first and opens and closes with a control. The cases are
// data under testdata/cases/round53, and each case's about field says what it
// asks.

// TestRound53PapseqMustCases runs round53/papseq-must.json.
func (s *ParitySuite) TestRound53PapseqMustCases() {
	s.runCaseFile("round53/papseq-must.json")
}

// TestRound53PapseqShouldCases runs round53/papseq-should.json.
func (s *ParitySuite) TestRound53PapseqShouldCases() {
	s.runCaseFile("round53/papseq-should.json")
}

// TestRound53PapseqMayCases runs round53/papseq-may.json.
func (s *ParitySuite) TestRound53PapseqMayCases() {
	s.runCaseFile("round53/papseq-may.json")
}
