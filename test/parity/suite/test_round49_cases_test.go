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

// Round 49 asks metamorphic relations over PAP operations: two sequences, or
// two points of one, whose reads and decisions must agree, such as a write
// repeated, undone, exported and imported again, reordered, split, or sent
// through another endpoint of the same operation. Each case runs in a tenant of
// its own, and a step that writes the same names in a second tenant names that
// tenant. Each file records the stand's version first and opens and closes with
// a control. The cases are data under testdata/cases/round49, and each case's
// about field says what it asks.

// TestRound49PapmetaMustCases runs round49/papmeta-must.json.
func (s *ParitySuite) TestRound49PapmetaMustCases() {
	s.runCaseFile("round49/papmeta-must.json")
}

// TestRound49PapmetaShouldCases runs round49/papmeta-should.json.
func (s *ParitySuite) TestRound49PapmetaShouldCases() {
	s.runCaseFile("round49/papmeta-should.json")
}

// TestRound49PapmetaMayCases runs round49/papmeta-may.json.
func (s *ParitySuite) TestRound49PapmetaMayCases() {
	s.runCaseFile("round49/papmeta-may.json")
}
