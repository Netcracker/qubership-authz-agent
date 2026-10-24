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

// Round 50 asks which object an identity names in the PAP, and the stored form
// of each field of a PAP write. The papident files write two objects of one
// identity beside a twin with distinct identities; the papfields files write
// one field in several states and read it back after each write. Each case runs
// in a tenant of its own. Each file records the stand's version first and opens
// and closes with a control. The cases are data under testdata/cases/round50,
// and each case's about field says what it asks.

// TestRound50PapfieldsMustCases runs round50/papfields-must.json.
func (s *ParitySuite) TestRound50PapfieldsMustCases() {
	s.runCaseFile("round50/papfields-must.json")
}

// TestRound50PapfieldsShouldCases runs round50/papfields-should.json.
func (s *ParitySuite) TestRound50PapfieldsShouldCases() {
	s.runCaseFile("round50/papfields-should.json")
}

// TestRound50PapidentMustCases runs round50/papident-must.json.
func (s *ParitySuite) TestRound50PapidentMustCases() {
	s.runCaseFile("round50/papident-must.json")
}

// TestRound50PapidentShouldCases runs round50/papident-should.json.
func (s *ParitySuite) TestRound50PapidentShouldCases() {
	s.runCaseFile("round50/papident-should.json")
}

// TestRound50PapidentMayCases runs round50/papident-may.json.
func (s *ParitySuite) TestRound50PapidentMayCases() {
	s.runCaseFile("round50/papident-may.json")
}
