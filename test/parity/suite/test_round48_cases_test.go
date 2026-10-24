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

// Round 48 asks what a PAP write keeps and what a read returns. Each case runs
// in a tenant of its own that no fixture creates and writes to a domain and an
// externalId of its own. Each file records the stand's version first and opens
// and closes with a control. The cases are data under testdata/cases/round48,
// and each case's about field says what it asks.

// TestRound48PapstateMustCases runs round48/papstate-must.json.
func (s *ParitySuite) TestRound48PapstateMustCases() {
	s.runCaseFile("round48/papstate-must.json")
}

// TestRound48PapstateShouldCases runs round48/papstate-should.json.
func (s *ParitySuite) TestRound48PapstateShouldCases() {
	s.runCaseFile("round48/papstate-should.json")
}
