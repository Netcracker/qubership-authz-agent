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

// Round 47 replays PAP writes that earlier goldens already answered, as
// sequence cases, each in a tenant of its own that no fixture creates. Each
// write now also records its error body, a read-back through the v3 export, a
// raw read of the case's tenant, and, where a check tells the write in effect
// from the state without it, a decision. The must, should, and may files hold
// the cases in the order they are wanted. Each file records the stand's version
// first and opens and closes with a control. The cases are data under
// testdata/cases/round47, and each case's about field says what it asks.

// TestRound47PaporacleMustCases runs round47/paporacle-must.json.
func (s *ParitySuite) TestRound47PaporacleMustCases() {
	s.runCaseFile("round47/paporacle-must.json")
}

// TestRound47PaporacleShouldCases runs round47/paporacle-should.json.
func (s *ParitySuite) TestRound47PaporacleShouldCases() {
	s.runCaseFile("round47/paporacle-should.json")
}

// TestRound47PaporacleMayCases runs round47/paporacle-may.json.
func (s *ParitySuite) TestRound47PaporacleMayCases() {
	s.runCaseFile("round47/paporacle-may.json")
}
