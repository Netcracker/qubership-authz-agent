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

// Round 55 asks what the status of a policy set, a policy, and a rule becomes
// after a lifecycle transition, a re-upload or an import with another status or
// none, or a customization, and whether the entity still takes part in
// decisions and in the v3 export. Each case runs in a tenant of its own. Each
// file records the stand's version first and opens and closes with a control.
// The cases are data under testdata/cases/round55, and each case's about field
// says what it asks.

// TestRound55PapstatusMustCases runs round55/papstatus-must.json.
func (s *ParitySuite) TestRound55PapstatusMustCases() {
	s.runCaseFile("round55/papstatus-must.json")
}

// TestRound55PapstatusShouldCases runs round55/papstatus-should.json.
func (s *ParitySuite) TestRound55PapstatusShouldCases() {
	s.runCaseFile("round55/papstatus-should.json")
}

// TestRound55PapstatusMayCases runs round55/papstatus-may.json.
func (s *ParitySuite) TestRound55PapstatusMayCases() {
	s.runCaseFile("round55/papstatus-may.json")
}
