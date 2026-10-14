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

// Round 51 asks whether one policySetId written in two tenants names one set or
// two. Each case writes the set in its own tenant and, from steps, in a second
// tenant, and decides in both. Each file records the stand's version first and
// opens and closes with a control. The cases are data under
// testdata/cases/round51, and each case's about field says what it asks.

// TestRound51PapidentMustCases runs round51/papident-must.json.
func (s *ParitySuite) TestRound51PapidentMustCases() {
	s.runCaseFile("round51/papident-must.json")
}
