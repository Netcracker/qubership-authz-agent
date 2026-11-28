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

// Round 73 asks which claim gives subject.id for the suite's service account,
// whose token has no client_id, sent alone in Authorization and under
// Authorization-Type: anonymous. The cases run in the default tenant on the
// plain stand. They are data under testdata/cases/round73, and each case's
// about field says what it asks.

// TestRound73TokensubjectClaimsCases runs round73/tokensubject-claims.json.
func (s *ParitySuite) TestRound73TokensubjectClaimsCases() {
	s.runCaseFile("round73/tokensubject-claims.json")
}
