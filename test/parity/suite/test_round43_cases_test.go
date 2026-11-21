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

// Round 43 asks which values of the level claim make subject.isM2M true:
// round 42 recorded true for a user whose level is m2m. It also gives a second
// carrier to the keys of a simplified policy's predicates object, with
// mongodbPredicate present so the upload is accepted. The cases are data under
// testdata/cases/round43, and each case's about field says what it asks.

// TestRound43OpenM2mLevelCases runs round43/open-m2m-level.json.
func (s *ParitySuite) TestRound43OpenM2mLevelCases() {
	s.runCaseFile("round43/open-m2m-level.json")
}

// TestRound43OpenPredicatesCarriersCases runs round43/open-predicates-carriers.json.
func (s *ParitySuite) TestRound43OpenPredicatesCarriersCases() {
	s.runCaseFile("round43/open-predicates-carriers.json")
}
