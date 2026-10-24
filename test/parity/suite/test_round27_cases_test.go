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

// Round 27 asks how a list inside a list compares, element by element or by
// its text, and whether order counts; and the four comparisons that no golden
// reached after round 26. Its cases are data under testdata/cases/round27, and
// each case's about field says what it asks. Each function runs one file, so
// that a recording run can be filtered to it and record it on a stand of its
// own.

// TestRound27ListsCases runs round27/lists.json.
func (s *ParitySuite) TestRound27ListsCases() { s.runCaseFile("round27/lists.json") }

// TestRound27ResidualCases runs round27/residual.json.
func (s *ParitySuite) TestRound27ResidualCases() { s.runCaseFile("round27/residual.json") }
