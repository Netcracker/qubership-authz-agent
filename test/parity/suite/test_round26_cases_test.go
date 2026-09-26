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

// Round 26 asks the comparisons that no golden reached after round 25: a GENERAL
// PIP that fails on the right beside a special state on the left, for the
// operator and state pairs not yet recorded; a number or boolean GENERAL body,
// mostly on the right of each operator; objects beside strings, a number
// beside a nested list, and a HEADER list beside a list; and a nested list
// under CONTAINS ANY and NOT CONTAINS ANY. Its cases are data under testdata/cases/round26, and
// each case's about field says what it asks. Each function runs one file, so
// that a recording run can be filtered to it and record it on a stand of its
// own.

// TestRound26RightErrorFirstCases runs round26/right-error-first.json.
func (s *ParitySuite) TestRound26RightErrorFirstCases() {
	s.runCaseFile("round26/right-error-first.json")
}

// TestRound26GeneralScalarCases runs round26/general-scalar.json.
func (s *ParitySuite) TestRound26GeneralScalarCases() { s.runCaseFile("round26/general-scalar.json") }

// TestRound26ResidualCases runs round26/residual.json.
func (s *ParitySuite) TestRound26ResidualCases() { s.runCaseFile("round26/residual.json") }

// TestRound26HypothesesCases runs round26/hypotheses.json.
func (s *ParitySuite) TestRound26HypothesesCases() { s.runCaseFile("round26/hypotheses.json") }
