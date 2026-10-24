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

// Round 13 asks, among other things, what an iterate node over zero, one, and
// two grants gives the sets around it, where the failure of a
// subject.permissionScope read outside iterate ends, what an ALLOW without a
// predicate and a set none of whose policies applies do in check/filter, what
// the PAP accepts, and what every operator answers over every operand state no
// golden fixes. Its cases are data
// under testdata/cases/round13, written by generate.py there, which says what each
// file asks. They were first written in Go, and each file sends the requests the
// Go cases sent, so the goldens recorded then still apply. Each function runs one
// file, so that a recording run can be filtered to it and record it on a stand of
// its own.

// TestRound13ScopeOutsideIterateCases runs round13/scope-outside-iterate.json.
func (s *ParitySuite) TestRound13ScopeOutsideIterateCases() {
	s.runCaseFile("round13/scope-outside-iterate.json")
}

// TestRound13FilterCases runs round13/filter.json.
func (s *ParitySuite) TestRound13FilterCases() { s.runCaseFile("round13/filter.json") }

// TestRound13PAPSyntaxCases runs round13/pap-syntax.json.
func (s *ParitySuite) TestRound13PAPSyntaxCases() { s.runCaseFile("round13/pap-syntax.json") }

// TestRound13CellCases runs round13/cells.json.
func (s *ParitySuite) TestRound13CellCases() { s.runCaseFile("round13/cells.json") }

// TestRound13FailingPIPInADenyRuleCases runs
// round13/failing-pip-in-a-deny-rule.json.
func (s *ParitySuite) TestRound13FailingPIPInADenyRuleCases() {
	s.runCaseFile("round13/failing-pip-in-a-deny-rule.json")
}

// TestRound13IterateCases runs round13/iterate.json.
func (s *ParitySuite) TestRound13IterateCases() { s.runCaseFile("round13/iterate.json") }
