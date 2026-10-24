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

// Round 7 asks, among other things, what a rule reading a failed GENERAL PIP
// does beside a rule that allows, whether a set target that reads an absent
// resource attribute is refused, and what check/filter does with a rule
// without a predicate. Three of its functions run data under
// testdata/cases/round7, written by generate.py there, which says what each
// file asks. They were first written in Go, and each file sends the requests
// the Go cases sent, so the goldens recorded then still apply. Each function
// runs one file, so that a recording run can be filtered to it and record it
// on a stand of its own.

// TestRound7FailedPIPCases runs round7/failed-pip-beside-allow.json.
func (s *ParitySuite) TestRound7FailedPIPCases() {
	s.runCaseFile("round7/failed-pip-beside-allow.json")
}

// TestRound7SetTargetRefusalCases runs round7/set-target-refusal.json.
func (s *ParitySuite) TestRound7SetTargetRefusalCases() {
	s.runCaseFile("round7/set-target-refusal.json")
}

// TestRound7FilterCases runs round7/filter.json.
func (s *ParitySuite) TestRound7FilterCases() { s.runCaseFile("round7/filter.json") }
