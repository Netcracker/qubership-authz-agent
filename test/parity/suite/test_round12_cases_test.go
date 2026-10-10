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

// Round 12 asks whether a read of subject.permissionScope outside iterate ends
// its rule or leaves its policy unreached, and what check/filter answers for a
// node with no applicable child. Its cases are data under
// testdata/cases/round12, written by generate.py there, which says what each
// file asks. They were first written in Go, and each file sends the requests
// the Go cases sent, so the goldens recorded then still apply.

// TestRound12ScopeOutsideIterateControlCases runs
// round12/scope-outside-iterate-control.json.
func (s *ParitySuite) TestRound12ScopeOutsideIterateControlCases() {
	s.runCaseFile("round12/scope-outside-iterate-control.json")
}

// TestRound12NotApplicableFilterCases runs round12/not-applicable-filter.json.
func (s *ParitySuite) TestRound12NotApplicableFilterCases() {
	s.runCaseFile("round12/not-applicable-filter.json")
}

// TestRound12IterateNodeInAFilterCases runs round12/iterate-node-in-a-filter.json.
func (s *ParitySuite) TestRound12IterateNodeInAFilterCases() {
	s.runCaseFile("round12/iterate-node-in-a-filter.json")
}
