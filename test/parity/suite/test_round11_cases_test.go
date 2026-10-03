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

// Round 11 asks, among other things, whether operators over an absent key, a
// null, and an empty collection are false or end the rule, what the PAP does
// with a PIP named subject.isM2M or subject.permissions, how check/filter
// combines a nested set that does not apply, what
// subject.permissionScope.<key> resolves to outside iterate, which fields a
// FILTERED declaration needs, how often a GENERAL PIP read twice in one
// condition is called, and whether a cacheable GENERAL PIP serves one
// subject's value to another. Those cases are
// data under testdata/cases/round11, written by generate.py there, which says
// what each file asks. They were first written in Go, and each file sends the
// requests the Go cases sent, so the goldens recorded then still apply. Each
// function runs one file, so that a recording run can be filtered to it and
// record it on a stand of its own.

// TestRound11AbsentKeyProbeCases runs round11/absent-key-probe.json.
func (s *ParitySuite) TestRound11AbsentKeyProbeCases() {
	s.runCaseFile("round11/absent-key-probe.json")
}

// TestRound11NullProbeCases runs round11/null-probe.json.
func (s *ParitySuite) TestRound11NullProbeCases() { s.runCaseFile("round11/null-probe.json") }

// TestRound11EmptyCollectionCases runs round11/empty-collection.json.
func (s *ParitySuite) TestRound11EmptyCollectionCases() {
	s.runCaseFile("round11/empty-collection.json")
}

// TestRound11NullBodyProbeCases runs round11/null-body-probe.json.
func (s *ParitySuite) TestRound11NullBodyProbeCases() {
	s.runCaseFile("round11/null-body-probe.json")
}

// TestRound11NullLiteralAndRightOperandCases runs
// round11/null-literal-and-right-operand.json.
func (s *ParitySuite) TestRound11NullLiteralAndRightOperandCases() {
	s.runCaseFile("round11/null-literal-and-right-operand.json")
}

// TestRound11DeclaredNameCases runs round11/declared-name.json.
func (s *ParitySuite) TestRound11DeclaredNameCases() {
	s.runCaseFile("round11/declared-name.json")
}

// TestRound11FilterNodeCases runs round11/filter-node.json.
func (s *ParitySuite) TestRound11FilterNodeCases() { s.runCaseFile("round11/filter-node.json") }

// TestRound11ScopeOutsideIterateCases runs round11/scope-outside-iterate.json.
func (s *ParitySuite) TestRound11ScopeOutsideIterateCases() {
	s.runCaseFile("round11/scope-outside-iterate.json")
}

// TestRound11FilteredDeclarationCases runs round11/filtered-declaration.json.
func (s *ParitySuite) TestRound11FilteredDeclarationCases() {
	s.runCaseFile("round11/filtered-declaration.json")
}

// TestRound11PIPCallsPerRequestCases runs round11/pip-calls-per-request.json.
func (s *ParitySuite) TestRound11PIPCallsPerRequestCases() {
	s.runCaseFile("round11/pip-calls-per-request.json")
}

// TestRound11PIPCachePerSubjectCases runs round11/pip-cache-per-subject.json.
func (s *ParitySuite) TestRound11PIPCachePerSubjectCases() {
	s.runCaseFile("round11/pip-cache-per-subject.json")
}
