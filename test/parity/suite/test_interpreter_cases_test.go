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

// The interpreter cases ask how access-control evaluates conditions, PIP
// declarations, placeholders, and regular policy sets in the corners no other
// golden records. Most of them are data under testdata/cases/interpreter,
// written by generate.py there, which says what each file asks. They were first
// written in Go, and each file sends the requests the Go cases sent, so the
// goldens recorded then still apply. Each function runs one file, so that a
// recording run can be filtered to it and record it on a stand of its own.

// TestInterpreterNullAndAbsenceCases runs interpreter/null-and-absence.json.
func (s *ParitySuite) TestInterpreterNullAndAbsenceCases() {
	s.runCaseFile("interpreter/null-and-absence.json")
}

// TestInterpreterPermissionCaseCases runs interpreter/permission-case.json.
func (s *ParitySuite) TestInterpreterPermissionCaseCases() {
	s.runCaseFile("interpreter/permission-case.json")
}

// TestInterpreterDeadFormCases runs interpreter/dead-form.json.
func (s *ParitySuite) TestInterpreterDeadFormCases() { s.runCaseFile("interpreter/dead-form.json") }

// TestInterpreterCombiningCases runs interpreter/combining.json.
func (s *ParitySuite) TestInterpreterCombiningCases() { s.runCaseFile("interpreter/combining.json") }

// TestInterpreterOperationAllCases runs interpreter/operation-all.json.
func (s *ParitySuite) TestInterpreterOperationAllCases() {
	s.runCaseFile("interpreter/operation-all.json")
}

// TestInterpreterRegularLoadCases runs interpreter/regular-load.json.
func (s *ParitySuite) TestInterpreterRegularLoadCases() {
	s.runCaseFile("interpreter/regular-load.json")
}

// TestInterpreterSetTargetCases runs interpreter/set-target.json.
func (s *ParitySuite) TestInterpreterSetTargetCases() { s.runCaseFile("interpreter/set-target.json") }

// TestInterpreterSubstitutionCases runs interpreter/substitution.json.
func (s *ParitySuite) TestInterpreterSubstitutionCases() {
	s.runCaseFile("interpreter/substitution.json")
}

// TestInterpreterPermissionListCases runs interpreter/permission-list.json.
func (s *ParitySuite) TestInterpreterPermissionListCases() {
	s.runCaseFile("interpreter/permission-list.json")
}

// TestInterpreterAccessOperatorCases runs interpreter/access-operator.json.
func (s *ParitySuite) TestInterpreterAccessOperatorCases() {
	s.runCaseFile("interpreter/access-operator.json")
}

// TestInterpreterBarePathCases runs interpreter/bare-path.json.
func (s *ParitySuite) TestInterpreterBarePathCases() { s.runCaseFile("interpreter/bare-path.json") }

// TestInterpreterDenyPredicateCases runs interpreter/deny-predicate.json.
func (s *ParitySuite) TestInterpreterDenyPredicateCases() {
	s.runCaseFile("interpreter/deny-predicate.json")
}

// TestInterpreterPIPDeclarationCases runs interpreter/pip-declaration.json.
func (s *ParitySuite) TestInterpreterPIPDeclarationCases() {
	s.runCaseFile("interpreter/pip-declaration.json")
}
