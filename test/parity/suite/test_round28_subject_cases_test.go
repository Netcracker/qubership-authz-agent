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

// Round 28 asks how a scalar placeholder and a placeholder in a GENERAL PIP's
// url carry a value that holds characters the filter dialects or a URL
// reserve, and whether the subject's own attributes compare without regard to
// case. Its cases are data under testdata/cases/round28, and each case's about
// field says what it asks. Each function runs one file, so that a recording
// run can be filtered to it and record it on a stand of its own.

// TestRound28SubjectResourceTypeCases runs round28/subject-resource-type.json.
func (s *ParitySuite) TestRound28SubjectResourceTypeCases() {
	s.runCaseFile("round28/subject-resource-type.json")
}

// TestRound28SubjectUrlCases runs round28/subject-url.json.
func (s *ParitySuite) TestRound28SubjectUrlCases() { s.runCaseFile("round28/subject-url.json") }

// TestRound28SubjectCaseCases runs round28/subject-case.json.
func (s *ParitySuite) TestRound28SubjectCaseCases() { s.runCaseFile("round28/subject-case.json") }

// TestRound28SubjectRealmCases runs round28/subject-realm.json. Its requests
// name users the parity realm has only after the users of
// testdata/realm/round28-subject-users.json are added to it; on a stand without
// them the first request fails on the token and records nothing.
func (s *ParitySuite) TestRound28SubjectRealmCases() { s.runCaseFile("round28/subject-realm.json") }
