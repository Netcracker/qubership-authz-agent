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

// Round 38 asks what a path after a builtin of the subject, such as
// ${subject.id.x}, does in a GENERAL PIP declaration: in the url and as a
// whole requestAttributes value, for every builtin. It also asks where a
// whole ${subject.isM2M} in requestAttributes fails: in a check that does
// not reach the PIP, and in a filter that reads it. Its cases are data
// under testdata/cases/round38, and each case's about field says what it
// asks. Each function runs one file, so that a recording run can be
// filtered to it and record it on a stand of its own.

// TestRound38OpenUrlPathCases runs round38/open-url-path.json.
func (s *ParitySuite) TestRound38OpenUrlPathCases() { s.runCaseFile("round38/open-url-path.json") }

// TestRound38OpenRaPathCases runs round38/open-ra-path.json.
func (s *ParitySuite) TestRound38OpenRaPathCases() { s.runCaseFile("round38/open-ra-path.json") }

// TestRound38OpenM2mCases runs round38/open-m2m.json.
func (s *ParitySuite) TestRound38OpenM2mCases() { s.runCaseFile("round38/open-m2m.json") }
