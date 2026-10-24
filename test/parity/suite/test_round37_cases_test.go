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

// Round 37 asks which ${subject.X} a GENERAL PIP declaration takes, for
// every builtin of the subject at once: in the url, as a whole
// requestAttributes value, and inside a requestAttributes text, where it
// also puts a declared PIP of each kind. Its cases are data under
// testdata/cases/round37, and each case's about field says what it asks.
// Each function runs one file, so that a recording run can be filtered to
// it and record it on a stand of its own.

// TestRound37OpenUrlCases runs round37/open-url.json.
func (s *ParitySuite) TestRound37OpenUrlCases() { s.runCaseFile("round37/open-url.json") }

// TestRound37OpenRaWholeCases runs round37/open-ra-whole.json.
func (s *ParitySuite) TestRound37OpenRaWholeCases() { s.runCaseFile("round37/open-ra-whole.json") }

// TestRound37OpenRaTextCases runs round37/open-ra-text.json.
func (s *ParitySuite) TestRound37OpenRaTextCases() { s.runCaseFile("round37/open-ra-text.json") }
