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

// Round 32 asks what round 31 left open: which child of a nested set decides
// the case that answered differently from stand to stand, a GENERAL PIP whose
// url names a HEADER, a MAPPING, or the PERMISSION_SCOPE PIP, inputs no golden
// reached, and forms that real configurations use and no golden sends. Its
// cases are data under testdata/cases/round32, and each case's about field
// says what it asks. Each function runs one file, so that a recording run can
// be filtered to it and record it on a stand of its own.

// TestRound32GapsCorpusIdsCases runs round32/gaps-corpus-ids.json.
func (s *ParitySuite) TestRound32GapsCorpusIdsCases() { s.runCaseFile("round32/gaps-corpus-ids.json") }

// TestRound32GapsCorpusPipsCases runs round32/gaps-corpus-pips.json.
func (s *ParitySuite) TestRound32GapsCorpusPipsCases() {
	s.runCaseFile("round32/gaps-corpus-pips.json")
}

// TestRound32GapsCorpusSyntaxCases runs round32/gaps-corpus-syntax.json.
func (s *ParitySuite) TestRound32GapsCorpusSyntaxCases() {
	s.runCaseFile("round32/gaps-corpus-syntax.json")
}

// TestRound32GapsFilterCases runs round32/gaps-filter.json.
func (s *ParitySuite) TestRound32GapsFilterCases() { s.runCaseFile("round32/gaps-filter.json") }

// TestRound32GapsOnBehalfCases runs round32/gaps-on-behalf.json.
func (s *ParitySuite) TestRound32GapsOnBehalfCases() { s.runCaseFile("round32/gaps-on-behalf.json") }

// TestRound32GapsPapCases runs round32/gaps-pap.json.
func (s *ParitySuite) TestRound32GapsPapCases() { s.runCaseFile("round32/gaps-pap.json") }

// TestRound32GapsValuesCases runs round32/gaps-values.json.
func (s *ParitySuite) TestRound32GapsValuesCases() { s.runCaseFile("round32/gaps-values.json") }

// TestRound32OpenOrderCases runs round32/open-order.json.
// Its requests classed by classifyBy take runs on several stands.
func (s *ParitySuite) TestRound32OpenOrderCases() { s.runCaseFile("round32/open-order.json") }

// TestRound32OpenUrlKindsCases runs round32/open-url-kinds.json.
func (s *ParitySuite) TestRound32OpenUrlKindsCases() {
	s.runCaseFile("round32/open-url-kinds.json")
}
