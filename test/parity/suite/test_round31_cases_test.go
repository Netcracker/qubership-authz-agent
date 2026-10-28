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

// Round 31 asks what round 30 left open: a GENERAL PIP whose url reads a
// remote PIP, customizations of a top-level set out of service, the sets of
// two round 30 cases that changed from stand to stand, asked again apart,
// inputs no golden reached, and the configuration pairs of a replace or a
// disable under a top-level set a customization sees. Its cases are data under
// testdata/cases/round31, and each case's about field says what it asks. Each
// function runs one file, so that a recording run can be filtered to it and
// record it on a stand of its own.

// TestRound31FixesOnBehalfCases runs round31/fixes-on-behalf.json.
func (s *ParitySuite) TestRound31FixesOnBehalfCases() { s.runCaseFile("round31/fixes-on-behalf.json") }

// TestRound31FixesOrderChildrenCases runs round31/fixes-order-children.json.
// Its requests classed by classifyBy take runs on several stands.
func (s *ParitySuite) TestRound31FixesOrderChildrenCases() {
	s.runCaseFile("round31/fixes-order-children.json")
}

// TestRound31GapsCustomPipsCases runs round31/gaps-custom-pips.json.
func (s *ParitySuite) TestRound31GapsCustomPipsCases() {
	s.runCaseFile("round31/gaps-custom-pips.json")
}

// TestRound31GapsFilterCases runs round31/gaps-filter.json.
func (s *ParitySuite) TestRound31GapsFilterCases() { s.runCaseFile("round31/gaps-filter.json") }

// TestRound31GapsPapCases runs round31/gaps-pap.json.
func (s *ParitySuite) TestRound31GapsPapCases() { s.runCaseFile("round31/gaps-pap.json") }

// TestRound31GapsValuesCases runs round31/gaps-values.json.
func (s *ParitySuite) TestRound31GapsValuesCases() { s.runCaseFile("round31/gaps-values.json") }

// TestRound31OpenHiddenTopCases runs round31/open-hidden-top.json.
func (s *ParitySuite) TestRound31OpenHiddenTopCases() { s.runCaseFile("round31/open-hidden-top.json") }

// TestRound31OpenUrlSubjectCases runs round31/open-url-subject.json.
func (s *ParitySuite) TestRound31OpenUrlSubjectCases() {
	s.runCaseFile("round31/open-url-subject.json")
}

// TestRound31PairsNoGrantCases runs round31/pairs-no-grant.json.
func (s *ParitySuite) TestRound31PairsNoGrantCases() { s.runCaseFile("round31/pairs-no-grant.json") }

// TestRound31PairsPlainCases runs round31/pairs-plain.json.
func (s *ParitySuite) TestRound31PairsPlainCases() { s.runCaseFile("round31/pairs-plain.json") }

// TestRound31PairsTwoGrantsCases runs round31/pairs-two-grants.json.
func (s *ParitySuite) TestRound31PairsTwoGrantsCases() {
	s.runCaseFile("round31/pairs-two-grants.json")
}
