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

// Round 28 asks what the earlier rounds never varied: the header and claim a
// PIP declaration names and the source a MAPPING key reads; how check/filter
// negates a DENY predicate and renders substituted values; and the inputs no
// golden reached, such as a null rule target or condition, a jsonPath function
// over a selection, and an iterating set with no permission scope PIP. Its
// cases are data under testdata/cases/round28, and each case's about field
// says what it asks. Each function runs one file, so that a recording run can
// be filtered to it and record it on a stand of its own.

// TestRound28PipHeaderCases runs round28/pip-header.json.
func (s *ParitySuite) TestRound28PipHeaderCases() { s.runCaseFile("round28/pip-header.json") }

// TestRound28PipTokenCases runs round28/pip-token.json.
func (s *ParitySuite) TestRound28PipTokenCases() { s.runCaseFile("round28/pip-token.json") }

// TestRound28PipMappingCases runs round28/pip-mapping.json.
func (s *ParitySuite) TestRound28PipMappingCases() { s.runCaseFile("round28/pip-mapping.json") }

// TestRound28RsqlNegationCases runs round28/rsql-negation.json.
func (s *ParitySuite) TestRound28RsqlNegationCases() { s.runCaseFile("round28/rsql-negation.json") }

// TestRound28RsqlSubstitutionCases runs round28/rsql-substitution.json.
func (s *ParitySuite) TestRound28RsqlSubstitutionCases() {
	s.runCaseFile("round28/rsql-substitution.json")
}

// TestRound28ReachValuesCases runs round28/reach-values.json.
func (s *ParitySuite) TestRound28ReachValuesCases() { s.runCaseFile("round28/reach-values.json") }

// TestRound28ReachSetsCases runs round28/reach-sets.json.
func (s *ParitySuite) TestRound28ReachSetsCases() { s.runCaseFile("round28/reach-sets.json") }

// TestRound28ReachScopeNoPipCases runs round28/reach-scope-no-pip.json. Its
// cases declare no permission scope PIP, and each iterating request records the
// calls to the pinned scope route, so a scope PIP that an earlier run of the
// suite left on the stand shows in the goldens.
func (s *ParitySuite) TestRound28ReachScopeNoPipCases() {
	s.runCaseFile("round28/reach-scope-no-pip.json")
}

// TestRound28ReachScopeTextCases runs round28/reach-scope-text.json.
func (s *ParitySuite) TestRound28ReachScopeTextCases() {
	s.runCaseFile("round28/reach-scope-text.json")
}
