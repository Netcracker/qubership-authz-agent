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

// Round 10 asks, among other things, what IS NOT NULL and the collection
// operators answer over dead forms, null, and a header holding one value, what
// operators answer over a GENERAL PIP answering a number or a null body, and
// what a set's algorithm and a rule reading the resource do to check/filter,
// what a GENERAL PIP sends for a placeholder in its requestAttributes, and
// whether a GENERAL PIP on the right of an OR is called once the left operand
// holds.
// Its cases that the case format expresses are data under
// testdata/cases/round10, written by generate.py there, which says what each
// file asks. They were first written in Go, and each file sends the requests
// the Go cases sent, so the goldens recorded then still apply. Each function
// runs one file, so that a recording run can be filtered to it and record it on
// a stand of its own.

// TestRound10DeadFormNotNullCases runs round10/dead-form-not-null.json.
func (s *ParitySuite) TestRound10DeadFormNotNullCases() {
	s.runCaseFile("round10/dead-form-not-null.json")
}

// TestRound10EmptyCollectionNotNullCases runs
// round10/empty-collection-not-null.json.
func (s *ParitySuite) TestRound10EmptyCollectionNotNullCases() {
	s.runCaseFile("round10/empty-collection-not-null.json")
}

// TestRound10UndeclaredPlaceholderCheckCases runs
// round10/undeclared-placeholder-check.json.
func (s *ParitySuite) TestRound10UndeclaredPlaceholderCheckCases() {
	s.runCaseFile("round10/undeclared-placeholder-check.json")
}

// TestRound10NullOperandCases runs round10/null-operand.json.
func (s *ParitySuite) TestRound10NullOperandCases() { s.runCaseFile("round10/null-operand.json") }

// TestRound10SingleValueHeaderCases runs round10/single-value-header.json.
func (s *ParitySuite) TestRound10SingleValueHeaderCases() {
	s.runCaseFile("round10/single-value-header.json")
}

// TestRound10NullBodyAndRightOperandCases runs
// round10/null-body-and-right-operand.json.
func (s *ParitySuite) TestRound10NullBodyAndRightOperandCases() {
	s.runCaseFile("round10/null-body-and-right-operand.json")
}

// TestRound10PathPatternAndWordOperatorCases runs
// round10/path-pattern-and-word-operator.json.
func (s *ParitySuite) TestRound10PathPatternAndWordOperatorCases() {
	s.runCaseFile("round10/path-pattern-and-word-operator.json")
}

// TestRound10NonStringPIPOperatorCases runs
// round10/non-string-pip-operator.json.
func (s *ParitySuite) TestRound10NonStringPIPOperatorCases() {
	s.runCaseFile("round10/non-string-pip-operator.json")
}

// TestRound10SetAlgorithmFilterCases runs round10/set-algorithm-filter.json.
func (s *ParitySuite) TestRound10SetAlgorithmFilterCases() {
	s.runCaseFile("round10/set-algorithm-filter.json")
}

// TestRound10FilterResourceConditionCases runs
// round10/filter-resource-condition.json.
func (s *ParitySuite) TestRound10FilterResourceConditionCases() {
	s.runCaseFile("round10/filter-resource-condition.json")
}

// TestRound10DenyListFilterCases runs round10/deny-list-filter.json.
func (s *ParitySuite) TestRound10DenyListFilterCases() {
	s.runCaseFile("round10/deny-list-filter.json")
}

// TestRound10RequestAttributesCases runs round10/request-attributes.json.
func (s *ParitySuite) TestRound10RequestAttributesCases() {
	s.runCaseFile("round10/request-attributes.json")
}

// TestRound10EitherSourceCases runs round10/either-source.json.
func (s *ParitySuite) TestRound10EitherSourceCases() { s.runCaseFile("round10/either-source.json") }
