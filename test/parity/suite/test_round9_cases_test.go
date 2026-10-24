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

// Round 9 asks, among other things, what operators answer over absent and
// single-element PIP values and plain arrays, what a PIP answering a number or a
// boolean does beside an allowing rule, and how check/filter combines rules
// without predicates. Its cases are data under testdata/cases/round9, written by generate.py there,
// which says what each file asks. They were first written in Go, and each file
// sends the requests the Go cases sent, so the goldens recorded then still
// apply. Each function runs one file, so that a recording run can be filtered
// to it and record it on a stand of its own.

// TestRound9EmptyHeaderAndClaimCases runs round9/empty-header-and-claim.json.
func (s *ParitySuite) TestRound9EmptyHeaderAndClaimCases() {
	s.runCaseFile("round9/empty-header-and-claim.json")
}

// TestRound9RightOperandCases runs round9/right-operand.json.
func (s *ParitySuite) TestRound9RightOperandCases() { s.runCaseFile("round9/right-operand.json") }

// TestRound9SingleElementListCases runs round9/single-element-list.json.
func (s *ParitySuite) TestRound9SingleElementListCases() {
	s.runCaseFile("round9/single-element-list.json")
}

// TestRound9PlainArrayEqualityCases runs round9/plain-array-equality.json.
func (s *ParitySuite) TestRound9PlainArrayEqualityCases() {
	s.runCaseFile("round9/plain-array-equality.json")
}

// TestRound9IsNullOverDeadFormsCases runs round9/is-null-over-dead-forms.json.
func (s *ParitySuite) TestRound9IsNullOverDeadFormsCases() {
	s.runCaseFile("round9/is-null-over-dead-forms.json")
}

// TestRound9TokenDefaultListCases runs round9/token-default-list.json.
func (s *ParitySuite) TestRound9TokenDefaultListCases() {
	s.runCaseFile("round9/token-default-list.json")
}

// TestRound9NonStringPIPValueCases runs round9/non-string-pip-value.json.
func (s *ParitySuite) TestRound9NonStringPIPValueCases() {
	s.runCaseFile("round9/non-string-pip-value.json")
}

// TestRound9DenyRuleWithoutPredicateCases runs
// round9/deny-rule-without-predicate.json.
func (s *ParitySuite) TestRound9DenyRuleWithoutPredicateCases() {
	s.runCaseFile("round9/deny-rule-without-predicate.json")
}

// TestRound9FalseConditionWithoutPredicateCases runs
// round9/false-condition-without-predicate.json.
func (s *ParitySuite) TestRound9FalseConditionWithoutPredicateCases() {
	s.runCaseFile("round9/false-condition-without-predicate.json")
}

// TestRound9FilterAlgebraCases runs round9/filter-algebra.json.
func (s *ParitySuite) TestRound9FilterAlgebraCases() { s.runCaseFile("round9/filter-algebra.json") }

// TestRound9UnresolvedPlaceholderCases runs round9/unresolved-placeholder.json.
func (s *ParitySuite) TestRound9UnresolvedPlaceholderCases() {
	s.runCaseFile("round9/unresolved-placeholder.json")
}

// TestRound9SubjectScalarSubstitutionCases runs
// round9/subject-scalar-substitution.json.
func (s *ParitySuite) TestRound9SubjectScalarSubstitutionCases() {
	s.runCaseFile("round9/subject-scalar-substitution.json")
}
