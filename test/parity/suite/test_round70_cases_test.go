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

// Round 70 asks how an operand is classified where readings of the
// condition language disagree: resource.x IN true,false as a list of the
// booleans or as one attribute named true,false; subject.x-y and subject.1x,
// names no PIP can have, as a PIP or as a path in the resource; the scope
// keys a[0] and a. as keys as written, as paths in the resource, or with the
// dot dropped; and a dot at the end of subject.roles. and resource.x. Each
// probe sits in a DENY_UNLESS_PERMIT rule `<probe> OR resource.a == 'y'`
// decided with a = n and a = y, so that a true probe, a false probe, and a
// probe that ends the condition answer apart. Each case runs in a tenant of
// its own, records its upload with the error body if refused, decides after
// it, and reads the v3 export back. The cases are data under
// testdata/cases/round70, and each file's about field says what it asks.

// TestRound70OperandsBoolCases runs round70/operands-bool.json.
func (s *ParitySuite) TestRound70OperandsBoolCases() {
	s.runCaseFile("round70/operands-bool.json")
}

// TestRound70OperandsDotCases runs round70/operands-dot.json.
func (s *ParitySuite) TestRound70OperandsDotCases() {
	s.runCaseFile("round70/operands-dot.json")
}

// TestRound70OperandsScopeCases runs round70/operands-scope.json.
func (s *ParitySuite) TestRound70OperandsScopeCases() {
	s.runCaseFile("round70/operands-scope.json")
}

// TestRound70OperandsSubjectCases runs round70/operands-subject.json.
func (s *ParitySuite) TestRound70OperandsSubjectCases() {
	s.runCaseFile("round70/operands-subject.json")
}
