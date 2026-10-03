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

// Round 21 asks again the seven context cases of round 20 whose answer changed
// between stands, each request classed by the GENERAL PIP its failing rule
// reads; asks a number or boolean GENERAL body on the left of IN, CONTAINS,
// NOT CONTAINS and CONTAINS ANY in forms that tell a false comparison from an
// ended rule; asks a failing GENERAL PIP on the right beside each special
// state on the left; and asks the operand contexts that round 20 left
// unreached. Its cases are data under testdata/cases/round21, and each file's
// about field says what it asks. Each function runs one file, so that a
// recording run can be filtered to it and record it on a stand of its own.

// TestRound21OrderCases runs round21/order.json. Its requests are classed by
// the call log of a GENERAL PIP, and a stand takes one class per request, so
// both classes of a request need recording runs on several stands.
func (s *ParitySuite) TestRound21OrderCases() { s.runCaseFile("round21/order.json") }

// TestRound21OrderOneGrantCases runs round21/order-one-grant.json, classed as
// TestRound21OrderCases is.
func (s *ParitySuite) TestRound21OrderOneGrantCases() {
	s.runCaseFile("round21/order-one-grant.json")
}

// TestRound21OrderTwoGrantsCases runs round21/order-two-grants.json, classed as
// TestRound21OrderCases is.
func (s *ParitySuite) TestRound21OrderTwoGrantsCases() {
	s.runCaseFile("round21/order-two-grants.json")
}

// TestRound21GeneralScalarLeftCases runs round21/general-scalar-left.json.
func (s *ParitySuite) TestRound21GeneralScalarLeftCases() {
	s.runCaseFile("round21/general-scalar-left.json")
}

// TestRound21RightErrorFirstCases runs round21/right-error-first.json.
func (s *ParitySuite) TestRound21RightErrorFirstCases() {
	s.runCaseFile("round21/right-error-first.json")
}

// TestRound21ContextCases runs round21/context.json.
func (s *ParitySuite) TestRound21ContextCases() { s.runCaseFile("round21/context.json") }

// TestRound21ContextOneGrantCases runs round21/context-one-grant.json. Some of its requests are
// classed as TestRound21OrderCases's are.
func (s *ParitySuite) TestRound21ContextOneGrantCases() {
	s.runCaseFile("round21/context-one-grant.json")
}

// TestRound21ContextTwoGrantsCases runs round21/context-two-grants.json. Some of its requests are
// classed as TestRound21OrderCases's are.
func (s *ParitySuite) TestRound21ContextTwoGrantsCases() {
	s.runCaseFile("round21/context-two-grants.json")
}
