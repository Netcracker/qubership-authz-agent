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

// Round 22 asks where the order of evaluation reaches: a child that fails the
// decision beside a sibling that permits, as two rules of a policy, two
// policies of a set, two nested sets, and two sets at the top, for a check and
// a filter; and the two operand contexts that round 21 left unreached. Its
// cases are data under testdata/cases/round22, and each file's about field
// says what it asks. Each function runs one file, so that a recording run can
// be filtered to it and record it on a stand of its own.

// TestRound22OrderLevelsCases runs round22/order-levels.json. Its requests are
// classed by the call log of a GENERAL PIP, and a stand takes one class per
// request, so it needs recording runs on several stands. A request may show
// one class on every stand: a filter that evaluates every child reads the PIP
// whatever the order.
func (s *ParitySuite) TestRound22OrderLevelsCases() { s.runCaseFile("round22/order-levels.json") }

// TestRound22ContextOneGrantCases runs round22/context-one-grant.json.
func (s *ParitySuite) TestRound22ContextOneGrantCases() {
	s.runCaseFile("round22/context-one-grant.json")
}
