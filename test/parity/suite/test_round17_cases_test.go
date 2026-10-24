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

import (
	"context"
	"net/http"
)

// Round 17 asks the readings round 16 left open and what no golden reached
// once round 16 was recorded: a permission scope read, a list on the right of
// ==, and operation in the places where one of them may fail the request with
// 400; a failing entitlements read in the target of an ALLOW rule, a policy,
// and a set; two nulls under each operator; whether a string equals a list
// or an object whose text it holds; PIP operands and value types no case
// combined; and the parts of round 16's t16-28, whose answer differed
// between stands. Its cases are data under testdata/cases/round17, and each
// file's about field says what it asks. Each function runs one file, so that a
// recording run can be filtered to it and record it on a stand of its own. The
// files are listed in the order that asks the most per golden first, except
// the order file, which needs several stands.

// TestRound17QuestionsCases runs round17/questions.json.
func (s *ParitySuite) TestRound17QuestionsCases() { s.runCaseFile("round17/questions.json") }

// TestRound17EntitlementTargetCases runs round17/entitlement-targets.json with
// the entitlements service answering 500 for parity-reader. It pins the
// service's API version first, as TestRound15EntitlementTargetCases does, so
// that the read fails at the user's entitlements and not at version discovery.
func (s *ParitySuite) TestRound17EntitlementTargetCases() {
	s.pinEntitlementsV3(parityReaderSubjectID, map[string]map[string][]string{
		"PARITY_R17_ENT": {"Owner": {"e1"}},
	})
	err := s.eaMock.PinEntitlementsV3ForUser(context.Background(), parityReaderSubjectID, PipStubResponse{
		StatusCode: http.StatusInternalServerError,
		Body:       map[string]any{"error": "parity round 17 case"},
	})
	s.Require().NoError(err)
	s.runCaseFile("round17/entitlement-targets.json")
}

// TestRound17HypothesesCases runs round17/hypotheses.json.
func (s *ParitySuite) TestRound17HypothesesCases() { s.runCaseFile("round17/hypotheses.json") }

// TestRound17ResidualCases runs round17/residual.json.
func (s *ParitySuite) TestRound17ResidualCases() { s.runCaseFile("round17/residual.json") }

// TestRound17PipOperandsCases runs round17/pip-operands.json.
func (s *ParitySuite) TestRound17PipOperandsCases() { s.runCaseFile("round17/pip-operands.json") }

// TestRound17ValuesCases runs round17/values.json.
func (s *ParitySuite) TestRound17ValuesCases() { s.runCaseFile("round17/values.json") }

// TestRound17OrderCases runs round17/order.json. It comes last because its
// answers are worth recording only from at least five stands: a case whose
// answer differs between them depends on an order the stand picks. A case
// counts as stable only across stands on which the unchanged t16-28 answered
// both ways.
func (s *ParitySuite) TestRound17OrderCases() { s.runCaseFile("round17/order.json") }
