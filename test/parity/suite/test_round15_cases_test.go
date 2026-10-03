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

// Round 15 asks every operand pair the PAP may accept that no golden has
// evaluated, one probe per pair, and the forms round 14 left open. Its cases
// are data under testdata/cases/round15, written by generate.py there, which
// says what each file asks. Each function runs one file, so that a recording
// run can be filtered to it and record it on a stand of its own.

// pinRound15Entitlements gives parity-reader the entitlements the pair cases
// read through subject.entitledResources.of('PARITY_R15_ENT').as('Owner').
func (s *ParitySuite) pinRound15Entitlements() {
	s.pinEntitlementsV3(parityReaderSubjectID, map[string]map[string][]string{
		"PARITY_R15_ENT": {"Owner": {"e1", "e2"}},
	})
}

// runRound15PairFile runs one file of operand pairs with the entitlements
// pinned.
func (s *ParitySuite) runRound15PairFile(name string) {
	s.pinRound15Entitlements()
	s.runCaseFile("round15/" + name)
}

// TestRound15EqualityPairCases runs round15/pairs-eq.json.
func (s *ParitySuite) TestRound15EqualityPairCases() { s.runRound15PairFile("pairs-eq.json") }

// TestRound15RelationalPairCases runs round15/pairs-rel.json.
func (s *ParitySuite) TestRound15RelationalPairCases() { s.runRound15PairFile("pairs-rel.json") }

// TestRound15MembershipPairCases runs round15/pairs-in.json.
func (s *ParitySuite) TestRound15MembershipPairCases() { s.runRound15PairFile("pairs-in.json") }

// TestRound15ContainsPairCases runs round15/pairs-contains.json.
func (s *ParitySuite) TestRound15ContainsPairCases() { s.runRound15PairFile("pairs-contains.json") }

// TestRound15ContainsAnyPairCases runs round15/pairs-any.json.
func (s *ParitySuite) TestRound15ContainsAnyPairCases() { s.runRound15PairFile("pairs-any.json") }

// TestRound15SubsetPairCases runs round15/pairs-subset.json.
func (s *ParitySuite) TestRound15SubsetPairCases() { s.runRound15PairFile("pairs-subset.json") }

// TestRound15MatchPairCases runs round15/pairs-match.json.
func (s *ParitySuite) TestRound15MatchPairCases() { s.runRound15PairFile("pairs-match.json") }

// TestRound15UnaryPairCases runs round15/pairs-unary.json.
func (s *ParitySuite) TestRound15UnaryPairCases() { s.runRound15PairFile("pairs-unary.json") }

// TestRound15QuestionCases runs round15/questions.json.
func (s *ParitySuite) TestRound15QuestionCases() { s.runCaseFile("round15/questions.json") }

// TestRound15EntitlementTargetCases runs round15/entitlement-targets.json with
// the entitlements service answering 500 for parity-reader.
func (s *ParitySuite) TestRound15EntitlementTargetCases() {
	s.pinRound15Entitlements()
	err := s.eaMock.PinEntitlementsV3ForUser(context.Background(), parityReaderSubjectID, PipStubResponse{
		StatusCode: http.StatusInternalServerError,
		Body:       map[string]any{"error": "parity round 15 case"},
	})
	s.Require().NoError(err)
	s.runCaseFile("round15/entitlement-targets.json")
}
