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

// Round 33 asks what round 32 left open: whether an absent key on the left of
// a comparison ends the rule before subject.permissionScope read outside
// iterate on the right fails the decision, and whether a set evaluates its
// own policies before its nested sets. It also sends second carriers of the
// readings round 32 settled on one golden each, value types no golden sent,
// and forms that real configurations use and no golden sends. Its cases are
// data under testdata/cases/round33, and each case's about field says what it
// asks. Each function runs one file, so that a recording run can be filtered
// to it and record it on a stand of its own.

// TestRound33GapsCarriersCases runs round33/gaps-carriers.json.
func (s *ParitySuite) TestRound33GapsCarriersCases() { s.runCaseFile("round33/gaps-carriers.json") }

// TestRound33GapsCorpusCases runs round33/gaps-corpus.json.
func (s *ParitySuite) TestRound33GapsCorpusCases() { s.runCaseFile("round33/gaps-corpus.json") }

// TestRound33GapsPapCases runs round33/gaps-pap.json.
func (s *ParitySuite) TestRound33GapsPapCases() { s.runCaseFile("round33/gaps-pap.json") }

// TestRound33GapsValuesCases runs round33/gaps-values.json.
func (s *ParitySuite) TestRound33GapsValuesCases() { s.runCaseFile("round33/gaps-values.json") }

// TestRound33OpenOwnPoliciesCases runs round33/open-own-policies.json.
// Its requests classed by classifyBy take runs on several stands.
func (s *ParitySuite) TestRound33OpenOwnPoliciesCases() {
	s.runCaseFile("round33/open-own-policies.json")
}

// TestRound33OpenScopeCases runs round33/open-scope.json.
func (s *ParitySuite) TestRound33OpenScopeCases() { s.runCaseFile("round33/open-scope.json") }
