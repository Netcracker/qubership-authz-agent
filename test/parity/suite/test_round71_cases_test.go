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

// Round 71 sends the lifecycle transitions again, now as PATCH: the PAP
// serves /access/v1/policySets/{id}/{transition} for PATCH only, so the POST
// that rounds 48 to 66 sent was answered with 500. Each transition step names
// the binding patch of testdata/pap-operations.json, and a step without a
// binding still sends the POST. The round also asks a customization entry
// that names another tenant's set or child set in upper case, a rule entry
// that sends a field null over a stored one, an import of PIPs that declares
// one name in two domains, and metamorphic pairs of the PATCH against the
// POST. Every step that asks for a decision is followed by raw reads of both
// exports. Each case runs in a tenant of its own, and each file opens and
// closes with a control. The cases are data under testdata/cases/round71, and
// each case's about field says what it asks.

// TestRound71OpenCopyIdsCases runs round71/open-copy-ids.json.
func (s *ParitySuite) TestRound71OpenCopyIdsCases() {
	s.runCaseFile("round71/open-copy-ids.json")
}

// TestRound71OpenGapsCases runs round71/open-gaps.json.
func (s *ParitySuite) TestRound71OpenGapsCases() {
	s.runCaseFile("round71/open-gaps.json")
}

// TestRound71OpenLifecycleCases runs round71/open-lifecycle.json.
func (s *ParitySuite) TestRound71OpenLifecycleCases() {
	s.runCaseFile("round71/open-lifecycle.json")
}

// TestRound71PapmetaMayCases runs round71/papmeta-may.json.
func (s *ParitySuite) TestRound71PapmetaMayCases() {
	s.runCaseFile("round71/papmeta-may.json")
}

// TestRound71PapmetaShouldCases runs round71/papmeta-should.json.
func (s *ParitySuite) TestRound71PapmetaShouldCases() {
	s.runCaseFile("round71/papmeta-should.json")
}
