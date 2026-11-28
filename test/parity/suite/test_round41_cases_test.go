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

// Round 40 found that a tenant holds the condition of a GENERAL PIP carrying
// a whole ${subject.isM2M} in requestAttributes as long as the tree after
// customizations names it, and fails every request with 400 meanwhile. Every
// such PIP of rounds 37 to 40 carried the value from its upload. Round 41
// asks which declaration of the PIP the tenant reads: one a CUSTOMER or
// PROJECT PIP customization changes, one a customization disables, one whose
// name another domain declares as a TOKEN, and one that carries the value
// inside a text. The policy-status file asks whether a decision reads the
// status of a policy. The cases are data under testdata/cases/round41, and
// each case's about field says what it asks.
//
// Each function runs one file and should be recorded on a fresh stand, for
// the reason round 40 gives: a case after which the tenant still holds such
// a condition makes every later request of the function answer 400.

// TestRound41OpenM2mHeldPipAddCases runs round41/open-m2m-held-pip-add.json.
func (s *ParitySuite) TestRound41OpenM2mHeldPipAddCases() {
	s.runCaseFile("round41/open-m2m-held-pip-add.json")
}

// TestRound41OpenM2mHeldPipDisableSimplifiedCases runs round41/open-m2m-held-pip-disable-simplified.json.
func (s *ParitySuite) TestRound41OpenM2mHeldPipDisableSimplifiedCases() {
	s.runCaseFile("round41/open-m2m-held-pip-disable-simplified.json")
}

// TestRound41OpenM2mHeldPipInTextCases runs round41/open-m2m-held-pip-in-text.json.
func (s *ParitySuite) TestRound41OpenM2mHeldPipInTextCases() {
	s.runCaseFile("round41/open-m2m-held-pip-in-text.json")
}

// TestRound41OpenM2mHeldPipProjectCases runs round41/open-m2m-held-pip-project.json.
func (s *ParitySuite) TestRound41OpenM2mHeldPipProjectCases() {
	s.runCaseFile("round41/open-m2m-held-pip-project.json")
}

// TestRound41OpenM2mHeldPipRemoveCases runs round41/open-m2m-held-pip-remove.json.
func (s *ParitySuite) TestRound41OpenM2mHeldPipRemoveCases() {
	s.runCaseFile("round41/open-m2m-held-pip-remove.json")
}

// TestRound41OpenM2mHeldPipTwinCases runs round41/open-m2m-held-pip-twin.json.
func (s *ParitySuite) TestRound41OpenM2mHeldPipTwinCases() {
	s.runCaseFile("round41/open-m2m-held-pip-twin.json")
}

// TestRound41OpenPolicyStatusCases runs round41/open-policy-status.json.
func (s *ParitySuite) TestRound41OpenPolicyStatusCases() {
	s.runCaseFile("round41/open-policy-status.json")
}
