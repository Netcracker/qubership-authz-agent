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

// Round 39 found that a GENERAL PIP carrying a whole ${subject.isM2M} in
// requestAttributes fails every request of the tenant with 400 for as long as
// the tenant holds one condition that names the PIP. Every set of round 39
// was ACTIVE and uploaded as is. Round 40 asks which conditions the tenant
// holds: those of a set, a nested set, a rule, or a policy out of service, of
// a rule or a policy for the user interface, and a condition that a
// customization disables, replaces, or puts in place. Its cases are data
// under testdata/cases/round40, and each case's about field says what it
// asks.
//
// Each function runs one file and should be recorded on a fresh stand. The
// case files cannot delete a set, so the sets of a function stay loaded until
// it ends, and a case after which the tenant still holds such a condition
// makes every later request of the function answer 400, the controls
// included. Whether the cleanup at the end of a function releases the tenant
// is not established, so a fresh stand keeps one file from deciding the
// answers of the next.

// TestRound40OpenM2mHeldArchivedCases runs round40/open-m2m-held-archived.json.
func (s *ParitySuite) TestRound40OpenM2mHeldArchivedCases() {
	s.runCaseFile("round40/open-m2m-held-archived.json")
}

// TestRound40OpenM2mHeldCustomAddConditionCases runs round40/open-m2m-held-custom-add-condition.json.
func (s *ParitySuite) TestRound40OpenM2mHeldCustomAddConditionCases() {
	s.runCaseFile("round40/open-m2m-held-custom-add-condition.json")
}

// TestRound40OpenM2mHeldCustomAddSetCases runs round40/open-m2m-held-custom-add-set.json.
func (s *ParitySuite) TestRound40OpenM2mHeldCustomAddSetCases() {
	s.runCaseFile("round40/open-m2m-held-custom-add-set.json")
}

// TestRound40OpenM2mHeldCustomDisableRuleCases runs round40/open-m2m-held-custom-disable-rule.json.
func (s *ParitySuite) TestRound40OpenM2mHeldCustomDisableRuleCases() {
	s.runCaseFile("round40/open-m2m-held-custom-disable-rule.json")
}

// TestRound40OpenM2mHeldCustomDisableSetCases runs round40/open-m2m-held-custom-disable-set.json.
func (s *ParitySuite) TestRound40OpenM2mHeldCustomDisableSetCases() {
	s.runCaseFile("round40/open-m2m-held-custom-disable-set.json")
}

// TestRound40OpenM2mHeldCustomReplaceConditionCases runs round40/open-m2m-held-custom-replace-condition.json.
func (s *ParitySuite) TestRound40OpenM2mHeldCustomReplaceConditionCases() {
	s.runCaseFile("round40/open-m2m-held-custom-replace-condition.json")
}

// TestRound40OpenM2mHeldDraftCases runs round40/open-m2m-held-draft.json.
func (s *ParitySuite) TestRound40OpenM2mHeldDraftCases() {
	s.runCaseFile("round40/open-m2m-held-draft.json")
}

// TestRound40OpenM2mHeldInactiveCases runs round40/open-m2m-held-inactive.json.
func (s *ParitySuite) TestRound40OpenM2mHeldInactiveCases() {
	s.runCaseFile("round40/open-m2m-held-inactive.json")
}

// TestRound40OpenM2mHeldNestedArchivedCases runs round40/open-m2m-held-nested-archived.json.
func (s *ParitySuite) TestRound40OpenM2mHeldNestedArchivedCases() {
	s.runCaseFile("round40/open-m2m-held-nested-archived.json")
}

// TestRound40OpenM2mHeldNestedDraftCases runs round40/open-m2m-held-nested-draft.json.
func (s *ParitySuite) TestRound40OpenM2mHeldNestedDraftCases() {
	s.runCaseFile("round40/open-m2m-held-nested-draft.json")
}

// TestRound40OpenM2mHeldNestedInactiveCases runs round40/open-m2m-held-nested-inactive.json.
func (s *ParitySuite) TestRound40OpenM2mHeldNestedInactiveCases() {
	s.runCaseFile("round40/open-m2m-held-nested-inactive.json")
}

// TestRound40OpenM2mHeldPolicyInactiveCases runs round40/open-m2m-held-policy-inactive.json.
func (s *ParitySuite) TestRound40OpenM2mHeldPolicyInactiveCases() {
	s.runCaseFile("round40/open-m2m-held-policy-inactive.json")
}

// TestRound40OpenM2mHeldRuleFrontendCases runs round40/open-m2m-held-rule-frontend.json.
func (s *ParitySuite) TestRound40OpenM2mHeldRuleFrontendCases() {
	s.runCaseFile("round40/open-m2m-held-rule-frontend.json")
}

// TestRound40OpenM2mHeldRuleInactiveCases runs round40/open-m2m-held-rule-inactive.json.
func (s *ParitySuite) TestRound40OpenM2mHeldRuleInactiveCases() {
	s.runCaseFile("round40/open-m2m-held-rule-inactive.json")
}

// TestRound40OpenM2mHeldSimplifiedFrontendCases runs round40/open-m2m-held-simplified-frontend.json.
func (s *ParitySuite) TestRound40OpenM2mHeldSimplifiedFrontendCases() {
	s.runCaseFile("round40/open-m2m-held-simplified-frontend.json")
}
