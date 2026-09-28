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

// Round 30 asks what round 29 left between two readings, and asks again what
// three round 29 cases could not record: a MAPPING key over a name that a
// failing GENERAL PIP took over, requestAttributes over a FILTERED PIP, the
// order of 24 permissions, a rule without an effect, customizations at an
// unknown level, of a DRAFT set, and adding sets that hold inactive parts,
// the filter of USE_FILTER_CONDITION and NOT_APPLICABLE under the
// *_OVERRIDES algorithms, remote PIPs for more subjects, inputs no golden
// reached, and configuration pairs round 29 reached only through refused
// imports. Its cases are data under testdata/cases/round30, and each case's
// about field says what it asks. Each function runs one file, so that a
// recording run can be filtered to it and record it on a stand of its own.

// TestRound30FixesEntitlementsCases runs round30/fixes-entitlements.json.
func (s *ParitySuite) TestRound30FixesEntitlementsCases() {
	s.runCaseFile("round30/fixes-entitlements.json")
}

// TestRound30FixesOrderCases runs round30/fixes-order.json. Its requests
// classed by classifyBy take runs on several stands.
func (s *ParitySuite) TestRound30FixesOrderCases() { s.runCaseFile("round30/fixes-order.json") }

// TestRound30GapsCustomCases runs round30/gaps-custom.json.
func (s *ParitySuite) TestRound30GapsCustomCases() { s.runCaseFile("round30/gaps-custom.json") }

// TestRound30GapsOnBehalfCases runs round30/gaps-on-behalf.json.
func (s *ParitySuite) TestRound30GapsOnBehalfCases() { s.runCaseFile("round30/gaps-on-behalf.json") }

// TestRound30GapsPapCases runs round30/gaps-pap.json.
func (s *ParitySuite) TestRound30GapsPapCases() { s.runCaseFile("round30/gaps-pap.json") }

// TestRound30GapsScopeMinuteCases runs round30/gaps-scope-minute.json.
// Its case r30gaps-scope-without-period-after-a-minute waits 61 s before its
// second request.
func (s *ParitySuite) TestRound30GapsScopeMinuteCases() {
	s.runCaseFile("round30/gaps-scope-minute.json")
}

// TestRound30GapsValuesCases runs round30/gaps-values.json.
func (s *ParitySuite) TestRound30GapsValuesCases() { s.runCaseFile("round30/gaps-values.json") }

// TestRound30OpenCustomizationCases runs round30/open-customization.json.
func (s *ParitySuite) TestRound30OpenCustomizationCases() {
	s.runCaseFile("round30/open-customization.json")
}

// TestRound30OpenEffectAbsentCases runs round30/open-effect-absent.json.
func (s *ParitySuite) TestRound30OpenEffectAbsentCases() {
	s.runCaseFile("round30/open-effect-absent.json")
}

// TestRound30OpenFilterEffectsCases runs round30/open-filter-effects.json.
func (s *ParitySuite) TestRound30OpenFilterEffectsCases() {
	s.runCaseFile("round30/open-filter-effects.json")
}

// TestRound30OpenMappingKeyCases runs round30/open-mapping-key.json.
func (s *ParitySuite) TestRound30OpenMappingKeyCases() {
	s.runCaseFile("round30/open-mapping-key.json")
}

// TestRound30OpenPermissionsOrderCases runs round30/open-permissions-order.json.
func (s *ParitySuite) TestRound30OpenPermissionsOrderCases() {
	s.runCaseFile("round30/open-permissions-order.json")
}

// TestRound30OpenRemoteCases runs round30/open-remote.json.
// It needs the two users of testdata/realm/round30-level-users.json in the
// parity realm, and the mapper of the end-user client from the user
// attribute level to the claim level that round 29 added.
func (s *ParitySuite) TestRound30OpenRemoteCases() { s.runCaseFile("round30/open-remote.json") }

// TestRound30OpenRequestAttributesCases runs round30/open-request-attributes.json.
func (s *ParitySuite) TestRound30OpenRequestAttributesCases() {
	s.runCaseFile("round30/open-request-attributes.json")
}

// TestRound30PairsNoGrantCases runs round30/pairs-no-grant.json.
func (s *ParitySuite) TestRound30PairsNoGrantCases() { s.runCaseFile("round30/pairs-no-grant.json") }

// TestRound30PairsOneGrantCases runs round30/pairs-one-grant.json.
func (s *ParitySuite) TestRound30PairsOneGrantCases() { s.runCaseFile("round30/pairs-one-grant.json") }

// TestRound30PairsPlainCases runs round30/pairs-plain.json.
func (s *ParitySuite) TestRound30PairsPlainCases() { s.runCaseFile("round30/pairs-plain.json") }
