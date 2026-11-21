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

// Round 72 asks what the caller check counts as M2M and how it treats a
// user's token sent alone in Authorization (the subject form
// bearer:<username>) on every check route, the service account's id in a
// filter, whether access-control verifies an Incoming-Token and reads claims
// Keycloak cannot issue, requests on behalf of a user and with a tenant no
// stand provisioned, how check/filter renders numbers and negations and
// treats an INACTIVE policy, whether bulk reads nested sets, and more operand
// forms after round 70. Some cases run in a tenant of their own and the rest
// in the default tenant, as each file's about field says. callers-m2m,
// callers-service-id, and tokensubject-claims need the clients of
// testdata/realm-clients/token-subject-clients.json, and callers-m2m and
// tokensubject-claims also the users of
// testdata/realm/round29-pipfield-users.json and
// testdata/realm/round72-token-users.json, whose level attribute the stand's
// mapper puts into the claim level. The cases are data under
// testdata/cases/round72, and each case's about field says what it asks.

// TestRound72CallersM2mCases runs round72/callers-m2m.json.
func (s *ParitySuite) TestRound72CallersM2mCases() {
	s.runCaseFile("round72/callers-m2m.json")
}

// TestRound72CallersRoutesCases runs round72/callers-routes.json.
func (s *ParitySuite) TestRound72CallersRoutesCases() {
	s.runCaseFile("round72/callers-routes.json")
}

// TestRound72CallersServiceIdCases runs round72/callers-service-id.json.
func (s *ParitySuite) TestRound72CallersServiceIdCases() {
	s.runCaseFile("round72/callers-service-id.json")
}

// TestRound72FilterCustomNumberCases runs round72/filter-custom-number.json.
func (s *ParitySuite) TestRound72FilterCustomNumberCases() {
	s.runCaseFile("round72/filter-custom-number.json")
}

// TestRound72FilterInactiveCases runs round72/filter-inactive.json.
func (s *ParitySuite) TestRound72FilterInactiveCases() {
	s.runCaseFile("round72/filter-inactive.json")
}

// TestRound72FilterNestedCases runs round72/filter-nested.json.
func (s *ParitySuite) TestRound72FilterNestedCases() {
	s.runCaseFile("round72/filter-nested.json")
}

// TestRound72FilterNumberCases runs round72/filter-number.json.
func (s *ParitySuite) TestRound72FilterNumberCases() {
	s.runCaseFile("round72/filter-number.json")
}

// TestRound72FilterOrderCases runs round72/filter-order.json.
func (s *ParitySuite) TestRound72FilterOrderCases() {
	s.runCaseFile("round72/filter-order.json")
}

// TestRound72FilterParensCases runs round72/filter-parens.json.
func (s *ParitySuite) TestRound72FilterParensCases() {
	s.runCaseFile("round72/filter-parens.json")
}

// TestRound72FilterRenderCases runs round72/filter-render.json.
func (s *ParitySuite) TestRound72FilterRenderCases() {
	s.runCaseFile("round72/filter-render.json")
}

// TestRound72GapsOnbehalfCases runs round72/gaps-onbehalf.json.
func (s *ParitySuite) TestRound72GapsOnbehalfCases() {
	s.runCaseFile("round72/gaps-onbehalf.json")
}

// TestRound72GapsTenantCases runs round72/gaps-tenant.json.
func (s *ParitySuite) TestRound72GapsTenantCases() {
	s.runCaseFile("round72/gaps-tenant.json")
}

// TestRound72IncomingClaimsCases runs round72/incoming-claims.json.
func (s *ParitySuite) TestRound72IncomingClaimsCases() {
	s.runCaseFile("round72/incoming-claims.json")
}

// TestRound72IncomingTokenCases runs round72/incoming-token.json.
func (s *ParitySuite) TestRound72IncomingTokenCases() {
	s.runCaseFile("round72/incoming-token.json")
}

// TestRound72OperandsJsonpathCases runs round72/operands-jsonpath.json.
func (s *ParitySuite) TestRound72OperandsJsonpathCases() {
	s.runCaseFile("round72/operands-jsonpath.json")
}

// TestRound72OperandsListsCases runs round72/operands-lists.json.
func (s *ParitySuite) TestRound72OperandsListsCases() {
	s.runCaseFile("round72/operands-lists.json")
}

// TestRound72OperandsMatchCases runs round72/operands-match.json.
func (s *ParitySuite) TestRound72OperandsMatchCases() {
	s.runCaseFile("round72/operands-match.json")
}

// TestRound72OperandsPathsCases runs round72/operands-paths.json.
func (s *ParitySuite) TestRound72OperandsPathsCases() {
	s.runCaseFile("round72/operands-paths.json")
}

// TestRound72OperandsPipnamesCases runs round72/operands-pipnames.json.
func (s *ParitySuite) TestRound72OperandsPipnamesCases() {
	s.runCaseFile("round72/operands-pipnames.json")
}

// TestRound72OperandsScopeCases runs round72/operands-scope.json.
func (s *ParitySuite) TestRound72OperandsScopeCases() {
	s.runCaseFile("round72/operands-scope.json")
}

// TestRound72TokensubjectClaimsCases runs round72/tokensubject-claims.json.
func (s *ParitySuite) TestRound72TokensubjectClaimsCases() {
	s.runCaseFile("round72/tokensubject-claims.json")
}
