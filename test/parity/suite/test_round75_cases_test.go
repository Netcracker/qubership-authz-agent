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

// Round 75 asks how access-control reads a source's answer by its status code
// (2xx other than 200, 3xx with and without Location, 304, codes outside the
// IANA registry) for GENERAL, the entitlements service, and the scope
// service; the decision on behalf of a user found in User Management; a
// failed source and an undefined target in conditions, targets, iterate
// passes, and rows of the filter; and the gaps of the PR 205 review. The
// pip-status files need the pipstub image that sends a route's headers and
// a route with no body, and the onbehalf files the stand of round 63, whose
// INTERNAL_APIGATEWAY_URL points at user-management-mock. Some cases run in
// a tenant of their own and the rest in the default tenant, as each file's
// about field says. The cases are data under testdata/cases/round75, and
// each case's about field says what it asks.

// TestRound75FailedSourceConditionsCases runs round75/failed-source-conditions.json.
func (s *ParitySuite) TestRound75FailedSourceConditionsCases() {
	s.runCaseFile("round75/failed-source-conditions.json")
}

// TestRound75FailedSourceIterateCases runs round75/failed-source-iterate.json.
func (s *ParitySuite) TestRound75FailedSourceIterateCases() {
	s.runCaseFile("round75/failed-source-iterate.json")
}

// TestRound75FilterNodeTargetsCases runs round75/filter-node-targets.json.
func (s *ParitySuite) TestRound75FilterNodeTargetsCases() {
	s.runCaseFile("round75/filter-node-targets.json")
}

// TestRound75FilterRuleTargetPredicatesCases runs round75/filter-rule-target-predicates.json.
func (s *ParitySuite) TestRound75FilterRuleTargetPredicatesCases() {
	s.runCaseFile("round75/filter-rule-target-predicates.json")
}

// TestRound75FilterUndefinedTargetsCases runs round75/filter-undefined-targets.json.
func (s *ParitySuite) TestRound75FilterUndefinedTargetsCases() {
	s.runCaseFile("round75/filter-undefined-targets.json")
}

// TestRound75GapsRolesCases runs round75/gaps-roles.json.
func (s *ParitySuite) TestRound75GapsRolesCases() {
	s.runCaseFile("round75/gaps-roles.json")
}

// TestRound75GapsTypesCases runs round75/gaps-types.json.
func (s *ParitySuite) TestRound75GapsTypesCases() {
	s.runCaseFile("round75/gaps-types.json")
}

// TestRound75GapsUrlCases runs round75/gaps-url.json.
func (s *ParitySuite) TestRound75GapsUrlCases() {
	s.runCaseFile("round75/gaps-url.json")
}

// TestRound75GapsValuesCases runs round75/gaps-values.json.
func (s *ParitySuite) TestRound75GapsValuesCases() {
	s.runCaseFile("round75/gaps-values.json")
}

// TestRound75OnbehalfMustCases runs round75/onbehalf-must.json.
func (s *ParitySuite) TestRound75OnbehalfMustCases() {
	s.runCaseFile("round75/onbehalf-must.json")
}

// TestRound75OnbehalfShouldCases runs round75/onbehalf-should.json.
func (s *ParitySuite) TestRound75OnbehalfShouldCases() {
	s.runCaseFile("round75/onbehalf-should.json")
}

// TestRound75PipStatusEnt203Cases runs round75/pip-status-ent-203.json.
func (s *ParitySuite) TestRound75PipStatusEnt203Cases() {
	s.runCaseFile("round75/pip-status-ent-203.json")
}

// TestRound75PipStatusEnt302EmptyCases runs round75/pip-status-ent-302-empty.json.
func (s *ParitySuite) TestRound75PipStatusEnt302EmptyCases() {
	s.runCaseFile("round75/pip-status-ent-302-empty.json")
}

// TestRound75PipStatusEnt302LocCases runs round75/pip-status-ent-302-loc.json.
func (s *ParitySuite) TestRound75PipStatusEnt302LocCases() {
	s.runCaseFile("round75/pip-status-ent-302-loc.json")
}

// TestRound75PipStatusEnt303LocCases runs round75/pip-status-ent-303-loc.json.
func (s *ParitySuite) TestRound75PipStatusEnt303LocCases() {
	s.runCaseFile("round75/pip-status-ent-303-loc.json")
}

// TestRound75PipStatusEnt307LocCases runs round75/pip-status-ent-307-loc.json.
func (s *ParitySuite) TestRound75PipStatusEnt307LocCases() {
	s.runCaseFile("round75/pip-status-ent-307-loc.json")
}

// TestRound75PipStatusGeneralCases runs round75/pip-status-general.json.
func (s *ParitySuite) TestRound75PipStatusGeneralCases() {
	s.runCaseFile("round75/pip-status-general.json")
}

// TestRound75PipStatusScope203Cases runs round75/pip-status-scope-203.json.
func (s *ParitySuite) TestRound75PipStatusScope203Cases() {
	s.runCaseFile("round75/pip-status-scope-203.json")
}

// TestRound75PipStatusScope302EmptyCases runs round75/pip-status-scope-302-empty.json.
func (s *ParitySuite) TestRound75PipStatusScope302EmptyCases() {
	s.runCaseFile("round75/pip-status-scope-302-empty.json")
}

// TestRound75PipStatusScope302LocCases runs round75/pip-status-scope-302-loc.json.
func (s *ParitySuite) TestRound75PipStatusScope302LocCases() {
	s.runCaseFile("round75/pip-status-scope-302-loc.json")
}

// TestRound75PipStatusScope303LocCases runs round75/pip-status-scope-303-loc.json.
func (s *ParitySuite) TestRound75PipStatusScope303LocCases() {
	s.runCaseFile("round75/pip-status-scope-303-loc.json")
}

// TestRound75PipStatusScope307LocCases runs round75/pip-status-scope-307-loc.json.
func (s *ParitySuite) TestRound75PipStatusScope307LocCases() {
	s.runCaseFile("round75/pip-status-scope-307-loc.json")
}
