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

// Round 67 asks what round 58 left for a later round and the owner's
// questions V18v and V18g. The rawpairs files hold combinations of raw input
// features no golden sent together, one file per answer pinned on the
// permission scope route, and a FILTERED PIP in a condition. The spellpos
// files hold spellings of a value at the other places of a condition. The
// spell files hold a PIP name spelled upper-first, with an underscore, or
// nested, each paired with the plain name, -0.5 beside 0.5, and the data and
// syntax spellings round 58 did not settle. The objnum files compare objects
// whose numbers are spelled two ways and request fractions near the limits of
// a double. The fields file holds the remaining states of the body of
// POST /permissions/assign, each case in a tenant of its own. The open files
// ask an INACTIVE policy beside an active one in a filter, an assignment with
// an empty mapping, and a request on behalf of a user. The owner-v18g files
// each pin one answer of the permission scope service for the whole file;
// owner-v18v asks a DENY rule with a predicate under each policy algorithm.
// Every file except the fields file records the stand's version first and
// opens with a control. The cases are data under testdata/cases/round67, and
// each file's about field says what it asks.

// TestRound67FieldsAssignCases runs round67/fields-assign.json.
func (s *ParitySuite) TestRound67FieldsAssignCases() {
	s.runCaseFile("round67/fields-assign.json")
}

// TestRound67ObjnumObjectNumbersCases runs round67/objnum-object-numbers.json.
func (s *ParitySuite) TestRound67ObjnumObjectNumbersCases() {
	s.runCaseFile("round67/objnum-object-numbers.json")
}

// TestRound67ObjnumRequestNumbersCases runs round67/objnum-request-numbers.json.
func (s *ParitySuite) TestRound67ObjnumRequestNumbersCases() {
	s.runCaseFile("round67/objnum-request-numbers.json")
}

// TestRound67OpenOnBehalfCases runs round67/open-on-behalf.json.
func (s *ParitySuite) TestRound67OpenOnBehalfCases() {
	s.runCaseFile("round67/open-on-behalf.json")
}

// TestRound67OpenSingleCases runs round67/open-single.json.
func (s *ParitySuite) TestRound67OpenSingleCases() {
	s.runCaseFile("round67/open-single.json")
}

// TestRound67OwnerV18gBareListEmptyCases runs round67/owner-v18g-bare-list-empty.json.
func (s *ParitySuite) TestRound67OwnerV18gBareListEmptyCases() {
	s.runCaseFile("round67/owner-v18g-bare-list-empty.json")
}

// TestRound67OwnerV18gEmptyObjectCases runs round67/owner-v18g-empty-object.json.
func (s *ParitySuite) TestRound67OwnerV18gEmptyObjectCases() {
	s.runCaseFile("round67/owner-v18g-empty-object.json")
}

// TestRound67OwnerV18gForbiddenCases runs round67/owner-v18g-forbidden.json.
func (s *ParitySuite) TestRound67OwnerV18gForbiddenCases() {
	s.runCaseFile("round67/owner-v18g-forbidden.json")
}

// TestRound67OwnerV18gNoContentCases runs round67/owner-v18g-no-content.json.
func (s *ParitySuite) TestRound67OwnerV18gNoContentCases() {
	s.runCaseFile("round67/owner-v18g-no-content.json")
}

// TestRound67OwnerV18gNotFoundCases runs round67/owner-v18g-not-found.json.
func (s *ParitySuite) TestRound67OwnerV18gNotFoundCases() {
	s.runCaseFile("round67/owner-v18g-not-found.json")
}

// TestRound67OwnerV18gNullBodyCases runs round67/owner-v18g-null-body.json.
func (s *ParitySuite) TestRound67OwnerV18gNullBodyCases() {
	s.runCaseFile("round67/owner-v18g-null-body.json")
}

// TestRound67OwnerV18gOneGrantCases runs round67/owner-v18g-one-grant.json.
func (s *ParitySuite) TestRound67OwnerV18gOneGrantCases() {
	s.runCaseFile("round67/owner-v18g-one-grant.json")
}

// TestRound67OwnerV18gScopeListEmptyCases runs round67/owner-v18g-scope-list-empty.json.
func (s *ParitySuite) TestRound67OwnerV18gScopeListEmptyCases() {
	s.runCaseFile("round67/owner-v18g-scope-list-empty.json")
}

// TestRound67OwnerV18gServerErrorCases runs round67/owner-v18g-server-error.json.
func (s *ParitySuite) TestRound67OwnerV18gServerErrorCases() {
	s.runCaseFile("round67/owner-v18g-server-error.json")
}

// TestRound67OwnerV18gUnavailableCases runs round67/owner-v18g-unavailable.json.
func (s *ParitySuite) TestRound67OwnerV18gUnavailableCases() {
	s.runCaseFile("round67/owner-v18g-unavailable.json")
}

// TestRound67OwnerV18vCases runs round67/owner-v18v.json.
func (s *ParitySuite) TestRound67OwnerV18vCases() {
	s.runCaseFile("round67/owner-v18v.json")
}

// TestRound67RawpairsG0Cases runs round67/rawpairs-g0.json.
func (s *ParitySuite) TestRound67RawpairsG0Cases() {
	s.runCaseFile("round67/rawpairs-g0.json")
}

// TestRound67RawpairsG1Cases runs round67/rawpairs-g1.json.
func (s *ParitySuite) TestRound67RawpairsG1Cases() {
	s.runCaseFile("round67/rawpairs-g1.json")
}

// TestRound67RawpairsG2Cases runs round67/rawpairs-g2.json.
func (s *ParitySuite) TestRound67RawpairsG2Cases() {
	s.runCaseFile("round67/rawpairs-g2.json")
}

// TestRound67RawpairsGfailCases runs round67/rawpairs-gfail.json.
func (s *ParitySuite) TestRound67RawpairsGfailCases() {
	s.runCaseFile("round67/rawpairs-gfail.json")
}

// TestRound67RawpairsGnoneCases runs round67/rawpairs-gnone.json.
func (s *ParitySuite) TestRound67RawpairsGnoneCases() {
	s.runCaseFile("round67/rawpairs-gnone.json")
}

// TestRound67RawpairsHeadsCases runs round67/rawpairs-heads.json.
func (s *ParitySuite) TestRound67RawpairsHeadsCases() {
	s.runCaseFile("round67/rawpairs-heads.json")
}

// TestRound67SpellDataCases runs round67/spell-data.json.
func (s *ParitySuite) TestRound67SpellDataCases() {
	s.runCaseFile("round67/spell-data.json")
}

// TestRound67SpellLiteralsCases runs round67/spell-literals.json.
func (s *ParitySuite) TestRound67SpellLiteralsCases() {
	s.runCaseFile("round67/spell-literals.json")
}

// TestRound67SpellPipNestedCases runs round67/spell-pip-nested.json.
func (s *ParitySuite) TestRound67SpellPipNestedCases() {
	s.runCaseFile("round67/spell-pip-nested.json")
}

// TestRound67SpellPipUnderscoreCases runs round67/spell-pip-underscore.json.
func (s *ParitySuite) TestRound67SpellPipUnderscoreCases() {
	s.runCaseFile("round67/spell-pip-underscore.json")
}

// TestRound67SpellPipUpperFirstCases runs round67/spell-pip-upper-first.json.
func (s *ParitySuite) TestRound67SpellPipUpperFirstCases() {
	s.runCaseFile("round67/spell-pip-upper-first.json")
}

// TestRound67SpellSyntaxCases runs round67/spell-syntax.json.
func (s *ParitySuite) TestRound67SpellSyntaxCases() {
	s.runCaseFile("round67/spell-syntax.json")
}

// TestRound67SpellposMayCases runs round67/spellpos-may.json.
func (s *ParitySuite) TestRound67SpellposMayCases() {
	s.runCaseFile("round67/spellpos-may.json")
}

// TestRound67SpellposMustCases runs round67/spellpos-must.json.
func (s *ParitySuite) TestRound67SpellposMustCases() {
	s.runCaseFile("round67/spellpos-must.json")
}

// TestRound67SpellposShouldCases runs round67/spellpos-should.json.
func (s *ParitySuite) TestRound67SpellposShouldCases() {
	s.runCaseFile("round67/spellpos-should.json")
}
