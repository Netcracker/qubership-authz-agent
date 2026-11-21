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

// Round 69 asks pairs of a filter and checks of its rows: each filtersub case
// asks check/filter and, as the same subject, in the same tenant and for the
// same operation, check/resource of rows of the filter's resource type, so a
// row the filter selects while the check denies it shows as a pair of
// goldens. The grids cover each algorithm of the policy and of the set; the
// class files ask each class of filter no golden or grid case pairs with its
// rows. The objlist files compare lists and objects under == and != and a
// MATCH over 1e400; the rtsub files ask ${resourceType} when the request's
// resource type is spelled other than the target. The open files ask how a
// negated DENY predicate is parenthesised in a filter, an INACTIVE policy,
// the nested sets of a SIMPLIFIED set, and the type of an anonymous subject.
// tokensubject-claims asks again the token subjects of round 68, rerun-rp67-041
// asks the unstable golden rp67-041/q1 again, and the rawpairs, spellpos,
// scope and antlrtokens files continue the topics of earlier rounds. The
// cases are data under testdata/cases/round69, and each file's about field
// says what it asks.

// TestRound69AntlrtokensScopeCases runs round69/antlrtokens-scope.json.
func (s *ParitySuite) TestRound69AntlrtokensScopeCases() {
	s.runCaseFile("round69/antlrtokens-scope.json")
}

// TestRound69AntlrtokensUndeclaredCases runs round69/antlrtokens-undeclared.json.
func (s *ParitySuite) TestRound69AntlrtokensUndeclaredCases() {
	s.runCaseFile("round69/antlrtokens-undeclared.json")
}

// TestRound69FiltersubClassesFactorsCases runs round69/filtersub-classes-factors.json.
func (s *ParitySuite) TestRound69FiltersubClassesFactorsCases() {
	s.runCaseFile("round69/filtersub-classes-factors.json")
}

// TestRound69FiltersubClassesJournal1Cases runs round69/filtersub-classes-journal-1.json.
func (s *ParitySuite) TestRound69FiltersubClassesJournal1Cases() {
	s.runCaseFile("round69/filtersub-classes-journal-1.json")
}

// TestRound69FiltersubClassesJournal10Cases runs round69/filtersub-classes-journal-10.json.
func (s *ParitySuite) TestRound69FiltersubClassesJournal10Cases() {
	s.runCaseFile("round69/filtersub-classes-journal-10.json")
}

// TestRound69FiltersubClassesJournal11Cases runs round69/filtersub-classes-journal-11.json.
func (s *ParitySuite) TestRound69FiltersubClassesJournal11Cases() {
	s.runCaseFile("round69/filtersub-classes-journal-11.json")
}

// TestRound69FiltersubClassesJournal2Cases runs round69/filtersub-classes-journal-2.json.
func (s *ParitySuite) TestRound69FiltersubClassesJournal2Cases() {
	s.runCaseFile("round69/filtersub-classes-journal-2.json")
}

// TestRound69FiltersubClassesJournal3Cases runs round69/filtersub-classes-journal-3.json.
func (s *ParitySuite) TestRound69FiltersubClassesJournal3Cases() {
	s.runCaseFile("round69/filtersub-classes-journal-3.json")
}

// TestRound69FiltersubClassesJournal4Cases runs round69/filtersub-classes-journal-4.json.
func (s *ParitySuite) TestRound69FiltersubClassesJournal4Cases() {
	s.runCaseFile("round69/filtersub-classes-journal-4.json")
}

// TestRound69FiltersubClassesJournal5Cases runs round69/filtersub-classes-journal-5.json.
func (s *ParitySuite) TestRound69FiltersubClassesJournal5Cases() {
	s.runCaseFile("round69/filtersub-classes-journal-5.json")
}

// TestRound69FiltersubClassesJournal6Cases runs round69/filtersub-classes-journal-6.json.
func (s *ParitySuite) TestRound69FiltersubClassesJournal6Cases() {
	s.runCaseFile("round69/filtersub-classes-journal-6.json")
}

// TestRound69FiltersubClassesJournal7Cases runs round69/filtersub-classes-journal-7.json.
func (s *ParitySuite) TestRound69FiltersubClassesJournal7Cases() {
	s.runCaseFile("round69/filtersub-classes-journal-7.json")
}

// TestRound69FiltersubClassesJournal8Cases runs round69/filtersub-classes-journal-8.json.
func (s *ParitySuite) TestRound69FiltersubClassesJournal8Cases() {
	s.runCaseFile("round69/filtersub-classes-journal-8.json")
}

// TestRound69FiltersubClassesJournal9Cases runs round69/filtersub-classes-journal-9.json.
func (s *ParitySuite) TestRound69FiltersubClassesJournal9Cases() {
	s.runCaseFile("round69/filtersub-classes-journal-9.json")
}

// TestRound69FiltersubClassesMirrored1Cases runs round69/filtersub-classes-mirrored-1.json.
func (s *ParitySuite) TestRound69FiltersubClassesMirrored1Cases() {
	s.runCaseFile("round69/filtersub-classes-mirrored-1.json")
}

// TestRound69FiltersubClassesMirrored2Cases runs round69/filtersub-classes-mirrored-2.json.
func (s *ParitySuite) TestRound69FiltersubClassesMirrored2Cases() {
	s.runCaseFile("round69/filtersub-classes-mirrored-2.json")
}

// TestRound69FiltersubClassesMirrored3Cases runs round69/filtersub-classes-mirrored-3.json.
func (s *ParitySuite) TestRound69FiltersubClassesMirrored3Cases() {
	s.runCaseFile("round69/filtersub-classes-mirrored-3.json")
}

// TestRound69FiltersubClassesMirrored4Cases runs round69/filtersub-classes-mirrored-4.json.
func (s *ParitySuite) TestRound69FiltersubClassesMirrored4Cases() {
	s.runCaseFile("round69/filtersub-classes-mirrored-4.json")
}

// TestRound69FiltersubClassesMirrored5Cases runs round69/filtersub-classes-mirrored-5.json.
func (s *ParitySuite) TestRound69FiltersubClassesMirrored5Cases() {
	s.runCaseFile("round69/filtersub-classes-mirrored-5.json")
}

// TestRound69FiltersubGridAllowPredNoneFalseAllowPredCases runs round69/filtersub-grid-allow-pred-none-false-allow-pred.json.
func (s *ParitySuite) TestRound69FiltersubGridAllowPredNoneFalseAllowPredCases() {
	s.runCaseFile("round69/filtersub-grid-allow-pred-none-false-allow-pred.json")
}

// TestRound69FiltersubGridAllowPredNoneFalseAloneCases runs round69/filtersub-grid-allow-pred-none-false-alone.json.
func (s *ParitySuite) TestRound69FiltersubGridAllowPredNoneFalseAloneCases() {
	s.runCaseFile("round69/filtersub-grid-allow-pred-none-false-alone.json")
}

// TestRound69FiltersubGridAllowPredSubjectFalseAllowPredCases runs round69/filtersub-grid-allow-pred-subject-false-allow-pred.json.
func (s *ParitySuite) TestRound69FiltersubGridAllowPredSubjectFalseAllowPredCases() {
	s.runCaseFile("round69/filtersub-grid-allow-pred-subject-false-allow-pred.json")
}

// TestRound69FiltersubGridAllowPredSubjectFalseAloneCases runs round69/filtersub-grid-allow-pred-subject-false-alone.json.
func (s *ParitySuite) TestRound69FiltersubGridAllowPredSubjectFalseAloneCases() {
	s.runCaseFile("round69/filtersub-grid-allow-pred-subject-false-alone.json")
}

// TestRound69FiltersubGridDenyNopredResourceAloneCases runs round69/filtersub-grid-deny-nopred-resource-alone.json.
func (s *ParitySuite) TestRound69FiltersubGridDenyNopredResourceAloneCases() {
	s.runCaseFile("round69/filtersub-grid-deny-nopred-resource-alone.json")
}

// TestRound69FiltersubGridDenyPredSubjectTrueAloneCases runs round69/filtersub-grid-deny-pred-subject-true-alone.json.
func (s *ParitySuite) TestRound69FiltersubGridDenyPredSubjectTrueAloneCases() {
	s.runCaseFile("round69/filtersub-grid-deny-pred-subject-true-alone.json")
}

// TestRound69ObjlistListLiteralCases runs round69/objlist-list-literal.json.
func (s *ParitySuite) TestRound69ObjlistListLiteralCases() {
	s.runCaseFile("round69/objlist-list-literal.json")
}

// TestRound69ObjlistPairsCases runs round69/objlist-pairs.json.
func (s *ParitySuite) TestRound69ObjlistPairsCases() {
	s.runCaseFile("round69/objlist-pairs.json")
}

// TestRound69ObjlistTextCases runs round69/objlist-text.json.
func (s *ParitySuite) TestRound69ObjlistTextCases() {
	s.runCaseFile("round69/objlist-text.json")
}

// TestRound69OpenAnonymousCases runs round69/open-anonymous.json.
func (s *ParitySuite) TestRound69OpenAnonymousCases() {
	s.runCaseFile("round69/open-anonymous.json")
}

// TestRound69OpenFilterCases runs round69/open-filter.json.
func (s *ParitySuite) TestRound69OpenFilterCases() {
	s.runCaseFile("round69/open-filter.json")
}

// TestRound69RawpairsG0Cases runs round69/rawpairs-g0.json.
func (s *ParitySuite) TestRound69RawpairsG0Cases() {
	s.runCaseFile("round69/rawpairs-g0.json")
}

// TestRound69RawpairsG2Cases runs round69/rawpairs-g2.json.
func (s *ParitySuite) TestRound69RawpairsG2Cases() {
	s.runCaseFile("round69/rawpairs-g2.json")
}

// TestRound69RawpairsGfailCases runs round69/rawpairs-gfail.json.
func (s *ParitySuite) TestRound69RawpairsGfailCases() {
	s.runCaseFile("round69/rawpairs-gfail.json")
}

// TestRound69RawpairsGnoneCases runs round69/rawpairs-gnone.json.
func (s *ParitySuite) TestRound69RawpairsGnoneCases() {
	s.runCaseFile("round69/rawpairs-gnone.json")
}

// TestRound69RawpairsHeadsCases runs round69/rawpairs-heads.json.
func (s *ParitySuite) TestRound69RawpairsHeadsCases() {
	s.runCaseFile("round69/rawpairs-heads.json")
}

// TestRound69RerunRp67041Cases runs round69/rerun-rp67-041.json.
func (s *ParitySuite) TestRound69RerunRp67041Cases() {
	s.runCaseFile("round69/rerun-rp67-041.json")
}

// TestRound69RtsubSetsCases runs round69/rtsub-sets.json.
func (s *ParitySuite) TestRound69RtsubSetsCases() {
	s.runCaseFile("round69/rtsub-sets.json")
}

// TestRound69RtsubSimplifiedCases runs round69/rtsub-simplified.json.
func (s *ParitySuite) TestRound69RtsubSimplifiedCases() {
	s.runCaseFile("round69/rtsub-simplified.json")
}

// TestRound69RtsubUnknownCases runs round69/rtsub-unknown.json.
func (s *ParitySuite) TestRound69RtsubUnknownCases() {
	s.runCaseFile("round69/rtsub-unknown.json")
}

// TestRound69ScopeNamesDeclaredCases runs round69/scope-names-declared.json.
func (s *ParitySuite) TestRound69ScopeNamesDeclaredCases() {
	s.runCaseFile("round69/scope-names-declared.json")
}

// TestRound69ScopeNamesUndeclaredCases runs round69/scope-names-undeclared.json.
func (s *ParitySuite) TestRound69ScopeNamesUndeclaredCases() {
	s.runCaseFile("round69/scope-names-undeclared.json")
}

// TestRound69ScopeQuerydslCases runs round69/scope-querydsl.json.
func (s *ParitySuite) TestRound69ScopeQuerydslCases() {
	s.runCaseFile("round69/scope-querydsl.json")
}

// TestRound69SpellposMayCases runs round69/spellpos-may.json.
func (s *ParitySuite) TestRound69SpellposMayCases() {
	s.runCaseFile("round69/spellpos-may.json")
}

// TestRound69SpellposMustCases runs round69/spellpos-must.json.
func (s *ParitySuite) TestRound69SpellposMustCases() {
	s.runCaseFile("round69/spellpos-must.json")
}

// TestRound69SpellposShouldCases runs round69/spellpos-should.json.
func (s *ParitySuite) TestRound69SpellposShouldCases() {
	s.runCaseFile("round69/spellpos-should.json")
}

// TestRound69TokensubjectClaimsCases runs round69/tokensubject-claims.json.
// It needs the clients of testdata/realm-clients/token-subject-clients.json
// and the users of testdata/realm/token-subject-users.json in the parity realm.
func (s *ParitySuite) TestRound69TokensubjectClaimsCases() {
	s.runCaseFile("round69/tokensubject-claims.json")
}
