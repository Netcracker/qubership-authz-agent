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

// Round 44 asks what no earlier golden tells apart: how one value is spelled
// in a condition, in the data, and in the fields of an upload; library
// behaviors at the points where a condition, a PIP value, or a filter text is
// handled; when a GENERAL PIP is read, recorded through the calls of a
// sentinel route; outcomes of a comparison that only a DENY rule separates;
// pairs of configurations whose answers the documented semantics says agree;
// and combinations of raw input features no golden sent together. Each file
// records the stand's version first and opens and closes with a control. The
// cases are data under testdata/cases/round44, and each file's about field
// says what it asks.

// TestRound44IdiomsConditionsCases runs round44/idioms-conditions.json.
func (s *ParitySuite) TestRound44IdiomsConditionsCases() {
	s.runCaseFile("round44/idioms-conditions.json")
}

// TestRound44IdiomsForwardedNamesCases runs round44/idioms-forwarded-names.json.
func (s *ParitySuite) TestRound44IdiomsForwardedNamesCases() {
	s.runCaseFile("round44/idioms-forwarded-names.json")
}

// TestRound44IdiomsUploadsCases runs round44/idioms-uploads.json.
func (s *ParitySuite) TestRound44IdiomsUploadsCases() {
	s.runCaseFile("round44/idioms-uploads.json")
}

// TestRound44MetamorphG1Cases runs round44/metamorph-g1.json.
func (s *ParitySuite) TestRound44MetamorphG1Cases() {
	s.runCaseFile("round44/metamorph-g1.json")
}

// TestRound44MetamorphG2Cases runs round44/metamorph-g2.json.
func (s *ParitySuite) TestRound44MetamorphG2Cases() {
	s.runCaseFile("round44/metamorph-g2.json")
}

// TestRound44ObservabilityCellsCases runs round44/observability-cells.json.
func (s *ParitySuite) TestRound44ObservabilityCellsCases() {
	s.runCaseFile("round44/observability-cells.json")
}

// TestRound44PatchesRightFirstCases runs round44/patches-right-first.json.
func (s *ParitySuite) TestRound44PatchesRightFirstCases() {
	s.runCaseFile("round44/patches-right-first.json")
}

// TestRound44RawpairsG0Cases runs round44/rawpairs-g0.json.
func (s *ParitySuite) TestRound44RawpairsG0Cases() {
	s.runCaseFile("round44/rawpairs-g0.json")
}

// TestRound44RawpairsG1Cases runs round44/rawpairs-g1.json.
func (s *ParitySuite) TestRound44RawpairsG1Cases() {
	s.runCaseFile("round44/rawpairs-g1.json")
}

// TestRound44RawpairsG2Cases runs round44/rawpairs-g2.json.
func (s *ParitySuite) TestRound44RawpairsG2Cases() {
	s.runCaseFile("round44/rawpairs-g2.json")
}

// TestRound44RawpairsGfailCases runs round44/rawpairs-gfail.json.
func (s *ParitySuite) TestRound44RawpairsGfailCases() {
	s.runCaseFile("round44/rawpairs-gfail.json")
}

// TestRound44RawpairsGnoneCases runs round44/rawpairs-gnone.json.
func (s *ParitySuite) TestRound44RawpairsGnoneCases() {
	s.runCaseFile("round44/rawpairs-gnone.json")
}

// TestRound44SentinelConditionsCases runs round44/sentinel-conditions.json.
func (s *ParitySuite) TestRound44SentinelConditionsCases() {
	s.runCaseFile("round44/sentinel-conditions.json")
}

// TestRound44SentinelNodesCases runs round44/sentinel-nodes.json.
func (s *ParitySuite) TestRound44SentinelNodesCases() {
	s.runCaseFile("round44/sentinel-nodes.json")
}

// TestRound44SpellDataCases runs round44/spell-data.json.
func (s *ParitySuite) TestRound44SpellDataCases() {
	s.runCaseFile("round44/spell-data.json")
}

// TestRound44SpellFieldsCases runs round44/spell-fields.json.
func (s *ParitySuite) TestRound44SpellFieldsCases() {
	s.runCaseFile("round44/spell-fields.json")
}

// TestRound44SpellLiteralsCases runs round44/spell-literals.json.
func (s *ParitySuite) TestRound44SpellLiteralsCases() {
	s.runCaseFile("round44/spell-literals.json")
}

// TestRound44SpellSyntaxCases runs round44/spell-syntax.json.
func (s *ParitySuite) TestRound44SpellSyntaxCases() {
	s.runCaseFile("round44/spell-syntax.json")
}
