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

// Round 39 asks which conditions fail when a GENERAL PIP carries a whole
// ${subject.isM2M} in requestAttributes. Round 38 found that a check fails
// with 400 once it builds a simplified condition that names such a PIP, and
// that a filter reads the same PIP in a predicate as a failed PIP. These
// files ask the rest of that dimension: the place of the condition, whether
// the check reaches it, and the endpoint. Its cases are data under
// testdata/cases/round39, and each case's about field says what it asks.
// Each function runs one file, so that a recording run can be filtered to
// it and record it on a stand of its own.

// TestRound39OpenM2mPlacesCases runs round39/open-m2m-places.json.
func (s *ParitySuite) TestRound39OpenM2mPlacesCases() { s.runCaseFile("round39/open-m2m-places.json") }

// TestRound39OpenM2mUnreachedCases runs round39/open-m2m-unreached.json.
func (s *ParitySuite) TestRound39OpenM2mUnreachedCases() {
	s.runCaseFile("round39/open-m2m-unreached.json")
}

// TestRound39OpenM2mFilterCases runs round39/open-m2m-filter.json.
func (s *ParitySuite) TestRound39OpenM2mFilterCases() { s.runCaseFile("round39/open-m2m-filter.json") }

// TestRound39OpenM2mBulkCases runs round39/open-m2m-bulk.json.
func (s *ParitySuite) TestRound39OpenM2mBulkCases() { s.runCaseFile("round39/open-m2m-bulk.json") }

// TestRound39OpenM2mAccessCases runs round39/open-m2m-access.json.
func (s *ParitySuite) TestRound39OpenM2mAccessCases() { s.runCaseFile("round39/open-m2m-access.json") }
