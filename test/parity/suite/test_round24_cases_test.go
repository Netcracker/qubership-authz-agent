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

// Round 24 gives a second golden to the rules that exactly one earlier golden
// pins and that round 23 could not ask again, because the case format had no
// field for their mechanism: an empty tenant_id, the roles of a simplified
// policy, the pip-mock calls of one request, an INACTIVE set, a rule id another
// loaded set already has, and a PIP name declared in a second domain. Its cases
// are data under testdata/cases/round24, and each case that seconds a golden
// names it in its about field. Each function runs one file, so that a recording run can
// be filtered to it and record it on a stand of its own.

// TestRound24SecondCarrierFormatCases runs round24/second-carrier-format.json.
func (s *ParitySuite) TestRound24SecondCarrierFormatCases() {
	s.runCaseFile("round24/second-carrier-format.json")
}

// TestRound24SecondDomainCases runs round24/second-domain.json, which also
// uploads into the domain PARITY_ISOLATED_B.
func (s *ParitySuite) TestRound24SecondDomainCases() {
	s.runCaseFile("round24/second-domain.json")
}
