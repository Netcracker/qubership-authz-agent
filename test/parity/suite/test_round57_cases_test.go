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

// Round 57 asks how the v3 export renders the members of a simplified policy
// that no earlier golden reads back: predicate, customPredicate, nested
// predicates, a member named "condition " with a trailing space, and fields.
// Each case uploads one in a tenant of its own and reads the tenant's whole
// export back. Each file records the stand's version first and opens and closes
// with a control. The cases are data under testdata/cases/round57, and each
// case's about field says what it asks.

// TestRound57PapexportMustCases runs round57/papexport-must.json.
func (s *ParitySuite) TestRound57PapexportMustCases() {
	s.runCaseFile("round57/papexport-must.json")
}
