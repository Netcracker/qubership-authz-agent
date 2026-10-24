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

// Round 42 is the first round recorded on access-control 6.1.6. It asks two
// things the re-recording on that release left open. One is subject.isM2M as
// the whole condition or target: 6.1.6 accepts it as the whole condition of a
// simplified policy, and its new goldens ask a user only. The other is which
// keys of a simplified policy's predicates object other than mongodbPredicate
// the filter reads. The cases are data under testdata/cases/round42, and each
// case's about field says what it asks.

// TestRound42OpenM2mAloneCases runs round42/open-m2m-alone.json.
func (s *ParitySuite) TestRound42OpenM2mAloneCases() {
	s.runCaseFile("round42/open-m2m-alone.json")
}

// TestRound42OpenPredicatesNestedCases runs round42/open-predicates-nested.json.
func (s *ParitySuite) TestRound42OpenPredicatesNestedCases() {
	s.runCaseFile("round42/open-predicates-nested.json")
}
