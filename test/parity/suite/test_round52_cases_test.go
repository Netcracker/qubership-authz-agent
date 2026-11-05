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

// Round 52 asks two readings of a PIP name: a GENERAL PIP declared twice with a
// whole ${subject.id} in its requestAttributes, and a DELETE of a PIP
// customization whose name ends in %41, each beside its twin. Each case runs in
// a tenant of its own. Each file records the stand's version first and opens
// and closes with a control. The cases are data under testdata/cases/round52,
// and each case's about field says what it asks.

// TestRound52PapidentMustCases runs round52/papident-must.json.
func (s *ParitySuite) TestRound52PapidentMustCases() {
	s.runCaseFile("round52/papident-must.json")
}

// TestRound52PapidentShouldCases runs round52/papident-should.json.
func (s *ParitySuite) TestRound52PapidentShouldCases() {
	s.runCaseFile("round52/papident-should.json")
}
