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

// Round 34 asks what round 33 left open: whether subject.permissionScope,
// read outside iterate on the right, fails the decision before the left side
// ends the rule, for three left states of IN that round 33 did not send and
// for an absent key under NOT IN and NOT CONTAINS ANY. It also sends forms
// that real configurations use and no golden sends.
// Its cases are data under testdata/cases/round34, and each case's about
// field says what it asks. Each function runs one file, so that a recording
// run can be filtered to it and record it on a stand of its own.

// TestRound34GapsCorpusCases runs round34/gaps-corpus.json.
func (s *ParitySuite) TestRound34GapsCorpusCases() { s.runCaseFile("round34/gaps-corpus.json") }

// TestRound34OpenScopeCases runs round34/open-scope.json.
func (s *ParitySuite) TestRound34OpenScopeCases() { s.runCaseFile("round34/open-scope.json") }
