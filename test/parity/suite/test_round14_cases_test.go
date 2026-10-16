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

// Round 14 asks for the forms of the condition language no golden has recorded
// yet. Its cases are data under testdata/cases/round14, written by generate.py
// there, which says what each file asks. Each function runs one file, so that a
// recording run can be filtered to it and record it on a stand of its own,
// leaving every golden already committed alone.

// TestRound14OperandKindCases runs round14/operand-kind.json.
func (s *ParitySuite) TestRound14OperandKindCases() { s.runCaseFile("round14/operand-kind.json") }

// TestRound14RightStateCases runs round14/right-state.json.
func (s *ParitySuite) TestRound14RightStateCases() { s.runCaseFile("round14/right-state.json") }

// TestRound14ValueCases runs round14/value.json.
func (s *ParitySuite) TestRound14ValueCases() { s.runCaseFile("round14/value.json") }

// TestRound14SyntaxCases runs round14/syntax.json.
func (s *ParitySuite) TestRound14SyntaxCases() { s.runCaseFile("round14/syntax.json") }

// TestRound14JSONPathCases runs round14/jsonpath.json.
func (s *ParitySuite) TestRound14JSONPathCases() { s.runCaseFile("round14/jsonpath.json") }

// TestRound14TargetCases runs round14/target.json.
func (s *ParitySuite) TestRound14TargetCases() { s.runCaseFile("round14/target.json") }

// TestRound14IteratePassCases runs round14/iterate-pass.json.
func (s *ParitySuite) TestRound14IteratePassCases() { s.runCaseFile("round14/iterate-pass.json") }
