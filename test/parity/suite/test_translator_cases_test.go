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

// The translator cases ask which wildcard dialect MATCH speaks on a path, and
// how equality, membership, and the relational operators treat a value whose
// JSON type or written form is not the literal's. Their cases are data under
// testdata/cases/translator, written by generate.py there, which says what
// each file asks. They were first written in Go, and each file sends the
// requests the Go cases sent, so the goldens recorded then still apply. Each
// function runs one file, so that a recording run can be filtered to it and
// record it on a stand of its own.

// TestTranslatorMatchDialectCases runs translator/match-dialect.json.
func (s *ParitySuite) TestTranslatorMatchDialectCases() {
	s.runCaseFile("translator/match-dialect.json")
}

// TestTranslatorValueSemanticsCases runs translator/value-semantics.json.
func (s *ParitySuite) TestTranslatorValueSemanticsCases() {
	s.runCaseFile("translator/value-semantics.json")
}
