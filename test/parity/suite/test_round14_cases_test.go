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

import (
	"context"
	"time"
)

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

// How the filter writes an iterate pass that gives two groups: the nested
// iterating set of round 13 whose pass holds two scoped policies with
// predicates, beside the allowed==1 policy. Round 13 showed that the groups of
// two passes stand as one parenthesised group of the parent; here each pass
// gives two groups of its own. The case stays in Go because each scope shape is
// pinned and then waited on.
//
// The case lives in its own test function so that a recording run can be
// filtered to it and leave every golden already committed alone. Legacy
// profile only.
func (s *ParitySuite) TestRound14IteratePassCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("iterate is a regular policy set field; the agent loads simplified policies")
	}
	ctx := context.Background()
	for _, shape := range round13ScopeShapes {
		if len(shape.grants) == 0 {
			continue // no grant, no pass: the shape has no group to write
		}
		s.Require().NoError(s.pipMock.PinRoute(ctx, permissionScopeWirePath(parityReaderSubjectID), iterateFilterGrants(shape.grants)))
		// Outlive the cachePeriod of the declaration, as permission-scope-wire does.
		time.Sleep(2 * time.Second)
		tc := round11NestedSetCase("r14-pass-with-two-predicates-"+shape.name, func(b regularBuilder) map[string]any {
			return round13IteratingSet(b, "nested", "true", "DENY_OVERRIDES", "DENY_OVERRIDES", []any{
				round13ScopedPolicy(b, "scoped", "DENY_UNLESS_PERMIT"),
				b.policy("kinded", readerTarget, "DENY_UNLESS_PERMIT",
					b.rule("kinded-list", "operation == 'LIST' AND subject.permissionScope.region IS NOT NULL", "true",
						"ALLOW", map[string]string{"rsqlPredicate": "kind==1"})),
			}, nil)
		}, round13RegionRequests)
		tc.pips = []any{permissionScopeWirePIP}
		s.runRegularCases([]regularCase{tc})
	}
}
