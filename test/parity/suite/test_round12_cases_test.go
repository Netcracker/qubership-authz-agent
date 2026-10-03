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

// Round 12 asks whether a read of subject.permissionScope outside iterate ends
// its rule or leaves its policy unreached, and what check/filter answers for a
// node with no applicable child. Two of its functions run data under
// testdata/cases/round12, written by generate.py there, which says what each
// file asks. They were first written in Go, and each file sends the requests
// the Go cases sent, so the goldens recorded then still apply.
// TestRound12IterateNodeInAFilterCases stays in Go, because it pins the scope
// service to another answer before each of its cases.

// TestRound12ScopeOutsideIterateControlCases runs
// round12/scope-outside-iterate-control.json.
func (s *ParitySuite) TestRound12ScopeOutsideIterateControlCases() {
	s.runCaseFile("round12/scope-outside-iterate-control.json")
}

// TestRound12NotApplicableFilterCases runs round12/not-applicable-filter.json.
func (s *ParitySuite) TestRound12NotApplicableFilterCases() {
	s.runCaseFile("round12/not-applicable-filter.json")
}

// round12IterateNodeShapes are the answers the scope service is pinned to in
// TestRound12IterateNodeInAFilterCases, one case each.
var round12IterateNodeShapes = []struct {
	name   string
	grants []permissionScopeGrant
}{
	{"no-grants", nil},
	{"one-grant-r1", []permissionScopeGrant{{"region": {"r1"}}}},
}

// round12IterateNodeInAFilterCase builds the case of
// TestRound12IterateNodeInAFilterCases for the scope shape named shape: a
// DENY_OVERRIDES set of round9PredicatePolicy and a nested DENY_OVERRIDES set
// whose iterate node, also DENY_OVERRIDES, holds the scoped LIST rule of
// scope-set-algorithm with the predicate region=in=(${subject.permissionScope.region}).
func round12IterateNodeInAFilterCase(shape string) regularCase {
	requests := []isolatedRequest{{name: "filter", filter: true}}
	for _, region := range []string{"r1", "r2"} {
		requests = append(requests, isolatedRequest{
			name: "check-list-in-region-" + region, operation: "LIST",
			resource: map[string]any{"id": "r12-iterate-node", "region": region},
		})
	}
	tc := round11NestedSetCase("fn-nested-deny-overrides-iterate-node-"+shape, func(b regularBuilder) map[string]any {
		return b.iteratingSet("nested", "true", "DENY_OVERRIDES", "subject.permissionScope", []any{
			b.policy("scoped", readerTarget, "DENY_UNLESS_PERMIT",
				b.rule("region-granted",
					"operation == 'LIST' AND subject.permissionScope.region IS NOT NULL",
					"subject.permissionScope.region CONTAINS resource.region",
					"ALLOW", map[string]string{"rsqlPredicate": "region=in=(${subject.permissionScope.region})"})),
		})
	}, requests)
	tc.pips = []any{permissionScopeWirePIP}
	return tc
}

// round12IterateNodeInAFilterCases builds every case of
// TestRound12IterateNodeInAFilterCases.
func round12IterateNodeInAFilterCases() []regularCase {
	var cases []regularCase
	for _, shape := range round12IterateNodeShapes {
		cases = append(cases, round12IterateNodeInAFilterCase(shape.name))
	}
	return cases
}

// What a DENY_OVERRIDES iterate node over zero grants contributes to a filter.
// scope-set-algorithm records such a node under a PERMIT_UNLESS_DENY set, where
// a node that denies and a node that does not apply give one answer, unless a
// PERMIT_UNLESS_DENY set with no child that applies gives ALLOW in a filter
// (TestRound12NotApplicableFilterCases).
//
// The node sits in a nested DENY_OVERRIDES set beside the allowed==1 policy
// under a DENY_OVERRIDES set, where the two differ: no-grants gives DENY if the
// node denies, and allowed==1 if it does not apply, the answer of
// fn-nested-set-without-an-applicable-policy-under-deny-overrides.
// one-grant-r1 is the control that the scope is read and the pass is reached:
// check/resource on LIST in region r2 is false, because the pass denies and
// DENY_OVERRIDES carries the deny up. check/resource in region r1 is true
// whether the pass applies or not, since the predicate policy allows LIST in
// check/resource. Each shape sends the filter on LIST and those two requests.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only.
func (s *ParitySuite) TestRound12IterateNodeInAFilterCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("iterate is a regular policy set field; the agent loads simplified policies")
	}
	ctx := context.Background()
	for _, shape := range round12IterateNodeShapes {
		s.Require().NoError(s.pipMock.PinRoute(ctx, permissionScopeWirePath(parityReaderSubjectID), iterateFilterGrants(shape.grants)))
		// Outlive the cachePeriod of the declaration, as permission-scope-wire does.
		time.Sleep(2 * time.Second)
		s.runRegularCases([]regularCase{round12IterateNodeInAFilterCase(shape.name)})
	}
}
