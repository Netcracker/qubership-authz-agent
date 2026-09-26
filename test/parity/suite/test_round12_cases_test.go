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

// round12ScopeOutsideIterateControlCases builds the case of
// TestRound12ScopeOutsideIterateControlCases.
func round12ScopeOutsideIterateControlCases() []regularCase {
	return []regularCase{scopeOutsideIterateCase("scope-outside-iterate-beside-a-control", true)}
}

// Whether a read of subject.permissionScope outside iterate ends the rule that
// reads it, or leaves every rule of its policy unreached.
// scope-is-empty-outside-iterate answers false for all three of its rules, the
// IS NULL rule included, and both explanations produce that.
//
// The case is the set of scope-is-empty-outside-iterate with three more rules in
// the same policy, and the scope service answers the same two grants.
// control-without-scope sends CONTROL, whose one rule has the condition true and
// reads no scope: true says the policy is reached on a request that reads no
// scope, false says the rules of the policy are not reached.
// scope-read-beside-a-true-rule sends MIXED, whose two rules are IS EMPTY over
// the scope key and the condition true: true says the scope read ends its own
// rule alone, false says it ends the policy or the whole answer, as a failed
// GENERAL PIP does. The three requests of scope-is-empty-outside-iterate are
// repeated against this upload.
//
// The case lives in its own test function so that a recording run can be
// filtered to it and leave every golden already committed alone. Legacy profile
// only.
func (s *ParitySuite) TestRound12ScopeOutsideIterateControlCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("iterate is a regular policy set field; the agent loads simplified policies")
	}
	s.pinTwoScopeGrants()
	s.runRegularCases(round12ScopeOutsideIterateControlCases())
}

// round12NotApplicableFilterCases builds the cases of
// TestRound12NotApplicableFilterCases.
func round12NotApplicableFilterCases() []regularCase {
	allowsList := func(b regularBuilder) map[string]any {
		return b.policy("allows-list", readerTarget, "DENY_UNLESS_PERMIT",
			b.rule("list-allow", "operation == 'LIST'", "true", "ALLOW", nil))
	}
	return []regularCase{
		round9SetCase("permit-unless-deny-set-without-an-applicable-policy", "PERMIT_UNLESS_DENY", func(b regularBuilder) []any {
			return []any{b.policy("for-nobody", round9FalseSubjectCondition, "DENY_UNLESS_PERMIT",
				b.rule("for-nobody-list-allow", "operation == 'LIST'", "true", "ALLOW", nil))}
		}),
		round9SetCase("deny-overrides-set-with-an-unrestricted-allow-beside-a-predicate", "DENY_OVERRIDES", func(b regularBuilder) []any {
			return []any{round9PredicatePolicy(b), allowsList(b)}
		}),
		round9SetCase("deny-overrides-set-with-the-unrestricted-allow-alone", "DENY_OVERRIDES", func(b regularBuilder) []any {
			return []any{allowsList(b)}
		}),
	}
}

// What check/filter answers for a PERMIT_UNLESS_DENY set none of whose
// policies applies, and for an ALLOW without a predicate beside a predicate
// under DENY_OVERRIDES.
// fn-nested-set-without-an-applicable-policy-under-permit-unless-deny nests such
// a set beside the allowed==1 policy under DENY_OVERRIDES and answers
// allowed==1. Two readings produce that: A, the set does not apply in a filter,
// although it permits in check/resource (algorithm-permit-unless-deny); B, the
// set gives ALLOW, and an ALLOW beside a predicate under DENY_OVERRIDES keeps the
// predicate.
//
// permit-unless-deny-set-without-an-applicable-policy is the set alone, its one
// policy targeting a role nobody holds: the filter is DENY under A and ALLOW
// under B, and check/resource is true under both.
//
// deny-overrides-set-with-an-unrestricted-allow-beside-a-predicate puts the
// allowed==1 policy beside a policy that allows LIST with no predicate: the
// filter is ALLOW under A and allowed==1 under B.
// deny-overrides-set-with-the-unrestricted-allow-alone is the control of the
// policy without a predicate, ALLOW under both, which shows that it lifts the
// filter on its own; deny-overrides-set-with-the-predicate-policy-alone is the
// control of the predicate policy.
//
// Every case sends the filter on LIST and check/resource on LIST.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case.
func (s *ParitySuite) TestRound12NotApplicableFilterCases() {
	s.runRegularCases(round12NotApplicableFilterCases())
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
