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
	"strings"
	"time"
)

// round13Algorithms are the four combining algorithms, in the order the round 13
// cases vary them.
var round13Algorithms = []string{"DENY_UNLESS_PERMIT", "DENY_OVERRIDES", "PERMIT_OVERRIDES", "PERMIT_UNLESS_DENY"}

// round13Key turns a combining algorithm into the part of a case id that names it.
func round13Key(algorithm string) string {
	return strings.ToLower(strings.ReplaceAll(algorithm, "_", "-"))
}

// round13ScopeShapes are the answers the scope service is pinned to in
// TestRound13IterateCases, one run of every case each.
var round13ScopeShapes = []struct {
	name   string
	grants []permissionScopeGrant
}{
	{"no-grants", nil},
	{"one-grant-r1", []permissionScopeGrant{{"region": {"r1"}}}},
	{"two-grants-r1-and-r2", []permissionScopeGrant{{"region": {"r1"}}, {"region": {"r2"}}}},
}

// round13RegionRequests are the filter on LIST and check/resource on LIST in the
// regions r1 and r2.
var round13RegionRequests = []isolatedRequest{
	{name: "filter", filter: true},
	{name: "check-list-in-region-r1", operation: "LIST", resource: map[string]any{"id": "r13-iterate", "region": "r1"}},
	{name: "check-list-in-region-r2", operation: "LIST", resource: map[string]any{"id": "r13-iterate", "region": "r2"}},
}

// round13ScopedPolicy is the policy of scope-set-algorithm under policyAlgorithm:
// one LIST rule whose target is subject.permissionScope.region IS NOT NULL,
// whose condition is subject.permissionScope.region CONTAINS resource.region, and
// whose predicate is region=in=(${subject.permissionScope.region}).
func round13ScopedPolicy(b regularBuilder, key, policyAlgorithm string) map[string]any {
	return b.policy(key, readerTarget, policyAlgorithm,
		b.rule(key+"-region-granted",
			"operation == 'LIST' AND subject.permissionScope.region IS NOT NULL",
			"subject.permissionScope.region CONTAINS resource.region",
			"ALLOW", map[string]string{"rsqlPredicate": "region=in=(${subject.permissionScope.region})"}))
}

// round13IteratingSet is a policy set under setAlgorithm whose iterate node over
// subject.permissionScope is under nodeAlgorithm, unlike
// regularBuilder.iteratingSet, which gives both one algorithm.
func round13IteratingSet(b regularBuilder, key, target, setAlgorithm, nodeAlgorithm string, policies, nested []any) map[string]any {
	set := b.set(key, target, setAlgorithm, emptyIfNil(policies), nested)
	set["iterate"] = map[string]any{"foreach": "subject.permissionScope", "combiningAlgorithm": nodeAlgorithm}
	return set
}

// round13TopLevelCase is a case of one top-level set that sets builds for the
// case's resource type, reading the scope service, with round13RegionRequests.
func round13TopLevelCase(id string, set func(b regularBuilder, rt string) map[string]any) regularCase {
	b := regularBuilder{caseID: id}
	rt := regularResourceType(id)
	return regularCase{
		id:           id,
		resourceType: rt,
		pips:         []any{permissionScopeWirePIP},
		uploads:      []regularUpload{{externalID: "parity-" + id, sets: []any{set(b, rt)}}},
		requests:     round13RegionRequests,
	}
}

// round13IterateCases builds the cases of TestRound13IterateCases for the scope
// shape named shape.
func round13IterateCases(shape string) []regularCase {
	var cases []regularCase
	for _, node := range round13Algorithms {
		tc := round11NestedSetCase("r13-node-"+round13Key(node)+"-"+shape, func(b regularBuilder) map[string]any {
			return round13IteratingSet(b, "nested", "true", "DENY_OVERRIDES", node,
				[]any{round13ScopedPolicy(b, "scoped", "DENY_UNLESS_PERMIT")}, nil)
		}, round13RegionRequests)
		tc.pips = []any{permissionScopeWirePIP}
		cases = append(cases, tc)
	}

	cases = append(cases, round13TopLevelCase("r13-pass-without-an-applicable-policy-"+shape, func(b regularBuilder, rt string) map[string]any {
		return round13IteratingSet(b, "set", "resourceType == '"+rt+"'", "PERMIT_UNLESS_DENY", "DENY_OVERRIDES",
			[]any{round13ScopedPolicy(b, "scoped", "PERMIT_OVERRIDES")}, nil)
	}))

	cases = append(cases, round13TopLevelCase("r13-scope-key-no-grant-carries-"+shape, func(b regularBuilder, rt string) map[string]any {
		return round13IteratingSet(b, "set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", "DENY_UNLESS_PERMIT", []any{
			b.policy("scoped", readerTarget, "DENY_UNLESS_PERMIT",
				b.rule("list-under-category-is-empty", "operation == 'LIST'", "subject.permissionScope.category IS EMPTY", "ALLOW", nil)),
		}, nil)
	}))

	cases = append(cases, round13TopLevelCase("r13-set-nested-in-a-pass-"+shape, func(b regularBuilder, rt string) map[string]any {
		return round13IteratingSet(b, "set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", "DENY_UNLESS_PERMIT", nil, []any{
			b.set("nested", "true", "DENY_UNLESS_PERMIT", []any{round13ScopedPolicy(b, "scoped", "DENY_UNLESS_PERMIT")}, nil),
		})
	}))
	return cases
}

// What an iterate node over zero, one, and two grants gives the sets around it,
// in check/resource and in the filter. Round 12 answered for a DENY_OVERRIDES
// node (r12 fn-nested-deny-overrides-iterate-node-*): it does not apply over zero
// grants, and with scope-set-algorithm this fits one model, in which the node's
// answer is its set's answer and the set's own algorithm combines the policies
// inside a pass only.
//
// r13-node-<algorithm>-<shape> repeats the round 12 case with the node under
// each algorithm: the DENY_OVERRIDES set nested beside the allowed==1 policy
// under a DENY_OVERRIDES set. Over zero grants a node that denies gives DENY and
// false; a node that does not apply and a node that permits both give
// allowed==1 and true, since an ALLOW beside a predicate under DENY_OVERRIDES
// keeps the predicate (r12 deny-overrides-set-with-an-unrestricted-allow-beside-a-predicate).
// So the DENY_UNLESS_PERMIT and PERMIT_OVERRIDES rows ask whether the node
// denies. The DENY_OVERRIDES rows repeat round 12 on the same stand, and the
// PERMIT_UNLESS_DENY rows are controls.
//
// r13-pass-without-an-applicable-policy-<shape> is a top-level PERMIT_UNLESS_DENY
// set over a DENY_OVERRIDES node whose PERMIT_OVERRIDES policy has no rule that
// applies outside the granted region. In region r2 with the grant r1 the pass has
// no policy that applies: check/resource is true if the set's algorithm turns
// that into its permit, and false if the pass does not apply.
//
// r13-scope-key-no-grant-carries-<shape> reads subject.permissionScope.category,
// a key no grant carries, under IS EMPTY inside the pass. With a grant,
// check/resource is true if the missing key reads as an empty list, and false if
// it reads as an absent attribute (IS EMPTY over an absent key answers false, s7).
//
// r13-set-nested-in-a-pass-<shape> puts the scoped policy in a set nested in the
// iterating set rather than in the iterating set itself. With the grant r1,
// check/resource in r1 is true if the nested set sees the grant, and false if it
// reads the scope as from outside iterate.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only.
func (s *ParitySuite) TestRound13IterateCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("iterate is a regular policy set field; the agent loads simplified policies")
	}
	ctx := context.Background()
	for _, shape := range round13ScopeShapes {
		s.Require().NoError(s.pipMock.PinRoute(ctx, permissionScopeWirePath(parityReaderSubjectID), iterateFilterGrants(shape.grants)))
		// Outlive the cachePeriod of the declaration, as permission-scope-wire does.
		time.Sleep(2 * time.Second)
		s.runRegularCases(round13IterateCases(shape.name))
	}
}

// The other round 13 functions ask where the failure of a subject.permissionScope
// read outside iterate ends, what an ALLOW without a predicate and a set none of
// whose policies applies do in check/filter, what the PAP accepts, and what every
// operator answers over every operand state no golden fixes. Their cases are data
// under testdata/cases/round13, written by generate.py there, which says what each
// file asks. They were first written in Go, and each file sends the requests the
// Go cases sent, so the goldens recorded then still apply. Each function runs one
// file, so that a recording run can be filtered to it and record it on a stand of
// its own.

// TestRound13ScopeOutsideIterateCases runs round13/scope-outside-iterate.json.
func (s *ParitySuite) TestRound13ScopeOutsideIterateCases() {
	s.runCaseFile("round13/scope-outside-iterate.json")
}

// TestRound13FilterCases runs round13/filter.json.
func (s *ParitySuite) TestRound13FilterCases() { s.runCaseFile("round13/filter.json") }

// TestRound13PAPSyntaxCases runs round13/pap-syntax.json.
func (s *ParitySuite) TestRound13PAPSyntaxCases() { s.runCaseFile("round13/pap-syntax.json") }

// TestRound13CellCases runs round13/cells.json.
func (s *ParitySuite) TestRound13CellCases() { s.runCaseFile("round13/cells.json") }

// TestRound13FailingPIPInADenyRuleCases runs
// round13/failing-pip-in-a-deny-rule.json.
func (s *ParitySuite) TestRound13FailingPIPInADenyRuleCases() {
	s.runCaseFile("round13/failing-pip-in-a-deny-rule.json")
}
