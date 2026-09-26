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

// round13ScopeTargetCase is a set under setAlgorithm of one policy under the
// same algorithm, whose target reads subject.permissionScope.region IS NULL
// outside iterate and whose one rule, with the condition true, has effect.
func round13ScopeTargetCase(id, setAlgorithm, effect string) regularCase {
	b := regularBuilder{caseID: id}
	rt := regularResourceType(id)
	return regularCase{
		id:           id,
		resourceType: rt,
		pips:         []any{permissionScopeWirePIP},
		uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
			b.set("set", "resourceType == '"+rt+"'", setAlgorithm, []any{
				b.policy("scoped", readerTarget+" AND subject.permissionScope.region IS NULL", setAlgorithm,
					b.rule("any", "true", "true", effect, nil)),
			}, nil),
		}}},
		requests: []isolatedRequest{{name: "read", resource: map[string]any{"id": "r13-scope-target"}}},
	}
}

// round13ScopeOutsideIterateCases builds the cases of
// TestRound13ScopeOutsideIterateCases.
func round13ScopeOutsideIterateCases() []regularCase {
	denyID := "r13-scope-outside-iterate-in-a-deny-rule"
	b := regularBuilder{caseID: denyID}
	rt := regularResourceType(denyID)
	cases := []regularCase{{
		id:           denyID,
		resourceType: rt,
		pips:         []any{permissionScopeWirePIP},
		uploads: []regularUpload{{externalID: "parity-" + denyID, sets: []any{
			b.set("set", "resourceType == '"+rt+"'", "PERMIT_UNLESS_DENY", []any{
				b.policy("scoped", readerTarget, "PERMIT_UNLESS_DENY",
					b.rule("read-deny-under-is-empty", "operation == 'READ'", "subject.permissionScope.region IS EMPTY", "DENY", nil),
					b.rule("control-deny-without-scope", "operation == 'CONTROL'", "resource.a == 'y'", "DENY", nil)),
			}, nil),
		}}},
		requests: []isolatedRequest{
			{name: "read-under-is-empty", resource: map[string]any{"id": "r13-scope-deny"}},
			{name: "control-without-scope", operation: "CONTROL", resource: map[string]any{"id": "r13-scope-deny", "a": "z"}},
		},
	}}
	cases = append(cases,
		round13ScopeTargetCase("r13-scope-outside-iterate-in-a-policy-target-under-deny-unless-permit", "DENY_UNLESS_PERMIT", "ALLOW"),
		round13ScopeTargetCase("r13-scope-outside-iterate-in-a-policy-target-under-permit-unless-deny", "PERMIT_UNLESS_DENY", "DENY"),
	)

	placeholder := round9SetCase("r13-scope-placeholder-outside-iterate", "DENY_UNLESS_PERMIT", func(b regularBuilder) []any {
		return []any{b.policy("scoped", readerTarget, "DENY_UNLESS_PERMIT",
			allowWithPredicate(b, "list-in-granted-regions", "region=in=(${subject.permissionScope.region})"))}
	})
	placeholder.pips = []any{permissionScopeWirePIP}
	cases = append(cases, placeholder)

	condition := round9SetCase("r13-scope-condition-outside-iterate-beside-a-predicate", "DENY_UNLESS_PERMIT", func(b regularBuilder) []any {
		return []any{round9PredicatePolicy(b), b.policy("scoped", readerTarget, "DENY_UNLESS_PERMIT",
			b.rule("list-under-is-empty", "operation == 'LIST'", "subject.permissionScope.region IS EMPTY", "ALLOW", nil))}
	})
	condition.pips = []any{permissionScopeWirePIP}
	condition.requests = []isolatedRequest{{name: "filter", filter: true}}
	cases = append(cases, condition)
	return cases
}

// Where the failure of a subject.permissionScope read outside iterate ends:
// round 12 showed it ends more than its own rule, and the one case that tells
// how much, scope-read-beside-a-true-rule, answers per stand. In each case here
// no second rule applies to the request, so no rule can decide before the read
// and the answer does not depend on the order.
//
// r13-scope-outside-iterate-in-a-deny-rule is a PERMIT_UNLESS_DENY policy whose
// DENY rule reads the scope: check/resource is true if the read ends the rule
// alone, and false if it ends the answer. control-without-scope is its control,
// a DENY rule on another operation that does not apply, so the policy permits.
//
// The two policy-target cases read the scope in the policy target, beside the
// role: under DENY_UNLESS_PERMIT with an ALLOW rule and under PERMIT_UNLESS_DENY
// with a DENY rule. A target that holds gives true and false, a target that does
// not apply gives false and true, and a read that ends the answer gives false
// twice.
//
// r13-scope-placeholder-outside-iterate renders the scope key into the predicate
// of a set that does not iterate, with no other rule on LIST: DENY says the
// placeholder denies the filter, a predicate says what it renders to.
// r13-scope-condition-outside-iterate-beside-a-predicate reads the key in the
// condition of a rule without a predicate beside the allowed==1 policy: DENY
// says the read denies the whole filter, allowed==1 that the rule drops out.
// The condition case sends the filter alone, since check/resource there has a
// permitting rule beside the read and answers per stand.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only.
func (s *ParitySuite) TestRound13ScopeOutsideIterateCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("iterate is a regular policy set field; the agent loads simplified policies")
	}
	s.pinTwoScopeGrants()
	s.runRegularCases(round13ScopeOutsideIterateCases())
}

// round13ForNobodySet is a set under algorithm whose one policy targets a role
// nobody holds, so none of its policies applies.
func round13ForNobodySet(b regularBuilder, key, algorithm string) map[string]any {
	return b.set(key, "true", algorithm, []any{
		b.policy(key+"-for-nobody", round9FalseSubjectCondition, "DENY_UNLESS_PERMIT",
			b.rule(key+"-for-nobody-list-allow", "operation == 'LIST'", "true", "ALLOW", nil)),
	}, nil)
}

// round13AllowsList is a policy that allows LIST with no predicate.
func round13AllowsList(b regularBuilder) map[string]any {
	return b.policy("allows-list", readerTarget, "DENY_UNLESS_PERMIT",
		b.rule("list-allow", "operation == 'LIST'", "true", "ALLOW", nil))
}

// round13OuterSetCase is a case of one set under setAlgorithm holding policies and
// nested sets, with round9FilterRequests.
func round13OuterSetCase(id, setAlgorithm string, policies func(b regularBuilder) []any, nested func(b regularBuilder) []any) regularCase {
	b := regularBuilder{caseID: id}
	rt := regularResourceType(id)
	return regularCase{
		id:           id,
		resourceType: rt,
		uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
			b.set("outer", "resourceType == '"+rt+"'", setAlgorithm, emptyIfNil(policies(b)), nested(b)),
		}}},
		requests: round9FilterRequests,
	}
}

// round13FilterCases builds the cases of TestRound13FilterCases.
func round13FilterCases() []regularCase {
	var cases []regularCase
	none := func(regularBuilder) []any { return nil }
	for _, algorithm := range []string{"PERMIT_OVERRIDES", "PERMIT_UNLESS_DENY"} {
		key := round13Key(algorithm)
		cases = append(cases,
			round9SetCase("r13-"+key+"-set-with-an-unrestricted-allow-beside-a-predicate", algorithm, func(b regularBuilder) []any {
				return []any{round9PredicatePolicy(b), round13AllowsList(b)}
			}),
			round9SetCase("r13-"+key+"-set-with-the-unrestricted-allow-alone", algorithm, func(b regularBuilder) []any {
				return []any{round13AllowsList(b)}
			}),
		)
	}
	for _, algorithm := range round13Algorithms {
		cases = append(cases, round13OuterSetCase("r13-only-child-"+round13Key(algorithm)+"-set-without-an-applicable-policy",
			"DENY_UNLESS_PERMIT", none, func(b regularBuilder) []any {
				return []any{round13ForNobodySet(b, "nested", algorithm)}
			}))
	}
	cases = append(cases,
		round13OuterSetCase("r13-deny-unless-permit-set-with-a-nested-allow-beside-a-predicate", "DENY_UNLESS_PERMIT",
			func(b regularBuilder) []any { return []any{round9PredicatePolicy(b)} },
			func(b regularBuilder) []any { return []any{round13ForNobodySet(b, "nested", "PERMIT_UNLESS_DENY")} }),
		round9SetCase("r13-deny-overrides-set-with-an-unrestricted-allow-beside-a-deny-predicate", "DENY_OVERRIDES", func(b regularBuilder) []any {
			return []any{round13AllowsList(b), b.policy("with-a-deny-predicate", readerTarget, "DENY_OVERRIDES",
				b.rule("list-deny-with-a-predicate", "operation == 'LIST'", "true", "DENY", map[string]string{"rsqlPredicate": "blocked==1"}))}
		}),
	)
	return cases
}

// What an ALLOW without a predicate does to a predicate beside it in check/filter,
// and what a set none of whose policies applies gives the set above it. Round 12
// showed that under DENY_OVERRIDES the predicate stays beside such an ALLOW
// (r12 deny-overrides-set-with-an-unrestricted-allow-beside-a-predicate), while
// under DENY_UNLESS_PERMIT the ALLOW lifts it (r10
// deny-list-without-predicate-beside-a-predicate), and that a
// PERMIT_UNLESS_DENY set with no policy that applies gives ALLOW.
//
// r13-<algorithm>-set-with-an-unrestricted-allow-beside-a-predicate asks the same
// under PERMIT_OVERRIDES and PERMIT_UNLESS_DENY: ALLOW if the ALLOW lifts the
// filter, allowed==1 if the predicate stays; the -alone cases are the controls.
//
// r13-only-child-<algorithm>-set-without-an-applicable-policy nests such a set as the only child of a DENY_UNLESS_PERMIT set: DENY says the
// nested set does not apply, ALLOW that it permits. The round 11 cases
// fn-nested-set-without-an-applicable-policy-under-* put the set beside
// allowed==1 under DENY_OVERRIDES, where the two give one answer. The
// DENY_UNLESS_PERMIT row is the control, DENY by round 11; the
// PERMIT_UNLESS_DENY row says whether that set still gives ALLOW when nested,
// which the next case needs.
//
// r13-deny-unless-permit-set-with-a-nested-allow-beside-a-predicate puts the
// PERMIT_UNLESS_DENY set with no policy that applies beside the allowed==1 policy
// under DENY_UNLESS_PERMIT: ALLOW if the ALLOW of a nested set lifts the
// predicate as a policy's ALLOW does, allowed==1 if it does not or if the nested
// set does not apply, which the PERMIT_UNLESS_DENY only-child row tells apart.
//
// r13-deny-overrides-set-with-an-unrestricted-allow-beside-a-deny-predicate puts
// the ALLOW beside a DENY rule with the predicate blocked==1 under
// DENY_OVERRIDES: ALLOW if the ALLOW lifts a negated predicate, the negation of
// blocked==1 if it stays.
//
// Every case sends the filter on LIST and check/resource on LIST. The cases live
// in their own test function so that a recording run can be filtered to them and
// leave every golden already committed alone. Legacy profile only.
func (s *ParitySuite) TestRound13FilterCases() {
	s.runRegularCases(round13FilterCases())
}

// Whether the PAP accepts a condition with a literal left over after a complete
// comparison, and a list whose second element is an attribute rather than a
// literal. No golden records either form. Each upload is recorded with its
// status, and an accepted one also with the answer to READ.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound13PAPSyntaxCases() {
	resource := map[string]any{"id": "r13-syntax", "a": "y", "x": "a", "y": "b"}
	s.runIsolatedCases([]isolatedCase{
		{id: "ps-trailing-literal", resourceType: round13ResourceType("ps-trailing-literal"),
			condition: "resource.a == 'y' 'z'", requests: []isolatedRequest{{name: "read", resource: resource}}},
		{id: "ps-attribute-in-a-list", resourceType: round13ResourceType("ps-attribute-in-a-list"),
			condition: "resource.x IN 'a', resource.y", requests: []isolatedRequest{{name: "read", resource: resource}}},
	})
}

// round13ResourceType is the resource type of the isolated round 13 case keyed key.
func round13ResourceType(key string) string {
	return "PARITY_SUITE_R13_" + strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
}
