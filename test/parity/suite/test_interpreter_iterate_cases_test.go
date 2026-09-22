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
	"net/http"
	"time"

	"authz-agent/test/parity/suite/model"
)

// iterateAlgorithms are the accepted combining algorithms other than
// DENY_UNLESS_PERMIT, the one recorded (permission-scope-wire). Under
// PERMIT_UNLESS_DENY and DENY_OVERRIDES a denying pass and a permitting pass
// meet; PERMIT_OVERRIDES is the fourth column of the algorithm table, where a
// permitting pass is expected to decide as under DENY_UNLESS_PERMIT.
var iterateAlgorithms = []struct{ key, name string }{
	{"permit-unless-deny", "PERMIT_UNLESS_DENY"},
	{"deny-overrides", "DENY_OVERRIDES"},
	{"permit-overrides", "PERMIT_OVERRIDES"},
}

// iterateAlgorithmResourceType is the resource type of the iterating set built for
// one algorithm.
func iterateAlgorithmResourceType(key string) string {
	return regularResourceType("scope-iterate-" + key)
}

// iterateAlgorithmGrants are the grant shapes each iterating set is asked under:
// two grants for two regions, one grant, and no grant at all. Under one grant
// there is one pass and nothing to combine, so the answer is the pass's own
// under every algorithm; it is the boundary between the two-grant and the
// no-grant shapes.
var iterateAlgorithmGrants = []struct {
	name   string
	grants []permissionScopeGrant
}{
	{"two-grants-one-region-each", []permissionScopeGrant{{"region": {"r1"}}, {"region": {"r2"}}}},
	{"one-grant", []permissionScopeGrant{{"region": {"r1"}}}},
	{"no-grants", nil},
}

// iterateAlgorithmRequests ask for the region of the first grant, of the second,
// and of neither. Under two grants each region is denied by one pass and permitted
// by the other, so the two answers say how the passes combine; under one grant
// r2 is denied by the only pass, like r9; r9 is denied by every pass and is the
// control that the DENY rule is live.
var iterateAlgorithmRequests = []isolatedRequest{
	{name: "region-of-the-first-grant", resource: map[string]any{"id": "scope-alg", "region": "r1"}},
	{name: "region-of-the-second-grant", resource: map[string]any{"id": "scope-alg", "region": "r2"}},
	{name: "region-of-no-grant", resource: map[string]any{"id": "scope-alg", "region": "r9"}},
}

// How the passes of an iterating set are combined under each accepted algorithm
// other than the recorded one, and what the set decides under one pass and
// under no pass at all. permission-scope-wire
// records that iterate.foreach over subject.permissionScope evaluates the set once
// per grant, under DENY_UNLESS_PERMIT, where the first pass that permits decides.
// Under PERMIT_UNLESS_DENY and DENY_OVERRIDES a pass that denies and a pass that
// permits meet, and the readings differ: the permits are joined and one permitting
// pass permits the set, or one denying pass denies it; under PERMIT_OVERRIDES
// the permitting pass is expected to win, as under DENY_UNLESS_PERMIT. One grant
// is the shape with nothing to combine. No grant at all is the last column: a
// set over zero passes permits by default, or has nothing to permit.
//
// Each set holds a DENY rule, region not granted, and an ALLOW rule with no
// condition, so under two grants the region of either grant is denied by the pass
// of the other grant and permitted by its own. Without the ALLOW no pass could
// permit under DENY_OVERRIDES, and every reading would answer false. The region of
// no grant is denied by both passes and is the control. The PIP, the wire body and
// the cache wait are permission-scope-wire's. The pip-mock call log is read after
// every shape, since a cached scope would answer the second shape with the first
// shape's grants.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy profile
// only.
func (s *ParitySuite) TestInterpreterIterateAlgorithmCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("iterate is a regular policy set field; the agent loads simplified policies")
	}
	ctx := context.Background()
	m2m := s.mustM2MToken()
	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s: %v", isolatedCaseDomain, err)
		}
	})

	var sets []any
	for _, algorithm := range iterateAlgorithms {
		b := regularBuilder{caseID: "scope-iterate-" + algorithm.key}
		rt := iterateAlgorithmResourceType(algorithm.key)
		sets = append(sets, b.iteratingSet("set", "resourceType == '"+rt+"'", algorithm.name,
			"subject.permissionScope", []any{
				b.policy("scoped", readerTarget, algorithm.name,
					b.rule("region-not-granted", "operation == 'READ'",
						"subject.permissionScope.region NOT CONTAINS resource.region", "DENY", nil),
					b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil)),
			}))
	}

	pipStatus, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, []any{permissionScopeWirePIP}, nil)
	s.Require().NoError(err)
	s.Run("declare-the-pip", func() {
		s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "scope-iterate/declare-the-pip", &model.PolicyLoadOutcome{Status: pipStatus})
	})
	if pipStatus < http.StatusOK || pipStatus >= http.StatusMultipleChoices {
		return
	}

	setStatus, _, err := HelperPutPolicySets(ctx, s.cfg, m2m, "parity-scope-iterate-algorithms", sets)
	s.Require().NoError(err)
	s.Run("upload-the-sets", func() {
		s.requirePendingGolden(PSUITE_LOAD_POLICY_SETS, "scope-iterate/upload-the-sets", &model.PolicyLoadOutcome{Status: setStatus})
	})
	if setStatus < http.StatusOK || setStatus >= http.StatusMultipleChoices {
		return
	}

	scopePath := permissionScopeWirePath(parityReaderSubjectID)
	for _, shape := range iterateAlgorithmGrants {
		// Outlive the cachePeriod of the declaration, as permission-scope-wire does,
		// so the body pinned next is the one the next request sees.
		time.Sleep(2 * time.Second)
		s.Run(shape.name, func() {
			s.Require().NoError(s.pipMock.ResetCalls(ctx))
			s.Require().NoError(s.pipMock.PinRoute(ctx, scopePath, PipStubResponse{
				StatusCode: http.StatusOK,
				Body:       permissionScopeWireBody(parityReaderSubjectID, shape.grants),
			}))
			for _, algorithm := range iterateAlgorithms {
				for _, req := range iterateAlgorithmRequests {
					s.Run(algorithm.key+"/"+req.name, func() {
						s.runPendingCheckResourceV1OutcomeCase(
							"scope-iterate/"+shape.name+"/"+algorithm.key+"/"+req.name,
							model.CheckAccessRequest{
								Operation: "READ",
								Type:      iterateAlgorithmResourceType(algorithm.key),
								Resource:  req.resource,
							},
							s.mustTokenBundle(UserProfileReader),
							PerCallOptions{},
						)
					})
				}
			}
			s.Run("the-pip-was-read", func() {
				calls, err := s.pipMock.GetCalls(ctx)
				s.Require().NoError(err)
				read := 0
				for _, call := range calls {
					if call.Path == scopePath {
						read++
					}
				}
				s.Assert().Positive(read, "pip-mock calls to %s over the requests with the %s body pinned", scopePath, shape.name)
			})
		})
	}
}

// Whether iterate.foreach is bound to subject.permissionScope, and whether
// subject.permissionScope is readable outside an iterating set. Product policies
// write foreach over subject.permissionScope only, and internal/acconfig knows no
// other collection. The first two cases name another collection in foreach and
// record the upload status; a set the PAP accepts is then sent a request whose
// rule is true, so the answer says whether such a set evaluates at all. The third
// case reads subject.permissionScope.region in a set with no iterate block, with
// two grants pinned. Its probe compares the scope with a literal: a true probe
// means the grants are merged and readable anywhere, a false probe means a set
// without iterate does not read the scope. The pip-mock call count is logged after
// the cases, so a run shows whether the PIP was called at all.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy profile
// only.
func (s *ParitySuite) TestInterpreterIterateBindingCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("iterate is a regular policy set field; the agent loads simplified policies")
	}
	ctx := context.Background()
	scopePath := permissionScopeWirePath(parityReaderSubjectID)
	s.Require().NoError(s.pipMock.ResetCalls(ctx))
	s.Require().NoError(s.pipMock.PinRoute(ctx, scopePath, PipStubResponse{
		StatusCode: http.StatusOK,
		Body: permissionScopeWireBody(parityReaderSubjectID, []permissionScopeGrant{
			{"region": {"r1"}}, {"region": {"r2"}},
		}),
	}))
	// Declare the PIP, then outlive its cachePeriod, in the order
	// permission-scope-wire uses: the declaration sets the expiry the cache applies,
	// and the wait then expires an entry another case wrote for the same reader.
	// scope-read-outside-iterate declares the same PIP again, which changes nothing.
	pipStatus, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, []any{permissionScopeWirePIP}, nil)
	s.Require().NoError(err)
	s.Require().GreaterOrEqual(pipStatus, http.StatusOK, "declare subject.permissionScope in %s", isolatedCaseDomain)
	s.Require().Less(pipStatus, http.StatusMultipleChoices, "declare subject.permissionScope in %s", isolatedCaseDomain)
	time.Sleep(2 * time.Second)

	s.runRegularCases(iterateBindingCases())

	s.Run("scope-read-outside-iterate/the-pip-calls", func() {
		calls, err := s.pipMock.GetCalls(ctx)
		s.Require().NoError(err)
		read := 0
		for _, call := range calls {
			if call.Path == scopePath {
				read++
			}
		}
		s.T().Logf("pip-mock received %d call(s) to %s over the iterate binding cases", read, scopePath)
	})
}

func iterateBindingCases() []regularCase {
	var cases []regularCase

	for _, collection := range []struct{ key, foreach string }{
		{"subject-roles", "subject.roles"},
		{"resource-items", "resource.items"},
	} {
		id := "iterate-over-" + collection.key
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.iteratingSet("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", collection.foreach, []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil)),
				}),
			}}},
			requests: []isolatedRequest{
				{name: "read-under-a-rule-that-is-true", resource: map[string]any{"id": "reg-iterate-" + collection.key, "items": []string{"a", "b"}}},
			},
		})
	}

	{
		id := "scope-read-outside-iterate"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			pips:         []any{permissionScopeWirePIP},
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("scoped", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("region-granted", "operation == 'READ'",
							"subject.permissionScope.region CONTAINS resource.region", "ALLOW", nil),
						b.rule("literal-region", "operation == 'PROBE'",
							"subject.permissionScope.region CONTAINS 'r1'", "ALLOW", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "resource-in-a-granted-region", resource: map[string]any{"id": "reg-scope-outside", "region": "r1"}},
				{name: "probe-with-a-literal-operand", operation: "PROBE", resource: map[string]any{"id": "reg-scope-outside", "region": "r9"}},
			},
		})
	}

	return cases
}

// iterateNodeAlgorithmPairs are the set and iterate-node algorithm pairs of
// TestInterpreterIterateNodeAlgorithmCases, each the other's opposite on a pass
// that denies beside a pass that permits.
var iterateNodeAlgorithmPairs = []struct{ key, set, node string }{
	{"set-deny-unless-permit-node-permit-unless-deny", "DENY_UNLESS_PERMIT", "PERMIT_UNLESS_DENY"},
	{"set-permit-unless-deny-node-deny-unless-permit", "PERMIT_UNLESS_DENY", "DENY_UNLESS_PERMIT"},
}

// Which algorithm combines the passes of an iterating set when the set and its
// iterate node name different ones. Every recorded iterating set, and every case
// of TestInterpreterIterateAlgorithmCases, gives the two the same algorithm, so
// nothing records which of the two the passes are combined by.
//
// Each set holds one policy under DENY_OVERRIDES with a DENY rule, region not
// granted, and an ALLOW rule with no condition, so under two grants the region
// of the first grant is permitted by its own pass and denied by the other. The
// set and the node take opposite algorithms: with the passes combined by the
// node, region-of-the-first-grant is false under a PERMIT_UNLESS_DENY node and
// true under a DENY_UNLESS_PERMIT node; combined by the set, the answers swap.
// region-of-no-grant is denied by both passes and is the control that the DENY
// rule is live. The PIP, the wire body and the cache wait are
// permission-scope-wire's.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy profile
// only.
func (s *ParitySuite) TestInterpreterIterateNodeAlgorithmCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("iterate is a regular policy set field; the agent loads simplified policies")
	}
	ctx := context.Background()
	m2m := s.mustM2MToken()
	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s: %v", isolatedCaseDomain, err)
		}
	})

	var sets []any
	for _, pair := range iterateNodeAlgorithmPairs {
		b := regularBuilder{caseID: "scope-node-" + pair.key}
		rt := regularResourceType("scope-node-" + pair.key)
		set := b.iteratingSet("set", "resourceType == '"+rt+"'", pair.set, "subject.permissionScope", []any{
			b.policy("scoped", readerTarget, "DENY_OVERRIDES",
				b.rule("region-not-granted", "operation == 'READ'",
					"subject.permissionScope.region NOT CONTAINS resource.region", "DENY", nil),
				b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil)),
		})
		set["iterate"].(map[string]any)["combiningAlgorithm"] = pair.node
		sets = append(sets, set)
	}

	pipStatus, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, []any{permissionScopeWirePIP}, nil)
	s.Require().NoError(err)
	s.Run("declare-the-pip", func() {
		s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "scope-node/declare-the-pip", &model.PolicyLoadOutcome{Status: pipStatus})
	})
	if pipStatus < http.StatusOK || pipStatus >= http.StatusMultipleChoices {
		return
	}
	setStatus, _, err := HelperPutPolicySets(ctx, s.cfg, m2m, "parity-scope-node-algorithms", sets)
	s.Require().NoError(err)
	s.Run("upload-the-sets", func() {
		s.requirePendingGolden(PSUITE_LOAD_POLICY_SETS, "scope-node/upload-the-sets", &model.PolicyLoadOutcome{Status: setStatus})
	})
	if setStatus < http.StatusOK || setStatus >= http.StatusMultipleChoices {
		return
	}

	scopePath := permissionScopeWirePath(parityReaderSubjectID)
	s.Require().NoError(s.pipMock.ResetCalls(ctx))
	s.Require().NoError(s.pipMock.PinRoute(ctx, scopePath, PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       permissionScopeWireBody(parityReaderSubjectID, []permissionScopeGrant{{"region": {"r1"}}, {"region": {"r2"}}}),
	}))
	// Outlive the cachePeriod of the declaration, as permission-scope-wire does,
	// so the body pinned above is the one the requests see.
	time.Sleep(2 * time.Second)
	for _, pair := range iterateNodeAlgorithmPairs {
		for _, req := range iterateAlgorithmRequests {
			s.Run(pair.key+"/"+req.name, func() {
				s.runPendingCheckResourceV1OutcomeCase(
					"scope-node/"+pair.key+"/"+req.name,
					model.CheckAccessRequest{
						Operation: "READ",
						Type:      regularResourceType("scope-node-" + pair.key),
						Resource:  req.resource,
					},
					s.mustTokenBundle(UserProfileReader),
					PerCallOptions{},
				)
			})
		}
	}
	s.Run("the-pip-was-read", func() {
		calls, err := s.pipMock.GetCalls(ctx)
		s.Require().NoError(err)
		read := 0
		for _, call := range calls {
			if call.Path == scopePath {
				read++
			}
		}
		s.Assert().Positive(read, "pip-mock calls to %s over the iterate node algorithm cases", scopePath)
	})
}
