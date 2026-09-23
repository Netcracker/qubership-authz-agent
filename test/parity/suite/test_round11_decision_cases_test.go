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
	"strings"
	"time"

	"authz-agent/test/parity/suite/model"
)

// round11FailedPIPOnTheRightCases builds the policy shape of failed-pip-scope
// with a PIP answering 500 on the right of IN, under two set algorithms. Under
// DENY_UNLESS_PERMIT the reading policy is DENY_UNLESS_PERMIT, as in
// failed-pip-scope; under DENY_OVERRIDES it is PERMIT_OVERRIDES, which does not
// apply when its one rule does not. Each case reads a PIP and a route of its own.
func round11FailedPIPOnTheRightCases() []regularCase {
	var cases []regularCase
	for _, shape := range []struct{ key, name, set, readingPolicy string }{
		{"deny-unless-permit", "DenyUnlessPermit", "DENY_UNLESS_PERMIT", "DENY_UNLESS_PERMIT"},
		{"deny-overrides", "DenyOverrides", "DENY_OVERRIDES", "PERMIT_OVERRIDES"},
	} {
		cases = append(cases, failedPIPScopeCaseWith("rf-failed-pip-on-the-right-beside-an-allowing-policy-under-"+shape.key, map[string]any{
			"name":      "subject.parityR11RightFailed" + shape.name,
			"url":       parityPipMockBase + "/r11-right-failed-" + shape.key,
			"cacheable": false,
		}, func(b regularBuilder, rt, pip string) []any {
			return []any{b.set("set", "resourceType == '"+rt+"'", shape.set, []any{
				b.policy("reads-the-pip", readerTarget, shape.readingPolicy,
					b.rule("reads-the-pip-read-allow", "operation == 'READ'", "resource.id IN "+pip, "ALLOW", nil)),
				b.policy("allows", readerTarget, "DENY_UNLESS_PERMIT",
					b.rule("allows-read-allow", "operation == 'READ'", "true", "ALLOW", nil)),
			}, nil)}
		}))
	}
	return cases
}

// How far a GENERAL PIP that answered 500 reaches when the condition reads it on
// the right of an operator. failed-pip-policy-beside-an-allowing-policy records
// the PIP on the left, under != 'x': when the PIP was read, the whole answer for
// the resource is false, although the neighbor policy allows. On the right the
// failure is recorded inside one policy only (ro-in-a-failed-pip), which tells
// none of three readings apart: the whole answer is refused, the reading rule
// denies, or the reading rule no longer applies.
//
// Under DENY_UNLESS_PERMIT, false when the PIP was read is the refusal, and true
// is either of the other two. Under DENY_OVERRIDES the PIP is read whichever
// policy comes first, and the reading policy is PERMIT_OVERRIDES: true is a rule
// that no longer applies, and false a refusal or a deny. Both cases are run by
// runFailedPIPScopeCase, which classes each upload by whether pip-mock saw a
// call on the case's route; the PIP-skipped class, where it fills, is the control
// that the neighbor allows.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case.
func (s *ParitySuite) TestRound11FailedPIPOnTheRightScopeCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("regular policy sets are evaluated by access-control only; authz-agent loads simplified policies")
	}
	ctx := context.Background()
	cases := round11FailedPIPOnTheRightCases()
	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s: %v", isolatedCaseDomain, err)
		}
	})
	var declarations []any
	for _, tc := range cases {
		declarations = append(declarations, tc.pips...)
	}
	status, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, declarations, nil)
	s.Require().NoError(err)
	s.Run("declare-the-pips", func() {
		s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "rf-failed-pip-on-the-right/declare-the-pips", &model.PolicyLoadOutcome{Status: status})
	})
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return
	}
	s.emptyPolicySetsOnCleanup(s.cfg, regularExternalIDs(cases)...)
	for _, tc := range cases {
		route := strings.TrimPrefix(tc.pips[0].(map[string]any)["url"].(string), "http://pip-mock:8090")
		s.runFailedPIPScopeCase(tc, route, PipStubResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       map[string]string{"error": "parity failed-pip-on-the-right case"},
		})
	}
}

// round11ScopeOutsideIterateCases builds a set that reads subject.permissionScope
// without iterating: IS EMPTY over the scope key on READ, the same on the left of
// a true OR on UPDATE, and IS NULL over it on PROBE.
func round11ScopeOutsideIterateCases() []regularCase {
	id := "scope-is-empty-outside-iterate"
	b := regularBuilder{caseID: id}
	rt := regularResourceType(id)
	return []regularCase{{
		id:           id,
		resourceType: rt,
		pips:         []any{permissionScopeWirePIP},
		uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
			b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
				b.policy("scoped", readerTarget, "DENY_UNLESS_PERMIT",
					b.rule("region-is-empty", "operation == 'READ'", "subject.permissionScope.region IS EMPTY", "ALLOW", nil),
					b.rule("region-is-empty-or-true", "operation == 'UPDATE'", "subject.permissionScope.region IS EMPTY OR resource.a == 'y'", "ALLOW", nil),
					b.rule("region-is-null", "operation == 'PROBE'", "subject.permissionScope.region IS NULL", "ALLOW", nil)),
			}, nil),
		}}},
		requests: []isolatedRequest{
			{name: "read-under-is-empty", resource: map[string]any{"id": "r11-scope-outside"}},
			{name: "update-under-is-empty-or-true", operation: "UPDATE", resource: map[string]any{"id": "r11-scope-outside", "a": "y"}},
			{name: "probe-under-is-null", operation: "PROBE", resource: map[string]any{"id": "r11-scope-outside"}},
		},
	}}
}

// What subject.permissionScope.<key> resolves to in a set that does not iterate.
// scope-read-outside-iterate records CONTAINS over it, false with a resource
// value and with a literal alike, which an absent attribute, a null, and an empty
// list all produce (nn1, n4, nc-contains). IS EMPTY on READ is true over an empty
// list only. On UPDATE it stands on the left of an OR whose right operand holds:
// true over a null or an empty list, false over an absent attribute, which ends
// the rule (nn1).
//
// The scope service answers two grants, r1 and r2, as in the iterate binding
// cases. IS NULL on PROBE is the control that the rule is reached: it is true
// over each of the three.
//
// The case lives in its own test function so that a recording run can be
// filtered to it and leave every golden already committed alone. Legacy profile
// only.
func (s *ParitySuite) TestRound11ScopeOutsideIterateCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("iterate is a regular policy set field; the agent loads simplified policies")
	}
	ctx := context.Background()
	s.Require().NoError(s.pipMock.PinRoute(ctx, permissionScopeWirePath(parityReaderSubjectID), PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       permissionScopeWireBody(parityReaderSubjectID, []permissionScopeGrant{{"region": {"r1"}}, {"region": {"r2"}}}),
	}))
	// Outlive the cachePeriod of the declaration, as permission-scope-wire does.
	time.Sleep(2 * time.Second)
	s.runRegularCases(round11ScopeOutsideIterateCases())
}

// iterateNodeUnderSetCaseID prefixes the goldens of
// TestRound11IterateNodeUnderSetCases.
const iterateNodeUnderSetCaseID = "scope-node-under-a-set"

// What a PERMIT_UNLESS_DENY iterate node over zero grants gives a
// DENY_UNLESS_PERMIT set above it. scope-set-algorithm records such a node under
// a PERMIT_UNLESS_DENY set, which allows everything over zero grants; that
// answer is the same whether the node permits or does not apply, since a
// PERMIT_UNLESS_DENY set with no child that applies permits too. Under a
// DENY_UNLESS_PERMIT set the two differ: a node that permits allows, and a node
// that does not apply leaves the set without a permit, so it denies.
//
// The set is scope-set-algorithm's, with a DENY_UNLESS_PERMIT set over a
// PERMIT_UNLESS_DENY node, and its ids and resource type are built the way
// scope-set-algorithm builds them, from a key no set of that test uses. no-grants is the question; one-grant-r1 is the
// control that the scope is read and the pass applies, r1 true and r2 false.
// Each shape sends the filter on LIST and check/resource on LIST in regions r1
// and r2.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only.
func (s *ParitySuite) TestRound11IterateNodeUnderSetCases() {
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
	pipStatus, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, []any{permissionScopeWirePIP}, nil)
	s.Require().NoError(err)
	s.Run("declare-the-pip", func() {
		s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, iterateNodeUnderSetCaseID+"/declare-the-pip", &model.PolicyLoadOutcome{Status: pipStatus})
	})
	if pipStatus < http.StatusOK || pipStatus >= http.StatusMultipleChoices {
		return
	}
	spec := iterateSetAlgorithmSet{"deny-unless-permit-set-permit-unless-deny-node", "DENY_UNLESS_PERMIT", "PERMIT_UNLESS_DENY"}
	externalID := "parity-" + iterateNodeUnderSetCaseID + "-" + spec.key
	s.emptyPolicySetsOnCleanup(s.cfg, externalID)
	setStatus, _, err := HelperPutPolicySets(ctx, s.cfg, m2m, externalID, []any{iterateSetAlgorithmBuildSet(spec)})
	s.Require().NoError(err)
	s.Run("upload", func() {
		s.requirePendingGolden(PSUITE_LOAD_POLICY_SETS, iterateNodeUnderSetCaseID+"/upload-"+spec.key, &model.PolicyLoadOutcome{Status: setStatus})
	})
	if setStatus < http.StatusOK || setStatus >= http.StatusMultipleChoices {
		return
	}
	rt := iterateSetAlgorithmResourceType(spec.key)
	scopePath := permissionScopeWirePath(parityReaderSubjectID)
	for _, shape := range []struct {
		name     string
		response PipStubResponse
	}{
		{"no-grants", iterateFilterGrants(nil)},
		{"one-grant-r1", iterateFilterGrants([]permissionScopeGrant{{"region": {"r1"}}})},
	} {
		// Outlive the cachePeriod of the declaration, as permission-scope-wire does.
		time.Sleep(2 * time.Second)
		s.Run(shape.name, func() {
			s.Require().NoError(s.pipMock.PinRoute(ctx, scopePath, shape.response))
			prefix := iterateNodeUnderSetCaseID + "/" + shape.name + "/" + spec.key
			s.Run("filter", func() {
				s.runPendingFilterV1OutcomeCase(prefix+"/filter", rt, "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
			})
			for _, region := range []string{"r1", "r2"} {
				s.Run("check-list-in-region-"+region, func() {
					s.runPendingCheckResourceV1OutcomeCase(
						prefix+"/check-list-in-region-"+region,
						model.CheckAccessRequest{Operation: "LIST", Type: rt, Resource: map[string]any{"id": "scope-node-under-a-set", "region": region}},
						s.mustTokenBundle(UserProfileReader),
						PerCallOptions{},
					)
				})
			}
		})
	}
}

// How many calls a GENERAL PIP receives when one condition reads it twice.
// pip-call/pip-cache-cacheable-false records one call per request for a
// condition that reads the PIP once, which a call per request and a call per
// read both produce.
//
// The PIP answers {"value": "b"}, so == 'a' is false and OR goes on to == 'b'.
// read-twice reads it on both sides of the OR; read-once, the control, reads it
// once. Each form declares the PIP at a route of its own, and the decision and
// the call count on that route are recorded.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound11PIPCallsPerRequestCases() {
	ctx := context.Background()
	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s: %v", isolatedCaseDomain, err)
		}
	})
	for _, form := range []struct{ key, condition string }{
		{"read-twice", "subject.parityR11Twice == 'a' OR subject.parityR11Twice == 'b'"},
		{"read-once", "subject.parityR11Twice == 'b'"},
	} {
		id := "calls-" + form.key
		route := "/api/v1/pip/r11-" + id
		s.Run(id, func() {
			s.Require().NoError(s.pipMock.PinRoute(ctx, route, PipStubResponse{StatusCode: http.StatusOK, Body: map[string]string{"value": "b"}}))
			s.Require().NoError(s.pipMock.ResetCalls(ctx))
			rt := round11ResourceType(id)
			status, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain,
				[]any{map[string]any{
					"name": "subject.parityR11Twice", "url": "http://pip-mock:8090" + route,
					"httpMethod": "POST", "pipType": "GENERAL", "type": "JSON", "jsonPath": "$.value", "cacheable": false,
					"requestAttributes": map[string]string{"case": id},
				}},
				[]any{map[string]any{
					"component": "PARITY", "reason": id, "resourceType": rt, "operation": "READ",
					"roles": []string{"ROLE_PARITY_READER"}, "applicableForFrontend": false,
					"condition": form.condition, "id": "00000000-0000-0000-0000-0000000f1101",
				}})
			s.Require().NoError(err)
			if !isAuthzAgentProfile(s.cfg.Profile) {
				s.Run("upload", func() {
					s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "isolated/"+id, &model.PolicyLoadOutcome{Status: status})
				})
				if status < http.StatusOK || status >= http.StatusMultipleChoices {
					return
				}
			}
			endpoint, outcome := s.sendRegularRequest(rt, isolatedRequest{resource: map[string]any{"id": "r11-calls"}})
			s.Run("read", func() {
				s.requirePendingGolden(endpoint, "isolated/"+id+"/read", outcome)
			})
			s.Run("the-pip-calls", func() {
				s.requirePendingGolden(PSUITE_PIP_CALL, "isolated/"+id, s.pipCallOutcome(route))
			})
		})
	}
}

// cachePerSubjectRoute is the pip-mock route of the PIP of
// TestRound11PIPCachePerSubjectCases.
const cachePerSubjectRoute = "/api/v1/pip/r11-cache-per-subject"

// Whether the cache of a GENERAL PIP declared cacheable true is kept per subject.
// pip-cache-cacheable-true records one subject reading the PIP after its answer
// changed, which a cache per subject and a cache per PIP name serve the same
// way.
//
// parity-reader and parity-multi-role both hold ROLE_PARITY_READER, and the
// policy allows == 'granted'. pip-mock answers "granted"; the reader reads, and
// pip-mock is re-pinned to "refused". Inside the cache period the multi-role user
// reads, which is true when the reader's cached value is served to another
// subject and false when the PIP is called again; then the reader reads once
// more, the control that the cache holds the first value. The call count on the
// route is recorded.
//
// The case lives in its own test function so that a recording run can be
// filtered to it and leave every golden already committed alone.
func (s *ParitySuite) TestRound11PIPCachePerSubjectCases() {
	ctx := context.Background()
	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s: %v", isolatedCaseDomain, err)
		}
	})
	const id = "cache-per-subject"
	rt := round11ResourceType(id)
	pin := func(value string) {
		s.Require().NoError(s.pipMock.PinRoute(ctx, cachePerSubjectRoute, PipStubResponse{StatusCode: http.StatusOK, Body: map[string]string{"value": value}}))
	}
	pin("granted")
	s.Require().NoError(s.pipMock.ResetCalls(ctx))
	status, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain,
		[]any{map[string]any{
			"name": "subject.parityR11PerSubject", "url": "http://pip-mock:8090" + cachePerSubjectRoute,
			"httpMethod": "POST", "pipType": "GENERAL", "type": "JSON", "jsonPath": "$.value", "cacheable": true,
			"requestAttributes": map[string]string{"case": id},
		}},
		[]any{map[string]any{
			"component": "PARITY", "reason": id, "resourceType": rt, "operation": "READ",
			"roles": []string{"ROLE_PARITY_READER"}, "applicableForFrontend": false,
			"condition": "subject.parityR11PerSubject == 'granted'", "id": "00000000-0000-0000-0000-0000000f1102",
		}})
	s.Require().NoError(err)
	if !isAuthzAgentProfile(s.cfg.Profile) {
		s.Run("upload", func() {
			s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "isolated/"+id, &model.PolicyLoadOutcome{Status: status})
		})
		if status < http.StatusOK || status >= http.StatusMultipleChoices {
			return
		}
	}
	read := func(name string, profile UserProfile) {
		s.Run(name, func() {
			s.runPendingCheckResourceV1OutcomeCase("isolated/"+id+"/"+name,
				model.CheckAccessRequest{Operation: "READ", Type: rt, Resource: map[string]any{"id": "r11-cache"}},
				s.mustTokenBundle(profile), PerCallOptions{})
		})
	}
	read("reader-first", UserProfileReader)
	pin("refused")
	read("multi-role-user-after-the-change", UserProfileMultiRole)
	read("reader-again", UserProfileReader)
	s.Run("the-pip-calls", func() {
		s.requirePendingGolden(PSUITE_PIP_CALL, "isolated/"+id, s.pipCallOutcome(cachePerSubjectRoute))
	})
}

// Which tenant a decision is taken in when tenant_id and the Tenant header name
// different tenants. t3 records tenant_id alone and t4 the header alone; no case
// sends both, so their precedence is recorded nowhere.
//
// Tenant B holds PARITY_R11_MT_ONLY_B for ROLE_MT_READER, which tenant A does not
// hold, and user B's token is sent with tenant_id and the header set to opposite
// tenants: true says tenant B was chosen. header-b-alone is the control that
// the header alone reaches tenant B, and param-a-alone the control that tenant A
// does not hold the policy.
//
// The case lives in its own test function so that a recording run can be
// filtered to it. It needs a two-tenant stand and the legacy PAP.
func (s *ParitySuite) TestRound11TenantParameterAgainstHeaderCases() {
	stand := s.round10TenantStand()
	if !s.round10UploadInTenant("tenant-param-against-header/declare-in-tenant-b", stand.B.ID, nil, []any{
		round10TenantPolicy("00000000-0000-0000-0000-0000000f1103", "PARITY_R11_MT_ONLY_B", "ROLE_MT_READER", ""),
	}) {
		return
	}
	userB := s.tenantUserTokens(stand.B, stand.B.User)
	for _, req := range []struct {
		name string
		opts PerCallOptions
	}{
		{"param-a-header-b", PerCallOptions{TenantID: &stand.A.ID, TenantHeader: stand.B.ID}},
		{"param-b-header-a", PerCallOptions{TenantID: &stand.B.ID, TenantHeader: stand.A.ID}},
		{"header-b-alone", PerCallOptions{OmitTenantID: true, TenantHeader: stand.B.ID}},
		{"param-a-alone", PerCallOptions{TenantID: &stand.A.ID}},
	} {
		s.Run(req.name, func() {
			s.runPendingCheckResourceV1OutcomeCase(
				"tenant-param-against-header/"+req.name,
				model.CheckAccessRequest{Operation: "READ", Type: "PARITY_R11_MT_ONLY_B", Resource: map[string]any{"id": "r11-only-b"}},
				userB,
				req.opts,
			)
		})
	}
}
