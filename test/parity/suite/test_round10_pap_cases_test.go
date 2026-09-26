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
	"net/url"

	"authz-agent/test/parity/suite/model"
)

const twoDomainMappingCaseID = "two-domain-mapping"

// twoDomainMappingMarkers narrow the export and the PAP reads to this case.
var twoDomainMappingMarkers = []string{"parity_r10_td", "PARITY_R10_TD"}

// twoDomainMappingPIP is the MAPPING PIP of one domain, granting each role of
// roles its permissions.
func twoDomainMappingPIP(suffix string, roles map[string][]string) map[string]any {
	return map[string]any{
		"name": "subject.permissions.PARITY_R10_TD_" + suffix, "type": "UUID", "pipType": "MAPPING", "cacheable": false,
		"customMapping": map[string]any{"subject.roles": roles},
	}
}

// What the tenant's subject.permissions holds when two domains of one tenant
// each declare a MAPPING PIP, and what the PAP answers to the reads that list
// MAPPING PIPs outside the v3 export. mapping-export records one domain per
// tenant, where the folded export element is that domain's mapping; whether a
// second domain adds its mapping to the same element and to the decision is
// recorded nowhere, and neither are the per-domain PIP read, the permission
// list by role, or /access/v1/pips.
//
// isolatedCaseDomain grants ROLE_PARITY_READER parity_r10_td_a; round9SecondDomain
// grants ROLE_PARITY_READER parity_r10_td_b and ROLE_PARITY_OTHER
// parity_r10_td_other. READ asks for the first permission, UPDATE for the
// second, and PROBE, unconditional, is the control that the policies loaded.
// The v3 PIP export, GET /access/v1/simplifiedPolicies/domainPIPs/{domain} for
// each domain, GET /access/v1/permissions/list/ROLE_PARITY_READER with no level,
// custom, product, and PRODUCT, and GET /access/v1/pips are recorded, narrowed to
// the case's names; an error answer is recorded by its status.
//
// The case lives in its own test function so that a recording run can be
// filtered to it. Legacy profile only: the reads are the PAP's.
func (s *ParitySuite) TestRound10TwoDomainMappingCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("the reads are access-control's; on the authz-agent profile authz-policy-admin serves them")
	}
	s.round9EmptyDomainsOnCleanup()
	ctx := context.Background()
	m2m := s.mustM2MToken()
	rt := regularResourceType(twoDomainMappingCaseID)
	policy := func(key, operation, condition string) map[string]any {
		p := map[string]any{
			"component": "PARITY", "reason": twoDomainMappingCaseID + " " + key, "resourceType": rt, "operation": operation,
			"roles": []string{"ROLE_PARITY_READER"}, "applicableForFrontend": false,
			"id": regularBuilder{caseID: twoDomainMappingCaseID}.id("simplified/" + key),
		}
		if condition != "" {
			p["condition"] = condition
		}
		return p
	}
	if !s.round9UploadDomain(twoDomainMappingCaseID+"/declare-the-first-domain", isolatedCaseDomain,
		[]any{twoDomainMappingPIP("A", map[string][]string{"ROLE_PARITY_READER": {"parity_r10_td_a"}})},
		[]any{
			policy("first-domain-permission", "READ", "subject.permissions CONTAINS 'parity_r10_td_a'"),
			policy("second-domain-permission", "UPDATE", "subject.permissions CONTAINS 'parity_r10_td_b'"),
			policy("unconditional", "PROBE", ""),
		}) {
		return
	}
	if !s.round9UploadDomain(twoDomainMappingCaseID+"/declare-the-second-domain", round9SecondDomain,
		[]any{twoDomainMappingPIP("B", map[string][]string{
			"ROLE_PARITY_READER": {"parity_r10_td_b"},
			"ROLE_PARITY_OTHER":  {"parity_r10_td_other"},
		})}, nil) {
		return
	}
	for _, req := range []struct{ name, operation string }{
		{"first-domain-permission-read", "READ"},
		{"second-domain-permission-update", "UPDATE"},
		{"unconditional-probe", "PROBE"},
	} {
		s.Run(req.name, func() {
			s.runPendingCheckResourceV1OutcomeCase(
				twoDomainMappingCaseID+"/"+req.name,
				model.CheckAccessRequest{Operation: req.operation, Type: rt, Resource: map[string]any{"id": "r10-two-domain"}},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
	s.Run("export-pips", func() {
		status, body, err := HelperGetConfigExport(ctx, s.cfg, PSUITE_CONFIG_PIPS_V3, m2m, PerCallOptions{})
		s.Require().NoError(err)
		s.requirePendingGolden(PSUITE_CONFIG_PIPS_V3, twoDomainMappingCaseID+"/export", narrowConfigExport(status, body, twoDomainMappingMarkers))
	})
	for _, read := range []struct {
		name, path string
		query      url.Values
	}{
		{"domain-pips-of-the-first-domain", "/access/v1/simplifiedPolicies/domainPIPs/" + isolatedCaseDomain, nil},
		{"domain-pips-of-the-second-domain", "/access/v1/simplifiedPolicies/domainPIPs/" + round9SecondDomain, nil},
		{"permission-list-with-no-level", "/access/v1/permissions/list/ROLE_PARITY_READER", nil},
		{"permission-list-level-custom", "/access/v1/permissions/list/ROLE_PARITY_READER", url.Values{"level": {"custom"}}},
		{"permission-list-level-product", "/access/v1/permissions/list/ROLE_PARITY_READER", url.Values{"level": {"product"}}},
		{"permission-list-level-product-in-upper-case", "/access/v1/permissions/list/ROLE_PARITY_READER", url.Values{"level": {"PRODUCT"}}},
		{"pips", "/access/v1/pips", nil},
	} {
		s.Run(read.name, func() {
			status, body, err := HelperGetPAP(ctx, s.cfg, m2m, read.path, read.query)
			s.Require().NoError(err)
			s.requirePendingGolden(PSUITE_PAP_READ, twoDomainMappingCaseID+"/"+read.name, narrowPAPRead(status, body, twoDomainMappingMarkers))
		})
	}
}

// What a GENERAL PIP whose body is the JSON literal null resolves to under IS
// EMPTY and IS NULL, and what an absent header and an absent claim answer on the
// right of an operator when nothing follows them. p7 records != over the null
// body, which is true for a null and for an empty list alike; the right-operand
// forms are recorded only on the left of an OR (ro-in-an-absent-header,
// ro-equals-an-absent-claim). The agent's condition parser accepts every
// condition here.
//
// Each condition is asked alone. The null body under IS EMPTY and IS NULL tells
// a null (false, true) from an empty list (true, true); null-body-equals-a-value
// is the control, a PIP at another route answering {"value": "v"} under == 'v'.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound10NullBodyAndRightOperandCases() {
	ctx := context.Background()
	const nullRoute, liveRoute = "/api/v1/pip/r10-null-body", "/api/v1/pip/r10-null-body-control"
	s.Require().NoError(s.pipMock.PinRoute(ctx, nullRoute, PipStubResponse{StatusCode: http.StatusOK, BodyRaw: "null"}))
	s.Require().NoError(s.pipMock.PinRoute(ctx, liveRoute, PipStubResponse{StatusCode: http.StatusOK, Body: map[string]string{"value": "v"}}))
	general := func(name, route string, jsonPath bool) map[string]any {
		pip := map[string]any{
			"name": name, "url": "http://pip-mock:8090" + route, "httpMethod": "POST", "pipType": "GENERAL",
			"requestAttributes": map[string]string{"case": "r10-null-body"}, "cacheable": false,
		}
		if jsonPath {
			pip["type"] = "JSON"
			pip["jsonPath"] = "$.value"
		}
		return pip
	}
	nullPIP := general("subject.parityR10NullBody", nullRoute, false)
	requests := []isolatedRequest{{name: "reader", resource: map[string]any{"id": "r10-null-body", "x": "v"}}}
	var cases []isolatedCase
	for _, form := range []struct {
		key, condition string
		pip            map[string]any
	}{
		{"nb-null-body-is-empty", "subject.parityR10NullBody IS EMPTY", nullPIP},
		{"nb-null-body-is-null", "subject.parityR10NullBody IS NULL", nullPIP},
		{"nb-null-body-equals-a-value", "subject.parityR10NullBodyControl == 'v'", general("subject.parityR10NullBodyControl", liveRoute, true)},
		{"nb-in-an-absent-header", "resource.x IN subject.parityR9NoHeader", round9NoHeaderPIP},
		{"nb-equals-an-absent-claim", "resource.x == subject.parityR9NoClaim", round9NoClaimPIP},
	} {
		cases = append(cases, isolatedCase{
			id: form.key, resourceType: round10ResourceType(form.key), condition: form.condition,
			pips: []any{form.pip}, requests: requests,
		})
	}
	s.runIsolatedCases(cases)
}

// Where the PAP accepts resourceType ALL in a simplified policy. t9b records the
// one form in the fixtures, component ALL with resourceType and operation ALL
// and no condition, which the upload accepts; no case records the other
// combinations, and the agent's converter accepts each of them.
//
// Each form is uploaded alone into isolatedCaseDomain for a role nobody holds,
// and its status is recorded. global-access is the control, the t9b form.
//
// The cases live in their own test function so that a recording run can be
// filtered to them. Legacy profile only: the statuses are the PAP's.
func (s *ParitySuite) TestRound10ResourceTypeAllUploadCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("the upload status is the PAP's; authz-policy-admin accepts anything")
	}
	ctx := context.Background()
	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s: %v", isolatedCaseDomain, err)
		}
	})
	for _, form := range []struct {
		key, component, operation string
		extra                     map[string]string
	}{
		{"global-access", "ALL", "ALL", nil},
		{"component-parity", "PARITY", "ALL", nil},
		{"operation-read", "ALL", "READ", nil},
		{"with-a-condition", "ALL", "ALL", map[string]string{"condition": "resource.a == 'y'"}},
		{"with-a-predicate", "ALL", "ALL", map[string]string{"rsqlPredicate": "a==1"}},
	} {
		s.Run(form.key, func() {
			policy := map[string]any{
				"component": form.component, "reason": "resource-type-all " + form.key, "resourceType": "ALL",
				"operation": form.operation, "roles": []string{"ROLE_PARITY_NOBODY"}, "applicableForFrontend": false,
				"id": "00000000-0000-0000-0000-0000000f1061",
			}
			for field, value := range form.extra {
				policy[field] = value
			}
			status, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, []any{policy})
			s.Require().NoError(err)
			s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "resource-type-all/"+form.key, &model.PolicyLoadOutcome{Status: status})
		})
	}
}

// What MATCH /ab.*/ selects on values of the path form, and whether the word
// form LESS THAN OR EQUAL is accepted without TO. df4 records MATCH /ab.*/
// against abc, which no path pattern selects, so what the form selects is
// recorded nowhere; LESS THAN OR EQUAL is recorded with TO only. The agent's
// condition parser accepts every condition here.
//
// The MATCH case is sent four values, alone and through orProbePair, whose
// control is true for a live policy. LESS THAN OR EQUAL is sent 5 and 6, and its
// upload status is an answer too; the form with TO is the control.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound10PathPatternAndWordOperatorCases() {
	value := func(name string, x any) isolatedRequest {
		return isolatedRequest{name: name, resource: map[string]any{"id": "r10-pattern", "x": x, "a": "y"}}
	}
	cases := round10AloneAndProbe("pp-match-slash-pattern", "resource.x MATCH /ab.*/", []isolatedRequest{
		value("x-slash-ab-dot-c-slash", "/ab.c/"), value("x-slash-ab-dot-slash", "/ab./"), value("x-slash-abc-slash", "/abc/"), value("x-abc", "abc"),
	})
	s.runIsolatedCases(append(cases, []isolatedCase{
		{id: "pp-less-than-or-equal-without-to", resourceType: round10ResourceType("pp-less-than-or-equal-without-to"), condition: "resource.x LESS THAN OR EQUAL 5", requests: []isolatedRequest{
			value("x-5", 5), value("x-6", 6),
		}},
		{id: "pp-less-than-or-equal-to", resourceType: round10ResourceType("pp-less-than-or-equal-to"), condition: "resource.x LESS THAN OR EQUAL TO 5", requests: []isolatedRequest{
			value("x-5", 5), value("x-6", 6),
		}},
	}...))
}

// repeatedValuesRoute is the pip-mock path of the PIP of
// TestRound10RepeatedValuesAndHeadersCases.
const repeatedValuesRoute = "/api/v1/pip/r10-repeated-values"

// repeatedValuesCase is the regular case whose LIST rule renders the list
// ["b", "a", "a"] in all five predicate fields.
func repeatedValuesCase() regularCase {
	id := "substitution-general-repeated-values"
	b := regularBuilder{caseID: id}
	rt := regularResourceType(id)
	return regularCase{
		id:           id,
		resourceType: rt,
		pips: []any{map[string]any{
			"name": "subject.parityR10Repeated", "url": "http://pip-mock:8090" + repeatedValuesRoute, "httpMethod": "POST",
			"pipType": "GENERAL", "requestAttributes": map[string]string{"case": "r10-repeated"}, "cacheable": false,
		}},
		uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
			b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
				b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT", substitutionRule(b, "subject.parityR10Repeated")),
			}, nil),
		}}},
		requests: []isolatedRequest{{name: "filter", filter: true}},
	}
}

// repeatedValuesRegularCases is repeatedValuesCase, for
// TestRegularCaseIDsAreUnique.
func repeatedValuesRegularCases() []regularCase { return []regularCase{repeatedValuesCase()} }

// Whether a placeholder outside iterate renders a list with its repeats and in
// its order, and which forms the headers field of a GENERAL PIP takes.
// substitution-general-list renders two distinct values; a repeated value and
// the order of an unsorted list are recorded nowhere. No golden records a
// GENERAL PIP declared with headers as a string or as an object. The agent's
// PIP loader takes headers as a list of names or an object of values.
//
// The PIP answers ["b", "a", "a"] into all five predicate fields of one LIST
// rule, the substitution-* shape, and has to be read. Then GENERAL PIPs are
// declared in turn in round9SecondDomain, which no set reads: one with no
// headers, the control, one with headers "X-A,X-B", and one with headers
// {"X-A": "v"}; each status is recorded, and the v3 export after each accepted
// one.
//
// The cases live in their own test function so that a recording run can be
// filtered to them. Legacy profile only, like every regular case.
func (s *ParitySuite) TestRound10RepeatedValuesAndHeadersCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("regular policy sets are evaluated by access-control only; authz-agent loads simplified policies")
	}
	ctx := context.Background()
	s.Require().NoError(s.pipMock.PinRoute(ctx, repeatedValuesRoute, PipStubResponse{StatusCode: http.StatusOK, Body: []string{"b", "a", "a"}}))
	s.Require().NoError(s.pipMock.ResetCalls(ctx))
	s.runRegularCases(repeatedValuesRegularCases())
	s.Run("the-pip-was-read", func() {
		s.Assert().Positive(s.pipCalls(repeatedValuesRoute), "pip-mock calls to %s over the filter request", repeatedValuesRoute)
	})
	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, round9SecondDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s: %v", round9SecondDomain, err)
		}
	})
	for _, form := range []struct {
		key     string
		headers any
	}{
		{"no-headers", nil},
		{"headers-as-a-string", "X-A,X-B"},
		{"headers-as-an-object", map[string]string{"X-A": "v"}},
	} {
		s.Run(form.key, func() {
			pip := map[string]any{
				"name": "subject.parityR10Headers", "url": parityPipMockBase + "/r10-headers", "httpMethod": "POST",
				"pipType": "GENERAL", "cacheable": false,
			}
			if form.headers != nil {
				pip["headers"] = form.headers
			}
			status, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, round9SecondDomain, []any{pip}, nil)
			s.Require().NoError(err)
			s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "pip-headers/"+form.key, &model.PolicyLoadOutcome{Status: status})
			if status >= http.StatusOK && status < http.StatusMultipleChoices {
				exportStatus, body, err := HelperGetConfigExport(ctx, s.cfg, PSUITE_CONFIG_PIPS_V3, s.mustM2MToken(), PerCallOptions{})
				s.Require().NoError(err)
				s.requirePendingGolden(PSUITE_CONFIG_PIPS_V3, "pip-headers/"+form.key, narrowConfigExport(exportStatus, body, []string{"parityR10Headers"}))
			}
		})
	}
}

// policyWithoutAlgorithmCases are the two sets of
// TestRound10PolicyWithoutAlgorithmCases: a DENY_OVERRIDES set of a policy with
// no rule on READ beside a policy that allows READ, the first policy with no
// combiningAlgorithm and, as the control, with DENY_UNLESS_PERMIT.
func policyWithoutAlgorithmCases() []regularCase {
	var cases []regularCase
	for _, form := range []struct{ key, algorithm string }{
		{"policy-without-an-algorithm-and-a-rule-beside-an-allowing-policy", ""},
		{"deny-unless-permit-policy-without-a-rule-beside-an-allowing-policy", "DENY_UNLESS_PERMIT"},
	} {
		c := round9SetCase(form.key, "DENY_OVERRIDES", func(b regularBuilder) []any {
			return []any{
				b.policy("update-only", readerTarget, form.algorithm,
					b.rule("update-allow", "operation == 'UPDATE'", "true", "ALLOW", nil),
					b.rule("update-only-probe-allow", "operation == 'PROBE'", "true", "ALLOW", nil)),
				b.policy("allows", readerTarget, "DENY_UNLESS_PERMIT",
					b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil),
					b.rule("allows-probe-allow", "operation == 'PROBE'", "true", "ALLOW", nil)),
			}
		})
		c.requests = []isolatedRequest{
			{name: "read", operation: "READ", resource: map[string]any{"id": "r10-no-algorithm"}},
			{name: "probe-allowed-by-both-policies", operation: "PROBE", resource: map[string]any{"id": "r10-no-algorithm"}},
		}
		cases = append(cases, c)
	}
	return cases
}

// What a policy with no combiningAlgorithm and no rule on the operation
// contributes to a DENY_OVERRIDES set beside a policy that allows, and what
// /api-version answers on the stand the round is recorded on. algorithm-absent
// records six answers that DENY_UNLESS_PERMIT and PERMIT_OVERRIDES give alike;
// under DENY_OVERRIDES a DENY_UNLESS_PERMIT policy with no applicable rule
// denies and overrides its neighbor (policy-without-a-rule-under-deny-overrides),
// and a PERMIT_OVERRIDES one does not apply. The agent's converter accepts both
// sets. The /api-version golden of row 1 is left alone; this one is the
// stand's own.
//
// The DENY_UNLESS_PERMIT policy in the same place is the control whose READ is
// recorded as false in the sibling case. PROBE, which both policies allow, is
// the control that the set applies at all.
//
// The cases live in their own test function so that a recording run can be
// filtered to them. Legacy profile only, like every regular case.
func (s *ParitySuite) TestRound10PolicyWithoutAlgorithmCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("regular policy sets are evaluated by access-control only; authz-agent loads simplified policies")
	}
	s.runRegularCases(policyWithoutAlgorithmCases())
	s.Run("api-version", func() {
		status, version, err := HelperApiVersion(context.Background(), s.cfg)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusOK, status)
		s.requirePendingGolden(PSUITE_ROW_1_API_VERSION, "round10-stand", &version)
	})
}
