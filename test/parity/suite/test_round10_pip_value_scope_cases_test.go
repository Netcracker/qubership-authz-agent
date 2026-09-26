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
	"encoding/json"
	"net/http"

	"authz-agent/test/parity/suite/model"
)

// pipValueRoute is the pip-mock path of the GENERAL PIP of
// TestRound10NonStringPIPOperatorCases that answers value kind.
func pipValueRoute(kind string) string { return "/api/v1/pip/r10-value-" + kind }

// pipValuePIP declares subject.parityR10Value<Kind>, reading $.value out of the
// body pip-mock answers at pipValueRoute(kind).
func pipValuePIP(kind, name string) map[string]any {
	return map[string]any{
		"name": "subject.parityR10Value" + name, "url": "http://pip-mock:8090" + pipValueRoute(kind),
		"httpMethod": "POST", "pipType": "GENERAL", "type": "JSON", "jsonPath": "$.value",
		"requestAttributes": map[string]string{"case": "r10-value"}, "cacheable": false,
	}
}

// What a condition answers when a GENERAL PIP it reads answers the JSON number
// 1000. non-string-pip-beside-allow-* records one form, != 'x', beside an
// allowing rule, which refuses the whole answer; a relational operator, an
// equality with the string 1000, IS NOT NULL, the PIP on the right of the
// operator, and a policy that does not read the PIP at all are recorded nowhere.
// The agent's condition parser accepts every condition here.
//
// Each condition is asked alone and through orProbePair, with resource.amount 5
// and resource.a y. resource.amount <= <PIP> is also asked at 5000, the other
// side of the limit. Every case is repeated with the PIP answering the string
// "1000", the control the number cases are read against. unrelated-policy
// declares the number PIP and reads only the resource, and has to allow.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound10NonStringPIPOperatorCases() {
	ctx := context.Background()
	for kind, value := range map[string]any{"number": json.Number("1000"), "string": "1000"} {
		s.Require().NoError(s.pipMock.PinRoute(ctx, pipValueRoute(kind), PipStubResponse{StatusCode: http.StatusOK, Body: map[string]any{"value": value}}))
	}
	requests := []isolatedRequest{{name: "amount-5", resource: map[string]any{"id": "r10-value", "amount": 5, "a": "y"}}}
	var cases []isolatedCase
	for _, source := range []struct{ kind, name string }{{"number", "Number"}, {"string", "String"}} {
		pip := "subject.parityR10Value" + source.name
		for _, form := range []struct{ key, operand string }{
			{"amount-at-most-the-pip", "resource.amount <= " + pip},
			{"pip-at-least-the-amount", pip + " >= resource.amount"},
			{"pip-equals-the-string", pip + " == '1000'"},
			{"pip-is-not-null", pip + " IS NOT NULL"},
		} {
			key := "nv-" + source.kind + "-" + form.key
			for _, tc := range round10AloneAndProbe(key, form.operand, requests) {
				tc.pips = []any{pipValuePIP(source.kind, source.name)}
				cases = append(cases, tc)
			}
		}
		key := "nv-" + source.kind + "-amount-at-most-the-pip-over-the-limit"
		cases = append(cases, isolatedCase{
			id: key, resourceType: round10ResourceType(key), condition: "resource.amount <= " + pip,
			pips:     []any{pipValuePIP(source.kind, source.name)},
			requests: []isolatedRequest{{name: "amount-5000", resource: map[string]any{"id": "r10-value", "amount": 5000}}},
		})
	}
	cases = append(cases, isolatedCase{
		id: "nv-number-unrelated-policy", resourceType: round10ResourceType("nv-number-unrelated-policy"), condition: "resource.a == 'y'",
		pips:     []any{pipValuePIP("number", "Number")},
		requests: requests,
	})
	s.runIsolatedCases(cases)
}

// pipScopeVariants are the PIP answers TestRound10PIPFailureScopeCases puts in
// the two failed-pip-scope shapes: a 404, recorded inside one policy only
// (missing-allow-beside-allow), the number 1000, recorded inside one policy only
// (non-string-pip-beside-allow-*), and the string "1000", the control, which
// resolves.
var pipScopeVariants = []struct {
	key, name string
	jsonPath  bool
	response  PipStubResponse
}{
	{"not-found", "NotFound", false, PipStubResponse{StatusCode: http.StatusNotFound, Body: map[string]string{"error": "parity pip scope case"}}},
	{"number", "Number", true, PipStubResponse{StatusCode: http.StatusOK, Body: map[string]any{"value": json.Number("1000")}}},
	{"string", "String", true, PipStubResponse{StatusCode: http.StatusOK, Body: map[string]any{"value": "1000"}}},
}

// pipScopeCase is the failed-pip-scope case of one shape for one variant, with
// the pip-mock route it reads.
type pipScopeCase struct {
	regular regularCase
	route   string
	answer  PipStubResponse
}

// pipScopeCases builds a case for every variant of pipScopeVariants in every
// shape of failedPIPScopeShapes, each reading a PIP and a route of its own.
func pipScopeCases() []pipScopeCase {
	var cases []pipScopeCase
	for _, variant := range pipScopeVariants {
		for _, shape := range failedPIPScopeShapes {
			id := variant.key + "-pip-" + shape.key + "-beside-an-allowing-" + shape.key
			route := "/api/v1/pip/r10-scope-" + variant.key + "-" + shape.key
			pip := map[string]any{
				"name":      "subject.parityR10Scope" + variant.name + map[string]string{"policy": "Policy", "set": "Set"}[shape.key],
				"url":       "http://pip-mock:8090" + route,
				"cacheable": false,
			}
			if variant.jsonPath {
				pip["type"] = "JSON"
				pip["jsonPath"] = "$.value"
			}
			cases = append(cases, pipScopeCase{regular: failedPIPScopeCaseWith(id, pip, shape.sets), route: route, answer: variant.response})
		}
	}
	return cases
}

// pipScopeRegularCases is the regular part of pipScopeCases, for
// TestRegularCaseIDsAreUnique.
func pipScopeRegularCases() []regularCase {
	var cases []regularCase
	for _, tc := range pipScopeCases() {
		cases = append(cases, tc.regular)
	}
	return cases
}

// How far a GENERAL PIP that answered 404 or the number 1000 reaches when the
// node reading it sits beside a node that allows: the two shapes of
// TestRound8FailedPIPScopeCases, a policy beside an allowing policy in one set
// and a set beside an allowing set in one upload, both under DENY_UNLESS_PERMIT.
// failed-pip-scope records that a 500 refuses the whole answer for the resource
// when the PIP was read; for a 404 and for a number only the answer inside one
// policy is recorded. The agent's converter accepts every set here.
//
// Each case reads a PIP of its own, and is run by runFailedPIPScopeCase: the
// sets are uploaded failedPIPScopeUploads times and each upload is classed by
// whether pip-mock saw a call on the case's route, one golden per class. The
// string variant is the control: when its PIP is read the rule allows.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case.
func (s *ParitySuite) TestRound10PIPFailureScopeCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("regular policy sets are evaluated by access-control only; authz-agent loads simplified policies")
	}
	ctx := context.Background()
	cases := pipScopeCases()
	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s: %v", isolatedCaseDomain, err)
		}
	})
	var declarations []any
	for _, tc := range cases {
		declarations = append(declarations, tc.regular.pips...)
	}
	status, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, declarations, nil)
	s.Require().NoError(err)
	s.Run("declare-the-pips", func() {
		s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "pip-scope/declare-the-pips", &model.PolicyLoadOutcome{Status: status})
	})
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return
	}
	s.emptyPolicySetsOnCleanup(s.cfg, regularExternalIDs(pipScopeRegularCases())...)
	for _, tc := range cases {
		s.runFailedPIPScopeCase(tc.regular, tc.route, tc.answer)
	}
}
