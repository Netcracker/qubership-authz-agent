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

	"authz-agent/test/parity/suite/model"
)

// round9SecondDomain is the second domain of the tenant the cases of this file
// upload into, beside isolatedCaseDomain.
const round9SecondDomain = "PARITY_ISOLATED_B"

// round9EmptyDomainsOnCleanup registers a cleanup that empties isolatedCaseDomain
// and round9SecondDomain.
func (s *ParitySuite) round9EmptyDomainsOnCleanup() {
	ctx := context.Background()
	s.T().Cleanup(func() {
		for _, domain := range []string{isolatedCaseDomain, round9SecondDomain} {
			if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, domain, nil, nil); err != nil {
				s.T().Logf("empty domain %s: %v", domain, err)
			}
		}
	})
}

// round9UploadDomain uploads pips and policies into domain and records the
// status under subCase. It reports whether the upload was accepted.
func (s *ParitySuite) round9UploadDomain(subCase, domain string, pips, policies []any) bool {
	s.T().Helper()
	status, err := UploadIsolatedPolicies(context.Background(), s.cfg, s.tokens, domain, pips, policies)
	s.Require().NoError(err)
	if !isAuthzAgentProfile(s.cfg.Profile) {
		s.Run(subCase, func() {
			s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, subCase, &model.PolicyLoadOutcome{Status: status})
		})
	}
	return status >= http.StatusOK && status < http.StatusMultipleChoices
}

// simplifiedGroupPolicy builds a simplified LIST policy on resourceType, of
// component, whose one predicate is rsql.
func simplifiedGroupPolicy(b regularBuilder, key, component, resourceType, rsql string) map[string]any {
	return map[string]any{
		"component":             component,
		"reason":                b.caseID + " " + key,
		"resourceType":          resourceType,
		"operation":             "LIST",
		"rsqlPredicate":         rsql,
		"roles":                 []string{"ROLE_PARITY_READER"},
		"applicableForFrontend": false,
		"id":                    b.id("simplified/" + key),
	}
}

// Which simplified policies check/filter brackets as one group. filter-four-groups-on-one-type
// records two simplified policies of one domain, one component and one type as
// one group, (simplified1==1,simplified2==2); which of the three the group is
// keyed on is recorded nowhere, and the configuration export names a simplified
// set after all three and after the type as written. The agent's converter
// accepts every policy here.
//
// Each case is two simplified LIST policies with a predicate each, on a resource
// type of its own, that differ in one of the three: two-domains in the domain,
// two-components in the component, two-spellings in the case of the type, whose
// filter is asked in both spellings. one-domain-component-and-type is the
// control, the recorded shape: one group without brackets.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound9SimplifiedGroupCases() {
	s.round9EmptyDomainsOnCleanup()
	b := regularBuilder{caseID: "simplified-group"}
	const (
		twoDomains     = "PARITY_SUITE_R9_SG_TWO_DOMAINS"
		twoComponents  = "PARITY_SUITE_R9_SG_TWO_COMPONENTS"
		upperSpelling  = "PARITY_SUITE_R9_SG_TWO_SPELLINGS"
		mixedSpelling  = "Parity_Suite_R9_Sg_Two_Spellings"
		oneOfEachThree = "PARITY_SUITE_R9_SG_ONE_OF_EACH"
	)
	first := []any{
		simplifiedGroupPolicy(b, "two-domains-first", "PARITY", twoDomains, "domain1==1"),
		simplifiedGroupPolicy(b, "two-components-first", "PARITY", twoComponents, "component1==1"),
		simplifiedGroupPolicy(b, "two-components-second", "PARITY_B", twoComponents, "component2==2"),
		simplifiedGroupPolicy(b, "two-spellings-upper", "PARITY", upperSpelling, "upper==1"),
		simplifiedGroupPolicy(b, "two-spellings-mixed", "PARITY", mixedSpelling, "mixed==2"),
		simplifiedGroupPolicy(b, "one-of-each-first", "PARITY", oneOfEachThree, "same1==1"),
		simplifiedGroupPolicy(b, "one-of-each-second", "PARITY", oneOfEachThree, "same2==2"),
	}
	second := []any{
		simplifiedGroupPolicy(b, "two-domains-second", "PARITY", twoDomains, "domain2==2"),
	}
	if !s.round9UploadDomain("simplified-group/upload-the-first-domain", isolatedCaseDomain, nil, first) {
		return
	}
	if !s.round9UploadDomain("simplified-group/upload-the-second-domain", round9SecondDomain, nil, second) {
		return
	}
	for _, req := range []struct{ name, resourceType string }{
		{"two-domains", twoDomains},
		{"two-components", twoComponents},
		{"two-spellings-asked-in-upper-case", upperSpelling},
		{"two-spellings-asked-in-mixed-case", mixedSpelling},
		{"one-domain-component-and-type", oneOfEachThree},
	} {
		s.Run(req.name, func() {
			s.runPendingFilterV1OutcomeCase("simplified-group/"+req.name, req.resourceType, "LIST",
				s.mustTokenBundle(UserProfileReader), PerCallOptions{})
		})
	}
}

// round9TwinRoutes are the pip-mock paths the two declarations of
// subject.parityR9Twin read, keyed by the domain that declares each, with the
// value each answers.
var round9TwinRoutes = map[string]struct{ route, suffix, value string }{
	isolatedCaseDomain: {"/api/v1/pip/r9-twin-first", "r9-twin-first", "first"},
	round9SecondDomain: {"/api/v1/pip/r9-twin-second", "r9-twin-second", "second"},
}

// round9TwinPIP declares subject.parityR9Twin for domain, at that domain's
// pip-mock path.
func round9TwinPIP(domain string) map[string]any {
	return map[string]any{
		"name":              "subject.parityR9Twin",
		"url":               parityPipMockBase + "/" + round9TwinRoutes[domain].suffix,
		"httpMethod":        "POST",
		"pipType":           "GENERAL",
		"type":              "JSON",
		"jsonPath":          "$.value",
		"requestAttributes": map[string]string{"resourceType": "PARITY_SUITE_R9_TWIN"},
		"cacheable":         false,
	}
}

// Which declaration a GENERAL PIP name resolves to when two domains of one
// tenant declare it with different addresses. PIPs belong to a domain and
// regular sets do not, so a regular set reading the name has no domain of its
// own to take the declaration from, and a simplified policy may read its own
// domain's or either. The agent's converter accepts every policy and set here.
//
// Each domain declares subject.parityR9Twin at a pip-mock path of its own that
// answers first or second, and holds a simplified READ policy that allows when
// the PIP answers the value of its own domain. The regular set allows READ on
// first and PROBE on second. Each request is followed by a read of the pip-mock
// call log, logged per path, so the run shows which address answered as well as
// the decision. A domain policy that is false, with a call logged to the other
// domain's path, reads the other declaration; the regular set true on exactly
// one operation reads one of the two. The upload status of the second domain
// is recorded too: a refused duplicate name is an answer.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case.
func (s *ParitySuite) TestRound9TwinPIPDeclarationCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("regular policy sets are evaluated by access-control only; authz-agent loads simplified policies")
	}
	ctx := context.Background()
	m2m := s.mustM2MToken()
	s.round9EmptyDomainsOnCleanup()
	for _, twin := range round9TwinRoutes {
		s.Require().NoError(s.pipMock.PinRoute(ctx, twin.route, PipStubResponse{
			StatusCode: http.StatusOK,
			Body:       map[string]string{"value": twin.value},
		}))
	}

	b := regularBuilder{caseID: "twin-pip"}
	policy := func(domain, resourceType string) map[string]any {
		return map[string]any{
			"component":             "PARITY",
			"reason":                "twin-pip " + domain,
			"resourceType":          resourceType,
			"operation":             "READ",
			"condition":             "subject.parityR9Twin == '" + round9TwinRoutes[domain].value + "'",
			"roles":                 []string{"ROLE_PARITY_READER"},
			"applicableForFrontend": false,
			"id":                    b.id("simplified/" + domain),
		}
	}
	const (
		firstType   = "PARITY_SUITE_R9_TWIN_FIRST_DOMAIN"
		secondType  = "PARITY_SUITE_R9_TWIN_SECOND_DOMAIN"
		regularType = "PARITY_SUITE_R9_TWIN_REGULAR_SET"
	)
	if !s.round9UploadDomain("twin-pip/upload-the-first-domain", isolatedCaseDomain,
		[]any{round9TwinPIP(isolatedCaseDomain)}, []any{policy(isolatedCaseDomain, firstType)}) {
		return
	}
	// The second domain's outcome is the answer to the case, so the requests run
	// whatever it is: a refused declaration leaves one declaration of the name.
	s.round9UploadDomain("twin-pip/upload-the-second-domain", round9SecondDomain,
		[]any{round9TwinPIP(round9SecondDomain)}, []any{policy(round9SecondDomain, secondType)})

	externalID := "parity-twin-pip"
	s.emptyPolicySetsOnCleanup(s.cfg, externalID)
	set := b.set("set", "resourceType == '"+regularType+"'", "DENY_UNLESS_PERMIT", []any{
		b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
			b.rule("read-on-first", "operation == 'READ'", "subject.parityR9Twin == 'first'", "ALLOW", nil),
			b.rule("probe-on-second", "operation == 'PROBE'", "subject.parityR9Twin == 'second'", "ALLOW", nil)),
	}, nil)
	setStatus, _, err := HelperPutPolicySets(ctx, s.cfg, m2m, externalID, []any{set})
	s.Require().NoError(err)
	s.Run("twin-pip/upload-the-set", func() {
		s.requirePendingGolden(PSUITE_LOAD_POLICY_SETS, "twin-pip/upload-the-set", &model.PolicyLoadOutcome{Status: setStatus})
	})
	setAccepted := setStatus >= http.StatusOK && setStatus < http.StatusMultipleChoices

	for _, req := range []struct {
		name, operation, resourceType string
		needsSet                      bool
	}{
		{"first-domain-policy", "READ", firstType, false},
		{"second-domain-policy", "READ", secondType, false},
		{"regular-set-on-first", "READ", regularType, true},
		{"regular-set-on-second", "PROBE", regularType, true},
	} {
		if req.needsSet && !setAccepted {
			continue
		}
		s.Run(req.name, func() {
			s.Require().NoError(s.pipMock.ResetCalls(ctx))
			status, decision, _, err := HelperCheckResourceV1(ctx, s.cfg,
				model.CheckAccessRequest{Operation: req.operation, Type: req.resourceType, Resource: map[string]any{"id": "r9-twin"}},
				s.mustTokenBundle(UserProfileReader), PerCallOptions{})
			s.Require().NoError(err)
			// The call log is read before the golden is compared, since a golden not
			// yet recorded skips the rest of the subtest.
			calls, err := s.pipMock.GetCalls(ctx)
			s.Require().NoError(err)
			read := map[string]int{}
			for _, call := range calls {
				read[call.Path]++
			}
			for domain, twin := range round9TwinRoutes {
				s.T().Logf("%s: pip-mock received %d call(s) to %s, the declaration of %s", req.name, read[twin.route], twin.route, domain)
				pipCall := s.pipCallOutcomeOf(calls, twin.route)
				s.Run("pip-calls-to-the-declaration-of-"+domain, func() {
					s.requirePendingGolden(PSUITE_PIP_CALL, "twin-pip/"+req.name+"/"+domain, pipCall)
				})
			}
			s.requirePendingGolden(PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, "twin-pip/"+req.name,
				&model.CheckResourceOutcome{Status: status, Decision: decision})
		})
	}
}
