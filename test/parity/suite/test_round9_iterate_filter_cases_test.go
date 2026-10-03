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

// iterateFilterCaseID prefixes the ids and resource types of the sets of
// TestRound9IterateFilterCases.
const iterateFilterCaseID = "scope-filter"

// iterateFilterSet is one iterating set of TestRound9IterateFilterCases: the
// algorithm of its iterate node and the predicate fields of its scoped rule.
type iterateFilterSet struct {
	key       string
	node      string
	predicate func(b regularBuilder) map[string]any
}

// iterateFilterResourceType is the resource type the set keyed key targets.
func iterateFilterResourceType(key string) string {
	return regularResourceType(iterateFilterCaseID + "-" + key)
}

// iterateFilterCustomOnly is the scoped rule's predicate in the one form the
// product policies in reach write: a customPredicate whose parameter reads the
// scope item of the current pass, and no string predicate.
func iterateFilterCustomOnly(regularBuilder) map[string]any {
	return map[string]any{
		"customPredicate": map[string]any{
			"predicate": "region:${p}",
			"params":    map[string]any{"p": "subject.permissionScope.region"},
		},
	}
}

// iterateFilterAllFields adds the four string predicates to the custom one, each
// naming the scope item as a placeholder.
func iterateFilterAllFields(b regularBuilder) map[string]any {
	fields := iterateFilterCustomOnly(b)
	fields["rsqlPredicate"] = "region=in=(${subject.permissionScope.region})"
	fields["sqlPredicate"] = "region IN (${subject.permissionScope.region})"
	fields["mongodbPredicate"] = `{ "region": ${subject.permissionScope.region} }`
	fields["predicate"] = "${resourceType}.region.in(${subject.permissionScope.region})"
	return fields
}

// iterateFilterLiteral is a predicate with no placeholder, so its set shows
// whether an iterating set reaches the filter response at all.
func iterateFilterLiteral(regularBuilder) map[string]any {
	return map[string]any{"rsqlPredicate": "scoped==1"}
}

// iterateFilterProductSet is the key of the set in the product form: the rule's
// customPredicate alone, under a DENY_UNLESS_PERMIT node.
const iterateFilterProductSet = "custom-deny-unless-permit"

// iterateFilterSets are the sets of TestRound9IterateFilterCases. The custom-*
// sets differ in the node algorithm alone and carry the product form of the
// rule; all-fields-deny-unless-permit puts all five predicate fields under the
// node algorithm of the product policies, and literal-deny-unless-permit is the
// control under the same node.
var iterateFilterSets = []iterateFilterSet{
	{iterateFilterProductSet, "DENY_UNLESS_PERMIT", iterateFilterCustomOnly},
	{"custom-permit-unless-deny", "PERMIT_UNLESS_DENY", iterateFilterCustomOnly},
	{"custom-deny-overrides", "DENY_OVERRIDES", iterateFilterCustomOnly},
	{"custom-permit-overrides", "PERMIT_OVERRIDES", iterateFilterCustomOnly},
	{"all-fields-deny-unless-permit", "DENY_UNLESS_PERMIT", iterateFilterAllFields},
	{"literal-deny-unless-permit", "DENY_UNLESS_PERMIT", iterateFilterLiteral},
}

// iterateFilterShapes are the answers the scope service is pinned to in turn.
// no-grants, one-grant-one-value and two-grants-different-values are the count
// of passes at zero, one and two; one-grant-two-values is one pass whose item
// holds two values, so that a placeholder rendering one value is told from one
// rendering the list; two-grants-one-without-the-key is two grants of which
// only one satisfies the rule target; scope-service-fails answers 500.
var iterateFilterShapes = []struct {
	name     string
	response PipStubResponse
}{
	{"no-grants", iterateFilterGrants(nil)},
	{"one-grant-one-value", iterateFilterGrants([]permissionScopeGrant{{"region": {"r1"}}})},
	{"one-grant-two-values", iterateFilterGrants([]permissionScopeGrant{{"region": {"r1", "r2"}}})},
	{"two-grants-different-values", iterateFilterGrants([]permissionScopeGrant{{"region": {"r1"}}, {"region": {"r2"}}})},
	{"two-grants-one-without-the-key", iterateFilterGrants([]permissionScopeGrant{{"region": {"r1"}}, {"category": {"c1"}}})},
	{"scope-service-fails", PipStubResponse{StatusCode: http.StatusInternalServerError, Body: map[string]string{"error": "parity scope-filter case"}}},
}

func iterateFilterGrants(grants []permissionScopeGrant) PipStubResponse {
	return PipStubResponse{StatusCode: http.StatusOK, Body: permissionScopeWireBody(parityReaderSubjectID, grants)}
}

// What check/filter returns for an iterating set in the one shape product policies
// give it: the set and its policy under DENY_UNLESS_PERMIT, a LIST rule whose
// target is subject.permissionScope.region IS NOT NULL, whose condition is
// subject.permissionScope.region CONTAINS resource.region, and whose
// customPredicate passes subject.permissionScope.region as a parameter. Every
// recorded iterate case is a check/resource request, so nothing records how
// the passes of an iterating set meet in a filter response, what a placeholder
// over the scope renders, or what the filter answers for zero passes or for a
// scope service that failed. The agent's own converter accepts every set here.
//
// The four custom sets vary the iterate node's algorithm, which combines the
// passes (scope-node). all-fields repeats the rule with the four string
// predicates beside the custom one, which says what each dialect renders for the
// scope item. literal is the control: its predicate names no placeholder, so a
// filter response that holds nothing for it says the iterating set never reaches
// the filter, and the answers of the other sets say nothing about placeholders.
//
// Each shape pins one answer of the scope service and sends one filter request
// per set, then check/resource requests on LIST for a resource in region r1 and
// in region r2 to the product-form set. They are the positive controls: r1 for
// every shape that grants it, where a false says the pinned scope was not read,
// and r2 under two-grants-different-values, where a false says the pass over
// the second grant was not reached.
// The PIP, the wire body and the cache wait are permission-scope-wire's; the
// pip-mock call log is read after every shape.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy profile
// only.
func (s *ParitySuite) TestRound9IterateFilterCases() {
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

	sets := make([]any, 0, len(iterateFilterSets))
	for _, spec := range iterateFilterSets {
		sets = append(sets, iterateFilterBuildSet(spec))
	}

	pipStatus, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, []any{permissionScopeWirePIP}, nil)
	s.Require().NoError(err)
	s.Run("declare-the-pip", func() {
		s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, iterateFilterCaseID+"/declare-the-pip", &model.PolicyLoadOutcome{Status: pipStatus})
	})
	if pipStatus < http.StatusOK || pipStatus >= http.StatusMultipleChoices {
		return
	}
	externalID := "parity-" + iterateFilterCaseID
	s.emptyPolicySetsOnCleanup(s.cfg, externalID)
	setStatus, _, err := HelperPutPolicySets(ctx, s.cfg, m2m, externalID, sets)
	s.Require().NoError(err)
	s.Run("upload-the-sets", func() {
		s.requirePendingGolden(PSUITE_LOAD_POLICY_SETS, iterateFilterCaseID+"/upload-the-sets", &model.PolicyLoadOutcome{Status: setStatus})
	})
	if setStatus < http.StatusOK || setStatus >= http.StatusMultipleChoices {
		return
	}

	scopePath := permissionScopeWirePath(parityReaderSubjectID)
	for _, shape := range iterateFilterShapes {
		// Outlive the cachePeriod of the declaration, as permission-scope-wire does,
		// so the answer pinned next is the one the next request sees.
		time.Sleep(2 * time.Second)
		s.Run(shape.name, func() {
			s.Require().NoError(s.pipMock.ResetCalls(ctx))
			s.Require().NoError(s.pipMock.PinRoute(ctx, scopePath, shape.response))
			for _, spec := range iterateFilterSets {
				s.Run("filter-"+spec.key, func() {
					s.runPendingFilterV1OutcomeCase(
						iterateFilterCaseID+"/"+shape.name+"/filter-"+spec.key,
						iterateFilterResourceType(spec.key), "LIST",
						s.mustTokenBundle(UserProfileReader), PerCallOptions{})
				})
			}
			for _, region := range []string{"r1", "r2"} {
				s.Run("check-list-in-region-"+region, func() {
					s.runPendingCheckResourceV1OutcomeCase(
						iterateFilterCaseID+"/"+shape.name+"/check-list-in-region-"+region,
						model.CheckAccessRequest{
							Operation: "LIST",
							Type:      iterateFilterResourceType(iterateFilterProductSet),
							Resource:  map[string]any{"id": "scope-filter", "region": region},
						},
						s.mustTokenBundle(UserProfileReader),
						PerCallOptions{},
					)
				})
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
				s.Assert().Positive(read, "pip-mock calls to %s over the requests with the %s answer pinned", scopePath, shape.name)
			})
		})
	}
}

// iterateFilterBuildSet builds the iterating set of spec: the set under
// DENY_UNLESS_PERMIT, its iterate node under spec.node, and one policy under
// DENY_UNLESS_PERMIT holding the scoped LIST rule with the predicate fields of
// spec.
func iterateFilterBuildSet(spec iterateFilterSet) map[string]any {
	b := regularBuilder{caseID: iterateFilterCaseID + "-" + spec.key}
	rt := iterateFilterResourceType(spec.key)
	set := b.iteratingSet("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", "subject.permissionScope", []any{
		b.policy("scoped", readerTarget, "DENY_UNLESS_PERMIT",
			b.rule("region-granted",
				"operation == 'LIST' AND subject.permissionScope.region IS NOT NULL",
				"subject.permissionScope.region CONTAINS resource.region",
				"ALLOW", nil)),
	})
	set["iterate"].(map[string]any)["combiningAlgorithm"] = spec.node
	rule := set["policies"].([]any)[0].(map[string]any)["rules"].([]any)[0].(map[string]any)
	for field, value := range spec.predicate(b) {
		rule[field] = value
	}
	return set
}
