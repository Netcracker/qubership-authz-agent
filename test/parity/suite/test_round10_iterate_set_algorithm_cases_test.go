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

// iterateSetAlgorithmCaseID prefixes the ids and resource types of the sets of
// TestRound10IterateSetAlgorithmCases.
const iterateSetAlgorithmCaseID = "scope-set-algorithm"

// iterateSetAlgorithmSet is one iterating set of
// TestRound10IterateSetAlgorithmCases: the algorithm of the set and the one its
// iterate node names, empty for a node that names none.
type iterateSetAlgorithmSet struct {
	key, set, node string
}

// iterateSetAlgorithmSets pair a set algorithm with a node algorithm. The three
// PERMIT_UNLESS_DENY sets over a node of another algorithm are the question.
// permit-unless-deny-set-permit-unless-deny-node is the pair scope-iterate
// records, and deny-unless-permit-set-deny-overrides-node and
// deny-unless-permit-set-deny-unless-permit-node are the pairs whose answer over
// no grants is false by scope-iterate and scope-node; the three are the
// controls. deny-unless-permit-set-node-without-algorithm leaves
// combiningAlgorithm out of the iterate block. Every shape is sent to every set.
var iterateSetAlgorithmSets = []iterateSetAlgorithmSet{
	{"permit-unless-deny-set-deny-overrides-node", "PERMIT_UNLESS_DENY", "DENY_OVERRIDES"},
	{"permit-unless-deny-set-permit-overrides-node", "PERMIT_UNLESS_DENY", "PERMIT_OVERRIDES"},
	{"permit-unless-deny-set-deny-unless-permit-node", "PERMIT_UNLESS_DENY", "DENY_UNLESS_PERMIT"},
	{"permit-unless-deny-set-permit-unless-deny-node", "PERMIT_UNLESS_DENY", "PERMIT_UNLESS_DENY"},
	{"deny-unless-permit-set-deny-overrides-node", "DENY_UNLESS_PERMIT", "DENY_OVERRIDES"},
	{"deny-unless-permit-set-deny-unless-permit-node", "DENY_UNLESS_PERMIT", "DENY_UNLESS_PERMIT"},
	{"deny-unless-permit-set-node-without-algorithm", "DENY_UNLESS_PERMIT", ""},
}

// iterateSetAlgorithmShapes are the answers the scope service is pinned to in
// turn. no-grants and one-grant-r1 are the answers scope-iterate records;
// one-grant-empty-region is a grant whose region key holds no value, alone and
// beside a grant of r1; scope-service-not-found answers 404 and
// scope-service-unparsed-body answers 200 with a body that is not a scope.
var iterateSetAlgorithmShapes = []struct {
	name     string
	response PipStubResponse
}{
	{"no-grants", iterateFilterGrants(nil)},
	{"one-grant-r1", iterateFilterGrants([]permissionScopeGrant{{"region": {"r1"}}})},
	{"one-grant-empty-region", iterateFilterGrants([]permissionScopeGrant{{"region": {}}})},
	{"empty-region-beside-r1", iterateFilterGrants([]permissionScopeGrant{{"region": {}}, {"region": {"r1"}}})},
	{"scope-service-not-found", PipStubResponse{StatusCode: http.StatusNotFound, Body: map[string]string{"error": "parity scope-set-algorithm case"}}},
	{"scope-service-unparsed-body", PipStubResponse{StatusCode: http.StatusOK, Body: map[string]int{"x": 1}}},
}

// iterateSetAlgorithmResourceType is the resource type the set keyed key targets.
func iterateSetAlgorithmResourceType(key string) string {
	return regularResourceType(iterateSetAlgorithmCaseID + "-" + key)
}

// iterateSetAlgorithmBuildSet builds the iterating set of spec: one
// DENY_UNLESS_PERMIT policy holding the scoped LIST rule of scope-filter, with
// the rsql predicate region=in=(${subject.permissionScope.region}).
func iterateSetAlgorithmBuildSet(spec iterateSetAlgorithmSet) map[string]any {
	b := regularBuilder{caseID: iterateSetAlgorithmCaseID + "-" + spec.key}
	rt := iterateSetAlgorithmResourceType(spec.key)
	set := b.iteratingSet("set", "resourceType == '"+rt+"'", spec.set, "subject.permissionScope", []any{
		b.policy("scoped", readerTarget, "DENY_UNLESS_PERMIT",
			b.rule("region-granted",
				"operation == 'LIST' AND subject.permissionScope.region IS NOT NULL",
				"subject.permissionScope.region CONTAINS resource.region",
				"ALLOW", map[string]string{"rsqlPredicate": "region=in=(${subject.permissionScope.region})"})),
	})
	iterate := set["iterate"].(map[string]any)
	if spec.node == "" {
		delete(iterate, "combiningAlgorithm")
	} else {
		iterate["combiningAlgorithm"] = spec.node
	}
	return set
}

// How the algorithm of a set combines its iterate node, and what the node does
// with a scope it cannot read or a grant with no value. Every recorded iterate
// case gives the set and its node one algorithm, except scope-node, where the
// two disagree over two grants and the node's algorithm decides. Over zero
// grants a node under DENY_OVERRIDES or PERMIT_OVERRIDES has no pass that
// applies, and a PERMIT_UNLESS_DENY set above a child that does not apply
// permits (algorithm-*), so the set may grant everything to a subject with no
// grant; scope-iterate/no-grants cannot show it, since there the set and the
// node are one algorithm. No golden records a 404 from the scope service, and a
// body that does not parse is recorded as false only under DENY_UNLESS_PERMIT
// (permission-scope/as-*), where an empty scope is false too.
// A grant whose region key holds no value is recorded nowhere, and the rule
// target reads the key with IS NOT NULL. A node that names no algorithm is
// recorded nowhere. The agent's converter accepts every set here.
//
// Each shape pins one answer of the scope service and sends to every set of
// iterateSetAlgorithmSets a filter on LIST and check/resource on LIST in region
// r1 and in region r2. one-grant-r1 is the positive control of every set: r1
// true and r2 false say the scope was read and the pass applied. The PIP, the
// wire body and the cache wait are permission-scope-wire's; the pip-mock call log
// is read after every shape.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only.
func (s *ParitySuite) TestRound10IterateSetAlgorithmCases() {
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
		s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, iterateSetAlgorithmCaseID+"/declare-the-pip", &model.PolicyLoadOutcome{Status: pipStatus})
	})
	if pipStatus < http.StatusOK || pipStatus >= http.StatusMultipleChoices {
		return
	}
	// Each set goes up under an externalID of its own, so that a set the PAP
	// refuses, such as one whose iterate block names no algorithm, leaves the
	// others on the stand.
	var loaded []iterateSetAlgorithmSet
	for _, spec := range iterateSetAlgorithmSets {
		externalID := "parity-" + iterateSetAlgorithmCaseID + "-" + spec.key
		s.emptyPolicySetsOnCleanup(s.cfg, externalID)
		setStatus, _, err := HelperPutPolicySets(ctx, s.cfg, m2m, externalID, []any{iterateSetAlgorithmBuildSet(spec)})
		s.Require().NoError(err)
		s.Run("upload-"+spec.key, func() {
			s.requirePendingGolden(PSUITE_LOAD_POLICY_SETS, iterateSetAlgorithmCaseID+"/upload-"+spec.key, &model.PolicyLoadOutcome{Status: setStatus})
		})
		if setStatus >= http.StatusOK && setStatus < http.StatusMultipleChoices {
			loaded = append(loaded, spec)
		}
	}

	scopePath := permissionScopeWirePath(parityReaderSubjectID)
	for _, shape := range iterateSetAlgorithmShapes {
		// Outlive the cachePeriod of the declaration, as permission-scope-wire does,
		// so the answer pinned next is the one the next request sees.
		time.Sleep(2 * time.Second)
		s.Run(shape.name, func() {
			s.Require().NoError(s.pipMock.ResetCalls(ctx))
			s.Require().NoError(s.pipMock.PinRoute(ctx, scopePath, shape.response))
			for _, spec := range loaded {
				rt := iterateSetAlgorithmResourceType(spec.key)
				prefix := iterateSetAlgorithmCaseID + "/" + shape.name + "/" + spec.key
				s.Run(spec.key+"/filter", func() {
					s.runPendingFilterV1OutcomeCase(prefix+"/filter", rt, "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
				})
				for _, region := range []string{"r1", "r2"} {
					s.Run(spec.key+"/check-list-in-region-"+region, func() {
						s.runPendingCheckResourceV1OutcomeCase(
							prefix+"/check-list-in-region-"+region,
							model.CheckAccessRequest{Operation: "LIST", Type: rt, Resource: map[string]any{"id": "scope-set-algorithm", "region": region}},
							s.mustTokenBundle(UserProfileReader),
							PerCallOptions{},
						)
					})
				}
			}
			s.Run("the-pip-was-read", func() {
				s.Assert().Positive(s.pipCalls(scopePath), "pip-mock calls to %s over the requests with the %s answer pinned", scopePath, shape.name)
			})
		})
	}
}
