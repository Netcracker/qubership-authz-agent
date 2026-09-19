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
	"fmt"
	"net/http"
	"time"

	"authz-agent/test/parity/suite/model"
)

// permissionScopeWireResourceType is the resource type the iterate set of this file
// targets. It is the case's own, so that the set here and the set of
// TestPermissionScopeIterateCases never answer each other's requests.
const permissionScopeWireResourceType = "PARITY_SUITE_SCOPE_WIRE"

// permissionScopeWirePath is the path access-control derives from a
// PERMISSION_SCOPE declaration, not a path the declaration carries. The client
// formats pip.getUrl() + "/api/v1/permission-scope/user/%s/policies?inherited=true"
// with the subject id (PermissionScopePipServiceImpl.java:31,47), so the stub — which
// matches a path literally and drops the query — is pinned at the derived path and
// the declaration's url ends where the derived part begins.
func permissionScopeWirePath(subjectID string) string {
	return fmt.Sprintf("/api/v1/permission-scope/user/%s/policies", subjectID)
}

// permissionScopeWirePIP declares subject.permissionScope with a url that carries no
// path of its own, since access-control appends one.
//
// cacheable is written false and is not honoured: the PAP answers the declaration
// with cacheable true and a cachePeriod, and the client caches a scope per
// (subject, tenant) for that many seconds (PermissionScopePipServiceImpl.java:49-54).
// cachePeriod is therefore declared as one second and each shape waits it out, so a
// re-pinned body reaches the next request instead of the previous shape's grants
// being served from the cache.
var permissionScopeWirePIP = map[string]any{
	"name":        "subject.permissionScope",
	"pipType":     "PERMISSION_SCOPE",
	"url":         "http://pip-mock:8090",
	"cacheable":   false,
	"cachePeriod": 1,
}

// permissionScopeGrant is one entry of a permission scope as the backend sends it:
// a set of values per scope item key. castResponseToPermissionsScopes turns every
// policy of every permissionScope entry into one Scope whose items are the policy's
// scopeItems keyed by key, with the value ids as the set
// (PermissionScopeInformationPointLoader.java:44-61).
type permissionScopeGrant map[string][]string

// permissionScopeWireBody builds the PermissionScopeBEResponse the client parses:
// {"permissionScope":[{ ..., "policies":[{"scopeItems":[{"key":k,"values":[{"id":v}]}]}]}]}.
// Every grant becomes one policy, so a body with two grants is a subject holding two
// scopes and a body with one grant is a subject holding one.
func permissionScopeWireBody(subjectID string, grants []permissionScopeGrant) map[string]any {
	policies := make([]any, 0, len(grants))
	for _, grant := range grants {
		items := make([]any, 0, len(grant))
		for key, values := range grant {
			ids := make([]any, 0, len(values))
			for _, value := range values {
				ids = append(ids, map[string]any{"id": value})
			}
			items = append(items, map[string]any{"key": key, "values": ids})
		}
		policies = append(policies, map[string]any{"scopeItems": items})
	}
	return map[string]any{"permissionScope": []any{map[string]any{
		"type":        "USER",
		"id":          subjectID,
		"name":        "parity-reader",
		"isInherited": false,
		"policies":    policies,
	}}}
}

// permissionScopeWireBodies are the grant shapes, all in the wire format above and
// all granting the region r1 and the category c1 where they grant anything.
var permissionScopeWireBodies = []struct {
	name   string
	grants []permissionScopeGrant
}{
	{"two-grants-one-key-each", []permissionScopeGrant{{"region": {"r1"}}, {"category": {"c1"}}}},
	{"one-grant-with-both-keys", []permissionScopeGrant{{"region": {"r1"}, "category": {"c1"}}}},
	{"no-grants", nil},
}

// What iterate.foreach over subject.permissionScope does, asked of the wire format
// the client actually parses. TestPermissionScopeIterateCases asks the same question
// of three guessed shapes and its positive control denies for all three, which says
// the shapes never reached the evaluator; the goldens of that case record a scope
// access-control could not read rather than iterate semantics.
//
// The set is the one that case builds — three scoped rules split by which keys a
// grant carries, plus a probe policy on operation PROBE whose condition compares the
// scope with a literal. The two readings of iterate are told apart by the two
// single-key requests under the two-grants shape, and the probe separates a scope
// that was read from one that was not.
//
// no-grants is the second control. It pins a well-formed body that grants nothing, so
// a run where every shape allows the probe would be a scope not being read at all
// rather than the pinned grants being applied.
func (s *ParitySuite) TestPermissionScopeWireCases() {
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

	b := regularBuilder{caseID: "permission-scope-wire"}
	set := b.iteratingSet("set", "resourceType == '"+permissionScopeWireResourceType+"'", "DENY_UNLESS_PERMIT",
		"subject.permissionScope", []any{
			b.policy("scoped", readerTarget, "DENY_UNLESS_PERMIT",
				b.rule("region-and-category",
					"subject.permissionScope.region IS NOT NULL AND subject.permissionScope.category IS NOT NULL",
					"subject.permissionScope.region CONTAINS resource.region AND subject.permissionScope.category CONTAINS resource.category",
					"ALLOW", nil),
				b.rule("region-only",
					"subject.permissionScope.region IS NOT NULL AND subject.permissionScope.category IS NULL",
					"subject.permissionScope.region CONTAINS resource.region",
					"ALLOW", nil),
				b.rule("category-only",
					"subject.permissionScope.category IS NOT NULL AND subject.permissionScope.region IS NULL",
					"subject.permissionScope.category CONTAINS resource.category",
					"ALLOW", nil)),
			b.policy("probe", readerTarget, "DENY_UNLESS_PERMIT",
				b.rule("literal-region", "operation == 'PROBE'",
					"subject.permissionScope.region CONTAINS 'r1'", "ALLOW", nil)),
		})

	pipStatus, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, []any{permissionScopeWirePIP}, nil)
	s.Require().NoError(err)
	s.Run("declare-the-pip", func() {
		s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "permission-scope-wire/declare-the-pip", &model.PolicyLoadOutcome{Status: pipStatus})
	})
	if pipStatus < http.StatusOK || pipStatus >= http.StatusMultipleChoices {
		return
	}

	setStatus, _, err := HelperPutPolicySets(ctx, s.cfg, m2m, "parity-permission-scope-wire", []any{set})
	s.Require().NoError(err)
	s.Run("upload-the-set", func() {
		s.requirePendingGolden(PSUITE_LOAD_POLICY_SETS, "permission-scope-wire/upload-the-set", &model.PolicyLoadOutcome{Status: setStatus})
	})
	if setStatus < http.StatusOK || setStatus >= http.StatusMultipleChoices {
		return
	}

	scopePath := permissionScopeWirePath(parityReaderSubjectID)
	for _, shape := range permissionScopeWireBodies {
		// Outlive the cachePeriod the declaration asked for, so the shape about to be
		// pinned is the one the next request sees. The first shape waits too: the
		// cache is keyed by (subject, tenant) and not by PIP, so an entry another
		// case wrote for the same reader is expired by the same wait, the client
		// having just reset the cache's expiry to this declaration's cachePeriod.
		time.Sleep(2 * time.Second)
		s.Run(shape.name, func() {
			s.Require().NoError(s.pipMock.ResetCalls(ctx))
			s.Require().NoError(s.pipMock.PinRoute(ctx, scopePath, PipStubResponse{
				StatusCode: http.StatusOK,
				Body:       permissionScopeWireBody(parityReaderSubjectID, shape.grants),
			}))
			for _, req := range permissionScopeRequests {
				s.Run(req.name, func() {
					s.runPendingCheckResourceV1OutcomeCase(
						"permission-scope-wire/"+shape.name+"/"+req.name,
						model.CheckAccessRequest{
							Operation: valueOr(req.operation, "READ"),
							Type:      permissionScopeWireResourceType,
							Resource:  req.resource,
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
				s.Assert().Positive(read, "pip-mock calls to %s over %d requests with the %s body pinned",
					scopePath, len(permissionScopeRequests), shape.name)
			})
		})
	}
}
