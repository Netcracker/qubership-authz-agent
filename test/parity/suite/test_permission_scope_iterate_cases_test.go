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

// permissionScopeResourceType is the resource type the iterate set targets.
const permissionScopeResourceType = "PARITY_SUITE_SCOPE_ITERATE"

// permissionScopeStubPath is the pip-mock path the PERMISSION_SCOPE PIP reads. The
// stub matches a path literally, so every body shape is pinned to this one path in
// turn rather than to a path of its own.
const permissionScopeStubPath = "/api/v1/pip/permission-scope"

// permissionScopePIP declares subject.permissionScope against pip-mock, the name and
// pipType a PERMISSION_SCOPE declaration carries in
// internal/acconfig/testdata/pipsV3_1.json. That declaration sets cachePeriod; this
// one sets cacheable to false instead, so that a re-pinned body reaches the next
// request. Whether it does is checked per shape, since nothing here can assume it.
var permissionScopePIP = map[string]any{
	"name":      "subject.permissionScope",
	"pipType":   "PERMISSION_SCOPE",
	"url":       "http://pip-mock:8090" + permissionScopeStubPath,
	"cacheable": false,
}

// iteratingSet builds a policy set that carries an iterate block. regularBuilder.set
// leaves the field out, because only a scoped set has one. algorithm is written both
// as the set's own combining algorithm and as the one the iterate block names, the
// way every scoped set in reach spells it.
func (b regularBuilder) iteratingSet(key, target, algorithm, foreach string, policies []any) map[string]any {
	set := b.set(key, target, algorithm, policies, nil)
	set["iterate"] = map[string]any{"foreach": foreach, "combiningAlgorithm": algorithm}
	return set
}

// permissionScopeBodies are the shapes the PERMISSION_SCOPE PIP may answer with. The
// wire format is documented nowhere the suite can read, so each shape grants the
// region r1 and the category c1 and the goldens record which ones access-control
// parses. probe-with-a-literal-operand is what separates a parsed shape from an
// unparsed one; the four scoped requests are read only for a shape whose probe
// allowed.
var permissionScopeBodies = []struct {
	name string
	body any
}{
	{"as-a-list-of-objects", []any{
		map[string]any{"region": []string{"r1"}},
		map[string]any{"category": []string{"c1"}},
	}},
	{"as-a-list-of-one-object", []any{
		map[string]any{"region": []string{"r1"}, "category": []string{"c1"}},
	}},
	{"as-one-object", map[string]any{"region": []string{"r1"}, "category": []string{"c1"}}},
}

// permissionScopeRequests probe the declaration first, then ask for a resource in the
// granted region, in the granted category, in both, and in neither.
var permissionScopeRequests = []isolatedRequest{
	{name: "probe-with-a-literal-operand", operation: "PROBE", resource: map[string]any{"id": "scope-iterate", "region": "r9", "category": "c9"}},
	{name: "resource-in-the-granted-region-only", resource: map[string]any{"id": "scope-iterate", "region": "r1", "category": "c9"}},
	{name: "resource-in-the-granted-category-only", resource: map[string]any{"id": "scope-iterate", "region": "r9", "category": "c1"}},
	{name: "resource-in-both", resource: map[string]any{"id": "scope-iterate", "region": "r1", "category": "c1"}},
	{name: "resource-in-neither", resource: map[string]any{"id": "scope-iterate", "region": "r9", "category": "c9"}},
}

// What iterate.foreach over subject.permissionScope does, which no golden has
// recorded and no document in reach describes. Product policies carry the block and
// the agent does not read it at all; internal/acconfig/testdata/policy_setsV3_1.json
// holds the only instance in this repository, a set whose single rule compares
// subject.permissionScope.role with two literals.
//
// The three scoped rules below are this case's own construction, not a policy copied
// from anywhere: they split on which scope keys a grant carries, so that a run tells
// the two readings of iterate apart. Two requests discriminate, both only for the
// as-a-list-of-objects body, where one grant carries the region and another the
// category:
//
//   - resource-in-the-granted-region-only, r1 with an ungranted category, and
//     resource-in-the-granted-category-only, c1 with an ungranted region.
//   - ALLOW on both means access-control evaluates the set once per grant. Each grant
//     reaches the rule written for a single key, and that rule ignores the other
//     attribute the resource carries.
//   - DENY on both means the grants are merged into one map before the rules run.
//     Both keys are then present, the rule that requires both fires, and one half of
//     the comparison fails.
//   - The two disagreeing is a finding rather than an answer, and neither golden is
//     then the record of iterate semantics.
//
// resource-in-both and resource-in-neither hold the columns where the readings agree.
//
// probe-with-a-literal-operand is the positive control, and the four scoped answers
// mean nothing without it. It reaches a policy of its own on operation PROBE, whose
// condition compares the scope with a literal rather than with an attribute of the
// resource, and it allows only once the PIP is declared, called, parsed, and readable
// by an operator. Without it, an all-false run is equally produced by a refused
// declaration, a shape access-control does not parse, a PIP that was never called,
// and CONTAINS against an attribute behaving the way MATCH against an attribute
// already does: accepted by the PAP and always false
// (check-resource-v1-outcome/isolated/a2-match-attribute-pattern).
//
// The pip-mock call log is read after every shape, because a cached scope would
// answer the second and third shapes with the first shape's grants and record three
// parsed formats where one was read.
func (s *ParitySuite) TestPermissionScopeIterateCases() {
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

	b := regularBuilder{caseID: "permission-scope-iterate"}
	set := b.iteratingSet("set", "resourceType == '"+permissionScopeResourceType+"'", "DENY_UNLESS_PERMIT",
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

	pipStatus, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, []any{permissionScopePIP}, nil)
	s.Require().NoError(err)
	s.Run("declare-the-pip", func() {
		s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "permission-scope/declare-the-pip", &model.PolicyLoadOutcome{Status: pipStatus})
	})
	if pipStatus < http.StatusOK || pipStatus >= http.StatusMultipleChoices {
		return
	}

	s.emptyPolicySetsOnCleanup(s.cfg, "parity-permission-scope-iterate")
	setStatus, _, err := HelperPutPolicySets(ctx, s.cfg, m2m, "parity-permission-scope-iterate", []any{set})
	s.Require().NoError(err)
	s.Run("upload-the-set", func() {
		s.requirePendingGolden(PSUITE_LOAD_POLICY_SETS, "permission-scope/upload-the-set", &model.PolicyLoadOutcome{Status: setStatus})
	})
	if setStatus < http.StatusOK || setStatus >= http.StatusMultipleChoices {
		return
	}

	for _, shape := range permissionScopeBodies {
		s.Run(shape.name, func() {
			s.Require().NoError(s.pipMock.ResetCalls(ctx))
			s.Require().NoError(s.pipMock.PinRoute(ctx, permissionScopeStubPath, PipStubResponse{
				StatusCode: http.StatusOK,
				Body:       shape.body,
			}))
			for _, req := range permissionScopeRequests {
				s.Run(req.name, func() {
					s.runPendingCheckResourceV1OutcomeCase(
						"permission-scope/"+shape.name+"/"+req.name,
						model.CheckAccessRequest{
							Operation: valueOr(req.operation, "READ"),
							Type:      permissionScopeResourceType,
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
					if call.Path == permissionScopeStubPath {
						read++
					}
				}
				s.Assert().Positive(read, "pip-mock calls to %s over %d requests with the %s body pinned",
					permissionScopeStubPath, len(permissionScopeRequests), shape.name)
			})
		})
	}
}
