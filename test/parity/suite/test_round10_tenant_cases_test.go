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

// round10TenantDomain is the domain the tenant cases of this file upload into,
// in each tenant they use.
const round10TenantDomain = "PARITY_R10_MT"

// round10TenantStand skips the test without a two-tenant stand or on the
// authz-agent profile, and otherwise returns the stand.
func (s *ParitySuite) round10TenantStand() TenantStand {
	s.T().Helper()
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("tenant-scoped uploads need the legacy PAP; authz-policy-admin keys a domain without the tenant")
	}
	stand := s.cfg.Tenants
	if !stand.Configured() {
		s.T().Skip("no two-tenant stand: set PARITY_MT_TENANT_A_ID, PARITY_MT_TENANT_A_IDP_BASE_URL, PARITY_MT_TENANT_B_ID, and PARITY_MT_TENANT_B_IDP_BASE_URL")
	}
	return stand
}

// round10UploadInTenant replaces round10TenantDomain in tenant with pips and
// policies, records the status under subCase, empties the domain when the test
// ends, and reports whether the upload was accepted.
func (s *ParitySuite) round10UploadInTenant(subCase, tenant string, pips, policies []any) bool {
	s.T().Helper()
	ctx := context.Background()
	cfg := s.cfg
	cfg.TenantID = tenant
	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, cfg, s.tokens, round10TenantDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s in tenant %s: %v", round10TenantDomain, tenant, err)
		}
	})
	status, err := UploadIsolatedPolicies(ctx, cfg, s.tokens, round10TenantDomain, pips, policies)
	s.Require().NoError(err)
	s.Run(subCase, func() {
		s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, subCase, &model.PolicyLoadOutcome{Status: status})
	})
	return status >= http.StatusOK && status < http.StatusMultipleChoices
}

// round10TenantPolicy is a simplified READ policy on resourceType for role,
// under condition when it is not empty.
func round10TenantPolicy(id, resourceType, role, condition string) map[string]any {
	policy := map[string]any{
		"component": "PARITY", "reason": resourceType, "resourceType": resourceType, "operation": "READ",
		"roles": []string{role}, "applicableForFrontend": false, "id": id,
	}
	if condition != "" {
		policy["condition"] = condition
	}
	return policy
}

// round10MappingPIP is a MAPPING PIP granting ROLE_PARITY_READER permission.
func round10MappingPIP(suffix, permission string) map[string]any {
	return map[string]any{
		"name": "subject.permissions.PARITY_R10_MAPISO_" + suffix, "type": "UUID", "pipType": "MAPPING", "cacheable": false,
		"customMapping": map[string]any{"subject.roles": map[string]any{"ROLE_PARITY_READER": []string{permission}}},
	}
}

// Whether the MAPPING PIP of tenant B grants its permission in tenant B at all.
// mapping-export records that the reader of tenant A holds tenant A's permission
// and not tenant B's, which does not tell a mapping kept to its tenant from a
// mapping of tenant B that grants nothing anywhere.
//
// Each tenant declares a MAPPING PIP granting ROLE_PARITY_READER a permission of
// its own, and holds one READ policy on PARITY_R10_MAPISO asking for that
// permission. The reader asks with tenant_id naming tenant B, the question, and
// naming tenant A, the half mapping-export records; each
// tenant also holds a PROBE policy asking for the other tenant's permission,
// which has to be false.
//
// The case lives in its own test function so that a recording run can be
// filtered to it. It needs a two-tenant stand and the legacy PAP.
func (s *ParitySuite) TestRound10MappingTenantIsolationCases() {
	stand := s.round10TenantStand()
	const rt = "PARITY_R10_MAPISO"
	probe := func(id, permission string) map[string]any {
		p := round10TenantPolicy(id, rt, "ROLE_PARITY_READER", "subject.permissions CONTAINS '"+permission+"'")
		p["operation"] = "PROBE"
		return p
	}
	if !s.round10UploadInTenant("mapping-tenant-isolation/declare-in-tenant-a", stand.A.ID,
		[]any{round10MappingPIP("A", "parity_r10_mapiso_a")},
		[]any{
			round10TenantPolicy("00000000-0000-0000-0000-0000000f1052", rt, "ROLE_PARITY_READER", "subject.permissions CONTAINS 'parity_r10_mapiso_a'"),
			probe("00000000-0000-0000-0000-0000000f1053", "parity_r10_mapiso_b"),
		}) {
		return
	}
	if !s.round10UploadInTenant("mapping-tenant-isolation/declare-in-tenant-b", stand.B.ID,
		[]any{round10MappingPIP("B", "parity_r10_mapiso_b")},
		[]any{
			round10TenantPolicy("00000000-0000-0000-0000-0000000f1054", rt, "ROLE_PARITY_READER", "subject.permissions CONTAINS 'parity_r10_mapiso_b'"),
			probe("00000000-0000-0000-0000-0000000f1055", "parity_r10_mapiso_a"),
		}) {
		return
	}
	for _, req := range []struct {
		name, operation, tenant string
	}{
		{"tenant-b-own-permission-read", "READ", stand.B.ID},
		{"tenant-a-own-permission-read", "READ", stand.A.ID},
		{"tenant-b-other-permission-probe", "PROBE", stand.B.ID},
		{"tenant-a-other-permission-probe", "PROBE", stand.A.ID},
	} {
		s.Run(req.name, func() {
			s.runPendingCheckResourceV1OutcomeCase(
				"mapping-tenant-isolation/"+req.name,
				model.CheckAccessRequest{Operation: req.operation, Type: rt, Resource: map[string]any{"id": "r10-mapiso"}},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{TenantID: &req.tenant},
			)
		})
	}
}

// Whether a decision takes its tenant from the end-user token when the request
// names none, and whether a user of tenant A reads a policy that exists in tenant
// B alone by naming tenant B. t3 and t4 name the default tenant for a user of
// tenant B, and t10d sends a claimless M2M token with no tenant; no case sends a
// user's token with no tenant against a policy the default tenant does not hold.
//
// Tenant B holds PARITY_R10_MT_ONLY_B for ROLE_MT_READER, which tenant A does not
// hold; the PARITY_MT packs of TestTenantScopedDecisions are seeded in both
// tenants for PARITY_MT_REGION. user-b-names-no-tenant sends user B's token with
// neither tenant_id nor Tenant: true says the tenant came from the token.
// user-b-names-tenant-b is its control. user-a-names-tenant-b-region-b sends user
// A's token with tenant_id naming tenant B against PARITY_MT_REGION with region B,
// which only tenant B allows; user-b-names-tenant-b-region-b, the request t7d
// records, is its control, and differs in the user alone.
//
// The case lives in its own test function so that a recording run can be
// filtered to it. It needs a two-tenant stand and the legacy PAP.
func (s *ParitySuite) TestRound10TenantFromTokenCases() {
	stand := s.round10TenantStand()
	ctx := context.Background()
	s.seedTenant(ctx, stand.A, tenantAFixtureFS)
	s.seedTenant(ctx, stand.B, tenantBFixtureFS)
	if !s.round10UploadInTenant("tenant-from-token/declare-in-tenant-b", stand.B.ID, nil, []any{
		round10TenantPolicy("00000000-0000-0000-0000-0000000f1056", "PARITY_R10_MT_ONLY_B", "ROLE_MT_READER", ""),
	}) {
		return
	}
	userA := s.tenantUserTokens(stand.A, stand.A.User)
	userB := s.tenantUserTokens(stand.B, stand.B.User)
	for _, req := range []struct {
		name         string
		tokens       TokenBundle
		opts         PerCallOptions
		resourceType string
		resource     map[string]any
	}{
		{"user-b-names-no-tenant", userB, PerCallOptions{OmitTenantID: true}, "PARITY_R10_MT_ONLY_B", map[string]any{"id": "r10-only-b"}},
		{"user-b-names-tenant-b", userB, PerCallOptions{TenantID: &stand.B.ID}, "PARITY_R10_MT_ONLY_B", map[string]any{"id": "r10-only-b"}},
		{"user-a-names-tenant-b-region-b", userA, PerCallOptions{TenantID: &stand.B.ID}, "PARITY_MT_REGION", map[string]any{"id": "r10-region", "region": "B"}},
		{"user-b-names-tenant-b-region-b", userB, PerCallOptions{TenantID: &stand.B.ID}, "PARITY_MT_REGION", map[string]any{"id": "r10-region", "region": "B"}},
	} {
		s.Run(req.name, func() {
			s.runPendingCheckResourceV1OutcomeCase(
				"tenant-from-token/"+req.name,
				model.CheckAccessRequest{Operation: "READ", Type: req.resourceType, Resource: req.resource},
				req.tokens,
				req.opts,
			)
		})
	}
}
