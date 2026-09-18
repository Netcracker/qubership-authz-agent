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
	"io/fs"
	"net/http"

	"authz-agent/test/parity/suite/model"
)

// tenantCaseDomain is uploaded once per tenant, so a PAP that keyed domains
// without the tenant would let tenant B's upload replace tenant A's, and the
// tenant A allow cases would deny.
const tenantCaseDomain = "PARITY_MT"

// unknownTenantID is a tenant identifier no stand creates.
const unknownTenantID = "7f3c2e1a-0b9d-4c6e-8a5f-2d1b3c4e5f60"

// Which tenant a decision is scoped to, given the token, tenant_id, and the Tenant
// header. Tenant A holds PARITY_MT_ONLY_A, a region rule that allows region A, a
// PIP named subject.mtLimit that answers 10, an ALL/ALL policy for ROLE_MT_ADMIN,
// and a filter predicate tenant==a. Tenant B holds the same names answering B,
// 100, and tenant==b, no ONLY_A and no ALL/ALL, and a ROLE_M2M policy on
// PARITY_MT_M2M. The case identifier prefixes (t1, …) follow the golden-capture
// case list kept outside this repository.
//
// The cases need a stand with two tenant realms (see TenantStand) and the legacy
// PAP: authz-policy-admin keys a domain without the tenant, so on the authz-agent
// profile tenant B's upload would replace tenant A's.
func (s *ParitySuite) TestTenantScopedDecisions() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("tenant-scoped uploads need the legacy PAP; authz-policy-admin keys a domain without the tenant")
	}
	stand := s.cfg.Tenants
	if !stand.Configured() {
		s.T().Skip("no two-tenant stand: set PARITY_MT_TENANT_A_ID, PARITY_MT_TENANT_A_IDP_BASE_URL, PARITY_MT_TENANT_B_ID, and PARITY_MT_TENANT_B_IDP_BASE_URL")
	}
	ctx := context.Background()
	s.seedTenant(ctx, stand.A, tenantAFixtureFS)
	s.seedTenant(ctx, stand.B, tenantBFixtureFS)
	// The limits are strings on purpose. Legacy access-control funnels every
	// GENERAL-PIP value through SinglePipDataConverter, which casts the JSONPath
	// match to String unconditionally, so a JSON number raises a
	// ClassCastException, the rule fails with a DenyEffectException logged as
	// "Can not calculate rule with id ...", and every t8 case denies for a reason
	// that has nothing to do with tenants. As strings the comparison operators
	// still coerce, so 50 <= "10" is false and 50 <= "100" is true, and the
	// t8a/t8b split is the tenant difference these cases exist to record.
	s.Require().NoError(s.pipMock.PinRoute(ctx, "/api/v1/pip/mt-limit-a", PipStubResponse{StatusCode: http.StatusOK, Body: map[string]any{"value": "10"}}))
	s.Require().NoError(s.pipMock.PinRoute(ctx, "/api/v1/pip/mt-limit-b", PipStubResponse{StatusCode: http.StatusOK, Body: map[string]any{"value": "100"}}))

	userA := s.tenantUserTokens(stand.A, stand.A.User)
	userB := s.tenantUserTokens(stand.B, stand.B.User)
	adminA := s.tenantUserTokens(stand.A, stand.A.AdminUser)
	adminB := s.tenantUserTokens(stand.B, stand.B.AdminUser)
	m2mOnly := TokenBundle{M2M: s.mustM2MToken()}
	empty := ""

	cases := []struct {
		subCase      string
		tokens       TokenBundle
		opts         PerCallOptions
		resourceType string
		resource     map[string]any
	}{
		{"t1-own-tenant", userA, PerCallOptions{TenantID: &stand.A.ID}, "PARITY_MT_ONLY_A", map[string]any{"id": "t1"}},
		{"t2-other-tenant-policy", userB, PerCallOptions{TenantID: &stand.B.ID}, "PARITY_MT_ONLY_A", map[string]any{"id": "t2"}},
		{"t3-query-names-other-tenant", userB, PerCallOptions{TenantID: &stand.A.ID}, "PARITY_MT_ONLY_A", map[string]any{"id": "t3"}},
		{"t4-header-names-other-tenant", userB, PerCallOptions{OmitTenantID: true, TenantHeader: stand.A.ID}, "PARITY_MT_ONLY_A", map[string]any{"id": "t4"}},
		{"t5-empty-tenant-id", userA, PerCallOptions{TenantID: &empty}, "PARITY_MT_ONLY_A", map[string]any{"id": "t5"}},
		{"t6-unknown-tenant-id", userA, PerCallOptions{TenantID: stringPtr(unknownTenantID)}, "PARITY_MT_ONLY_A", map[string]any{"id": "t6"}},
		{"t7a-tenant-a-region-a", userA, PerCallOptions{TenantID: &stand.A.ID}, "PARITY_MT_REGION", map[string]any{"id": "t7a", "region": "A"}},
		{"t7b-tenant-a-region-b", userA, PerCallOptions{TenantID: &stand.A.ID}, "PARITY_MT_REGION", map[string]any{"id": "t7b", "region": "B"}},
		{"t7c-tenant-b-region-a", userB, PerCallOptions{TenantID: &stand.B.ID}, "PARITY_MT_REGION", map[string]any{"id": "t7c", "region": "A"}},
		{"t7d-tenant-b-region-b", userB, PerCallOptions{TenantID: &stand.B.ID}, "PARITY_MT_REGION", map[string]any{"id": "t7d", "region": "B"}},
		{"t8a-tenant-a-pip-limit", userA, PerCallOptions{TenantID: &stand.A.ID}, "PARITY_MT_PIP", map[string]any{"id": "t8a", "amount": 50}},
		{"t8b-tenant-b-pip-limit", userB, PerCallOptions{TenantID: &stand.B.ID}, "PARITY_MT_PIP", map[string]any{"id": "t8b", "amount": 50}},
		{"t9a-tenant-b-admin-no-wildcard", adminB, PerCallOptions{TenantID: &stand.B.ID}, "PARITY_MT_ANY", map[string]any{"id": "t9a"}},
		{"t9b-tenant-a-admin-wildcard", adminA, PerCallOptions{TenantID: &stand.A.ID}, "PARITY_MT_ANY", map[string]any{"id": "t9b"}},
		{"t10a-m2m-query-tenant-b", m2mOnly, PerCallOptions{TenantID: &stand.B.ID}, "PARITY_MT_M2M", map[string]any{"id": "t10a"}},
		{"t10b-m2m-query-tenant-a", m2mOnly, PerCallOptions{TenantID: &stand.A.ID}, "PARITY_MT_M2M", map[string]any{"id": "t10b"}},
		{"t10c-m2m-header-tenant-b", m2mOnly, PerCallOptions{OmitTenantID: true, TenantHeader: stand.B.ID}, "PARITY_MT_M2M", map[string]any{"id": "t10c"}},
		{"t10d-m2m-no-tenant", m2mOnly, PerCallOptions{OmitTenantID: true}, "PARITY_MT_M2M", map[string]any{"id": "t10d"}},
	}
	for _, tc := range cases {
		s.Run(tc.subCase, func() {
			s.runPendingCheckResourceV1Case(
				"tenant/"+tc.subCase,
				model.CheckAccessRequest{Operation: "READ", Type: tc.resourceType, Resource: tc.resource},
				tc.tokens,
				tc.opts,
			)
		})
	}

	filterCases := []struct {
		subCase string
		tokens  TokenBundle
		tenant  string
	}{
		{"t12a-tenant-a-filter", userA, stand.A.ID},
		{"t12b-tenant-b-filter", userB, stand.B.ID},
	}
	for _, tc := range filterCases {
		s.Run(tc.subCase, func() {
			s.runPendingFilterV1Case("tenant/"+tc.subCase, "PARITY_MT_FILTER", "LIST", tc.tokens, PerCallOptions{TenantID: &tc.tenant})
		})
	}
}

// seedTenant replaces tenantCaseDomain in one tenant with the given pack and
// empties it again when the test ends.
func (s *ParitySuite) seedTenant(ctx context.Context, realm TenantRealm, pack fs.FS) {
	s.T().Helper()
	cfg := s.cfg
	cfg.TenantID = realm.ID
	seeder := NewDomainSeeder(cfg, s.tokens)
	s.Require().NoError(seeder.WipeDomain(ctx, tenantCaseDomain), "empty %s in tenant %s", tenantCaseDomain, realm.ID)
	s.Require().NoError(seeder.SeedDomain(ctx, tenantCaseDomain, pack), "seed %s in tenant %s", tenantCaseDomain, realm.ID)
	s.T().Cleanup(func() {
		if err := seeder.WipeDomain(ctx, tenantCaseDomain); err != nil {
			s.T().Logf("empty %s in tenant %s: %v", tenantCaseDomain, realm.ID, err)
		}
	})
}

// tenantUserTokens mints an end-user token from the tenant's realm and pairs it
// with the suite's M2M token.
func (s *ParitySuite) tenantUserTokens(realm TenantRealm, username string) TokenBundle {
	s.T().Helper()
	cfg := s.cfg
	cfg.IDPBaseURL = realm.IDPBaseURL
	token, err := NewTokenFactory(cfg).EndUserTokenFor(username)
	s.Require().NoError(err, "token for %s in realm %s", username, realm.IDPBaseURL)
	return TokenBundle{M2M: s.mustM2MToken(), EndUser: token}
}
