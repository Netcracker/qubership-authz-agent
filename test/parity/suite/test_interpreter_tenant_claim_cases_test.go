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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"authz-agent/test/parity/suite/model"
)

// tenantClaimResourceType is the resource type of the one policy the tenant-claim
// cases read; the policy allows READ to ROLE_M2M and to ROLE_PARITY_READER
// without a condition, so a false decision is the tenant's, not the rule's.
const tenantClaimResourceType = "PARITY_SUITE_CLAIM_TC"

// tenantClaimName is the claim the cases put in the token.
const tenantClaimName = "tenant-id"

// tenantClaimPolicy is uploaded into PARITY_ISOLATED of tenant A and of no other
// tenant, so that a decision scoped to tenant A is true and one scoped to any
// other tenant is false.
var tenantClaimPolicy = map[string]any{
	"component":             "PARITY",
	"reason":                "tenant-claim",
	"resourceType":          tenantClaimResourceType,
	"operation":             "READ",
	"roles":                 []string{"ROLE_M2M", "ROLE_PARITY_READER"},
	"applicableForFrontend": false,
	"id":                    "00000000-0000-0000-0000-0000000f00c1",
}

// What a tenant-id claim in a token does to a decision. The recorded tenant cases
// (t3, t4, t10a-t10d) carry tokens with no such claim, and their runner,
// runPendingCheckResourceV1Case, requires a 200 before it records: nothing
// records a request access-control refuses over the tenant. Each case here
// sends a claim-bearing token against a tenant and records the status with the
// decision, so a refusal (403) is told from a decision the claim did not enter
// (200) and, because the policy is in tenant A alone, a decision scoped to
// tenant A (true) is told from one scoped to tenant B (false).
//
// tc1-own-tenant-by-param, whose claim and query name the same tenant, is the
// control that the claim-bearing client is accepted at all. tc2 and tc3 name
// tenant B by the query parameter and by the Tenant header under a claim for
// tenant A: 403 refuses the mismatch, false scopes to the named tenant and
// ignores the claim, true scopes to the claim's tenant. tc4 names no tenant
// under a claim for tenant A, where the claim's tenant and the default tenant
// are the same on every stand the suite knows, so its answer is the status
// alone; tc4b names no tenant under a claim for tenant B, where true means the
// default tenant was used and false means the claim selected tenant B. tc5
// carries a claim for a tenant no stand has, and tc6 an empty claim, both
// against tenant A: tc6 is read against tc5, since an empty claim that is
// treated as absent is 200 where tc5 is 403. tc7 carries the claim for tenant A
// in the end-user token with a claimless M2M token beside it, against tenant B,
// which says whether the claim is read from the end-user slot at all. tc8
// repeats t10b as the claimless control: false, since the policy is not in
// tenant B. The cases that name tenant B skip on a stand with one tenant and on
// the authz-agent profile, whose PAP keys a domain without the tenant.
//
// The tokens come from the clients of TenantClaimClients, which the realm import
// under test/k8s/parity/idp-seed declares. Each token is decoded and its claim
// compared with the value the case assumes before any request is sent, so a
// mapper the realm dropped or a stand whose clients carry other values fails
// here rather than recording the claimless answer.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestInterpreterTenantClaimCases() {
	ctx := context.Background()
	stand := s.cfg.Tenants
	twoTenants := stand.Configured() && !isAuthzAgentProfile(s.cfg.Profile)
	tenantA := s.cfg.TenantID
	if twoTenants {
		tenantA = stand.A.ID
	}

	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s: %v", isolatedCaseDomain, err)
		}
	})
	status, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, []any{tenantClaimPolicy})
	s.Require().NoError(err, "upload of the tenant-claim policy into %s", isolatedCaseDomain)
	s.Require().GreaterOrEqual(status, http.StatusOK, "upload of the tenant-claim policy into %s", isolatedCaseDomain)
	s.Require().Less(status, http.StatusMultipleChoices, "upload of the tenant-claim policy into %s", isolatedCaseDomain)

	// claimed mints a token and checks that it carries the claim with the given
	// value, or no claim when present is false.
	claimed := func(client ClientCredentials, present bool, value string) string {
		token, err := s.tokens.M2MTokenFor(client)
		s.Require().NoError(err, "M2M token from client %s", client.ID)
		s.requireTenantClaim(token, client.ID, present, value)
		return token
	}
	claimA := TokenBundle{M2M: claimed(s.cfg.TenantClaim.M2MTenantA, true, tenantA)}
	claimUnknown := TokenBundle{M2M: claimed(s.cfg.TenantClaim.M2MTenantUnknown, true, unknownTenantID)}
	// A mapper with an empty value may add no claim at all; that is a property
	// of the identity provider, not of access-control, so tc6 skips rather than
	// records a claimless answer under its name.
	emptyToken, err := s.tokens.M2MTokenFor(s.cfg.TenantClaim.M2MTenantEmpty)
	s.Require().NoError(err, "M2M token from client %s", s.cfg.TenantClaim.M2MTenantEmpty.ID)
	emptyClaimSkip := ""
	if got, has := s.decodeJWTClaims(emptyToken, s.cfg.TenantClaim.M2MTenantEmpty.ID)[tenantClaimName]; !has {
		emptyClaimSkip = "the token of " + s.cfg.TenantClaim.M2MTenantEmpty.ID + " carries no " + tenantClaimName + " claim: the identity provider drops an empty hardcoded claim"
	} else {
		s.Require().Equal("", got, "%s claim in the token of %s", tenantClaimName, s.cfg.TenantClaim.M2MTenantEmpty.ID)
	}
	claimEmpty := TokenBundle{M2M: emptyToken}
	noClaim := TokenBundle{M2M: s.mustM2MToken()}
	s.requireTenantClaim(noClaim.M2M, s.cfg.M2MClientID, false, "")
	endUserToken, err := s.tokens.EndUserTokenVia(s.cfg.TenantClaim.EndUserTenantA, UserProfileReader.Username())
	s.Require().NoError(err, "end-user token from client %s", s.cfg.TenantClaim.EndUserTenantA.ID)
	s.requireTenantClaim(endUserToken, s.cfg.TenantClaim.EndUserTenantA.ID, true, tenantA)
	endUserClaimA := TokenBundle{M2M: noClaim.M2M, EndUser: endUserToken}
	var claimB TokenBundle
	if twoTenants {
		claimB = TokenBundle{M2M: claimed(s.cfg.TenantClaim.M2MTenantB, true, stand.B.ID)}
	}

	cases := []struct {
		name   string
		tokens TokenBundle
		opts   PerCallOptions
		// needsTenantB marks a case that names tenant B, in the request or in
		// the claim, and is skipped on a stand with one tenant and on the
		// authz-agent profile.
		needsTenantB bool
		// skip, when set, is the reason the case cannot be sent on this stand.
		skip string
	}{
		{name: "tc1-own-tenant-by-param", tokens: claimA, opts: PerCallOptions{TenantID: &tenantA}},
		{name: "tc2-other-tenant-by-param", tokens: claimA, opts: PerCallOptions{TenantID: &stand.B.ID}, needsTenantB: true},
		{name: "tc3-other-tenant-by-header", tokens: claimA, opts: PerCallOptions{OmitTenantID: true, TenantHeader: stand.B.ID}, needsTenantB: true},
		{name: "tc4-no-tenant-named", tokens: claimA, opts: PerCallOptions{OmitTenantID: true}},
		{name: "tc4b-no-tenant-named-under-a-claim-for-b", tokens: claimB, opts: PerCallOptions{OmitTenantID: true}, needsTenantB: true},
		{name: "tc5-unknown-tenant-in-claim", tokens: claimUnknown, opts: PerCallOptions{TenantID: &tenantA}},
		{name: "tc6-empty-claim", tokens: claimEmpty, opts: PerCallOptions{TenantID: &tenantA}, skip: emptyClaimSkip},
		{name: "tc7-claim-in-the-end-user-token", tokens: endUserClaimA, opts: PerCallOptions{TenantID: &stand.B.ID}, needsTenantB: true},
		{name: "tc8-no-claim", tokens: noClaim, opts: PerCallOptions{TenantID: &stand.B.ID}, needsTenantB: true},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			if tc.needsTenantB && !twoTenants {
				s.T().Skip("tenant B needs the legacy PAP and a two-tenant stand: set PARITY_MT_TENANT_A_ID, PARITY_MT_TENANT_A_IDP_BASE_URL, PARITY_MT_TENANT_B_ID, and PARITY_MT_TENANT_B_IDP_BASE_URL")
			}
			if tc.skip != "" {
				s.T().Skip(tc.skip)
			}
			s.runPendingCheckResourceV1OutcomeCase(
				"tenant-claim/"+tc.name,
				model.CheckAccessRequest{Operation: "READ", Type: tenantClaimResourceType, Resource: map[string]any{"id": "tc"}},
				tc.tokens,
				tc.opts,
			)
		})
	}
}

// requireTenantClaim fails the test when the access token's tenant-id claim is
// not what the case assumes: present with the given value, or absent when
// present is false. The token is decoded, not verified; the claim's presence is
// what the realm's mapper decides, and the case has no other way to see it.
func (s *ParitySuite) requireTenantClaim(token, clientID string, present bool, value string) {
	s.T().Helper()
	claims := s.decodeJWTClaims(token, clientID)
	got, has := claims[tenantClaimName]
	if !present {
		s.Require().False(has, "token of %s carries %s = %v, want no such claim", clientID, tenantClaimName, got)
		return
	}
	s.Require().True(has, "token of %s carries no %s claim; the realm's mapper is missing", clientID, tenantClaimName)
	s.Require().Equal(value, got, "%s claim in the token of %s", tenantClaimName, clientID)
}

// decodeJWTClaims returns the payload of a JWS compact token as a map, without
// checking the signature.
func (s *ParitySuite) decodeJWTClaims(token, clientID string) map[string]any {
	s.T().Helper()
	parts := strings.Split(token, ".")
	s.Require().Len(parts, 3, "token of %s is not a JWS compact serialization", clientID)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	s.Require().NoError(err, "payload of the token of %s", clientID)
	var claims map[string]any
	s.Require().NoError(json.Unmarshal(payload, &claims), "claims of the token of %s", clientID)
	return claims
}
