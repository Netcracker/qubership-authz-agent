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
	"slices"

	"authz-agent/test/parity/suite/model"
)

// callerUserTokenResourceType is the resource type of the one policy the
// caller-user-token cases read; the policy allows READ to ROLE_PARITY_READER
// without a condition, so a false decision is the tenant's, not the rule's.
const callerUserTokenResourceType = "PARITY_SUITE_CALLER_UT"

// callerUserTokenPolicy is uploaded into PARITY_ISOLATED of tenant A and of no
// other tenant, so that a decision scoped to tenant A is true and one scoped to
// any other tenant is false.
var callerUserTokenPolicy = map[string]any{
	"component":             "PARITY",
	"reason":                "caller-user-token",
	"resourceType":          callerUserTokenResourceType,
	"operation":             "READ",
	"roles":                 []string{"ROLE_PARITY_READER"},
	"applicableForFrontend": false,
	"id":                    "00000000-0000-0000-0000-0000000f00c2",
}

// What access-control does with a user's token sent in Authorization, with no
// Incoming-Token, on a check route. The existing cases put a service account's
// token in Authorization, and such a token skips the check the route makes on
// its caller, so none of them reaches that check. Read from the code, the check
// admits a token whose tenant-id claim equals the tenant of the request, or a
// token with no claim that goes to the default tenant, and refuses anything else
// with 403. The cases record the status with the decision: 403 is the refusal,
// 200 with true is a decision in tenant A, where the policy is, and 200 with
// false a decision in another tenant. With no Incoming-Token the subject is the
// token in Authorization, as tenant-claim/tc1 shows for a service account, so
// the reader's role is what the policy grants.
//
// The token is always parity-reader's, minted by password grant through a client
// whose hardcoded mapper sets the claim: parity-end-user sets none,
// parity-end-user-tenant-a sets tenant A, and the parity-m2m-tenant-* clients set
// tenant B, a tenant no stand has, or an empty value. Tenant A is the default
// tenant on every stand the suite knows, so the cases that name tenant A or no
// tenant cannot tell the matching claim from the default tenant; the claim for
// tenant B against tenant B tells them apart. tenant-claim/tc7 sends the same
// claim-A token in Incoming-Token against tenant B and is the control for
// claim-a-names-tenant-b. The cases that name tenant B, in the request or in the
// claim, skip on a stand with one tenant and on the authz-agent profile.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestCallerUserTokenCases() {
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
	status, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, []any{callerUserTokenPolicy})
	s.Require().NoError(err, "upload of the caller-user-token policy into %s", isolatedCaseDomain)
	s.Require().GreaterOrEqual(status, http.StatusOK, "upload of the caller-user-token policy into %s", isolatedCaseDomain)
	s.Require().Less(status, http.StatusMultipleChoices, "upload of the caller-user-token policy into %s", isolatedCaseDomain)

	reader := UserProfileReader.Username()
	// userVia mints parity-reader's token through client and checks that it is a
	// user's token carrying the claim with the given value, or no claim when
	// present is false.
	userVia := func(client ClientCredentials, present bool, value string) TokenBundle {
		token, err := s.tokens.EndUserTokenVia(client, reader)
		s.Require().NoError(err, "token of %s from client %s", reader, client.ID)
		s.requireUserToken(token, client.ID, reader)
		s.requireTenantClaim(token, client.ID, present, value)
		return TokenBundle{M2M: token}
	}
	noClaimToken, err := s.tokens.EndUserTokenFor(reader)
	s.Require().NoError(err, "token of %s", reader)
	s.requireUserToken(noClaimToken, s.cfg.EndUserClientID, reader)
	s.requireTenantClaim(noClaimToken, s.cfg.EndUserClientID, false, "")
	noClaim := TokenBundle{M2M: noClaimToken}
	claimA := userVia(s.cfg.TenantClaim.EndUserTenantA, true, tenantA)
	claimUnknown := userVia(s.cfg.TenantClaim.M2MTenantUnknown, true, unknownTenantID)
	// A mapper with an empty value may add no claim at all; that is a property
	// of the identity provider, so the empty-claim case skips rather than
	// records a claimless answer under its name.
	emptyToken, err := s.tokens.EndUserTokenVia(s.cfg.TenantClaim.M2MTenantEmpty, reader)
	s.Require().NoError(err, "token of %s from client %s", reader, s.cfg.TenantClaim.M2MTenantEmpty.ID)
	s.requireUserToken(emptyToken, s.cfg.TenantClaim.M2MTenantEmpty.ID, reader)
	emptyClaimSkip := ""
	if got, has := s.decodeJWTClaims(emptyToken, s.cfg.TenantClaim.M2MTenantEmpty.ID)[tenantClaimName]; !has {
		emptyClaimSkip = "the token of " + s.cfg.TenantClaim.M2MTenantEmpty.ID + " carries no " + tenantClaimName + " claim: the identity provider drops an empty hardcoded claim"
	} else {
		s.Require().Equal("", got, "%s claim in the token of %s", tenantClaimName, s.cfg.TenantClaim.M2MTenantEmpty.ID)
	}
	claimEmpty := TokenBundle{M2M: emptyToken}
	var claimB TokenBundle
	if twoTenants {
		claimB = userVia(s.cfg.TenantClaim.M2MTenantB, true, stand.B.ID)
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
		{name: "claim-a-names-tenant-a", tokens: claimA, opts: PerCallOptions{TenantID: &tenantA}},
		{name: "claim-a-names-no-tenant", tokens: claimA, opts: PerCallOptions{OmitTenantID: true}},
		{name: "no-claim-names-no-tenant", tokens: noClaim, opts: PerCallOptions{OmitTenantID: true}},
		{name: "no-claim-names-tenant-a", tokens: noClaim, opts: PerCallOptions{TenantID: &tenantA}},
		{name: "unknown-claim-names-tenant-a", tokens: claimUnknown, opts: PerCallOptions{TenantID: &tenantA}},
		{name: "empty-claim-names-tenant-a", tokens: claimEmpty, opts: PerCallOptions{TenantID: &tenantA}, skip: emptyClaimSkip},
		{name: "claim-a-names-tenant-b", tokens: claimA, opts: PerCallOptions{TenantID: &stand.B.ID}, needsTenantB: true},
		{name: "claim-a-names-tenant-b-by-header", tokens: claimA, opts: PerCallOptions{OmitTenantID: true, TenantHeader: stand.B.ID}, needsTenantB: true},
		{name: "no-claim-names-tenant-b", tokens: noClaim, opts: PerCallOptions{TenantID: &stand.B.ID}, needsTenantB: true},
		{name: "claim-b-names-tenant-b", tokens: claimB, opts: PerCallOptions{TenantID: &stand.B.ID}, needsTenantB: true},
		{name: "claim-b-names-no-tenant", tokens: claimB, opts: PerCallOptions{OmitTenantID: true}, needsTenantB: true},
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
				"caller-user-token/"+tc.name,
				model.CheckAccessRequest{Operation: "READ", Type: callerUserTokenResourceType, Resource: map[string]any{"id": "cut"}},
				tc.tokens,
				tc.opts,
			)
		})
	}
}

// requireUserToken fails the test when the access token is not username's own
// token: its preferred_username has to be username, and it may carry neither
// the role ROLE_M2M nor a level claim. A level of m2m makes subject.isM2M true,
// and the service accounts that skip the caller check carry ROLE_M2M, so either
// may make access-control skip the check these cases ask about.
func (s *ParitySuite) requireUserToken(token, clientID, username string) {
	s.T().Helper()
	claims := s.decodeJWTClaims(token, clientID)
	s.Require().Equal(username, claims["preferred_username"], "preferred_username in the token of %s", clientID)
	level, hasLevel := claims["level"]
	s.Require().False(hasLevel, "token of %s carries level = %v, want no such claim", clientID, level)
	var roles []string
	if access, ok := claims["realm_access"].(map[string]any); ok {
		if list, ok := access["roles"].([]any); ok {
			for _, r := range list {
				if name, ok := r.(string); ok {
					roles = append(roles, name)
				}
			}
		}
	}
	s.Require().False(slices.Contains(roles, "ROLE_M2M"), "realm roles in the token of %s: %v, want no ROLE_M2M", clientID, roles)
}
