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

// callerAudience is the audience the parity-m2m family of clients adds to
// every token it issues.
const callerAudience = "netcracker"

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
// The token is always parity-reader's, minted by password grant. The clients
// that mint it are configured alike in the realm import and differ in one
// mapper each: parity-m2m sets no tenant-id, the parity-m2m-tenant-* clients set
// tenant A, tenant B, a tenant no stand has, or an empty value, and
// parity-m2m-no-audience is parity-m2m without the netcracker audience. Each
// token also names its own client in azp; read from the code, the caller check
// reads the claim and whether the token is an M2M token, not azp, so the cases
// take azp as inert. Each case is read against one that differs from it in the
// claim, the audience, or the tenant named, and in nothing else:
//
//   - claim-a-names-tenant-b against claim-a-names-tenant-a: the claim compared
//     with the request's tenant, refused or not. tenant-claim/tc7 sends a claim
//     for tenant A in Incoming-Token against tenant B and answers 200 with false.
//   - claim-a-names-tenant-b-by-header against claim-a-names-tenant-b: the
//     tenant named by the Tenant header compared the same way as tenant_id.
//   - claim-b-names-tenant-b against claim-a-names-tenant-b: a claim that
//     matches a tenant other than the default one. Tenant A is the default
//     tenant on every stand the suite knows, so only this pair tells a matching
//     claim from the default tenant.
//   - claim-b-names-no-tenant against claim-b-names-tenant-b: a claim for
//     another tenant against the default tenant refused, or used to select its
//     own tenant.
//   - claim-a-names-no-tenant against claim-a-names-tenant-a, and
//     no-claim-names-no-tenant against no-claim-names-tenant-a: the default
//     tenant reached by naming no tenant, and by naming it.
//   - no-claim-names-tenant-b against no-claim-names-no-tenant: a token with no
//     claim refused outside the default tenant, or admitted.
//   - unknown-claim-names-tenant-a and empty-claim-names-tenant-a against
//     claim-a-names-tenant-a: a claim no stand knows, and whether an empty claim
//     counts as no claim.
//   - no-claim-no-audience-names-no-tenant against no-claim-names-no-tenant:
//     whether the route reads the audience of the token in Authorization. Every
//     other case carries the audience, so a refusal there is not the audience's.
//
// The cases that name tenant B, in the request or in the claim, skip on a stand
// with one tenant and on the authz-agent profile. The case without the audience
// skips on a stand whose realm lacks parity-m2m-no-audience.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestCallerUserTokenCases() {
	stand, twoTenants, tenantA := s.tenantClaimStand()
	s.uploadIsolatedCasePolicy("caller-user-token", callerUserTokenPolicy)

	reader := UserProfileReader.Username()
	// userVia mints parity-reader's token through client and checks that it is
	// a user's token with the audience, and with the claim of the given value,
	// or no claim when present is false.
	userVia := func(client ClientCredentials, present bool, value string) TokenBundle {
		token, err := s.tokens.EndUserTokenVia(client, reader)
		s.Require().NoError(err, "token of %s from client %s", reader, client.ID)
		s.requireUserToken(token, client.ID, reader, true)
		s.requireTenantClaim(token, client.ID, present, value)
		return TokenBundle{M2M: token}
	}
	// The suite's M2M client is parity-m2m unless PARITY_M2M_CLIENT_ID names
	// another one, which then has to be configured like parity-m2m-tenant-*
	// without the tenant-id mapper for the pairs above to differ in one claim.
	noClaim := userVia(ClientCredentials{ID: s.cfg.M2MClientID, Secret: s.cfg.M2MClientSecret}, false, "")
	claimA := userVia(s.cfg.TenantClaim.M2MTenantA, true, tenantA)
	claimUnknown := userVia(s.cfg.TenantClaim.M2MTenantUnknown, true, unknownTenantID)
	emptyToken, err := s.tokens.EndUserTokenVia(s.cfg.TenantClaim.M2MTenantEmpty, reader)
	s.Require().NoError(err, "token of %s from client %s", reader, s.cfg.TenantClaim.M2MTenantEmpty.ID)
	s.requireUserToken(emptyToken, s.cfg.TenantClaim.M2MTenantEmpty.ID, reader, true)
	emptyClaimSkip := s.emptyClaimSkip(emptyToken, s.cfg.TenantClaim.M2MTenantEmpty.ID)
	claimEmpty := TokenBundle{M2M: emptyToken}
	var claimB TokenBundle
	if twoTenants {
		claimB = userVia(s.cfg.TenantClaim.M2MTenantB, true, stand.B.ID)
	}
	// The realm of a stand set up before parity-m2m-no-audience was added has
	// no such client, and the password grant fails there; the case skips with
	// the error, which does not tell a missing client from a wrong secret.
	var noAudience TokenBundle
	noAudienceSkip := ""
	if token, err := s.tokens.EndUserTokenVia(s.cfg.NoAudience, reader); err != nil {
		noAudienceSkip = "no token of " + reader + " from client " + s.cfg.NoAudience.ID + ": " + err.Error()
	} else {
		s.requireUserToken(token, s.cfg.NoAudience.ID, reader, false)
		s.requireTenantClaim(token, s.cfg.NoAudience.ID, false, "")
		noAudience = TokenBundle{M2M: token}
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
		{name: "no-claim-no-audience-names-no-tenant", tokens: noAudience, opts: PerCallOptions{OmitTenantID: true}, skip: noAudienceSkip},
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
// token with the audience the case assumes. Its preferred_username has to be
// username, and it may carry neither the role ROLE_M2M nor a level claim: the
// service accounts whose tokens skip the caller check carry ROLE_M2M, and a
// level claim may mark a token as M2M too. Its aud has to include
// callerAudience when withAudience is true, and to omit it otherwise.
func (s *ParitySuite) requireUserToken(token, clientID, username string, withAudience bool) {
	s.T().Helper()
	claims := s.decodeJWTClaims(token, clientID)
	s.Require().Equal(username, claims["preferred_username"], "preferred_username in the token of %s", clientID)
	level, hasLevel := claims["level"]
	s.Require().False(hasLevel, "token of %s carries level = %v, want no such claim", clientID, level)
	var roles []string
	if access, ok := claims["realm_access"].(map[string]any); ok {
		roles = stringClaims(access["roles"])
	}
	s.Require().NotContains(roles, "ROLE_M2M", "realm roles in the token of %s", clientID)
	audiences := stringClaims(claims["aud"])
	if withAudience {
		s.Require().Contains(audiences, callerAudience, "aud in the token of %s", clientID)
	} else {
		s.Require().NotContains(audiences, callerAudience, "aud in the token of %s", clientID)
	}
}

// stringClaims returns the strings of a claim that is a string or a list of
// strings, as aud is in a JWT, and nil for any other value.
func stringClaims(v any) []string {
	switch v := v.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
