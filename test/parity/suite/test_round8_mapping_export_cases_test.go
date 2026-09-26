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

const mappingExportCaseID = "mapping-export"

// mappingExportPermission prefixes the permission each tenant's MAPPING PIP
// grants ROLE_PARITY_READER: parity_mapexport_a in tenant A, parity_mapexport_b
// in tenant B. It is one of mappingExportMarkers: a folded subject.permissions
// element keeps the permissions in its customMapping and loses the domain from
// its name, so the permission is what its text still carries.
const mappingExportPermission = "parity_mapexport"

// mappingExportMarkers narrow the export to the elements of this case: the
// permission prefix, which a folded element carries, and the domain suffix of the
// declared names, which an element exported under its declared name would carry
// instead. narrowConfigExport matches case-sensitively, so both spellings are
// listed.
var mappingExportMarkers = []string{mappingExportPermission, "PARITY_MAPEXPORT"}

// mappingExportPIP declares the MAPPING PIP of the tenant with suffix a or b.
func mappingExportPIP(suffix string) map[string]any {
	return map[string]any{
		"name":      "subject.permissions.PARITY_MAPEXPORT_" + suffix,
		"type":      "UUID",
		"pipType":   "MAPPING",
		"cacheable": false,
		"customMapping": map[string]any{
			"subject.roles": map[string]any{
				"ROLE_PARITY_READER": []string{mappingExportPermission + "_" + suffix},
			},
		},
	}
}

// mappingExportSimplifiedPolicies are the two policies of tenant A: READ, whose
// condition asks for the permission tenant A's own MAPPING PIP grants, and PROBE,
// whose condition asks for the permission only tenant B's grants.
func mappingExportSimplifiedPolicies() []any {
	b := regularBuilder{caseID: mappingExportCaseID}
	policy := func(key, operation, permission string) map[string]any {
		return map[string]any{
			"component":             "PARITY",
			"reason":                mappingExportCaseID + " " + key,
			"resourceType":          regularResourceType(mappingExportCaseID),
			"operation":             operation,
			"roles":                 []string{"ROLE_PARITY_READER"},
			"applicableForFrontend": false,
			"condition":             "subject.permissions CONTAINS '" + permission + "'",
			"id":                    b.id("simplified/" + key),
		}
	}
	return []any{
		policy("own", "READ", mappingExportPermission+"_a"),
		policy("other-tenant", "PROBE", mappingExportPermission+"_b"),
	}
}

// What the v3 export and the decision do with the MAPPING PIPs of two tenants.
// The export folds every MAPPING PIP of a stand into one element named
// subject.permissions, with no domain and with the customMapping of all of them
// merged, and config-export never showed it because the element carries none of
// that case's markers. A pull-based reader takes its permission mapping from that
// element, so whether the stand folds per tenant, into one element per tenantId,
// or across tenants, into one element holding both tenants' grants, decides
// whether the element is enough to keep the tenants' permissions apart. The
// decisions ask the same of the evaluator: the reader of tenant A holds the
// permission tenant A's PIP grants and, if the stand merged across tenants, the
// one tenant B's grants too.
//
// The read that names tenant B is skipped on a stand with one tenant; the tenant
// A reads still record the folded element's shape, and the PROBE is recorded
// under a name of its own there, where nothing grants tenant B's permission and
// false is the control of the READ. The case lives in its own test function so
// that a recording run can be filtered to it. Legacy profile only: the export is
// access-control's.
func (s *ParitySuite) TestRound8MappingExportCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("the v3 export is access-control's; on the authz-agent profile authz-policy-admin serves it")
	}
	ctx := context.Background()
	m2m := s.mustM2MToken()
	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s: %v", isolatedCaseDomain, err)
		}
	})
	status, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, []any{mappingExportPIP("a")}, mappingExportSimplifiedPolicies())
	s.Require().NoError(err)
	s.Run("declare-the-domain", func() {
		s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, mappingExportCaseID+"/declare-the-domain", &model.PolicyLoadOutcome{Status: status})
	})
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return
	}
	stand := s.cfg.Tenants
	tenantA := s.cfg.TenantID
	if stand.Configured() {
		cfgB := s.cfg
		cfgB.TenantID = stand.B.ID
		s.T().Cleanup(func() {
			if _, err := UploadIsolatedPolicies(ctx, cfgB, s.tokens, isolatedCaseDomain, nil, nil); err != nil {
				s.T().Logf("empty domain %s in tenant %s: %v", isolatedCaseDomain, stand.B.ID, err)
			}
		})
		status, err := UploadIsolatedPolicies(ctx, cfgB, s.tokens, isolatedCaseDomain, []any{mappingExportPIP("b")}, nil)
		s.Require().NoError(err)
		s.Run("declare-the-domain-in-tenant-b", func() {
			s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, mappingExportCaseID+"/declare-the-domain-in-tenant-b", &model.PolicyLoadOutcome{Status: status})
		})
		tenantA = stand.A.ID
	}
	reads := []struct {
		name         string
		opts         PerCallOptions
		needsTenantB bool
	}{
		{name: "tenant-a-by-param", opts: PerCallOptions{TenantID: &tenantA}},
		{name: "no-tenant", opts: PerCallOptions{OmitTenantID: true}},
		{name: "tenant-b-by-param", opts: PerCallOptions{TenantID: &stand.B.ID}, needsTenantB: true},
	}
	for _, read := range reads {
		s.Run(read.name, func() {
			if read.needsTenantB && !stand.Configured() {
				s.T().Skip("no two-tenant stand: set PARITY_MT_TENANT_A_ID, PARITY_MT_TENANT_A_IDP_BASE_URL, PARITY_MT_TENANT_B_ID, and PARITY_MT_TENANT_B_IDP_BASE_URL")
			}
			status, body, err := HelperGetConfigExport(ctx, s.cfg, PSUITE_CONFIG_PIPS_V3, m2m, read.opts)
			s.Require().NoError(err)
			s.requirePendingGolden(PSUITE_CONFIG_PIPS_V3, mappingExportCaseID+"/"+read.name, narrowConfigExport(status, body, mappingExportMarkers))
		})
	}
	otherTenantProbe := "other-tenant-permission-probe"
	if !stand.Configured() {
		otherTenantProbe += "-on-one-tenant"
	}
	for _, decision := range []struct {
		name, operation string
	}{
		{name: "own-permission-read", operation: "READ"},
		{name: otherTenantProbe, operation: "PROBE"},
	} {
		s.Run(decision.name, func() {
			s.runPendingCheckResourceV1OutcomeCase(
				mappingExportCaseID+"/"+decision.name,
				model.CheckAccessRequest{Operation: decision.operation, Type: regularResourceType(mappingExportCaseID), Resource: map[string]any{"id": "reg-mapping-export"}},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{TenantID: &tenantA},
			)
		})
	}
}
