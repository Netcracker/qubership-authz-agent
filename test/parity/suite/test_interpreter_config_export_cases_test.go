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

// configExportCaseID names the case; the resource type of every uploaded set
// and policy derives from it, and so do the ids of the sets.
const configExportCaseID = "config-export"

// configExportPIPPrefix starts the name of every PIP the case declares, except
// the PERMISSION_SCOPE PIP, which keeps the name every declaration in the suite
// uses.
const configExportPIPPrefix = "subject.parityConfigExport"

// configExportMarkers are the strings by which an element of the export is
// recognized as one the case uploaded: the resource type in every set target and
// every simplified policy, the PIP name prefix, the MAPPING PIP name suffix, and
// the fixed PERMISSION_SCOPE name. An element that carries none of them was
// uploaded by another case or another test and is left out of the golden.
var configExportMarkers = []string{
	regularResourceType(configExportCaseID),
	configExportPIPPrefix,
	"PARITY_CONFIG_EXPORT",
	permissionScopeWirePIP["name"].(string),
}

// configExportEndpoints are the two export reads every request of the case makes.
var configExportEndpoints = []ParityEndpointID{PSUITE_CONFIG_POLICY_SETS_V3, PSUITE_CONFIG_PIPS_V3}

// What the v3 configuration export carries for the policy sets, the simplified
// policies, and the PIP declarations the suite uploads, and how the tenant of a
// read selects what is exported. The agent reads the export
// (GET /access/v3/config/policySets and /pips) rather than the uploads, and no
// golden records it: the shape of a regular set in the export is known from
// product policies and a fixture captured elsewhere, and a reader written to
// that shape is not checked against the PAP the goldens come from.
//
// The case uploads, into tenant A, regular sets with the forms an evaluator has
// to read, each under an externalID of its own so that a form the PAP refuses
// records its refusal and leaves the other forms exported: a set with no
// combining algorithm holding a DENY rule and a rule with every predicate field,
// customPredicate with a parameter among them; a nested set; an iterating set; an
// inactive set; and a policy with no rules. Of these, only the inactive set has a
// recorded acceptance (inactive-set). The domain gets two simplified policies and
// the PIP types with a recorded acceptance: GENERAL, HEADER, TOKEN, MAPPING
// (pm1-mapping-pip-merged-list) and PERMISSION_SCOPE (permission-scope-wire). A
// FILTERED PIP is added in a second upload of the domain, because
// h3-filtered-pip-plain-reference records a refusal of a declaration without a
// top-level resourceType; when the second upload is refused, the first is
// repeated so that the reads see a domain whose content is recorded. A refused
// first upload ends the case before any read, since the reads would then record
// what another case left in the domain. Into tenant B, where the stand has one,
// the case uploads a set and a GENERAL PIP under the same names with another
// address.
//
// Each read is recorded with the tenant named in the query, the other tenant,
// no tenant at all, a tenant no stand has, and tenant A in the query beside
// tenant B in the Tenant header. Together the reads record whether the export
// is per tenant or merged, which parameter selects the tenant, where the
// element carries its tenant, whether an absent algorithm is filled in,
// whether an inactive set and a DENY rule are exported, and how the simplified
// policies and the PIP fields come back.
//
// The body is recorded with the envelope fields that change on every write
// removed and every array narrowed to the elements the case uploaded, sorted by
// their JSON text, so that the golden holds the same elements whatever else the
// stand holds and whatever order the PAP lists them in. A value the PAP fills in
// that differs between two runs is not masked; it shows as a diff between two
// recordings.
//
// The case lives in its own test function so that a recording run can be
// filtered to it and leave every golden already committed alone. Legacy profile
// only: the agent profile serves the export from authz-policy-admin.
func (s *ParitySuite) TestInterpreterConfigExportCases() {
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
	domainStatus, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, configExportPIPs(), configExportSimplifiedPolicies())
	s.Require().NoError(err)
	s.Run("declare-the-domain", func() {
		s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, configExportCaseID+"/declare-the-domain", &model.PolicyLoadOutcome{Status: domainStatus})
	})
	if domainStatus < http.StatusOK || domainStatus >= http.StatusMultipleChoices {
		return
	}
	withFiltered := append(configExportPIPs(), configExportFilteredPIP())
	filteredStatus, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, withFiltered, configExportSimplifiedPolicies())
	s.Require().NoError(err)
	s.Run("declare-the-filtered-pip", func() {
		s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, configExportCaseID+"/declare-the-filtered-pip", &model.PolicyLoadOutcome{Status: filteredStatus})
	})
	if filteredStatus < http.StatusOK || filteredStatus >= http.StatusMultipleChoices {
		status, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, configExportPIPs(), configExportSimplifiedPolicies())
		s.Require().NoError(err)
		s.Require().Equal(domainStatus, status, "repeat the accepted upload of %s after the FILTERED PIP was refused", isolatedCaseDomain)
	}
	for _, upload := range configExportUploads() {
		status, _, err := HelperPutPolicySets(ctx, s.cfg, m2m, upload.externalID, upload.sets)
		s.Require().NoError(err)
		s.Run("upload-"+upload.externalID, func() {
			s.requirePendingGolden(PSUITE_LOAD_POLICY_SETS, configExportCaseID+"/upload-"+upload.externalID, &model.PolicyLoadOutcome{Status: status})
		})
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
		status, err := UploadIsolatedPolicies(ctx, cfgB, s.tokens, isolatedCaseDomain, configExportTenantBPIPs(), nil)
		s.Require().NoError(err)
		s.Run("declare-the-domain-in-tenant-b", func() {
			s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, configExportCaseID+"/declare-the-domain-in-tenant-b", &model.PolicyLoadOutcome{Status: status})
		})
		upload := configExportTenantBUpload()
		status, _, err = HelperPutPolicySets(ctx, cfgB, m2m, upload.externalID, upload.sets)
		s.Require().NoError(err)
		s.Run("upload-"+upload.externalID, func() {
			s.requirePendingGolden(PSUITE_LOAD_POLICY_SETS, configExportCaseID+"/upload-"+upload.externalID, &model.PolicyLoadOutcome{Status: status})
		})
		tenantA = stand.A.ID
	}

	reads := []struct {
		name string
		opts PerCallOptions
		// needsTenantB marks a read that names tenant B and is skipped on a stand
		// with one tenant.
		needsTenantB bool
	}{
		{name: "tenant-a-by-param", opts: PerCallOptions{TenantID: &tenantA}},
		{name: "tenant-b-by-param", opts: PerCallOptions{TenantID: &stand.B.ID}, needsTenantB: true},
		{name: "no-tenant", opts: PerCallOptions{OmitTenantID: true}},
		{name: "unknown-tenant", opts: PerCallOptions{TenantID: stringPtr(unknownTenantID)}},
		{name: "tenant-a-by-param-and-b-by-header", opts: PerCallOptions{TenantID: &tenantA, TenantHeader: stand.B.ID}, needsTenantB: true},
	}
	for _, read := range reads {
		s.Run(read.name, func() {
			if read.needsTenantB && !stand.Configured() {
				s.T().Skip("no two-tenant stand: set PARITY_MT_TENANT_A_ID, PARITY_MT_TENANT_A_IDP_BASE_URL, PARITY_MT_TENANT_B_ID, and PARITY_MT_TENANT_B_IDP_BASE_URL")
			}
			for _, id := range configExportEndpoints {
				s.Run(Meta(id).Name, func() {
					status, body, err := HelperGetConfigExport(ctx, s.cfg, id, m2m, read.opts)
					s.Require().NoError(err)
					s.requirePendingGolden(id, configExportCaseID+"/"+read.name, narrowConfigExport(status, body, configExportMarkers))
				})
			}
		})
	}
}

// configExportUploads are the regular sets of tenant A, one externalID per form,
// so that a refused form is recorded on its own and the others are exported.
func configExportUploads() []regularUpload {
	b := regularBuilder{caseID: configExportCaseID}
	rt := regularResourceType(configExportCaseID)
	rtTarget := "resourceType == '" + rt + "'"

	everyPredicate := b.rule("list-with-every-predicate", "operation == 'LIST'", "true", "ALLOW", map[string]string{
		"rsqlPredicate":    "a==${subject.id}",
		"sqlPredicate":     "a=${subject.id}",
		"mongodbPredicate": `{ "a": "${subject.id}" }`,
		"predicate":        `${resourceType}.a.eq("${subject.id}")`,
	})
	everyPredicate["customPredicate"] = map[string]any{
		"predicate": `[{"value":${owner},"property":"a","operator":"in"}]`,
		"params":    map[string]any{"owner": "subject.id"},
	}

	inactive := b.set("inactive", rtTarget, "DENY_UNLESS_PERMIT", []any{
		b.policy("inactive-reader", readerTarget, "DENY_UNLESS_PERMIT",
			b.rule("inactive-read-allow", "operation == 'READ'", "true", "ALLOW", nil)),
	}, nil)
	inactive["status"] = "INACTIVE"

	forms := []struct {
		key string
		set map[string]any
	}{
		{"plain", b.set("plain", rtTarget, "", []any{
			b.policy("reader", readerTarget, "",
				b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil),
				b.rule("read-deny-when-n", "operation == 'READ'", "resource.a == 'n'", "DENY", nil),
				everyPredicate),
		}, nil)},
		{"nested", b.set("nested-outer", rtTarget, "PERMIT_UNLESS_DENY", []any{}, []any{
			b.set("nested-inner", rtTarget, "DENY_UNLESS_PERMIT", []any{
				b.policy("inner-reader", readerTarget, "DENY_UNLESS_PERMIT",
					b.rule("inner-read-allow", "operation == 'READ'", "true", "ALLOW", nil)),
			}, nil),
		})},
		{"iterating", b.iteratingSet("iterating", rtTarget, "DENY_UNLESS_PERMIT", "subject.permissionScope", []any{
			b.policy("scoped", readerTarget, "DENY_UNLESS_PERMIT",
				b.rule("region-granted", "operation == 'READ'",
					"subject.permissionScope.region CONTAINS resource.region", "ALLOW", nil)),
		})},
		{"inactive", inactive},
		{"empty-rules", b.set("empty-rules", rtTarget, "PERMIT_UNLESS_DENY", []any{
			b.policy("no-rules", readerTarget, "PERMIT_UNLESS_DENY"),
		}, nil)},
	}
	uploads := make([]regularUpload, 0, len(forms))
	for _, form := range forms {
		uploads = append(uploads, regularUpload{externalID: "parity-" + configExportCaseID + "-" + form.key, sets: []any{form.set}})
	}
	return uploads
}

// configExportSimplifiedPolicies are the two simplified policies of tenant A: one
// on READ with a condition and a predicate, one on the operation ALL.
func configExportSimplifiedPolicies() []any {
	b := regularBuilder{caseID: configExportCaseID}
	rt := regularResourceType(configExportCaseID)
	simplified := func(key, operation string) map[string]any {
		return map[string]any{
			"component":             "PARITY",
			"reason":                configExportCaseID + " " + key,
			"resourceType":          rt,
			"operation":             operation,
			"roles":                 []string{"ROLE_PARITY_READER"},
			"applicableForFrontend": false,
			"id":                    b.id("simplified/" + key),
		}
	}
	read := simplified("read", "READ")
	read["condition"] = "resource.a == 'y'"
	read["rsqlPredicate"] = "a==y"
	return []any{read, simplified("all", "ALL")}
}

// configExportPIPs declare a PIP of each type with a recorded acceptance, in the
// shapes the recorded declarations use (suite-pips.json, parityPermissionsPIP,
// permissionScopeWirePIP).
func configExportPIPs() []any {
	rt := regularResourceType(configExportCaseID)
	return []any{
		map[string]any{
			"name":              configExportPIPPrefix + "General",
			"url":               parityPipMockBase + "/" + configExportCaseID,
			"httpMethod":        "POST",
			"pipType":           "GENERAL",
			"type":              "JSON",
			"jsonPath":          "$.value",
			"requestAttributes": map[string]string{"resourceType": rt},
			"cacheable":         false,
		},
		map[string]any{
			"name":         configExportPIPPrefix + "Header",
			"type":         "UUID",
			"pipType":      "HEADER",
			"header":       "x-parity-config-export",
			"defaultValue": "none",
			"cacheable":    false,
		},
		map[string]any{
			"name":         configExportPIPPrefix + "Token",
			"type":         "UUID",
			"pipType":      "TOKEN",
			"claim":        "department",
			"defaultValue": "none",
			"cacheable":    false,
		},
		map[string]any{
			"name":      "subject.permissions.PARITY_CONFIG_EXPORT",
			"type":      "UUID",
			"pipType":   "MAPPING",
			"cacheable": false,
			"customMapping": map[string]any{
				"subject.roles": map[string]any{
					"ROLE_PARITY_READER": []string{"parity_config_export"},
				},
			},
		},
		permissionScopeWirePIP,
	}
}

// configExportFilteredPIP declares a FILTERED PIP with the top-level resourceType
// that parityFilteredPIP lacks, which is the field h3-filtered-pip-plain-reference
// records the PAP refusing the declaration without.
func configExportFilteredPIP() map[string]any {
	rt := regularResourceType(configExportCaseID)
	return map[string]any{
		"name":              configExportPIPPrefix + "Filtered",
		"url":               parityPipMockBase + "/" + configExportCaseID + "-filtered",
		"httpMethod":        "POST",
		"pipType":           "FILTERED",
		"resourceType":      rt,
		"requestAttributes": map[string]string{"resourceType": rt},
		"cacheable":         false,
	}
}

// configExportTenantBPIPs declare, in tenant B, the GENERAL PIP of tenant A under
// the same name and another address.
func configExportTenantBPIPs() []any {
	rt := regularResourceType(configExportCaseID)
	return []any{
		map[string]any{
			"name":              configExportPIPPrefix + "General",
			"url":               parityPipMockBase + "/" + configExportCaseID + "-b",
			"httpMethod":        "POST",
			"pipType":           "GENERAL",
			"type":              "JSON",
			"jsonPath":          "$.value",
			"requestAttributes": map[string]string{"resourceType": rt},
			"cacheable":         false,
		},
	}
}

// configExportTenantBUpload is the one regular set of tenant B, on the resource
// type of tenant A's sets, with ids of its own.
func configExportTenantBUpload() regularUpload {
	b := regularBuilder{caseID: configExportCaseID + "-b"}
	rt := regularResourceType(configExportCaseID)
	return regularUpload{externalID: "parity-" + configExportCaseID + "-b", sets: []any{
		b.set("plain", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
			b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
				b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil)),
		}, nil),
	}}
}
