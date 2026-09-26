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

	"authz-agent/test/parity/suite/model"
)

const productMappingCaseID = "product-mapping"

// productMappingMarkers narrow the v3 export to the elements of this case: the
// permission prefix, which a folded subject.permissions element carries in its
// mappings, and the domain suffix of the declared names.
var productMappingMarkers = []string{"parity_r10_", "PARITY_R10_"}

// productMappingPIP declares, in isolatedCaseDomain, a MAPPING PIP with a
// productMapping and no customMapping, granting ROLE_PARITY_READER the
// permission parity_r10_product.
var productMappingPIP = map[string]any{
	"name":      "subject.permissions.PARITY_R10_PM",
	"type":      "UUID",
	"pipType":   "MAPPING",
	"cacheable": false,
	"productMapping": map[string]any{
		"subject.roles": map[string]any{"ROLE_PARITY_READER": []string{"parity_r10_product"}},
	},
}

// productMappingCustomPIP declares, in round9SecondDomain, a MAPPING PIP with a
// customMapping and no productMapping, granting each role of roles the
// permission paired with it.
func productMappingCustomPIP(roles map[string][]string) map[string]any {
	return map[string]any{
		"name":          "subject.permissions.PARITY_R10_CM",
		"type":          "UUID",
		"pipType":       "MAPPING",
		"cacheable":     false,
		"customMapping": map[string]any{"subject.roles": roles},
	}
}

// productMappingPolicies are the simplified policies of the case: READ on the
// permission the productMapping grants, UPDATE on the one the reader's
// customMapping grants, and an unconditional PROBE.
func productMappingPolicies() []any {
	b := regularBuilder{caseID: productMappingCaseID}
	policy := func(key, operation, condition string) map[string]any {
		p := map[string]any{
			"component":             "PARITY",
			"reason":                productMappingCaseID + " " + key,
			"resourceType":          regularResourceType(productMappingCaseID),
			"operation":             operation,
			"roles":                 []string{"ROLE_PARITY_READER"},
			"applicableForFrontend": false,
			"id":                    b.id("simplified/" + key),
		}
		if condition != "" {
			p["condition"] = condition
		}
		return p
	}
	return []any{
		policy("product-permission", "READ", "subject.permissions CONTAINS 'parity_r10_product'"),
		policy("custom-permission", "UPDATE", "subject.permissions CONTAINS 'parity_r10_custom'"),
		policy("unconditional", "PROBE", ""),
	}
}

// Whether a MAPPING PIP declared with a productMapping alone grants its
// permissions in a decision, and whether a customMapping on another MAPPING PIP
// of the tenant changes that. No golden records a productMapping in a decision.
// A productMapping declared beside a customMapping on the same PIP was seen not
// to grant its permission, without a golden, and the documentation says a
// customMapping on any PIP of the tenant turns every productMapping off; that
// shape does not tell the documented rule from a productMapping that never
// reaches a decision. The agent's configuration reader keeps productMapping as
// raw JSON and grants nothing from it.
//
// Three steps, each followed by the READ on parity_r10_product, the requests
// that stay, and the v3 export of the tenant's PIPs narrowed to this case:
//
//   - productMapping alone: the MAPPING PIP of isolatedCaseDomain is the only
//     one the case declares; the export shows whether the tenant holds any other
//     with the case's markers. PROBE, unconditional, is the control that the
//     policies loaded.
//   - beside a customMapping for another role: round9SecondDomain declares a
//     MAPPING PIP granting ROLE_PARITY_OTHER, which the reader does not hold,
//     the permission parity_r10_custom_other.
//   - beside a customMapping for the reader: the same PIP also grants
//     ROLE_PARITY_READER parity_r10_custom. UPDATE, on that permission, is the
//     control that a customMapping of the second domain reaches the decision.
//
// The case lives in its own test function so that a recording run can be
// filtered to it. Legacy profile only: on the authz-agent profile the export is
// authz-policy-admin's.
func (s *ParitySuite) TestRound10ProductMappingCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("the v3 export is access-control's; on the authz-agent profile authz-policy-admin serves it")
	}
	s.round9EmptyDomainsOnCleanup()
	ctx := context.Background()
	m2m := s.mustM2MToken()

	steps := []struct {
		name     string
		declare  func() bool
		requests []struct{ name, operation string }
	}{
		{
			name: "product-mapping-alone",
			declare: func() bool {
				return s.round9UploadDomain(productMappingCaseID+"/product-mapping-alone/declare", isolatedCaseDomain,
					[]any{productMappingPIP}, productMappingPolicies())
			},
			requests: []struct{ name, operation string }{
				{"product-permission-read", "READ"},
				{"unconditional-probe", "PROBE"},
			},
		},
		{
			name: "beside-a-custom-mapping-for-another-role",
			declare: func() bool {
				return s.round9UploadDomain(productMappingCaseID+"/beside-a-custom-mapping-for-another-role/declare", round9SecondDomain,
					[]any{productMappingCustomPIP(map[string][]string{"ROLE_PARITY_OTHER": {"parity_r10_custom_other"}})}, nil)
			},
			requests: []struct{ name, operation string }{
				{"product-permission-read", "READ"},
			},
		},
		{
			name: "beside-a-custom-mapping-for-the-reader",
			declare: func() bool {
				return s.round9UploadDomain(productMappingCaseID+"/beside-a-custom-mapping-for-the-reader/declare", round9SecondDomain,
					[]any{productMappingCustomPIP(map[string][]string{
						"ROLE_PARITY_OTHER":  {"parity_r10_custom_other"},
						"ROLE_PARITY_READER": {"parity_r10_custom"},
					})}, nil)
			},
			requests: []struct{ name, operation string }{
				{"product-permission-read", "READ"},
				{"custom-permission-update", "UPDATE"},
			},
		},
	}
	for _, step := range steps {
		if !step.declare() {
			return
		}
		s.Run(step.name, func() {
			for _, req := range step.requests {
				s.Run(req.name, func() {
					s.runPendingCheckResourceV1OutcomeCase(
						productMappingCaseID+"/"+step.name+"/"+req.name,
						model.CheckAccessRequest{Operation: req.operation, Type: regularResourceType(productMappingCaseID), Resource: map[string]any{"id": "r10-product-mapping"}},
						s.mustTokenBundle(UserProfileReader),
						PerCallOptions{},
					)
				})
			}
			s.Run("export-pips", func() {
				status, body, err := HelperGetConfigExport(ctx, s.cfg, PSUITE_CONFIG_PIPS_V3, m2m, PerCallOptions{})
				s.Require().NoError(err)
				s.requirePendingGolden(PSUITE_CONFIG_PIPS_V3, productMappingCaseID+"/"+step.name, narrowConfigExport(status, body, productMappingMarkers))
			})
		})
	}
}
