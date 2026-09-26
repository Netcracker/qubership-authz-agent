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

// requestAttributesDepartmentPIP is the TOKEN PIP the token form of
// TestRound10RequestAttributesCases names, over the reader's department claim.
var requestAttributesDepartmentPIP = map[string]any{
	"name": "subject.parityR10RaDepartment", "type": "UUID", "pipType": "TOKEN", "claim": "department", "cacheable": false,
}

// What a GENERAL PIP sends in the requestAttributes of its call when a value
// there is a placeholder. The documentation writes ${subject.<TOKEN or HEADER
// PIP>} there; every recorded GENERAL PIP sends literal values only, so what a
// placeholder over subject.roles, a resource attribute holding an object, and a
// resource attribute the request does not carry become is recorded nowhere,
// and neither is whether an unresolved one sends the call at all. The agent's
// PIP loader validates placeholders in requestAttributes and expands them when
// it calls the PIP.
//
// Each form is its own case: one GENERAL PIP whose requestAttributes hold
// {"value": <placeholder>}, answering {"value": "v"} at a route of its own, and
// a READ policy whose condition reads the PIP. literal is the control whose
// answer is known, true after one call carrying {"value": "lit"}; token is the
// form the documentation gives, and resource-id, a resource attribute holding a
// string, is the one the resource forms differ from. Every request carries the resource
// {"id": "r10-ra", "obj": {"k": "v"}}. The decision and what pip-mock received,
// its call count and the requestAttributes of the first call, are recorded.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound10RequestAttributesCases() {
	ctx := context.Background()
	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s: %v", isolatedCaseDomain, err)
		}
	})
	for _, form := range []struct{ key, placeholder string }{
		{"literal", "lit"},
		{"token", "${subject.parityR10RaDepartment}"},
		{"subject-roles", "${subject.roles}"},
		{"resource-id", "${resource.id}"},
		{"resource-object", "${resource.obj}"},
		{"resource-missing", "${resource.missing}"},
	} {
		id := "ra-" + form.key
		route := "/api/v1/pip/r10-" + id
		s.Run(id, func() {
			s.Require().NoError(s.pipMock.PinRoute(ctx, route, PipStubResponse{StatusCode: http.StatusOK, Body: map[string]string{"value": "v"}}))
			s.Require().NoError(s.pipMock.ResetCalls(ctx))
			rt := round10ResourceType(id)
			general := map[string]any{
				"name": "subject.parityR10RaGeneral", "url": "http://pip-mock:8090" + route,
				"httpMethod": "POST", "pipType": "GENERAL", "type": "JSON", "jsonPath": "$.value", "cacheable": false,
				"requestAttributes": map[string]string{"value": form.placeholder},
			}
			status, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain,
				[]any{requestAttributesDepartmentPIP, general},
				[]any{map[string]any{
					"component": "PARITY", "reason": id, "resourceType": rt, "operation": "READ",
					"roles": []string{"ROLE_PARITY_READER"}, "applicableForFrontend": false,
					"condition": "subject.parityR10RaGeneral == 'v'", "id": "00000000-0000-0000-0000-0000000f1044",
				}})
			s.Require().NoError(err)
			if !isAuthzAgentProfile(s.cfg.Profile) {
				s.Run("upload", func() {
					s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "isolated/"+id, &model.PolicyLoadOutcome{Status: status})
				})
				if status < http.StatusOK || status >= http.StatusMultipleChoices {
					return
				}
			}
			endpoint, outcome := s.sendRegularRequest(rt, isolatedRequest{resource: map[string]any{"id": "r10-ra", "obj": map[string]any{"k": "v"}}})
			s.Run("read", func() {
				s.requirePendingGolden(endpoint, "isolated/"+id+"/read", outcome)
			})
			s.Run("the-pip-call", func() {
				s.requirePendingGolden(PSUITE_PIP_CALL, "isolated/"+id, s.pipCallOutcome(route))
			})
		})
	}
}
