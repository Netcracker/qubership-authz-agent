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

package runtimetest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────
// ADR-0054 / D-AG-11 / D-AG-15 — runtime integration coverage for the
// container-pinned entitlements PIP.
//
// Each Step pins a per-user V3 entitlements-aggregator response on the
// `entitlements-mock` pip-stub instance (wired into
// tests/integration/runtime/docker-compose.yml by Step 6 sub-step 3 +
// reached by pap-client via AUTHZ_ENTITLEMENTS_URL), uploads a
// policy set that references `subject.entitledResources.of(...).as(...)`
// in its condition, and asserts the resulting decision on
// `/access/v1/check/resource`.
//
// The tests share one policy upload per step so the harness stays flat
// — each case calls `uploadEntitlementsPolicies` with the ENT condition
// it wants. This mirrors how Step 6's parity suite pins per-user EA
// responses and then drives rows 76–83 through the canonical check
// surface.
// ──────────────────────────────────────────────────────────────────────────

// adminSubjectID extracts the `sub` claim from the admin access token the
// suite minted during SetupSuite so tests can pin entitlements scoped
// exactly to the user who issues the `/access/v1/check/resource` call.
// Keycloak auto-generates the user id; reading it from the live token
// keeps the test independent of realm-import snapshots.
func (s *RuntimeSuite) adminSubjectID() string {
	s.T().Helper()
	parts := strings.Split(s.validAdminToken, ".")
	s.Require().GreaterOrEqual(len(parts), 2)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	s.Require().NoError(err)
	var claims struct {
		Sub string `json:"sub"`
	}
	s.Require().NoError(json.Unmarshal(payload, &claims))
	s.Require().NotEmpty(claims.Sub)
	return claims.Sub
}

// pinEntitlements pins a single /api/v3/user-entitlements/user/{userId}
// response on the entitlements-mock stub at the host-published control
// URL. The pap-client container reaches the same stub via the
// in-Compose DNS alias declared on AUTHZ_ENTITLEMENTS_URL.
func (s *RuntimeSuite) pinEntitlements(userID string, refs map[string]map[string][]string) {
	s.T().Helper()
	path := fmt.Sprintf("/api/v3/user-entitlements/user/%s", userID)

	body := entitlementsResponse(refs)
	payload := []map[string]interface{}{{
		"path": path,
		"responses": []map[string]interface{}{{
			"statusCode": 200,
			"body":       body,
		}},
	}}
	raw, err := json.Marshal(payload)
	s.Require().NoError(err)

	req, err := http.NewRequest(http.MethodPut, s.cfg.EntitlementsMockURL+"/pip-stub/configure", bytes.NewReader(raw))
	s.Require().NoError(err)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	s.Require().NoError(err)
	defer func() { _ = resp.Body.Close() }()
	s.Require().Equalf(http.StatusOK, resp.StatusCode, "pip-stub configure failed: %d", resp.StatusCode)
}

func entitlementsResponse(refs map[string]map[string][]string) map[string]interface{} {
	ents := []map[string]interface{}{}
	for rt, names := range refs {
		refList := []map[string]interface{}{}
		for name, ids := range names {
			resources := []map[string]interface{}{}
			for _, id := range ids {
				resources = append(resources, map[string]interface{}{"resourceId": id})
			}
			refList = append(refList, map[string]interface{}{"name": name, "resources": resources})
		}
		ents = append(ents, map[string]interface{}{"resourceType": rt, "references": refList})
	}
	return map[string]interface{}{
		"entitlements": ents,
		"definitions":  []interface{}{},
	}
}

// uploadEntitlementsPolicies uploads the baseline runtime-simplified-
// policies.json set (from setup.policy_upload) PLUS the ENT policies
// passed in to the authz-policy-admin control surface and waits for the pull loop.
// UploadPoliciesToACStub replaces the full policy set so we must merge
// the ENT entries with the baseline to avoid wiping the policies that
// other Test* methods depend on (TestPIPDenyReason, TestPIPGeneralActivation,
// TestPIPJsonPathExtraction, TestZZDecisionLogsCatalogCoverage, etc.).
//
// The `policies` argument is a JSON array string containing the ENT
// policy objects this test step wants to exercise. The baseline is
// read from the committed testdata fixture so the runtime suite
// doesn't hard-code its own copy.
func (s *RuntimeSuite) uploadEntitlementsPolicies(policies string) {
	s.T().Helper()

	basePolicies, err := os.ReadFile("testdata/runtime-simplified-policies.json")
	s.Require().NoError(err, "read baseline runtime-simplified-policies.json")

	var base []any
	s.Require().NoError(json.Unmarshal(basePolicies, &base), "decode baseline policies array")

	var extra []any
	s.Require().NoError(json.Unmarshal([]byte(policies), &extra), "decode ENT policies array argument")

	merged, err := json.Marshal(append(base, extra...))
	s.Require().NoError(err, "marshal merged policy set")

	s.Require().NoError(
		UploadPoliciesToACStub(s.cfg.ACStubURL, merged, s.currentRequestID()),
		"upload ENT policies to authz-policy-admin",
	)
	s.waitForACPull()
}

func (s *RuntimeSuite) checkResourceDecision(resourceType, operation string, resource map[string]interface{}) bool {
	s.T().Helper()
	token := "Bearer " + s.validAdminToken
	body := map[string]interface{}{
		"type":      resourceType,
		"operation": operation,
		"resource":  resource,
	}
	h := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": token,
	}
	code, b := s.post("/access/v1/check/resource", h, body)
	s.Require().Equalf(http.StatusOK, code, "check/resource returned %d: %s", code, string(b))
	return strings.TrimSpace(string(b)) == "true"
}

// TestEntitlementsRuntime exercises the ADR-0054 matrix end-to-end.
// Requires the runtime compose stack (tests/integration/runtime/docker-compose.yml)
// with the entitlements-mock service from D-AG-15 and
// AUTHZ_ENTITLEMENTS_URL set on the pap-client container. Per
// D-AG-19 this coverage is mandatory on every integration-suite run —
// if the stub is unreachable the test fails loudly rather than
// skipping, so a stack that omits the D-AG-15 wiring cannot hide a
// regression in the resolver, the pivot, or the upload-rejection
// path.
func (s *RuntimeSuite) TestEntitlementsRuntime() {
	s.Require().True(
		entitlementsMockReachable(s.cfg),
		"entitlements-mock must be reachable at %s — the runtime stack must include the D-AG-15 entitlements-mock service block; per D-AG-19 this is not optional",
		s.cfg.EntitlementsMockURL,
	)

	userID := s.adminSubjectID()

	s.Step("entitlements.contains.allow_hit", func() {
		s.pinEntitlements(userID, map[string]map[string][]string{
			"ENT_CONTRACT": {"Owner": {"id-1"}},
		})
		s.uploadEntitlementsPolicies(`[{
			"component": "RUNTIME_TESTS",
			"resourceType": "ENT_CONTRACT",
			"operation": "READ",
			"condition": "subject.entitledResources.of('ENT_CONTRACT').as('Owner') CONTAINS resource.id",
			"roles": ["ROLE_ADMINISTRATOR"]
		}]`)
		allow := s.checkResourceDecision("ENT_CONTRACT", "READ", map[string]interface{}{"id": "id-1"})
		s.Assert().True(allow, "entitlements CONTAINS should allow when resource.id is in the Owner bucket")
	})

	s.Step("entitlements.contains.deny_miss", func() {
		s.pinEntitlements(userID, map[string]map[string][]string{
			"ENT_CONTRACT": {"Owner": {"id-1"}},
		})
		s.uploadEntitlementsPolicies(`[{
			"component": "RUNTIME_TESTS",
			"resourceType": "ENT_CONTRACT",
			"operation": "READ",
			"condition": "subject.entitledResources.of('ENT_CONTRACT').as('Owner') CONTAINS resource.id",
			"roles": ["ROLE_ADMINISTRATOR"]
		}]`)
		allow := s.checkResourceDecision("ENT_CONTRACT", "READ", map[string]interface{}{"id": "id-99"})
		s.Assert().False(allow, "entitlements CONTAINS should deny when resource.id is outside the Owner bucket")
	})

	s.Step("entitlements.is_empty.allow_when_empty", func() {
		s.pinEntitlements(userID, map[string]map[string][]string{})
		s.uploadEntitlementsPolicies(`[{
			"component": "RUNTIME_TESTS",
			"resourceType": "ENT_EMPTY",
			"operation": "READ",
			"condition": "subject.entitledResources.of('ENT_EMPTY').as('Owner') IS EMPTY",
			"roles": ["ROLE_ADMINISTRATOR"]
		}]`)
		allow := s.checkResourceDecision("ENT_EMPTY", "READ", map[string]interface{}{"id": "id-any"})
		s.Assert().True(allow, "IS EMPTY on an empty entitlement tree should allow")
	})

	s.Step("entitlements.multi_as_union.allow", func() {
		s.pinEntitlements(userID, map[string]map[string][]string{
			"ENT_MULTI": {"Owner": {"id-1"}, "Accountant": {"id-2"}},
		})
		s.uploadEntitlementsPolicies(`[{
			"component": "RUNTIME_TESTS",
			"resourceType": "ENT_MULTI",
			"operation": "READ",
			"condition": "subject.entitledResources.of('ENT_MULTI').as('Owner', 'Accountant') CONTAINS resource.id",
			"roles": ["ROLE_ADMINISTRATOR"]
		}]`)
		allow := s.checkResourceDecision("ENT_MULTI", "READ", map[string]interface{}{"id": "id-2"})
		s.Assert().True(allow, "chained/multi-name .as(...) union must let ids from any named bucket match")
	})
}

// entitlementsMockReachable probes the entitlements-mock pip-stub
// control plane for liveness. Per D-AG-19 this is used as a hard
// precondition in TestEntitlementsRuntime — if the runtime compose
// stack was brought up without the D-AG-15 service block, the
// integration suite fails loudly on this check instead of silently
// skipping ENT coverage.
func entitlementsMockReachable(cfg RuntimeConfig) bool {
	req, err := http.NewRequest(http.MethodGet, cfg.EntitlementsMockURL+"/pip-stub/calls", nil)
	if err != nil {
		return false
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == http.StatusOK
}
