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
	"encoding/json"
)

// TestHealth covers the GET /health endpoint runtime integration scenarios.
// Negative scenarios that require runtime state not achievable with the shared
// Compose stack (OPA not ready, missing/invalid status, transition) are covered
// exhaustively by unit tests in components/pap-client/internal/policyadmin/health_test.go.
func (s *RuntimeSuite) TestHealth() {

	// ── Scenario 1: Healthy strict ─────────────────────────────────────────
	// The Compose stack starts authz-agent after keycloak is healthy and the
	// JWKS bootstrap completes. The test suite itself runs only after
	// setup.wait_for_agent passes, which implicitly validates service_healthy
	// wiring (Scenario 10). A direct GET /health call confirms the endpoint.
	s.Step("health.healthy_strict", func() {
		code, body := s.get("/health", nil)
		s.Require().Equal(200, code, "GET /health should return 200 when stack is ready; body: %s", string(body))

		var resp map[string]interface{}
		s.Require().NoError(json.Unmarshal(body, &resp), "response should be valid JSON")
		s.Require().Equal("healthy", resp["status"], "status field must be 'healthy'")
	})

	// ── Scenario 2: Healthy permissive (partial bootstrap) ─────────────────
	// authz-agent-partial-permissive: 2 providers (keycloak OK + broken-idp),
	// permissive mode (AUTHZ_JWKS_BOOTSTRAP_REQUIRED=false).
	// Bootstrap: successCount=1, configuredCount=2, threshold=1 → healthy.
	s.Step("health.healthy_permissive.degraded", func() {
		code, body := s.doHTTPDirect("GET", s.cfg.DegradedPermissiveURL+"/health", nil, nil)
		s.Require().Equal(200, code,
			"permissive agent with ≥1 IdP success must return 200; body: %s", string(body))

		var resp map[string]interface{}
		s.Require().NoError(json.Unmarshal(body, &resp), "response should be valid JSON")
		s.Require().Equal("healthy", resp["status"], "status field must be 'healthy'")
	})

	// ── Scenario 4: Unhealthy strict — partial bootstrap ───────────────────
	// authz-agent-partial-strict: 2 providers (keycloak OK + broken-idp),
	// strict mode (AUTHZ_JWKS_BOOTSTRAP_REQUIRED=true).
	// Bootstrap: successCount=1, configuredCount=2, threshold=2 → not met → 503.
	s.Step("health.unhealthy.strict_partial", func() {
		code, body := s.doHTTPDirect("GET", s.cfg.DegradedStrictURL+"/health", nil, nil)
		s.Require().Equal(503, code,
			"strict agent with partial bootstrap must return 503; body: %s", string(body))

		var resp map[string]interface{}
		s.Require().NoError(json.Unmarshal(body, &resp), "response should be valid JSON")
		s.Require().NotEmpty(resp["message"], "unhealthy response must include message")
	})

	// ── Method enforcement: POST /health → 405 ─────────────────────────────
	// Validates that the Envoy route (without method guard) forwards all methods
	// to the Go handler, which returns 405 for non-GET requests.
	s.Step("health.method_not_allowed", func() {
		code, _ := s.post("/health", nil, nil)
		s.Require().Equal(405, code, "POST /health must return 405 Method Not Allowed")
	})

	// ── Scenario 9: Regression guard ──────────────────────────────────────
	// Adding the /health route must not affect existing authorization endpoints.
	s.Step("health.regression.check_resource", func() {
		headers := incomingTokenHeader(s.validAdminToken)
		code, body := s.post("/access/v1/check/resource",
			headers,
			map[string]interface{}{
				"type":      "ATTACHMENT",
				"operation": "READ",
				"resource":  map[string]interface{}{},
			},
		)
		// Expect 200 (decision returned as boolean, not an HTTP error).
		s.Require().Equal(200, code, "/access/v1/check/resource must still work after health route added; body: %s", string(body))
	})

	// ── Scenario 10: Compose wiring ────────────────────────────────────────
	// Verified implicitly: the runtime test suite runs only after
	// authz-agent passes the service_healthy condition (which uses GET /health).
	// We add an explicit check here to confirm the health endpoint existed
	// before any test ran, by verifying it still returns 200 at test-time.
	s.Step("health.compose_wiring", func() {
		code, body := s.get("/health", nil)
		s.Require().Equal(200, code, "health endpoint must be reachable (Compose service_healthy already cleared); body: %s", string(body))
	})
}
