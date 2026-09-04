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

// TestHealth covers the GET /health endpoint runtime integration scenarios
// that the agent under test answers itself. Scenarios that need a differently
// configured agent or state the harness cannot produce (partial or failed JWKS
// bootstrap in strict and permissive mode, OPA not ready, missing or invalid
// status, transitions) are covered by the unit tests in
// components/pap-client/internal/policyadmin/health_test.go.
func (s *RuntimeSuite) TestHealth() {

	// ── Scenario 1: Healthy strict ─────────────────────────────────────────
	// The stack starts the agent after Keycloak is up and the JWKS bootstrap
	// completes, and the suite itself runs only after setup.wait_for_agent
	// passes. A direct GET /health call confirms the endpoint.
	s.Step("health.healthy_strict", func() {
		code, body := s.get("/health", nil)
		s.Require().Equal(200, code, "GET /health should return 200 when stack is ready; body: %s", string(body))

		var resp map[string]interface{}
		s.Require().NoError(json.Unmarshal(body, &resp), "response should be valid JSON")
		s.Require().Equal("healthy", resp["status"], "status field must be 'healthy'")
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
}
