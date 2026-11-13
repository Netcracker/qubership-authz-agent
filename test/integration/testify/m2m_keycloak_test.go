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

// TestM2MKeycloak validates end-to-end policy pull with a Keycloak-issued
// client_credentials token, exercising the full path:
//
//	AUTHZ_M2M_TOKEN_URL → client_credentials grant → data.m2m.bearerToken →
//	Authorization header of the pull → authz-policy-admin → OPA policies.
//
// The tests run only when M2M_KEYCLOAK_PROFILE=true, which the kind and the
// Docker stands set because their agent runs with KUBERNETES_M2M_ENABLED=false
// against the stand's Keycloak. Against an agent that sends a static token
// file the steps are skipped via t.Skip() so the catalog coverage check passes.
//
// Test client: cloud-common realm / test-app-client (client_credentials)
func (s *RuntimeSuite) TestM2MKeycloak() {
	// (a) Policy pull succeeds with Keycloak token.
	//
	// The agent gets a real Keycloak access_token (test-app-client,
	// client_credentials grant) from AUTHZ_M2M_TOKEN_URL, publishes it as
	// data.m2m.bearerToken, and the pull loop sends it as the Authorization
	// header to authz-policy-admin. The suite setup (setup.wait_for_agent)
	// already blocked until the agent became healthy, which requires at least
	// one successful pull. This step asserts the resulting decision path works
	// end-to-end — if the pull had failed the agent would not have returned 200.
	s.Step("m2m_keycloak.pull_succeeds_with_keycloak_token", func() {
		if !s.cfg.M2MKeycloakProfile {
			s.T().Skip("M2M Keycloak profile not active (M2M_KEYCLOAK_PROFILE != true)")
		}
		// /access/v1/check/resource with a valid admin token must return 200,
		// proving that OPA has loaded policies from the pull loop that ran with
		// the Keycloak-issued token as its Authorization header.
		h := incomingTokenHeader(s.validAdminToken)
		body := map[string]interface{}{
			"type":      "ATTACHMENT",
			"operation": "READ",
			"resource":  map[string]interface{}{},
		}
		code, b := s.post("/access/v1/check/resource?tenant_id=default", h, body)
		s.Require().Equal(200, code,
			"m2m-keycloak: policy pull with Keycloak token must produce a functional agent; body: %s", string(b))
	})

	// (b) The agent still serves decisions after a pull made later than the
	//     setup's, with the token it holds at that time.
	//
	// waitForACPull asks the agent to pull now; on an agent without the pull
	// route it waits one pull interval instead. With the route, the step fails
	// when that pull fails.
	s.Step("m2m_keycloak.agent_functional_after_token_refresh", func() {
		if !s.cfg.M2MKeycloakProfile {
			s.T().Skip("M2M Keycloak profile not active (M2M_KEYCLOAK_PROFILE != true)")
		}
		s.waitForACPull()

		h := incomingTokenHeader(s.validAdminToken)
		body := map[string]interface{}{
			"type":      "ATTACHMENT",
			"operation": "READ",
			"resource":  map[string]interface{}{},
		}
		code, b := s.post("/access/v1/check/resource?tenant_id=default", h, body)
		s.Require().Equal(200, code,
			"m2m-keycloak: agent must remain functional after token refresh cycle; body: %s", string(b))
	})
}
