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

// TestTenantRealm checks tenant realms, which Keycloak names by an identifier
// the chart cannot know. The chart names such a realm by its tenant's name,
// and the agent asks tenant-manager for the identifier before it loads the
// realm's keys. The tenant-manager emulator knows the name default and not
// unregistered, whose realm is otherwise built the same way, so the token
// from default is accepted because of that lookup and not because the agent
// accepts any token the harness Keycloak signs.
func (s *RuntimeSuite) TestTenantRealm() {
	body := map[string]interface{}{"type": "ORDER", "operation": "READ", "resource": map[string]interface{}{}}

	s.Step("tenant_realm.resolved_realm_token_accepted", func() {
		token, err := GetKeycloakToken(s.cfg.KcTenantBaseURL, s.cfg.KcClientID, s.cfg.KcClientSecret,
			s.cfg.KcTokenScope, s.cfg.KcAdminUser, s.cfg.KcPassword, s.currentRequestID())
		s.Require().NoError(err, "token from %s", s.cfg.KcTenantBaseURL)

		code, b := s.post("/access/v1/check/resource", incomingTokenHeader(token), body)
		s.Require().Equal(200, code, "body: %s", string(b))
		s.Assert().Equal("true", bodyStr(b))
	})

	s.Step("tenant_realm.unregistered_realm_token.401", func() {
		token, err := GetKeycloakToken(s.cfg.KcUnregisteredTenantBaseURL, s.cfg.KcClientID, s.cfg.KcClientSecret,
			s.cfg.KcTokenScope, s.cfg.KcAdminUser, s.cfg.KcPassword, s.currentRequestID())
		s.Require().NoError(err, "token from %s", s.cfg.KcUnregisteredTenantBaseURL)

		mark := s.decisionLogMark()
		code, b := s.post("/access/v1/check/resource", incomingTokenHeader(token), body)
		s.Require().Equal(401, code, "body: %s", string(b))
		authError, _ := s.loggedDecision(mark)["authError"].(map[string]interface{})
		s.Assert().Equal("JWT kid is not found in trusted provider keys", authError["reason"])
	})
}
