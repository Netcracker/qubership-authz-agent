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

func (s *RuntimeSuite) TestCheckResource() {
	s.Step("check_resource.order_read.rls_deny", func() {
		h := incomingTokenHeader(s.validOrderReaderToken)
		body := map[string]interface{}{
			"type": "ORDER", "operation": "READ",
			"resource": map[string]interface{}{"id": "order-1", "ownerId": "order-reader-1"},
		}
		code, b := s.post("/access/v1/check/resource?tenant_id=default", h, body)
		s.Require().Equal(200, code)
		s.Assert().Equal("false", bodyStr(b))
	})

	// ADR-0049: Incoming-Token is the preferred subject source on legacy
	// ingress. The thin client sends the M2M token in Authorization (for
	// admission) and the end-user token in Incoming-Token (for policy
	// evaluation). Here we send an expired end-user token in Incoming-Token
	// so subject validation fails and the canonical DENY path fires; the
	// Authorization (admission) token is valid, so this returns HTTP 200
	// with body "false" (not HTTP 401). Under pre-ADR-0049 behavior this
	// test erroneously asserted the header was ignored.
	s.Step("check_resource.incoming_token_used_for_subject", func() {
		h := map[string]string{
			"Content-Type":   "application/json",
			"Incoming-Token": "Bearer " + s.expiredOrderReaderToken,
			"Authorization":  "Bearer " + s.validAdminToken,
		}
		body := map[string]interface{}{
			"type": "ORDER", "operation": "READ",
			"resource": map[string]interface{}{"id": "order-1", "ownerId": "order-reader-1"},
		}
		code, b := s.post("/access/v1/check/resource?tenant_id=default", h, body)
		s.Require().Equal(200, code, "admission via valid Authorization must pass; subject DENY is 200 not 401")
		s.Assert().Equal("false", bodyStr(b), "expired Incoming-Token subject must DENY")
	})

	s.Step("check_resource.expired_authorization.401", func() {
		h := map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer " + s.expiredOrderReaderToken,
		}
		body := map[string]interface{}{
			"type": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{},
		}
		code, _ := s.post("/access/v1/check/resource?tenant_id=default", h, body)
		s.Require().Equal(401, code)
	})

	s.Step("check_resource.no_token.401", func() {
		body := map[string]interface{}{
			"type": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{},
		}
		code, b := s.post("/access/v1/check/resource?tenant_id=default", jsonHeader(), body)
		s.Require().Equal(401, code)
		s.Assert().NotEmpty(jsonObj(b)["message"], "legacy 401 must include message")
	})

	s.Step("check_resource.tenant_id_ignored", func() {
		h := incomingTokenHeader(s.validOrderReaderToken)
		body := map[string]interface{}{
			"type": "ORDER", "operation": "READ",
			"resource": map[string]interface{}{"id": "order-1", "ownerId": "order-reader-1"},
		}
		code, b := s.post("/access/v1/check/resource?tenant_id=other-tenant", h, body)
		s.Require().Equal(200, code)
		s.Assert().Equal("false", bodyStr(b))
	})

	s.Step("check_resource.tenant_id_absent", func() {
		h := incomingTokenHeader(s.validOrderReaderToken)
		body := map[string]interface{}{
			"type": "ORDER", "operation": "READ",
			"resource": map[string]interface{}{"id": "order-1", "ownerId": "order-reader-1"},
		}
		code, b := s.post("/access/v1/check/resource", h, body)
		s.Require().Equal(200, code)
		s.Assert().Equal("false", bodyStr(b))
	})

	s.Step("check_resource.null_body.400", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.postRaw("/access/v1/check/resource?tenant_id=default", h, nil)
		s.Require().Equal(400, code)
		s.Assert().Equal("bad request", jsonObj(b)["message"])
	})

	s.Step("check_resource.boolean_response", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := map[string]interface{}{
			"type": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{},
		}
		code, b := s.post("/access/v1/check/resource?tenant_id=default", h, body)
		s.Require().Equal(200, code)
		v := bodyStr(b)
		s.Assert().True(v == "true" || v == "false", "response must be boolean string, got: %s", v)
	})

	// Parity catalogue row 10: the legacy CheckRequestValidator
	// rejects missing required parameters with a field-specific message
	// (CheckRequestValidator.java:31-44). Envoy Lua now emits
	// "Missing required parameter: <field>" so the body substring
	// includes "parameter"/"type"/"operation" — matching the tolerance
	// set the parity suite's TestRow11ValidationMissingOperation uses.
	s.Step("check_resource.missing_fields.400", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := map[string]interface{}{
			"resource": map[string]interface{}{"id": "1"},
		}
		code, b := s.postRaw("/access/v1/check/resource?tenant_id=default", h, body)
		s.Require().Equal(400, code)
		msg, _ := jsonObj(b)["message"].(string)
		s.Assert().Contains(msg, "Missing required parameter",
			"expected field-specific validation message, got: %s", msg)
	})

	s.Step("check_resource.wrong_address.404", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := map[string]interface{}{
			"type": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{},
		}
		code, b := s.post("/access/v1/check/resourc?tenant_id=default", h, body)
		s.Require().Equal(404, code)
		s.Assert().Equal("not found", jsonObj(b)["message"])
	})

	// ADR-0049: on legacy ingress the policy-evaluation subject comes from
	// Incoming-Token when present, with Authorization reserved for admission.
	// BULK_OPEN READ is allowed for ROLE_ADMINISTRATOR only; sending an
	// admin Authorization (admission) together with an order-reader
	// Incoming-Token (subject) must deny because the end-user subject lacks
	// the admin role. This proves the precedence ordering: Incoming-Token
	// overrides Authorization when both are present.
	s.Step("check_resource.incoming_token_precedence_over_authorization", func() {
		h := map[string]string{
			"Content-Type":   "application/json",
			"Authorization":  "Bearer " + s.validAdminToken,
			"Incoming-Token": "Bearer " + s.validOrderReaderToken,
		}
		body := map[string]interface{}{
			"type": "BULK_OPEN", "operation": "READ",
			"resource": map[string]interface{}{"id": "bulk-open-1"},
		}
		code, b := s.post("/access/v1/check/resource?tenant_id=default", h, body)
		s.Require().Equal(200, code)
		s.Assert().Equal("false", bodyStr(b),
			"Incoming-Token (order-reader) must take precedence over Authorization (admin) for subject evaluation")
	})

	// ADR-0049: anonymous ingress is signalled by Authorization-Type:
	// anonymous. Envoy must leave subject empty so canonical identity.rego
	// matches the anonymous_subject path. Admission still requires a valid
	// Authorization (M2M) token.
	s.Step("check_resource.anonymous_subject_marker", func() {
		h := map[string]string{
			"Content-Type":       "application/json",
			"Authorization":      "Bearer " + s.validAdminToken,
			"Authorization-Type": "anonymous",
		}
		body := map[string]interface{}{
			"type": "BULK_OPEN", "operation": "READ",
			"resource": map[string]interface{}{"id": "bulk-open-anon"},
		}
		code, b := s.post("/access/v1/check/resource?tenant_id=default", h, body)
		s.Require().Equal(200, code, "admission via valid M2M passes; anonymous subject evaluates as DENY not 401")
		s.Assert().Equal("false", bodyStr(b),
			"anonymous subject has no roles — BULK_OPEN READ must DENY")
	})

	// ADR-0049 decision item 3: incoming-token must never appear in
	// input.requestHeaders. We rely on HEADER PIP resolution to never see
	// the bearer string; a misconfigured HEADER PIP that tried to bind
	// subject.incomingToken would otherwise leak the raw token. This step
	// covers the negative path: sending an incoming-token header with a
	// well-known literal and then asserting the subsequent decision is
	// unchanged from the no-header baseline. (Direct header-leak inspection
	// would require decision-log scraping — we cover that in
	// tests/unit/policies/pip_resolution_test.rego.)
	s.Step("check_resource.incoming_token_stripped_from_header_pip", func() {
		baseline := map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer " + s.validAdminToken,
		}
		body := map[string]interface{}{
			"type": "ATTACHMENT", "operation": "READ",
			"resource": map[string]interface{}{"id": "atch-1"},
		}
		code1, b1 := s.post("/access/v1/check/resource?tenant_id=default", baseline, body)
		s.Require().Equal(200, code1)

		withIncoming := map[string]string{
			"Content-Type":   "application/json",
			"Authorization":  "Bearer " + s.validAdminToken,
			"Incoming-Token": "Bearer " + s.validAdminToken,
		}
		code2, b2 := s.post("/access/v1/check/resource?tenant_id=default", withIncoming, body)
		s.Require().Equal(200, code2)

		s.Assert().Equal(bodyStr(b1), bodyStr(b2),
			"incoming-token must not alter decision through HEADER PIP resolution")
	})
}
