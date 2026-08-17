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

// TestAuthorizeEnvoyOpaDirectParity is the authz-agent-ADR-0062 cross-transport
// contract test: the same canonical authorize request must produce a
// byte-identical response on both transports.
//
// Pre-ADR-0062 the canonical wire was Envoy-only — `/access/v1/authorize`
// was rewritten to `/v1/data/authorize/result` by Envoy and unwrapped by
// the per-route Lua filter. Post-ADR-0062 the Envoy route no longer rewrites
// to a `.result` sub-path and no longer mounts a per-route Lua filter
// (Steps 7 + 8): both transports surface the OPA Data API envelope
// `{"result": <AuthorizeResponse>}` byte-for-byte. This test is the
// regression catch for that invariant.
//
// The test is hermetic to compute determinism — it does NOT assert decision
// content, only response-byte identity. PIP staleness or token-expiry skew
// between back-to-back calls is the only source of legitimate drift, so the
// test fires the two requests back-to-back with the same X-Request-Id and
// the same body bytes.
//
// Deferred per the canonical OPA-direct + Envoy parity handover (Step 13):
// requires the live runtime stack to actually green. The test is integration-
// build-tagged and will run automatically with the rest of the testify suite
// once the live compose stack is up.
func (s *RuntimeSuite) TestAuthorizeEnvoyOpaDirectParity() {
	s.Step("authorize.envoy_opa_direct.bytewise_response_parity", func() {
		token := "Bearer " + s.validAdminToken
		body := canonicalAuthorizeBody(token, token, map[string]interface{}{
			"resources": []map[string]interface{}{
				{"resourceType": "ORDER", "operation": "READ"},
			},
			"ignoreRls": false,
		})
		bodyBytes, err := json.Marshal(body)
		s.Require().NoError(err)

		headers := s.headersWithRequestID(jsonHeader())

		envoyURL := s.cfg.BaseURL + "/access/v1/authorize"
		envoyCode, envoyBody, envoyReqBody, envoyRespHdr, err := DoHTTPFull("POST", envoyURL, headers, bodyBytes)
		s.Require().NoError(err)
		// Conformance only declares the Envoy mount; OPA-direct is the same
		// envelope by ADR-0062 contract but is intentionally out of the
		// public spec surface.
		assertConformsToSpec(s.T(), "POST", envoyURL, headers, envoyReqBody, envoyCode, envoyRespHdr, envoyBody)

		opaURL := s.cfg.OPADirectURL + "/v1/data/authorize"
		opaCode, opaBody, _, _, err := DoHTTPFull("POST", opaURL, headers, bodyBytes)
		s.Require().NoError(err)

		s.Require().Equal(envoyCode, opaCode,
			"ADR-0062 cross-transport parity: status codes must match (envoy=%d, opa-direct=%d)",
			envoyCode, opaCode)
		s.Require().Equal(200, envoyCode,
			"both transports must return 200 OK for a well-formed canonical authorize request; got envoy=%d, opa-direct=%d; envoy-body=%s; opa-direct-body=%s",
			envoyCode, opaCode, truncateBody(envoyBody), truncateBody(opaBody))
		// decision_id is OPA-minted per evaluation — two independent calls produce
		// two distinct UUIDs by design. Mask before bytewise compare so the test
		// catches drift in every other byte of the envelope.
		s.Require().Equal(maskDecisionID(envoyBody), maskDecisionID(opaBody),
			"ADR-0062 cross-transport parity: response bodies must be byte-identical modulo OPA decision_id (envelope shape `{\"result\": <AuthorizeResponse>}` exposed verbatim on both transports)")
	})
}

// maskDecisionID replaces the OPA-minted per-evaluation decision_id with a
// fixed sentinel so two independent calls can be compared bytewise. OPA always
// emits a fresh UUID for each evaluation, so this field is the only non-stable
// byte in the canonical envelope.
func maskDecisionID(b []byte) string {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(b, &env); err != nil {
		return string(b)
	}
	if _, ok := env["decision_id"]; ok {
		env["decision_id"] = json.RawMessage(`"<masked>"`)
	}
	// ADR-0069: result.requestId is per-request (inbound x-request-id on the
	// Envoy transport, OPA-generated uuid on the OPA-direct transport), so it is
	// non-stable across the two independent calls — mask it like decision_id so
	// the envelopes compare byte-identical modulo the correlation ids.
	if resultRaw, ok := env["result"]; ok {
		var result map[string]json.RawMessage
		if err := json.Unmarshal(resultRaw, &result); err == nil {
			if _, ok := result["requestId"]; ok {
				result["requestId"] = json.RawMessage(`"<masked>"`)
				if remarshaled, err := json.Marshal(result); err == nil {
					env["result"] = remarshaled
				}
			}
		}
	}
	out, err := json.Marshal(env)
	if err != nil {
		return string(b)
	}
	return string(out)
}

func truncateBody(b []byte) string {
	const max = 512
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "…"
}
