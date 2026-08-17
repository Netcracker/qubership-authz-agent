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

// TestOPALockdown validates the OPA --authorization=basic + --authentication=token
// lock-down per authz-agent-ADR-0077. The combined policy:
//   - Blocks all direct GET reads of /v1/data/m2m so the M2M bearer token
//     (published there by the TokenWatcher) is not readable by any pod in the
//     namespace, and of /v1/data/pips alongside it.
//   - Blocks PUT /v1/data/** without the shared OPA auth token.
//   - Allows PUT /v1/data/** with the correct OPA auth token.
//
// POST /v1/data/authorize → 200 is a regression check confirming the lock-down
// did not block the canonical authorization path. That assertion is already
// part of authorize.envoy_opa_direct.bytewise_response_parity; we cross-
// reference it here in a comment only.
func (s *RuntimeSuite) TestOPALockdown() {
	// ── GET /v1/data/m2m and /v1/data/pips → 401 ───────────────────────────
	// system_authz.rego: default allow := false — no rule permits GET on any
	// /v1/data/* path. OPA with --authorization=basic returns 401 when the
	// policy denies a request (observed with OPA ≥ 1.16). The 401 on
	// /v1/data/m2m protects the bearer token published there by the
	// TokenWatcher goroutine; the one on /v1/data/pips covers the PIP
	// configuration next to it.
	//
	// The token lives under its own document root and NOT under data.pips:
	// PolicyPuller replaces data.pips wholesale every tick, so a token stored
	// there is erased within one interval (ADR-0076).
	//
	// NOTE: OPA's --authorization=basic returns 401 (not 403) for policy denials.
	// We accept both to stay robust across OPA version changes. See ADR-0077.
	s.Step("opa_lockdown.m2m_get_forbidden.403", func() {
		opaURL := s.cfg.OPADirectURL + "/v1/data/m2m"
		code, body, err := DoHTTP("GET", opaURL, nil, nil)
		s.Require().NoError(err, "GET %s should not produce a network error", opaURL)
		s.Assert().Contains([]int{401, 403}, code,
			"GET /v1/data/m2m on OPA-direct port must be blocked by system.authz policy (ADR-0077); got HTTP %d",
			code)
		// Verify the body does not leak the token under either key name.
		var parsed map[string]any
		if json.Unmarshal(body, &parsed) == nil {
			s.Assert().NotContains(string(body), "bearerToken",
				"GET /v1/data/m2m response must not expose the M2M bearer token")
		}
	})

	s.Step("opa_lockdown.pips_get_forbidden.403", func() {
		opaURL := s.cfg.OPADirectURL + "/v1/data/pips"
		code, body, err := DoHTTP("GET", opaURL, nil, nil)
		s.Require().NoError(err, "GET %s should not produce a network error", opaURL)
		s.Assert().Contains([]int{401, 403}, code,
			"GET /v1/data/pips on OPA-direct port must be blocked by system.authz policy (ADR-0077); got HTTP %d",
			code)
		// The token must not be reachable through the PIP document either — it
		// was co-located there before ADR-0076 was corrected.
		var parsed map[string]any
		if json.Unmarshal(body, &parsed) == nil {
			s.Assert().NotContains(string(body), "m2mBearerToken",
				"GET /v1/data/pips response must not expose m2mBearerToken")
		}
	})

	// ── POST /v1/data/authorize?explain=full → 401 ─────────────────────────
	// The canonical endpoint must stay open (it is published on the public
	// gateway with no ext_authz hop), but OPA honours query parameters on that
	// same POST. `?explain=full` returns the evaluation trace, whose `locals`
	// carry resolved values — including data.m2m.bearerToken as bound by
	// pip.rego. Envoy's prefix_rewrite pins the path and preserves the query
	// string, so an open `explain` is an unauthenticated credential read from
	// the public internet. system_authz.rego refuses it for everyone (ADR-0077).
	s.Step("opa_lockdown.authorize_explain_forbidden.401", func() {
		opaURL := s.cfg.OPADirectURL + "/v1/data/authorize?explain=full"
		code, body, err := DoHTTP("POST", opaURL, nil, []byte(`{"input":{}}`))
		s.Require().NoError(err, "POST %s should not produce a network error", opaURL)
		s.Assert().Contains([]int{401, 403}, code,
			"POST /v1/data/authorize?explain=full must be refused (ADR-0077); got HTTP %d", code)
		// Belt and braces: whatever the status, no trace may come back.
		s.Assert().NotContains(string(body), "\"locals\"",
			"the explain trace must not be returned on the canonical endpoint")
	})

	// The plain POST must still work — the guard is on introspection, not on
	// the decision. A regression that closed the endpoint itself would break
	// every public-gateway caller.
	s.Step("opa_lockdown.authorize_plain_still_open.200", func() {
		opaURL := s.cfg.OPADirectURL + "/v1/data/authorize"
		// This is the only step here that reaches the authorize path, so it
		// produces a decision-log entry. TestZZDecisionLogsCatalogCoverage
		// requires every authorize entry to carry x-request-id equal to a
		// catalog step name — without the header the run fails there, several
		// tests away from the cause.
		headers := map[string]string{"x-request-id": "opa_lockdown.authorize_plain_still_open.200"}
		code, _, err := DoHTTP("POST", opaURL, headers, []byte(`{"input":{}}`))
		s.Require().NoError(err, "POST %s should not produce a network error", opaURL)
		s.Assert().Equal(200, code,
			"POST /v1/data/authorize without parameters must remain open (ADR-0062); got HTTP %d", code)
	})

	// ── PUT /v1/data/opa-lockdown-test WITHOUT Authorization → 401 ──────────
	// With --authentication=token, a request with no Bearer token has
	// input.identity.token undefined in system_authz.rego, which does not
	// satisfy input.identity.token == data.opa_auth_secret → deny → 401.
	s.Step("opa_lockdown.write_without_auth.401", func() {
		opaURL := s.cfg.OPADirectURL + "/v1/data/opa-lockdown-test"
		code, _, err := DoHTTP("PUT", opaURL, nil, []byte(`{"probe":true}`))
		s.Require().NoError(err, "PUT %s without auth should not produce a network error", opaURL)
		s.Assert().Contains([]int{401, 403}, code,
			"PUT /v1/data/opa-lockdown-test without Authorization must be blocked (ADR-0077); got HTTP %d",
			code)
	})

	// ── PUT /v1/data/opa-lockdown-test WITH correct Authorization → 204 ─────
	// With the correct OPA auth token in Authorization: Bearer, system_authz.rego
	// allows the PUT: input.identity.token == data.opa_auth_secret → allow → 204.
	// OPA returns 204 No Content for successful data API writes.
	s.Step("opa_lockdown.write_with_auth.204", func() {
		opaURL := s.cfg.OPADirectURL + "/v1/data/opa-lockdown-test"
		headers := map[string]string{
			"Authorization": "Bearer " + s.cfg.OPAAuthToken,
		}
		code, _, err := DoHTTP("PUT", opaURL, headers, []byte(`{"probe":true}`))
		s.Require().NoError(err, "PUT %s with auth should not produce a network error", opaURL)
		s.Assert().Equal(204, code,
			"PUT /v1/data/opa-lockdown-test with correct OPA auth token must succeed (ADR-0077); got HTTP %d",
			code)
	})
}
