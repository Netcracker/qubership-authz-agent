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
	"sort"
	"strings"
)

// normalizeOPAInput parses captured OPA request body and returns a normalized
// map for comparison. It removes the "input" envelope if present and strips
// x-authz-original-path from the requestHeaders sub-object.
func normalizeOPAInput(raw string) (map[string]interface{}, error) {
	var envelope map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		return nil, err
	}
	input, ok := envelope["input"].(map[string]interface{})
	if !ok {
		input = envelope
	}
	// ADR-0069: requestId is the inbound x-request-id plumbed by the Lua filter;
	// it is per-request (Envoy mints a fresh one per call) and therefore differs
	// between the two independent captures — strip it before the shape compare,
	// like the other transport-injected, non-deterministic fields.
	delete(input, "requestId")
	return input, nil
}

// compareOPAInputs compares two OPA input maps and returns any mismatched keys.
// The comparison ignores JSON key ordering by using parsed maps.
func compareOPAInputs(a, b map[string]interface{}) []string {
	var diffs []string

	allKeys := make(map[string]bool)
	for k := range a {
		allKeys[k] = true
	}
	for k := range b {
		allKeys[k] = true
	}

	for k := range allKeys {
		va, oka := a[k]
		vb, okb := b[k]
		if !oka {
			diffs = append(diffs, "key "+k+" missing in canonical")
			continue
		}
		if !okb {
			diffs = append(diffs, "key "+k+" missing in legacy")
			continue
		}
		ja, _ := json.Marshal(va)
		jb, _ := json.Marshal(vb)
		if string(ja) != string(jb) {
			diffs = append(diffs, "key "+k+" differs: canonical="+string(ja)+" legacy="+string(jb))
		}
	}

	sort.Strings(diffs)
	return diffs
}

// skipParityHeaders lists OPA-bound HTTP-frame headers excluded from parity
// comparison. The parity contract that matters is the OPA *input body*
// (compareOPAInputs) — Rego reads its decision inputs from the body, never
// from these transport-frame headers. The headers below are excluded because
// they are transport-level and, under ADR-0062, diverge by design between the
// routing-only canonical path and the Lua-normalized legacy path:
//   - authorization: ADR-0062 moves the admission token into the body
//     (input.authorizationToken); canonical sends no HTTP Authorization header
//     while legacy still carries the inbound Bearer on the frame. OPA reads the
//     token from the body on both, so the frame header is policy-irrelevant and
//     cannot be made identical without re-adding a header canonical doesn't use.
//   - accept-encoding / content-length: pure transport framing. The legacy Lua
//     strips them from the OPA-bound request (check_resource.lua) and the bodies
//     differ in size between transports, so these can never match and are not
//     decision inputs.
//   - x-authz-original-path: routing-only canonical no longer injects it (R6,
//     ADR-0062); legacy check-family Lua still sets it (ADR-0032). Informational
//     only — no policy logic depends on it.
//   - x-envoy-original-path: Envoy infrastructure header (path before prefix_rewrite).
//   - x-request-id: unique per request, used for correlation only.
var skipParityHeaders = map[string]bool{
	"authorization":         true,
	"accept-encoding":       true,
	"content-length":        true,
	"x-authz-original-path": true,
	"x-envoy-original-path": true,
	"x-request-id":          true,
}

// compareHeaders compares two header maps, ignoring parity-excluded headers (case-insensitive).
func compareHeaders(a, b map[string]string) []string {
	var diffs []string
	allKeys := make(map[string]bool)
	for k := range a {
		allKeys[strings.ToLower(k)] = true
	}
	for k := range b {
		allKeys[strings.ToLower(k)] = true
	}

	for k := range allKeys {
		if skipParityHeaders[k] {
			continue
		}
		va := headerGet(a, k)
		vb := headerGet(b, k)
		if va != vb {
			diffs = append(diffs, "header "+k+" differs: canonical="+va+" legacy="+vb)
		}
	}

	sort.Strings(diffs)
	return diffs
}

func headerGet(h map[string]string, key string) string {
	for k, v := range h {
		if strings.ToLower(k) == key {
			return v
		}
	}
	return ""
}

func (s *RuntimeSuite) TestOPARequestParity() {
	s.Step("parity.capture_reset", func() {
		err := ResetCapture(s.cfg.UpstreamCaptureURL)
		s.Require().NoError(err, "capture reset must succeed")
	})

	s.Step("parity.single_resource", func() {
		token := "Bearer " + s.validAdminToken

		// ── canonical request (ADR-0062 envelope, admission token in body) ──
		s.Require().NoError(ResetCapture(s.cfg.UpstreamCaptureURL))
		code, _ := s.postAuthorize(token, token,
			map[string]interface{}{
				"resources": []map[string]interface{}{
					{"resourceType": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{}},
				},
				// Mirror the requestHeaders the legacy Lua captures from the
				// inbound frame (user-agent is not in skip_headers, so it lands
				// in the OPA input body). ADR-0062 moves header capture to the
				// client, so the canonical caller supplies it explicitly.
				"requestHeaders": map[string]interface{}{"user-agent": "Go-http-client/1.1"},
			},
			map[string]string{"X-Request-Id": "parity-single-canonical"},
		)
		s.Require().Equal(200, code, "canonical request must succeed")

		canonicalCaptures, err := GetCapturedRequests(s.cfg.UpstreamCaptureURL, "parity-single-canonical")
		s.Require().NoError(err)
		s.Require().Len(canonicalCaptures, 1, "exactly one canonical capture expected")

		// ── legacy request ──
		s.Require().NoError(ResetCapture(s.cfg.UpstreamCaptureURL))
		legacyH := map[string]string{
			"Content-Type":  "application/json",
			"Authorization": token,
			"X-Request-Id":  "parity-single-legacy",
		}
		legacyBody := map[string]interface{}{
			"type": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{},
		}
		code, _ = s.post("/access/v1/check/resource?tenant_id=default", legacyH, legacyBody)
		s.Require().Equal(200, code, "legacy request must succeed")

		legacyCaptures, err := GetCapturedRequests(s.cfg.UpstreamCaptureURL, "parity-single-legacy")
		s.Require().NoError(err)
		s.Require().Len(legacyCaptures, 1, "exactly one legacy capture expected")

		// ── compare OPA-bound bodies ──
		canonicalInput, err := normalizeOPAInput(canonicalCaptures[0].Body)
		s.Require().NoError(err)
		legacyInput, err := normalizeOPAInput(legacyCaptures[0].Body)
		s.Require().NoError(err)

		bodyDiffs := compareOPAInputs(canonicalInput, legacyInput)
		s.Assert().Empty(bodyDiffs, "OPA input body must be identical for single-resource parity; diffs: %v", bodyDiffs)

		// ── compare OPA-bound headers (excluding skipParityHeaders) ──
		headerDiffs := compareHeaders(canonicalCaptures[0].Headers, legacyCaptures[0].Headers)
		s.Assert().Empty(headerDiffs, "OPA-bound headers must be identical except skipParityHeaders; diffs: %v", headerDiffs)

		// ── verify x-authz-original-path: routing-only canonical injects none
		// (R6, ADR-0062); legacy check-family Lua still sets it (ADR-0032). ──
		canonicalPath := headerGet(canonicalCaptures[0].Headers, "x-authz-original-path")
		legacyPath := headerGet(legacyCaptures[0].Headers, "x-authz-original-path")
		s.Assert().Equal("", canonicalPath)
		s.Assert().Equal("/access/v1/check/resource", legacyPath)
	})

	s.Step("parity.bulk", func() {
		token := "Bearer " + s.validAdminToken

		// ── canonical request (ADR-0062 envelope, admission token in body) ──
		s.Require().NoError(ResetCapture(s.cfg.UpstreamCaptureURL))
		code, _ := s.postAuthorize(token, token,
			map[string]interface{}{
				"resources": []map[string]interface{}{
					{"resourceType": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{}},
					{"resourceType": "ORDER", "operation": "READ", "resource": map[string]interface{}{}},
				},
				"requestHeaders": map[string]interface{}{"user-agent": "Go-http-client/1.1"},
			},
			map[string]string{"X-Request-Id": "parity-bulk-canonical"},
		)
		s.Require().Equal(200, code)

		canonicalCaptures, err := GetCapturedRequests(s.cfg.UpstreamCaptureURL, "parity-bulk-canonical")
		s.Require().NoError(err)
		s.Require().Len(canonicalCaptures, 1)

		// ── legacy bulk request ──
		s.Require().NoError(ResetCapture(s.cfg.UpstreamCaptureURL))
		legacyH := map[string]string{
			"Content-Type":  "application/json",
			"Authorization": token,
			"X-Request-Id":  "parity-bulk-legacy",
		}
		legacyBody := []map[string]interface{}{
			{"id": "b1", "type": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{}},
			{"id": "b2", "type": "ORDER", "operation": "READ", "resource": map[string]interface{}{}},
		}
		code, _ = s.post("/access/v1/check/resource/bulk?tenant_id=default", legacyH, legacyBody)
		s.Require().Equal(200, code)

		legacyCaptures, err := GetCapturedRequests(s.cfg.UpstreamCaptureURL, "parity-bulk-legacy")
		s.Require().NoError(err)
		s.Require().Len(legacyCaptures, 1)

		// ── compare OPA-bound bodies ──
		canonicalInput, err := normalizeOPAInput(canonicalCaptures[0].Body)
		s.Require().NoError(err)
		legacyInput, err := normalizeOPAInput(legacyCaptures[0].Body)
		s.Require().NoError(err)

		bodyDiffs := compareOPAInputs(canonicalInput, legacyInput)
		s.Assert().Empty(bodyDiffs, "OPA input body must be identical for bulk parity; diffs: %v", bodyDiffs)

		// ── compare OPA-bound headers ──
		headerDiffs := compareHeaders(canonicalCaptures[0].Headers, legacyCaptures[0].Headers)
		s.Assert().Empty(headerDiffs, "OPA-bound headers must match for bulk parity; diffs: %v", headerDiffs)

		// ── verify x-authz-original-path: canonical injects none (R6); legacy sets it ──
		s.Assert().Equal("", headerGet(canonicalCaptures[0].Headers, "x-authz-original-path"))
		s.Assert().Equal("/access/v1/check/resource/bulk", headerGet(legacyCaptures[0].Headers, "x-authz-original-path"))
	})

	s.Step("parity.filter", func() {
		token := "Bearer " + s.validAdminToken

		// ── canonical request (ADR-0062 envelope, admission token in body) ──
		s.Require().NoError(ResetCapture(s.cfg.UpstreamCaptureURL))
		code, _ := s.postAuthorize(token, token,
			map[string]interface{}{
				"resources": []map[string]interface{}{
					{"resourceType": "ORDER", "operation": "READ", "resource": map[string]interface{}{}},
				},
				"requestHeaders": map[string]interface{}{"user-agent": "Go-http-client/1.1"},
			},
			map[string]string{"X-Request-Id": "parity-filter-canonical"},
		)
		s.Require().Equal(200, code)

		canonicalCaptures, err := GetCapturedRequests(s.cfg.UpstreamCaptureURL, "parity-filter-canonical")
		s.Require().NoError(err)
		s.Require().Len(canonicalCaptures, 1)

		// ── legacy filter request ──
		s.Require().NoError(ResetCapture(s.cfg.UpstreamCaptureURL))
		legacyH := map[string]string{
			"Content-Type":  "application/json",
			"Authorization": token,
			"X-Request-Id":  "parity-filter-legacy",
		}
		code, _ = s.post("/access/v1/check/filter?resourceType=ORDER&operation=READ", legacyH, map[string]interface{}{})
		s.Require().Equal(200, code)

		legacyCaptures, err := GetCapturedRequests(s.cfg.UpstreamCaptureURL, "parity-filter-legacy")
		s.Require().NoError(err)
		s.Require().Len(legacyCaptures, 1)

		// ── compare OPA-bound bodies ──
		canonicalInput, err := normalizeOPAInput(canonicalCaptures[0].Body)
		s.Require().NoError(err)
		legacyInput, err := normalizeOPAInput(legacyCaptures[0].Body)
		s.Require().NoError(err)

		bodyDiffs := compareOPAInputs(canonicalInput, legacyInput)
		s.Assert().Empty(bodyDiffs, "OPA input body must be identical for filter parity; diffs: %v", bodyDiffs)

		// ── compare OPA-bound headers ──
		headerDiffs := compareHeaders(canonicalCaptures[0].Headers, legacyCaptures[0].Headers)
		s.Assert().Empty(headerDiffs, "OPA-bound headers must match for filter parity; diffs: %v", headerDiffs)

		// ── verify x-authz-original-path: canonical injects none (R6); legacy sets it ──
		s.Assert().Equal("", headerGet(canonicalCaptures[0].Headers, "x-authz-original-path"))
		s.Assert().Equal("/access/v1/check/filter", headerGet(legacyCaptures[0].Headers, "x-authz-original-path"))
	})

	s.Step("parity.response_envelope_shape", func() {
		// authz-agent-ADR-0062: the canonical Envoy surface
		// (`/access/v1/authorize`) must surface the OPA Data API envelope
		// `{"result": <AuthorizeResponse>}` verbatim. Pre-ADR-0062 the
		// per-route Lua filter unwrapped `.result` before returning to the
		// caller; post-cutover the filter is gone and the envelope is
		// passed through. The other parity steps go through
		// `s.postAuthorize`, which transparently unwraps `result` for
		// assertion convenience — so a regression that breaks the
		// envelope on the wire would not be caught by those steps. This
		// step bypasses the unwrap helper and asserts the raw wire shape.
		token := "Bearer " + s.validAdminToken
		body := canonicalAuthorizeBody(token, token, map[string]interface{}{
			"resources": []map[string]interface{}{
				{"resourceType": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{}},
			},
		})
		headers := s.headersWithRequestID(jsonHeader())
		envoyURL := s.cfg.BaseURL + "/access/v1/authorize"
		code, raw, reqBody, respHdr, err := DoHTTPFull("POST", envoyURL, headers, body)
		s.Require().NoError(err)
		assertConformsToSpec(s.T(), "POST", envoyURL, headers, reqBody, code, respHdr, raw)
		s.Require().Equal(200, code, "canonical authorize must succeed; body=%s", string(raw))

		var env map[string]json.RawMessage
		s.Require().NoError(json.Unmarshal(raw, &env),
			"canonical authorize response must be a JSON object; body=%s", string(raw))
		result, ok := env["result"]
		s.Require().True(ok,
			"canonical authorize response must carry the OPA Data API envelope `result` (ADR-0062); body=%s", string(raw))

		var inner map[string]interface{}
		s.Require().NoError(json.Unmarshal(result, &inner),
			"envelope.result must decode as the canonical AuthorizeResponse object; result=%s", string(result))
		_, hasResults := inner["results"]
		s.Assert().True(hasResults,
			"envelope.result must carry the canonical AuthorizeResponse.results field; result=%s", string(result))
	})

	s.Step("parity.original_path_no_effect", func() {
		token := "Bearer " + s.validAdminToken

		// Two identical canonical requests with different x-authz-original-path injected
		// via the same canonical endpoint. We test this by comparing the OPA policy
		// result for a canonical call vs the same semantic request via a legacy path.
		// Both must produce the same authorization outcome.

		// ── canonical authorize (ADR-0062 envelope, admission token in body) ──
		code1, b1 := s.postAuthorize(token, token,
			map[string]interface{}{
				"resources": []map[string]interface{}{
					{"resourceType": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{}},
				},
				"ignoreRls": false,
			},
			map[string]string{"X-Request-Id": "parity-path-canonical"},
		)
		s.Require().Equal(200, code1)

		// ── legacy check/resource (same semantic request) ──
		h2 := map[string]string{
			"Content-Type":  "application/json",
			"Authorization": token,
			"X-Request-Id":  "parity-path-legacy",
		}
		legacyBody := map[string]interface{}{
			"type": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{},
		}
		code2, b2 := s.post("/access/v1/check/resource?tenant_id=default", h2, legacyBody)
		s.Require().Equal(200, code2)

		// Extract canonical isAllowed.
		j1 := jsonObj(b1)
		results1, ok := j1["results"].([]interface{})
		s.Require().True(ok && len(results1) > 0)
		isAllowed1 := results1[0].(map[string]interface{})["isAllowed"].(bool)

		// Legacy returns boolean string.
		legacyResult := bodyStr(b2)
		expectedLegacy := "false"
		if isAllowed1 {
			expectedLegacy = "true"
		}
		s.Assert().Equal(expectedLegacy, legacyResult,
			"x-authz-original-path must not affect policy result; canonical=%v legacy=%s", isAllowed1, legacyResult)
	})
}
