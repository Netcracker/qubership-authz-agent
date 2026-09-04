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
	"time"
)

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

// TestOPARequestParity checks that the canonical /access/v1/authorize route
// and the check-family Lua routes hand OPA the same input for one semantic
// request. The evidence is OPA's own decision log: every event carries the
// input OPA evaluated and the two request headers the chart tells OPA to
// record, x-request-id and x-authz-original-path. Each pair of requests is
// tagged with distinct X-Request-Id values, and the collector's download
// endpoint is polled until both events land.
func (s *RuntimeSuite) TestOPARequestParity() {
	s.Step("parity.single_resource", func() {
		token := "Bearer " + s.validAdminToken
		canonical, legacy := s.parityDecisionLogs("parity-single-canonical", "parity-single-legacy",
			func() {
				// Canonical envelope, admission token in the body. The Lua
				// copies user-agent from the inbound frame into the input, so
				// the canonical caller supplies it explicitly to keep the two
				// inputs comparable.
				code, _ := s.postAuthorize(token, token,
					map[string]interface{}{
						"resources": []map[string]interface{}{
							{"resourceType": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{}},
						},
						"requestHeaders": map[string]interface{}{"user-agent": "Go-http-client/1.1"},
					},
					map[string]string{"X-Request-Id": "parity-single-canonical"},
				)
				s.Require().Equal(200, code, "canonical request must succeed")
			},
			func() {
				code, _ := s.post("/access/v1/check/resource?tenant_id=default",
					legacyParityHeaders(token, "parity-single-legacy"),
					map[string]interface{}{"type": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{}},
				)
				s.Require().Equal(200, code, "legacy request must succeed")
			},
		)
		s.assertOPAInputParity(canonical, legacy, "/access/v1/check/resource", "single-resource")
	})

	s.Step("parity.bulk", func() {
		token := "Bearer " + s.validAdminToken
		canonical, legacy := s.parityDecisionLogs("parity-bulk-canonical", "parity-bulk-legacy",
			func() {
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
				s.Require().Equal(200, code, "canonical request must succeed")
			},
			func() {
				code, _ := s.post("/access/v1/check/resource/bulk?tenant_id=default",
					legacyParityHeaders(token, "parity-bulk-legacy"),
					[]map[string]interface{}{
						{"id": "b1", "type": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{}},
						{"id": "b2", "type": "ORDER", "operation": "READ", "resource": map[string]interface{}{}},
					},
				)
				s.Require().Equal(200, code, "legacy request must succeed")
			},
		)
		s.assertOPAInputParity(canonical, legacy, "/access/v1/check/resource/bulk", "bulk")
	})

	s.Step("parity.filter", func() {
		token := "Bearer " + s.validAdminToken
		canonical, legacy := s.parityDecisionLogs("parity-filter-canonical", "parity-filter-legacy",
			func() {
				code, _ := s.postAuthorize(token, token,
					map[string]interface{}{
						"resources": []map[string]interface{}{
							{"resourceType": "ORDER", "operation": "READ", "resource": map[string]interface{}{}},
						},
						"requestHeaders": map[string]interface{}{"user-agent": "Go-http-client/1.1"},
					},
					map[string]string{"X-Request-Id": "parity-filter-canonical"},
				)
				s.Require().Equal(200, code, "canonical request must succeed")
			},
			func() {
				code, _ := s.post("/access/v1/check/filter?resourceType=ORDER&operation=READ",
					legacyParityHeaders(token, "parity-filter-legacy"),
					map[string]interface{}{},
				)
				s.Require().Equal(200, code, "legacy request must succeed")
			},
		)
		s.assertOPAInputParity(canonical, legacy, "/access/v1/check/filter", "filter")
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

// legacyParityHeaders builds the headers of a check-family request tagged
// with the given X-Request-Id.
func legacyParityHeaders(token, requestID string) map[string]string {
	return map[string]string{
		"Content-Type":  "application/json",
		"Authorization": token,
		"X-Request-Id":  requestID,
	}
}

// parityDecisionLogs sends the canonical and the legacy form of one request
// and returns the decision-log event OPA produced for each. The collector
// keeps every event since it started, so the helper counts the events per
// request id first and waits for one more, which keeps reruns against the
// same install honest.
func (s *RuntimeSuite) parityDecisionLogs(canonicalID, legacyID string, sendCanonical, sendLegacy func()) (canonical, legacy map[string]any) {
	before := s.decisionLogsByRequestID()
	wanted := map[string]int{
		canonicalID: len(before[canonicalID]) + 1,
		legacyID:    len(before[legacyID]) + 1,
	}
	sendCanonical()
	sendLegacy()
	latest := s.waitForDecisionLogs(wanted)
	return latest[canonicalID], latest[legacyID]
}

// decisionLogsByRequestID downloads the collector's NDJSON through Envoy and
// groups the events by x-request-id, in ingestion order.
func (s *RuntimeSuite) decisionLogsByRequestID() map[string][]map[string]any {
	status, body := s.get("/internal/v1/decision-logs", nil)
	s.Require().Equal(200, status, "decision-log download must succeed; body: %s", string(body))
	byID := map[string][]map[string]any{}
	for i, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var event map[string]any
		s.Require().NoError(json.Unmarshal([]byte(line), &event), "decision log line %d is not valid JSON: %q", i+1, line)
		for _, id := range decisionLogHeaderValues(event, "x-request-id") {
			byID[id] = append(byID[id], event)
		}
	}
	return byID
}

// waitForDecisionLogs polls until every request id has at least the wanted
// number of events and returns the newest event per id.
func (s *RuntimeSuite) waitForDecisionLogs(wanted map[string]int) map[string]map[string]any {
	deadline := time.Now().Add(40 * time.Second)
	for {
		byID := s.decisionLogsByRequestID()
		latest := map[string]map[string]any{}
		for id, count := range wanted {
			if events := byID[id]; len(events) >= count {
				latest[id] = events[len(events)-1]
			}
		}
		if len(latest) == len(wanted) {
			return latest
		}
		s.Require().True(time.Now().Before(deadline), "decision logs for %v did not arrive within 40s", wanted)
		time.Sleep(500 * time.Millisecond)
	}
}

// decisionLogInput returns the input OPA evaluated, without requestId: the
// two requests of a pair carry different x-request-id values by
// construction, and the Lua plumbs that header into the field. An event
// without an input object fails the step, because comparing two empty maps
// would pass without having compared anything.
func (s *RuntimeSuite) decisionLogInput(event map[string]any, what string) map[string]interface{} {
	input, _ := event["input"].(map[string]any)
	s.Require().NotEmpty(input, "%s decision-log event carries no input object", what)
	out := make(map[string]interface{}, len(input))
	for k, v := range input {
		out[k] = v
	}
	delete(out, "requestId")
	return out
}

// assertOPAInputParity compares what OPA received for the two forms of one
// request: the inputs must match, the canonical route must not set
// x-authz-original-path, and the legacy route must set it to its own path.
func (s *RuntimeSuite) assertOPAInputParity(canonical, legacy map[string]any, legacyPath, what string) {
	diffs := compareOPAInputs(s.decisionLogInput(canonical, "canonical"), s.decisionLogInput(legacy, "legacy"))
	s.Assert().Empty(diffs, "OPA input must be identical for %s parity; diffs: %v", what, diffs)
	s.Assert().Empty(decisionLogHeaderValues(canonical, "x-authz-original-path"),
		"canonical route must not set x-authz-original-path")
	s.Assert().Equal([]string{legacyPath}, decisionLogHeaderValues(legacy, "x-authz-original-path"),
		"legacy route must set x-authz-original-path to its own path")
}
