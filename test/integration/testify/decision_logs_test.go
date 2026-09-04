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
	"regexp"
	"sort"
	"strings"
	"time"
)

// fullJWTPattern matches a complete JWT with or without a `Bearer ` prefix:
// header, payload and signature. `eyJ` is base64url for `{"`, the start of
// every JWT header. A logged token must have lost its signature.
var fullJWTPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

func (s *RuntimeSuite) TestDecisionLogs() {
	// Positive regression: GET /internal/v1/decision-logs with no
	// pap-client token header must succeed. Body may be empty when
	// the collector has not received any events yet; the assertion is
	// purely on the 200 status and on a parseable JSON-stream body when
	// non-empty.
	s.Step("decision_logs.download_no_token.200", func() {
		status, body := s.get("/internal/v1/decision-logs", nil)
		s.Require().Equal(200, status, "expected 200 without token, got %d body=%s", status, bodyStr(body))
		content := strings.TrimSpace(string(body))
		if content == "" {
			return
		}
		for i, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var obj map[string]any
			err := json.Unmarshal([]byte(line), &obj)
			s.Require().NoError(err, "line %d is not valid JSON: %q", i+1, line)
		}
	})

	// Make a canonical authorize request to seed a decision log entry with a known request ID.
	s.Step("decision_logs.canonical_path_header", func() {
		token := "Bearer " + s.validAdminToken
		code, _ := s.postAuthorize(token, token, map[string]interface{}{
			"resources": []map[string]interface{}{
				{"resourceType": "ORDER", "operation": "READ"},
			},
			"ignoreRls": true,
		})
		s.Require().Equal(200, code)
	})

	// Make a legacy check/resource request to seed a decision log entry with a known request ID.
	s.Step("decision_logs.legacy_path_header", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := map[string]interface{}{
			"type": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{},
		}
		code, _ := s.post("/access/v1/check/resource?tenant_id=default", h, body)
		s.Require().Equal(200, code)
	})

	s.Step("decision_logs.content_is_ndjson", func() {
		// OPA ships decision logs in async batches (~once/second, see
		// opa-config.yaml min_delay_seconds/max_delay_seconds), so the two
		// RLS-deny events emitted by the immediately-preceding steps can land
		// a beat after this step starts. Retry until the specific request IDs
		// this step asserts are all present (or the deadline lapses), instead
		// of breaking on the first non-empty batch (R11).
		requiredRequestIDs := []string{
			"setup.wait_for_agent",
			"authorize.order_read.rls_true.deny",
			"check_resource.order_read.rls_deny",
			"check_resource_bulk.owner_mismatch.denied",
			"check_filter.calculation_result_present",
		}

		var content string
		var seenRequestIDs map[string]bool
		var logsByRequestID map[string]map[string]any
		authorizeEvents := 0

		deadline := time.Now().Add(35 * time.Second)
		for {
			status, responseBody := s.get("/internal/v1/decision-logs", nil)
			s.Require().Equal(200, status)
			content = strings.TrimSpace(string(responseBody))

			seenRequestIDs = map[string]bool{}
			logsByRequestID = map[string]map[string]any{}
			authorizeEvents = 0

			// Verify every non-empty line is valid JSON and index by x-request-id.
			for i, line := range strings.Split(content, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var obj map[string]any
				err := json.Unmarshal([]byte(line), &obj)
				s.Require().NoError(err, "line %d is not valid JSON: %q", i+1, line)

				if !decisionLogTargetsAuthorize(obj) {
					continue
				}

				authorizeEvents++
				requestIDs := decisionLogHeaderValues(obj, "x-request-id")
				s.Require().NotEmpty(requestIDs, "authorize decision log line %d must include x-request-id", i+1)
				for _, requestID := range requestIDs {
					if isParityTestRequestID(requestID) {
						continue
					}
					_, knownStep := CatalogByName[requestID]
					s.Require().True(knownStep, "authorize decision log line %d contains unknown x-request-id %q", i+1, requestID)
					seenRequestIDs[requestID] = true
					logsByRequestID[requestID] = obj
				}
			}

			allPresent := true
			for _, requestID := range requiredRequestIDs {
				if !seenRequestIDs[requestID] {
					allPresent = false
					break
				}
			}
			if allPresent || time.Now().After(deadline) {
				break
			}
			time.Sleep(1 * time.Second)
		}

		s.Require().NotEmpty(content, "decision log file remained empty before timeout")
		s.Assert().NotRegexp(fullJWTPattern, content, "decision logs must not contain reusable full JWTs")

		s.Require().Greater(authorizeEvents, 0, "expected at least one authorize decision log event")
		for _, requestID := range requiredRequestIDs {
			s.Assert().True(seenRequestIDs[requestID], "expected authorize decision logs to include x-request-id %q", requestID)
		}

		// Canonical route is routing-only (ADR-0062 audit row 6 = D): Envoy
		// only prefix_rewrites /access/v1/authorize → /v1/data/authorize with
		// zero header/body mutation, so x-authz-original-path is NOT injected.
		// An OPA-direct caller on /v1/data/authorize wouldn't carry it either —
		// asserting its absence locks in cross-transport parity.
		if canonicalLog, ok := logsByRequestID["decision_logs.canonical_path_header"]; ok {
			originalPath := decisionLogSingleHeaderValue(canonicalLog, "x-authz-original-path")
			s.Assert().Equal("", originalPath,
				"canonical route is routing-only: x-authz-original-path must be absent, got %q", originalPath)

			// Canonical result must have rlsIgnored + results shape.
			s.Assert().True(decisionLogResultIsCanonical(canonicalLog),
				"canonical authorize decision log must have canonical result shape (rlsIgnored + results)")
		}

		// Assert x-authz-original-path for legacy route (/access/v1/check/resource).
		if legacyLog, ok := logsByRequestID["decision_logs.legacy_path_header"]; ok {
			originalPath := decisionLogSingleHeaderValue(legacyLog, "x-authz-original-path")
			s.Assert().Equal("/access/v1/check/resource", originalPath,
				"legacy check/resource decision log must have x-authz-original-path=/access/v1/check/resource, got %q", originalPath)

			// Legacy route OPA result must be canonical shape (not boolean/array/filter).
			s.Assert().True(decisionLogResultIsCanonical(legacyLog),
				"legacy check/resource decision log must have canonical OPA result shape (rlsIgnored + results), not legacy shape")
		}
	})
}

// TestZZDecisionLogsCatalogCoverage runs at the end of the suite (lexicographically)
// and verifies that all catalog steps that should reach OPA decisioning are persisted
// in decision logs with x-request-id equal to the step name.
func (s *RuntimeSuite) TestZZDecisionLogsCatalogCoverage() {
	s.Step("decision_logs.catalog_coverage", func() {
		expected := expectedDecisionLogStepNames(s.cfg)
		s.Require().NotEmpty(expected, "expected decision-log step set must not be empty")

		deadline := time.Now().Add(35 * time.Second)
		var missing []string

		for {
			status, body := s.get("/internal/v1/decision-logs", nil)
			s.Require().Equal(200, status)

			content := strings.TrimSpace(string(body))
			seen := map[string]bool{}
			logsByRequestID := map[string]map[string]any{}

			if content != "" {
				for i, line := range strings.Split(content, "\n") {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}

					var obj map[string]any
					err := json.Unmarshal([]byte(line), &obj)
					s.Require().NoError(err, "line %d is not valid JSON: %q", i+1, line)

					if !decisionLogTargetsAuthorize(obj) {
						continue
					}

					requestIDs := decisionLogHeaderValues(obj, "x-request-id")
					s.Require().NotEmpty(requestIDs,
						"authorize decision log line %d must include x-request-id", i+1)

					for _, requestID := range requestIDs {
						if isParityTestRequestID(requestID) {
							continue
						}
						_, knownStep := CatalogByName[requestID]
						s.Require().True(knownStep,
							"authorize decision log line %d contains unknown x-request-id %q", i+1, requestID)
						seen[requestID] = true
						logsByRequestID[requestID] = obj
					}
				}
			}

			missing = missingExpectedDecisionLogSteps(expected, seen)
			if len(missing) == 0 {
				// Canonical route is routing-only: x-authz-original-path must be
				// absent (audit row 6 = D). The canonical result shape is the
				// surviving route discriminator in the decision log.
				canonicalLog, ok := logsByRequestID["decision_logs.canonical_path_header"]
				s.Require().True(ok, "missing decision log for decision_logs.canonical_path_header")
				s.Assert().Equal("", decisionLogSingleHeaderValue(canonicalLog, "x-authz-original-path"),
					"canonical route is routing-only: x-authz-original-path must be absent")
				s.Assert().True(decisionLogResultIsCanonical(canonicalLog),
					"canonical route decision log must keep canonical result shape")

				// Legacy path header must be preserved and result must stay canonical in OPA logs.
				legacyLog, ok := logsByRequestID["decision_logs.legacy_path_header"]
				s.Require().True(ok, "missing decision log for decision_logs.legacy_path_header")
				s.Assert().Equal("/access/v1/check/resource", decisionLogSingleHeaderValue(legacyLog, "x-authz-original-path"))
				s.Assert().True(decisionLogResultIsCanonical(legacyLog),
					"legacy route decision log must keep canonical result shape in OPA logs")

				// GENERAL PIP full HTTP response must be persisted in decision logs
				// via OPA-native nd_builtin_cache (authz-agent-ADR-0063 — replaces
				// the retired result.pipTrace[] channel). The allowedCustomers PIP
				// is the http.send whose request URL hits /api/v1/pip/allowed.
				pipLog, ok := logsByRequestID["pip_general.active_pip_called"]
				s.Require().True(ok, "missing decision log for pip_general.active_pip_called")
				pipResponse, ok := decisionLogHTTPSendResponse(pipLog, "/api/v1/pip/allowed")
				s.Require().True(ok, "decision log for pip_general.active_pip_called must include nd_builtin_cache http.send entry for allowedCustomers")
				s.Require().Contains(pipResponse, "body")
				s.Require().Contains(pipResponse, "headers")
				s.Require().Contains(pipResponse, "raw_body")
				s.Require().Contains(pipResponse, "status")
				s.Require().Contains(pipResponse, "status_code")

				pipBodyRaw := pipResponse["body"]
				pipBody, ok := pipBodyRaw.([]any)
				s.Require().True(ok, "nd_builtin_cache http.send (allowedCustomers) body must be JSON array")
				s.Assert().Equal([]any{"C1", "C2", "C3"}, pipBody,
					"decision log must store full PIP response body for allowedCustomers")

				pipStatusCode, ok := pipResponse["status_code"].(float64)
				s.Require().True(ok, "nd_builtin_cache http.send (allowedCustomers) status_code must be numeric")
				s.Assert().Equal(float64(200), pipStatusCode)

				pipStatus, ok := pipResponse["status"].(string)
				s.Require().True(ok, "nd_builtin_cache http.send (allowedCustomers) status must be string")
				s.Assert().Equal("200 OK", pipStatus)

				pipRawBody, ok := pipResponse["raw_body"].(string)
				s.Require().True(ok, "nd_builtin_cache http.send (allowedCustomers) raw_body must be string")
				s.Assert().Contains(pipRawBody, "\"C1\"")

				pipHeaders, ok := pipResponse["headers"].(map[string]any)
				s.Require().True(ok, "nd_builtin_cache http.send (allowedCustomers) headers must be object")
				s.Assert().NotEmpty(pipHeaders)

				return
			}

			if time.Now().After(deadline) {
				s.Failf("decision_logs.catalog_coverage",
					"missing %d expected decision-log request IDs: %v", len(missing), missing)
				return
			}

			time.Sleep(1 * time.Second)
		}
	})
}

func decisionLogTargetsAuthorize(obj map[string]any) bool {
	path, _ := obj["path"].(string)
	return strings.Contains(path, "authorize")
}

func decisionLogHeaderValues(obj map[string]any, headerName string) []string {
	requestContext, _ := obj["request_context"].(map[string]any)
	httpContext, _ := requestContext["http"].(map[string]any)
	headers, _ := httpContext["headers"].(map[string]any)
	rawValues, ok := headers[headerName]
	if !ok {
		return nil
	}

	switch typed := rawValues.(type) {
	case []any:
		values := make([]string, 0, len(typed))
		for _, value := range typed {
			if str, ok := value.(string); ok && str != "" {
				values = append(values, str)
			}
		}
		return values
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	default:
		return nil
	}
}

// decisionLogSingleHeaderValue returns the first value of a header from a decision log entry.
func decisionLogSingleHeaderValue(obj map[string]any, headerName string) string {
	values := decisionLogHeaderValues(obj, headerName)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// decisionLogResultIsCanonical checks that the OPA decision log result has the canonical
// AuthorizeResponse shape: an object with "rlsIgnored" (bool) and "results" (array).
func decisionLogResultIsCanonical(obj map[string]any) bool {
	result, ok := obj["result"].(map[string]any)
	if !ok {
		return false
	}
	_, hasRlsIgnored := result["rlsIgnored"]
	_, hasResults := result["results"]
	return hasRlsIgnored && hasResults
}

// decisionLogHTTPSendResponse extracts the http.send result for the PIP call
// whose request URL contains urlSubstring from the event's nd_builtin_cache
// (authz-agent-ADR-0063 — replaces the retired result.pipTrace[] channel). OPA
// keys nd_builtin_cache["http.send"] by the JSON-serialized request operand, so
// the backend URL is matched against the cache key.
func decisionLogHTTPSendResponse(obj map[string]any, urlSubstring string) (map[string]any, bool) {
	ndCache, ok := obj["nd_builtin_cache"].(map[string]any)
	if !ok {
		return map[string]any{}, false
	}

	httpSend, ok := ndCache["http.send"].(map[string]any)
	if !ok {
		return map[string]any{}, false
	}

	for key, value := range httpSend {
		if !strings.Contains(key, urlSubstring) {
			continue
		}

		response, ok := value.(map[string]any)
		if !ok {
			return map[string]any{}, false
		}

		return response, true
	}

	return map[string]any{}, false
}

// expectedDecisionLogStepNames returns the list of catalog step names that are
// expected to appear in OPA decision logs. Steps are excluded when:
//   - Their endpoint does not reach the OPA authorize path (e.g. setup, health).
//   - They are rejected before reaching OPA (e.g. 400 validation errors).
//   - They belong to a profile that is not active in this run:
//     m2m_keycloak.* steps are skipped when M2MKeycloakProfile is false, so no
//     decision log entries are produced for them. Including them in the expected
//     set would cause a spurious failure on every non-m2m run (Defect 4).
func expectedDecisionLogStepNames(cfg RuntimeConfig) []string {
	expected := make([]string, 0)

	for _, entry := range Catalog {
		if !catalogStepShouldReachOPA(entry) {
			continue
		}
		if catalogStepRejectedBeforeOPA(entry.Name) {
			continue
		}
		// m2m_keycloak steps are profile-gated: when the m2m-keycloak Compose
		// overlay is not active they call t.Skip() and produce no decision logs.
		if !cfg.M2MKeycloakProfile && strings.HasPrefix(entry.Name, "m2m_keycloak.") {
			continue
		}
		expected = append(expected, entry.Name)
	}

	sort.Strings(expected)
	return expected
}

func catalogStepShouldReachOPA(entry StepEntry) bool {
	parts := strings.Fields(entry.Endpoint)
	if len(parts) < 2 {
		return false
	}

	method := parts[0]
	path := parts[1]
	if method != "POST" {
		return false
	}

	return path == "/access/v1/authorize" ||
		path == "/access/v1/check/resource" ||
		path == "/access/v1/check/resource/bulk" ||
		path == "/access/v1/check/resource/bulk/operations" ||
		path == "/preview/v1/check/resource/bulk/operations" ||
		path == "/access/v1/check/filter" ||
		path == "/access/v2/check/resource" ||
		path == "/access/v2/check/resource/bulk/operations" ||
		path == "/preview/v2/check/resource/bulk/operations" ||
		path == "/access/v2/check/filter"
}

func catalogStepRejectedBeforeOPA(stepName string) bool {
	switch stepName {
	case "check_resource.null_body.400",
		"check_resource.missing_fields.400",
		"check_resource_bulk.null_body.400",
		"check_resource_bulk.missing_type_op.400",
		"check_resource_bulk.duplicate_ids.400",
		"check_filter.missing_resource_type.400":
		return true
	default:
		// Parity tests use custom X-Request-Id values (not the step name)
		// for upstream-capture correlation, so they won't appear in decision
		// logs under their catalog step name.
		if strings.HasPrefix(stepName, "parity.") {
			return true
		}
		return false
	}
}

// isParityTestRequestID returns true for X-Request-Id values used by parity
// tests for upstream-capture correlation. These are not catalog step names.
func isParityTestRequestID(requestID string) bool {
	return strings.HasPrefix(requestID, "parity-")
}

func missingExpectedDecisionLogSteps(expected []string, seen map[string]bool) []string {
	missing := make([]string, 0)
	for _, step := range expected {
		if !seen[step] {
			missing = append(missing, step)
		}
	}
	return missing
}
