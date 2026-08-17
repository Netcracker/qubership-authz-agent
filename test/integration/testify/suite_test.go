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
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type stepResult struct {
	Name    string
	Status  string
	Elapsed time.Duration
}

// RuntimeSuite is the top-level Testify suite for runtime integration tests.
// It bootstraps Keycloak tokens, uploads policies, and validates step coverage.
type RuntimeSuite struct {
	suite.Suite

	cfg                     RuntimeConfig
	validOrderReaderToken   string
	validAdminToken         string
	expiredOrderReaderToken string
	expiredAdminToken       string
	currentStepName         string

	results []stepResult
	mu      sync.Mutex
}

func TestRuntimeSuite(t *testing.T) {
	suite.Run(t, new(RuntimeSuite))
}

func (s *RuntimeSuite) SetupSuite() {
	s.cfg = LoadConfig()
	s.results = make([]stepResult, 0, len(Catalog))

	s.SetupStep("setup.wait_for_keycloak", func() error {
		return WaitForKeycloak(s.cfg.KcBaseURL, 60*time.Second, s.currentRequestID())
	})

	s.SetupStep("setup.token_acquire_expired", func() error {
		var err error
		s.expiredOrderReaderToken, err = GetKeycloakToken(
			s.cfg.KcBaseURL, s.cfg.KcExpiredClientID, s.cfg.KcExpiredClientSecret,
			s.cfg.KcTokenScope, s.cfg.KcOrderReaderUser, s.cfg.KcPassword, s.currentRequestID())
		if err != nil {
			return err
		}
		s.expiredAdminToken, err = GetKeycloakToken(
			s.cfg.KcBaseURL, s.cfg.KcExpiredClientID, s.cfg.KcExpiredClientSecret,
			s.cfg.KcTokenScope, s.cfg.KcAdminUser, s.cfg.KcPassword, s.currentRequestID())
		return err
	})

	s.SetupStep("setup.token_expiry_wait", func() error {
		fmt.Printf("[setup] waiting %ds for token expiry\n", s.cfg.KcExpiredWaitSeconds)
		time.Sleep(time.Duration(s.cfg.KcExpiredWaitSeconds) * time.Second)
		return nil
	})

	s.SetupStep("setup.token_acquire_valid", func() error {
		var err error
		s.validOrderReaderToken, err = GetKeycloakToken(
			s.cfg.KcBaseURL, s.cfg.KcClientID, s.cfg.KcClientSecret,
			s.cfg.KcTokenScope, s.cfg.KcOrderReaderUser, s.cfg.KcPassword, s.currentRequestID())
		if err != nil {
			return err
		}
		s.validAdminToken, err = GetKeycloakToken(
			s.cfg.KcBaseURL, s.cfg.KcClientID, s.cfg.KcClientSecret,
			s.cfg.KcTokenScope, s.cfg.KcAdminUser, s.cfg.KcPassword, s.currentRequestID())
		return err
	})

	s.SetupStep("setup.wait_for_authz_policy_admin", func() error {
		return WaitForACStub(s.cfg.ACStubURL, 30*time.Second, s.currentRequestID())
	})

	s.SetupStep("setup.policy_upload", func() error {
		policies, err := os.ReadFile("testdata/runtime-simplified-policies.json")
		if err != nil {
			return err
		}
		return UploadPoliciesToACStub(s.cfg.ACStubURL, policies, s.currentRequestID())
	})

	s.SetupStep("setup.pip_upload", func() error {
		pips := fmt.Sprintf(`[{"name":"subject.allowedCustomers","url":"%s/api/v1/pip/allowed","requestAttributes":{"resourceType":"Customer"}}]`,
			s.cfg.PIPStubInternalURL)
		return UploadPIPsToACStub(s.cfg.ACStubURL, []byte(pips), s.currentRequestID())
	})

	s.SetupStep("setup.wait_for_agent", func() error {
		// Wait for the pull loop to apply the uploaded policies before the
		// agent health check, so the first decision assertions see live data.
		time.Sleep(s.cfg.PullInterval + 2*time.Second)
		return WaitForAgent(s.cfg.BaseURL, s.validAdminToken, 90*time.Second, s.currentRequestID())
	})

	fmt.Println("[setup] suite starting")
}

// SetupStep executes a named setup action with catalog validation, timing,
// and STEP PASS/FAIL output. On failure it aborts the suite.
func (s *RuntimeSuite) SetupStep(name string, fn func() error) {
	s.T().Helper()
	if _, ok := CatalogByName[name]; !ok {
		s.T().Fatalf("STEP FAIL %s 0ms — step not registered in catalog", name)
	}

	s.currentStepName = name
	defer func() {
		s.currentStepName = ""
	}()

	start := time.Now()
	err := fn()
	elapsed := time.Since(start)

	status := "PASS"
	if err != nil {
		status = "FAIL"
	}

	r := stepResult{Name: name, Status: status, Elapsed: elapsed}
	s.mu.Lock()
	s.results = append(s.results, r)
	s.mu.Unlock()

	fmt.Printf("STEP %s %s %dms\n", status, name, elapsed.Milliseconds())

	if err != nil {
		s.Require().NoError(err, "setup step %s failed", name)
	}
}

// Step executes a named test step, validates it against the catalog, measures
// duration, and prints a STEP PASS/FAIL line to stdout.
func (s *RuntimeSuite) Step(name string, fn func()) {
	s.T().Helper()
	if _, ok := CatalogByName[name]; !ok {
		s.T().Fatalf("STEP FAIL %s 0ms — step not registered in catalog", name)
	}

	s.currentStepName = name
	defer func() {
		s.currentStepName = ""
	}()

	start := time.Now()
	passed := s.Run(name, fn)
	elapsed := time.Since(start)

	status := "PASS"
	if !passed {
		status = "FAIL"
	}

	r := stepResult{Name: name, Status: status, Elapsed: elapsed}
	s.mu.Lock()
	s.results = append(s.results, r)
	s.mu.Unlock()

	fmt.Printf("STEP %s %s %dms\n", status, name, elapsed.Milliseconds())
}

func (s *RuntimeSuite) TearDownSuite() {
	fmt.Println("\n=== STEP SUMMARY ===")
	for _, r := range s.results {
		fmt.Printf("STEP %s %s %dms\n", r.Status, r.Name, r.Elapsed.Milliseconds())
	}
	fmt.Printf("=== %d/%d steps executed ===\n", len(s.results), len(Catalog))

	if os.Getenv("FULL_RUNTIME_SUITE") != "true" {
		return
	}

	executed := make(map[string]bool, len(s.results))
	for _, r := range s.results {
		executed[r.Name] = true
	}
	for _, e := range Catalog {
		if !executed[e.Name] {
			s.T().Errorf("catalog step %q was never executed", e.Name)
		}
	}
}

// ── request helpers ──────────────────────────────────────────────────────

func (s *RuntimeSuite) currentRequestID() string {
	return strings.TrimSpace(s.currentStepName)
}

func (s *RuntimeSuite) headersWithRequestID(headers map[string]string) map[string]string {
	cloned := make(map[string]string, len(headers)+1)
	hasRequestID := false
	for key, value := range headers {
		cloned[key] = value
		if strings.EqualFold(key, "X-Request-Id") {
			hasRequestID = true
		}
	}
	if !hasRequestID && s.currentRequestID() != "" {
		cloned["X-Request-Id"] = s.currentRequestID()
	}
	return cloned
}

func (s *RuntimeSuite) post(path string, headers map[string]string, body interface{}) (int, []byte) {
	s.T().Helper()
	hdr := s.headersWithRequestID(headers)
	rawURL := s.cfg.BaseURL + path
	code, b, reqBody, respHdr, err := DoHTTPFull("POST", rawURL, hdr, body)
	s.Require().NoError(err)
	assertConformsToSpec(s.T(), "POST", rawURL, hdr, reqBody, code, respHdr, b)
	return code, b
}

// postRaw posts to the public Envoy listener without running the request-side
// spec validator. Use this for tests that intentionally send a malformed body
// to exercise the runtime's 400 reject path — the kin-openapi request-side
// schema check would otherwise reject the body client-side. Response-side
// validation still runs so the 400 envelope must remain spec-conformant.
func (s *RuntimeSuite) postRaw(path string, headers map[string]string, body interface{}) (int, []byte) {
	s.T().Helper()
	hdr := s.headersWithRequestID(headers)
	rawURL := s.cfg.BaseURL + path
	code, b, reqBody, respHdr, err := DoHTTPFull("POST", rawURL, hdr, body)
	s.Require().NoError(err)
	assertConformsToSpecResponseOnly(s.T(), "POST", rawURL, hdr, reqBody, code, respHdr, b)
	return code, b
}

// waitForACPull sleeps for the PolicyPuller tick interval plus a grace period,
// ensuring that a policy or PIP upload to the authz-policy-admin is applied to OPA before
// follow-up decision assertions run. The sleep duration is controlled by
// RuntimeConfig.PullInterval (read from AUTHZ_PAP_CLIENT_PULL_INTERVAL) so the test
// stack can keep it short (e.g. AUTHZ_PAP_CLIENT_PULL_INTERVAL=2).
func (s *RuntimeSuite) waitForACPull() {
	s.T().Helper()
	time.Sleep(s.cfg.PullInterval + 2*time.Second)
}

func (s *RuntimeSuite) get(path string, headers map[string]string) (int, []byte) {
	s.T().Helper()
	hdr := s.headersWithRequestID(headers)
	rawURL := s.cfg.BaseURL + path
	code, b, reqBody, respHdr, err := DoHTTPFull("GET", rawURL, hdr, nil)
	s.Require().NoError(err)
	assertConformsToSpec(s.T(), "GET", rawURL, hdr, reqBody, code, respHdr, b)
	return code, b
}

func (s *RuntimeSuite) doHTTPDirect(method, url string, headers map[string]string, body interface{}) (int, []byte) {
	s.T().Helper()
	hdr := s.headersWithRequestID(headers)
	code, b, reqBody, respHdr, err := DoHTTPFull(method, url, hdr, body)
	s.Require().NoError(err)
	assertConformsToSpec(s.T(), method, url, hdr, reqBody, code, respHdr, b)
	return code, b
}

func jsonObj(b []byte) map[string]interface{} {
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	return m
}

// authErrorFrom extracts the canonical authError object from an unwrapped
// AuthorizeResponse body. ADR-0062 surfaces admission/subject auth failures as
// HTTP 200 with `result.authError = {status, message, reason}` instead of an
// HTTP-level 401. The caller passes the already-unwrapped inner result.
func authErrorFrom(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	j := jsonObj(body)
	raw, ok := j["authError"]
	if !ok {
		t.Fatalf("expected canonical result.authError; body=%s", string(body))
	}
	authErr, ok := raw.(map[string]interface{})
	if !ok {
		t.Fatalf("authError must be object; body=%s", string(body))
	}
	return authErr
}

func jsonArr(b []byte) []interface{} {
	var a []interface{}
	_ = json.Unmarshal(b, &a)
	return a
}

func jsonStrArr(b []byte) []string {
	var a []string
	_ = json.Unmarshal(b, &a)
	return a
}

func bodyStr(b []byte) string {
	return strings.TrimSpace(string(b))
}

func incomingTokenHeader(token string) map[string]string {
	return map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer " + token,
	}
}

func jsonHeader() map[string]string {
	return map[string]string{"Content-Type": "application/json"}
}

// canonicalAuthorizeBody builds an ADR-0062-shaped /access/v1/authorize body.
//
// The (R) fields (authorizationToken / authorizationType / requestHeaders)
// move from Envoy Lua injection into the canonical body, and the whole shape
// is wrapped in the OPA Data API envelope {"input": <body>}. admissionToken
// and subject must already carry the "Bearer " prefix; pass empty strings to
// model admission-failure / no-subject scenarios. The caller-supplied `extra`
// fields (resources, ignoreRls, flsRequired, ...) are folded into input.
func canonicalAuthorizeBody(admissionToken, subject string, extra map[string]interface{}) map[string]interface{} {
	input := map[string]interface{}{
		"authorizationToken": admissionToken,
		"authorizationType":  "",
		"requestHeaders":     map[string]interface{}{},
	}
	input["subject"] = subject
	for k, v := range extra {
		input[k] = v
	}
	return map[string]interface{}{"input": input}
}

// postAuthorize posts a canonical /access/v1/authorize request with no HTTP
// Authorization header (ADR-0062 — the admission token rides inside
// body.authorizationToken). Extra request headers (e.g. X-Request-Id) can be
// supplied via extraHeaders.
//
// The wire response is the OPA Data API envelope `{"result": <AuthorizeResponse>}`
// (authz-agent-ADR-0062). Spec conformance validates the envelope inside
// s.post; this helper then unwraps `result` so existing assertions can keep
// accessing the canonical `AuthorizeResponse` fields (`rlsIgnored`, `results`,
// ...) directly. Non-200 / non-enveloped bodies pass through unchanged.
func (s *RuntimeSuite) postAuthorize(admissionToken, subject string, body map[string]interface{}, extraHeaders ...map[string]string) (int, []byte) {
	s.T().Helper()
	h := jsonHeader()
	for _, eh := range extraHeaders {
		for k, v := range eh {
			h[k] = v
		}
	}
	code, raw := s.post("/access/v1/authorize", h, canonicalAuthorizeBody(admissionToken, subject, body))
	return code, unwrapOPAResultEnvelope(raw)
}

// unwrapOPAResultEnvelope returns the bytes of envelope.result when the body
// is an OPA Data API envelope, or the body unchanged otherwise. Used by
// authorize-call helpers so assertion code keeps speaking the canonical
// AuthorizeResponse shape after the ADR-0062 cutover.
func unwrapOPAResultEnvelope(raw []byte) []byte {
	if len(raw) == 0 {
		return raw
	}
	var env struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return raw
	}
	if len(env.Result) == 0 {
		return raw
	}
	return []byte(env.Result)
}
