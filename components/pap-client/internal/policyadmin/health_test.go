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

package policyadmin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// ── loadBootstrapStatus ────────────────────────────────────────────────────

func TestLoadBootstrapStatus_MissingFile(t *testing.T) {
	_, err := loadBootstrapStatus("/nonexistent/path/bootstrap-status.json")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadBootstrapStatus_MalformedJSON(t *testing.T) {
	f := writeTempFile(t, []byte("not-json"))
	_, err := loadBootstrapStatus(f)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestLoadBootstrapStatus_UnknownMode(t *testing.T) {
	raw := `{"mode":"unknown","configuredCount":1,"successCount":1,"failureCount":0,"providers":[],"completedAt":"2026-01-01T00:00:00Z"}`
	f := writeTempFile(t, []byte(raw))
	_, err := loadBootstrapStatus(f)
	if err == nil {
		t.Fatal("expected error for unknown mode, got nil")
	}
}

func TestLoadBootstrapStatus_MissingCompletedAt(t *testing.T) {
	raw := `{"mode":"strict","configuredCount":1,"successCount":1,"failureCount":0,"providers":[],"completedAt":""}`
	f := writeTempFile(t, []byte(raw))
	_, err := loadBootstrapStatus(f)
	if err == nil {
		t.Fatal("expected error for missing completedAt, got nil")
	}
}

func TestLoadBootstrapStatus_ValidStrict(t *testing.T) {
	raw := `{"mode":"strict","configuredCount":2,"successCount":2,"failureCount":0,"providers":[{"id":"kc","result":"success"}],"completedAt":"2026-01-01T00:00:00Z"}`
	f := writeTempFile(t, []byte(raw))
	status, err := loadBootstrapStatus(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Mode != "strict" {
		t.Errorf("expected mode strict, got %q", status.Mode)
	}
	if status.ConfiguredCount != 2 {
		t.Errorf("expected configuredCount 2, got %d", status.ConfiguredCount)
	}
	if status.SuccessCount != 2 {
		t.Errorf("expected successCount 2, got %d", status.SuccessCount)
	}
}

func TestLoadBootstrapStatus_ValidPermissive(t *testing.T) {
	raw := `{"mode":"permissive","configuredCount":2,"successCount":1,"failureCount":1,"providers":[],"completedAt":"2026-01-01T00:00:00Z"}`
	f := writeTempFile(t, []byte(raw))
	status, err := loadBootstrapStatus(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Mode != "permissive" {
		t.Errorf("expected mode permissive, got %q", status.Mode)
	}
}

// ── evaluateHealth ──────────────────────────────────────────────────────────

func TestEvaluateHealth_OPANotReady(t *testing.T) {
	healthy, msg, details := evaluateHealth(false, nil)
	if healthy {
		t.Fatal("expected unhealthy when OPA not ready")
	}
	if msg == "" {
		t.Error("expected non-empty message")
	}
	if details == nil || details.OPAReady == nil || *details.OPAReady != false {
		t.Error("expected details.opaReady=false")
	}
}

func TestEvaluateHealth_OPAReadyNoStatus(t *testing.T) {
	healthy, msg, details := evaluateHealth(true, nil)
	if healthy {
		t.Fatal("expected unhealthy when bootstrap status is nil")
	}
	if msg == "" {
		t.Error("expected non-empty message")
	}
	if details == nil || details.OPAReady == nil || *details.OPAReady != true {
		t.Error("expected details.opaReady=true")
	}
}

func TestEvaluateHealth_StrictAllSuccess(t *testing.T) {
	status := &BootstrapStatus{
		Mode:            "strict",
		ConfiguredCount: 2,
		SuccessCount:    2,
		FailureCount:    0,
		CompletedAt:     "2026-01-01T00:00:00Z",
	}
	healthy, msg, _ := evaluateHealth(true, status)
	if !healthy {
		t.Fatalf("expected healthy, got unhealthy: %s", msg)
	}
}

func TestEvaluateHealth_StrictPartialSuccess(t *testing.T) {
	// Scenario 4: strict mode, 1 of 2 IdPs succeeded → unhealthy.
	status := &BootstrapStatus{
		Mode:            "strict",
		ConfiguredCount: 2,
		SuccessCount:    1,
		FailureCount:    1,
		CompletedAt:     "2026-01-01T00:00:00Z",
	}
	healthy, msg, details := evaluateHealth(true, status)
	if healthy {
		t.Fatal("expected unhealthy for strict partial success")
	}
	if msg == "" {
		t.Error("expected non-empty message")
	}
	if details == nil || details.Bootstrap == nil {
		t.Fatal("expected bootstrap details")
	}
	if details.Bootstrap.SuccessCount != 1 || details.Bootstrap.RequiredCount != 2 {
		t.Errorf("unexpected bootstrap details: success=%d required=%d",
			details.Bootstrap.SuccessCount, details.Bootstrap.RequiredCount)
	}
}

func TestEvaluateHealth_StrictZeroSuccess(t *testing.T) {
	// Scenario 5: strict mode, 0 IdPs succeeded → unhealthy.
	status := &BootstrapStatus{
		Mode:            "strict",
		ConfiguredCount: 2,
		SuccessCount:    0,
		FailureCount:    2,
		CompletedAt:     "2026-01-01T00:00:00Z",
	}
	healthy, _, details := evaluateHealth(true, status)
	if healthy {
		t.Fatal("expected unhealthy for strict zero success")
	}
	if details.Bootstrap.SuccessCount != 0 || details.Bootstrap.RequiredCount != 2 {
		t.Errorf("unexpected bootstrap details")
	}
}

func TestEvaluateHealth_PermissiveAtLeastOne(t *testing.T) {
	// Scenario 2: permissive mode, 1 of 2 succeeded → healthy.
	status := &BootstrapStatus{
		Mode:            "permissive",
		ConfiguredCount: 2,
		SuccessCount:    1,
		FailureCount:    1,
		CompletedAt:     "2026-01-01T00:00:00Z",
	}
	healthy, msg, _ := evaluateHealth(true, status)
	if !healthy {
		t.Fatalf("expected healthy for permissive with 1 success, got: %s", msg)
	}
}

func TestEvaluateHealth_PermissiveZeroSuccess(t *testing.T) {
	// Scenario 6: permissive mode, 0 IdPs succeeded → unhealthy.
	status := &BootstrapStatus{
		Mode:            "permissive",
		ConfiguredCount: 2,
		SuccessCount:    0,
		FailureCount:    2,
		CompletedAt:     "2026-01-01T00:00:00Z",
	}
	healthy, _, details := evaluateHealth(true, status)
	if healthy {
		t.Fatal("expected unhealthy for permissive zero success")
	}
	if details.Bootstrap.RequiredCount != 1 {
		t.Errorf("expected requiredCount=1 for permissive, got %d", details.Bootstrap.RequiredCount)
	}
}

// ── handleHealth via httptest ───────────────────────────────────────────────

func newTestServiceWithOPA(t *testing.T, opaReady bool, statusJSON string) (*Service, string) {
	t.Helper()

	// Spin up a fake OPA server.
	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if opaReady {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(opaServer.Close)

	// Write bootstrap status file if given.
	var statusFile string
	if statusJSON != "" {
		statusFile = writeTempFile(t, []byte(statusJSON))
	} else {
		statusFile = filepath.Join(t.TempDir(), "bootstrap-status.json")
		// leave it absent to simulate missing status
	}

	svc := New(Config{
		OPAHealthURL:        opaServer.URL,
		BootstrapStatusFile: statusFile,
	})
	return svc, opaServer.URL
}

func TestHandleHealth_HealthyStrict(t *testing.T) {
	// Scenario 1: OPA ready + strict all-success → 200 healthy.
	statusJSON := `{"mode":"strict","configuredCount":1,"successCount":1,"failureCount":0,"providers":[{"id":"kc","result":"success"}],"completedAt":"2026-01-01T00:00:00Z"}`
	svc, _ := newTestServiceWithOPA(t, true, statusJSON)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	svc.handleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var resp HealthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if resp.Status != "healthy" {
		t.Errorf("expected status=healthy, got %q", resp.Status)
	}
}

func TestHandleHealth_HealthyPermissive(t *testing.T) {
	// Scenario 2: OPA ready + permissive ≥1 success → 200 healthy.
	statusJSON := `{"mode":"permissive","configuredCount":2,"successCount":1,"failureCount":1,"providers":[],"completedAt":"2026-01-01T00:00:00Z"}`
	svc, _ := newTestServiceWithOPA(t, true, statusJSON)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	svc.handleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleHealth_OPANotReady(t *testing.T) {
	// Scenario 3: OPA process up but readiness probe fails → 503.
	statusJSON := `{"mode":"strict","configuredCount":1,"successCount":1,"failureCount":0,"providers":[],"completedAt":"2026-01-01T00:00:00Z"}`
	svc, _ := newTestServiceWithOPA(t, false, statusJSON)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	svc.handleHealth(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	var resp HealthErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if resp.Message == "" {
		t.Error("expected non-empty message")
	}
	if resp.Details == nil || resp.Details.OPAReady == nil || *resp.Details.OPAReady != false {
		t.Error("expected details.opaReady=false")
	}
}

func TestHandleHealth_StrictPartialIdP(t *testing.T) {
	// Scenario 4: strict mode, 1 of 2 IdPs failed → 503.
	statusJSON := `{"mode":"strict","configuredCount":2,"successCount":1,"failureCount":1,"providers":[],"completedAt":"2026-01-01T00:00:00Z"}`
	svc, _ := newTestServiceWithOPA(t, true, statusJSON)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	svc.handleHealth(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	var resp HealthErrorResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Details == nil || resp.Details.Bootstrap == nil {
		t.Fatal("expected bootstrap details in error response")
	}
	if resp.Details.Bootstrap.RequiredCount != 2 {
		t.Errorf("expected requiredCount=2, got %d", resp.Details.Bootstrap.RequiredCount)
	}
}

func TestHandleHealth_StrictZeroIdP(t *testing.T) {
	// Scenario 5: strict mode, 0 IdPs succeeded → 503.
	statusJSON := `{"mode":"strict","configuredCount":2,"successCount":0,"failureCount":2,"providers":[],"completedAt":"2026-01-01T00:00:00Z"}`
	svc, _ := newTestServiceWithOPA(t, true, statusJSON)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	svc.handleHealth(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestHandleHealth_PermissiveZeroIdP(t *testing.T) {
	// Scenario 6: permissive mode, 0 IdPs succeeded → 503.
	statusJSON := `{"mode":"permissive","configuredCount":2,"successCount":0,"failureCount":2,"providers":[],"completedAt":"2026-01-01T00:00:00Z"}`
	svc, _ := newTestServiceWithOPA(t, true, statusJSON)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	svc.handleHealth(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	var resp HealthErrorResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Details == nil || resp.Details.Bootstrap == nil {
		t.Fatal("expected bootstrap details")
	}
	if resp.Details.Bootstrap.RequiredCount != 1 {
		t.Errorf("expected requiredCount=1 for permissive, got %d", resp.Details.Bootstrap.RequiredCount)
	}
}

func TestHandleHealth_MissingBootstrapStatus(t *testing.T) {
	// Scenario 7: OPA ready but bootstrap status file absent → 503.
	svc, _ := newTestServiceWithOPA(t, true, "" /* no status file written */)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	svc.handleHealth(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	var resp HealthErrorResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Message == "" {
		t.Error("expected non-empty message")
	}
}

func TestHandleHealth_InvalidBootstrapStatus(t *testing.T) {
	// Scenario 7 variant: malformed status file → 503.
	svc, _ := newTestServiceWithOPA(t, true, "not-json")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	svc.handleHealth(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestHandleHealth_MethodNotAllowed(t *testing.T) {
	statusJSON := `{"mode":"strict","configuredCount":1,"successCount":1,"failureCount":0,"providers":[],"completedAt":"2026-01-01T00:00:00Z"}`
	svc, _ := newTestServiceWithOPA(t, true, statusJSON)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/health", nil)
		svc.handleHealth(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: expected 405, got %d", method, rec.Code)
		}
	}
}

func TestHandleHealth_ResponseContentType(t *testing.T) {
	statusJSON := `{"mode":"strict","configuredCount":1,"successCount":1,"failureCount":0,"providers":[],"completedAt":"2026-01-01T00:00:00Z"}`
	svc, _ := newTestServiceWithOPA(t, true, statusJSON)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	svc.handleHealth(rec, req)

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

func TestHandleHealth_Transition_UnhealthyToHealthy(t *testing.T) {
	// Scenario 8: initially unhealthy (status absent), then status appears → healthy.
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "bootstrap-status.json")

	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(opaServer.Close)

	svc := New(Config{
		OPAHealthURL:        opaServer.URL,
		BootstrapStatusFile: statusPath,
	})

	// First call: status file absent → 503.
	rec := httptest.NewRecorder()
	svc.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("pre-transition: expected 503, got %d", rec.Code)
	}

	// Write status file.
	statusJSON := `{"mode":"strict","configuredCount":1,"successCount":1,"failureCount":0,"providers":[{"id":"kc","result":"success"}],"completedAt":"2026-01-01T00:00:00Z"}`
	if err := os.WriteFile(statusPath, []byte(statusJSON), 0o644); err != nil {
		t.Fatalf("failed to write status file: %v", err)
	}

	// Second call: status present → 200.
	rec = httptest.NewRecorder()
	svc.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("post-transition: expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func writeTempFile(t *testing.T, content []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "bootstrap-status-*.json")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.Write(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	_ = f.Close()
	return f.Name()
}

// ── required-provider readiness (authz-agent-ADR-0075) ───────────────────

// The generated platform list runs permissive on purpose — most namespaces
// have only one of the four realms — so permissive alone would let a Pod serve
// with cloud-common missing and only `external` up. That is the opposite of
// what `required` is for.
func TestEvaluateHealth_PermissiveMissingRequiredProvider(t *testing.T) {
	status := &BootstrapStatus{
		Mode:            "permissive",
		ConfiguredCount: 2,
		SuccessCount:    1,
		Providers: []BootstrapProviderResult{
			{ID: "cloud-common", Result: "failure", Required: true},
			{ID: "external", Result: "success"},
		},
		CompletedAt: "2026-07-30T00:00:00Z",
	}

	healthy, message, details := evaluateHealth(true, status)
	if healthy {
		t.Fatal("a Pod without its required provider must not be Ready")
	}
	if message != "required identity providers did not bootstrap" {
		t.Errorf("unexpected message: %q", message)
	}
	if got := details.Bootstrap.MissingRequired; len(got) != 1 || got[0] != "cloud-common" {
		t.Errorf("the message must name what is missing, got %v", got)
	}
}

func TestEvaluateHealth_PermissiveOptionalProvidersMayBeAbsent(t *testing.T) {
	status := &BootstrapStatus{
		Mode:            "permissive",
		ConfiguredCount: 4,
		SuccessCount:    1,
		Providers: []BootstrapProviderResult{
			{ID: "cloud-common", Result: "success", Required: true},
			{ID: "default", Result: "failure"},
			{ID: "cpq", Result: "failure"},
			{ID: "external", Result: "failure"},
		},
		CompletedAt: "2026-07-30T00:00:00Z",
	}

	if healthy, message, _ := evaluateHealth(true, status); !healthy {
		t.Fatalf("optional realms may be absent: %s", message)
	}
}

// Nothing marked required: only the mode threshold applies, exactly as before.
func TestEvaluateHealth_NoRequiredMarkersKeepsCountBehaviour(t *testing.T) {
	status := &BootstrapStatus{
		Mode:            "permissive",
		ConfiguredCount: 2,
		SuccessCount:    1,
		Providers: []BootstrapProviderResult{
			{ID: "a", Result: "success"},
			{ID: "b", Result: "failure"},
		},
		CompletedAt: "2026-07-30T00:00:00Z",
	}

	if healthy, message, _ := evaluateHealth(true, status); !healthy {
		t.Fatalf("expected the permissive count threshold to decide: %s", message)
	}
}

// A config the strict parser rejects reports zero configured providers, and
// zero clears every count threshold — so without the explicit marker this Pod
// would report Ready and then 401 every request. The ADR promises this failure
// is loud; this is what makes it so.
func TestEvaluateHealth_ConfigErrorIsNotReadyInBothModes(t *testing.T) {
	for _, mode := range []string{"strict", "permissive"} {
		t.Run(mode, func(t *testing.T) {
			status := &BootstrapStatus{
				Mode:            mode,
				ConfiguredCount: 0,
				SuccessCount:    0,
				ConfigError:     `json: unknown field "algorithms"`,
				CompletedAt:     "2026-07-31T00:00:00Z",
			}

			healthy, message, details := evaluateHealth(true, status)
			if healthy {
				t.Fatal("a Pod whose provider config was rejected must not be Ready")
			}
			if message != "trusted providers configuration is invalid" {
				t.Errorf("unexpected message: %q", message)
			}
			if details.ConfigError == "" {
				t.Error("the parse error must reach the health response body")
			}
		})
	}
}

// An operator who genuinely configures nothing is a different case: that is a
// deliberate "trust nobody", not a broken file, and it stays Ready as before.
func TestEvaluateHealth_EmptyProviderListStaysReady(t *testing.T) {
	status := &BootstrapStatus{
		Mode:            "strict",
		ConfiguredCount: 0,
		SuccessCount:    0,
		CompletedAt:     "2026-07-31T00:00:00Z",
	}

	if healthy, message, _ := evaluateHealth(true, status); !healthy {
		t.Fatalf("an empty list is not a config error: %s", message)
	}
}
