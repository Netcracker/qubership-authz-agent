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

const healthyBootstrapJSON = `{"mode":"strict","configuredCount":1,"successCount":1,"failureCount":0,` +
	`"providers":[{"id":"kc","result":"success"}],"completedAt":"2026-01-01T00:00:00Z"}`

// newServiceWithPullStatus builds a Service whose OPA is ready and whose pull
// status file contains pullStatusJSON (absent when empty).
func newServiceWithPullStatus(t *testing.T, pullStatusJSON string) *Service {
	t.Helper()

	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(opaServer.Close)

	pullStatusFile := filepath.Join(t.TempDir(), "pull-status.json")
	if pullStatusJSON != "" {
		if err := os.WriteFile(pullStatusFile, []byte(pullStatusJSON), 0o644); err != nil {
			t.Fatalf("write pull status: %v", err)
		}
	}

	return New(Config{
		OPAHealthURL:        opaServer.URL,
		BootstrapStatusFile: writeTempFile(t, []byte(healthyBootstrapJSON)),
		PullStatusFile:      pullStatusFile,
	})
}

func getHealth(t *testing.T, svc *Service) (int, HealthResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	svc.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	var resp HealthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal %q: %v", rec.Body.String(), err)
	}
	return rec.Code, resp
}

// TestHandleHealth_ReportsConversionCounts is the observability half of the
// 2026-08-01 converter fix: a Pod whose converter dropped every rule was Ready,
// had policiesLoaded=true, and answered DENY to everything. The counts make
// that state readable without grepping the log stream.
func TestHandleHealth_ReportsConversionCounts(t *testing.T) {
	svc := newServiceWithPullStatus(t, `{"policiesLoaded":true,"lastSuccessAt":"2026-08-01T00:00:00Z",`+
		`"conversion":{"policySets":1294,"policySetsSkipped":0,"rules":2207,"rulesSkipped":2207,`+
		`"rulesDenySkipped":0,"policies":0}}`)

	code, resp := getHealth(t, svc)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if resp.PolicyConversion == nil {
		t.Fatal("expected policyConversion in the health body")
	}
	if resp.PolicyConversion.RulesSkipped != 2207 || resp.PolicyConversion.Policies != 0 {
		t.Errorf("counts not passed through: %+v", resp.PolicyConversion)
	}
}

// A ConfigMap-mount installation runs no conversion, so the field must be
// absent rather than reported as an all-zero conversion.
func TestHandleHealth_OmitsConversionWhenAbsent(t *testing.T) {
	svc := newServiceWithPullStatus(t, `{"policiesLoaded":true,"reason":"mount mode"}`)

	code, resp := getHealth(t, svc)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if resp.PolicyConversion != nil {
		t.Errorf("expected no policyConversion, got %+v", resp.PolicyConversion)
	}
}

func TestHandleHealth_MissingPullStatusIsNotAnError(t *testing.T) {
	svc := newServiceWithPullStatus(t, "")

	code, resp := getHealth(t, svc)
	if code != http.StatusOK {
		t.Fatalf("a missing pull status file must not affect health; got %d", code)
	}
	if resp.PolicyConversion != nil {
		t.Errorf("expected no policyConversion, got %+v", resp.PolicyConversion)
	}
}

func TestPullStatus_ConversionRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pull-status.json")
	want := PullStatus{
		PoliciesLoaded: true,
		LastSuccessAt:  "2026-08-01T00:00:00Z",
		Conversion: &ConversionStats{
			PolicySets: 3, PolicySetsSkipped: 1,
			Rules: 10, RulesSkipped: 2, RulesDenySkipped: 1, Policies: 7,
		},
	}
	if err := WritePullStatus(path, want); err != nil {
		t.Fatalf("WritePullStatus: %v", err)
	}
	got, err := LoadPullStatus(path)
	if err != nil {
		t.Fatalf("LoadPullStatus: %v", err)
	}
	if got.Conversion == nil || *got.Conversion != *want.Conversion {
		t.Errorf("conversion round-trip: want %+v got %+v", want.Conversion, got.Conversion)
	}
}
