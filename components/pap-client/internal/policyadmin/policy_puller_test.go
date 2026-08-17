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
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// minimalPolicySetsResponse is a v3 policy-sets response containing one
// SIMPLIFIED policy set and one DEFAULT policy set.
const minimalPolicySetsResponse = `{
  "hash": "hash-ps-v1",
  "lastModificationTimestamp": "2026-01-01T00:00:00",
  "policySets": [
    {
      "policySetId": "ps-1",
      "name": "Test PS",
      "type": "SIMPLIFIED",
      "domain": "TestDomain",
      "status": "ACTIVE",
      "target": "resourceType == 'TestResource'",
      "combiningAlgorithm": "DENY_UNLESS_PERMIT",
      "tenantId": "default",
      "policies": [
        {
          "policyId": "pol-1",
          "target": "subject.roles CONTAINS 'ROLE_TEST'",
          "combiningAlgorithm": "DENY_UNLESS_PERMIT",
          "rules": [
            {
              "ruleId": "rule-1",
              "target": "operation == 'READ'",
              "condition": null,
              "effect": "ALLOW"
            }
          ]
        }
      ]
    },
    {
      "policySetId": "ps-default",
      "name": "Default type PS",
      "type": "DEFAULT",
      "domain": "OtherDomain",
      "status": "ACTIVE",
      "target": "resourceType == 'Other'",
      "combiningAlgorithm": "DENY_UNLESS_PERMIT",
      "tenantId": "default",
      "policies": []
    }
  ]
}`

// minimalPIPsResponse is a v3 PIPs response containing one TOKEN PIP (supported)
// and one FILTERED PIP (silently skipped).
const minimalPIPsResponse = `{
  "hash": "hash-pip-v1",
  "lastModificationTimestamp": "2026-01-01T00:00:00",
  "pips": [
    {
      "name": "subject.azp",
      "pipType": "TOKEN",
      "claim": "azp",
      "domain": "TestDomain",
      "tenantId": "default"
    },
    {
      "name": "subject.filtered",
      "pipType": "FILTERED",
      "domain": "TestDomain",
      "tenantId": "default"
    }
  ]
}`

// emptyPolicySetsResponse is a v3 response with no policy sets.
const emptyPolicySetsResponse = `{
  "hash": "hash-empty-ps",
  "lastModificationTimestamp": "2026-01-01T00:00:00",
  "policySets": []
}`

// emptyPIPsResponse is a v3 PIP response with no PIPs.
const emptyPIPsResponse = `{
  "hash": "hash-empty-pip",
  "lastModificationTimestamp": "2026-01-01T00:00:00",
  "pips": []
}`

func TestPolicyPuller_PullOnce_BasicSuccess(t *testing.T) {
	psBody := minimalPolicySetsResponse
	pipBody := minimalPIPsResponse

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/access/v3/config/policySets":
			_, _ = w.Write([]byte(psBody))
		case "/access/v3/config/pips":
			_, _ = w.Write([]byte(pipBody))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Capture OPA push payloads.
	var pushedPolicies, pushedPIPs []byte
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "bad method", http.StatusMethodNotAllowed)
			return
		}
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		switch r.URL.Path {
		case "/v1/data/policies":
			pushedPolicies = body
		case "/v1/data/pips":
			pushedPIPs = body
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer opaSrv.Close()

	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policies.json")
	pipFile := filepath.Join(dir, "pips.json")

	puller := NewPolicyPuller(PullConfig{
		SourceURL:      srv.URL,
		Interval:       time.Second,
		PolicyFile:     policyFile,
		PIPFile:        pipFile,
		OPAPoliciesURL: opaSrv.URL + "/v1/data/policies",
		OPAPIPsURL:     opaSrv.URL + "/v1/data/pips",
		Logger:         log.New(os.Stderr, "[test] ", 0),
	})

	if err := puller.PullOnce(context.Background()); err != nil {
		t.Fatalf("PullOnce: %v", err)
	}

	// Policy file must exist and contain the {"policies": …} envelope.
	raw, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatalf("policy file not written: %v", err)
	}
	var policyDoc map[string]any
	if err := json.Unmarshal(raw, &policyDoc); err != nil {
		t.Fatalf("policy file not valid JSON: %v", err)
	}
	if _, ok := policyDoc["policies"]; !ok {
		t.Error("policy file missing 'policies' key")
	}

	// PIP file must exist.
	if _, err := os.Stat(pipFile); err != nil {
		t.Fatalf("pip file not written: %v", err)
	}

	// OPA must have received PUT requests.
	if len(pushedPolicies) == 0 {
		t.Error("no policies pushed to OPA")
	}
	if len(pushedPIPs) == 0 {
		t.Error("no PIPs pushed to OPA")
	}

	// Only the TOKEN PIP should be in the pushed data (FILTERED is skipped).
	var pipPushed map[string]any
	if err := json.Unmarshal(pushedPIPs, &pipPushed); err != nil {
		t.Fatalf("pushed PIPs not valid JSON: %v", err)
	}
	byName, _ := pipPushed["byName"].(map[string]any)
	if _, ok := byName["subject.azp"]; !ok {
		t.Error("subject.azp PIP missing from pushed OPA data")
	}
	if _, ok := byName["subject.filtered"]; ok {
		t.Error("subject.filtered (FILTERED type) must not appear in pushed OPA data")
	}
}

// TestPolicyPuller_PullOnce_RepublishesOnEveryTick pins the removal of
// envelope-hash change detection. Access-control froze `hash` and
// `lastModificationTimestamp` in October 2025 (see
// docs/parity/access-control-v3-config-hash-contract.md), so an agent that
// skipped the push when the hash had not moved served its first-seen
// configuration forever. A repeated, byte-identical response must still reach
// OPA.
func TestPolicyPuller_PullOnce_RepublishesOnEveryTick(t *testing.T) {
	// A frozen non-empty hash — exactly what a real access-control serves.
	const frozenPS = `{"hash":"17605e82","lastModificationTimestamp":"2026-07-16T08:30:03","policySets":[]}`
	const frozenPIP = `{"hash":"e3b0c442","lastModificationTimestamp":"2026-07-16T08:30:03","pips":[]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/access/v3/config/policySets":
			_, _ = w.Write([]byte(frozenPS))
		case "/access/v3/config/pips":
			_, _ = w.Write([]byte(frozenPIP))
		}
	}))
	defer srv.Close()

	opaCalls := 0
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		opaCalls++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer opaSrv.Close()

	dir := t.TempDir()
	puller := NewPolicyPuller(PullConfig{
		SourceURL:      srv.URL,
		Interval:       time.Second,
		PolicyFile:     filepath.Join(dir, "policies.json"),
		PIPFile:        filepath.Join(dir, "pips.json"),
		OPAPoliciesURL: opaSrv.URL + "/v1/data/policies",
		OPAPIPsURL:     opaSrv.URL + "/v1/data/pips",
		Logger:         log.New(os.Stderr, "[test] ", 0),
	})

	for i := 1; i <= 3; i++ {
		if err := puller.PullOnce(context.Background()); err != nil {
			t.Fatalf("PullOnce #%d: %v", i, err)
		}
		// Two pushes per pull: policies and PIPs.
		if opaCalls != i*2 {
			t.Fatalf("after pull #%d: want %d OPA calls, got %d", i, i*2, opaCalls)
		}
	}
}

func TestPolicyPuller_PullOnce_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	dir := t.TempDir()
	puller := NewPolicyPuller(PullConfig{
		SourceURL:  srv.URL,
		Interval:   time.Second,
		PolicyFile: filepath.Join(dir, "policies.json"),
		PIPFile:    filepath.Join(dir, "pips.json"),
		Logger:     log.New(os.Stderr, "[test] ", 0),
	})

	err := puller.PullOnce(context.Background())
	if err == nil {
		t.Fatal("expected error on server 503, got nil")
	}

	// Nothing must be persisted when the fetch itself failed.
	if _, statErr := os.Stat(filepath.Join(dir, "policies.json")); statErr == nil {
		t.Error("policy file was written despite fetch failure")
	}
}

func TestPolicyPuller_PullOnce_MissingTokenFileIsIgnored(t *testing.T) {
	// A missing token file must not prevent pulling — token file may not
	// exist yet on first boot (projected token not yet mounted).
	var receivedAuthz string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthz = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/access/v3/config/policySets":
			_, _ = w.Write([]byte(emptyPolicySetsResponse))
		case "/access/v3/config/pips":
			_, _ = w.Write([]byte(emptyPIPsResponse))
		}
	}))
	defer srv.Close()

	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer opaSrv.Close()

	dir := t.TempDir()
	puller := NewPolicyPuller(PullConfig{
		SourceURL:      srv.URL,
		Interval:       time.Second,
		TokenFile:      filepath.Join(dir, "nonexistent-token"),
		PolicyFile:     filepath.Join(dir, "policies.json"),
		PIPFile:        filepath.Join(dir, "pips.json"),
		OPAPoliciesURL: opaSrv.URL + "/v1/data/policies",
		OPAPIPsURL:     opaSrv.URL + "/v1/data/pips",
		Logger:         log.New(os.Stderr, "[test] ", 0),
	})

	if err := puller.PullOnce(context.Background()); err != nil {
		t.Fatalf("PullOnce with missing token file: %v", err)
	}
	if receivedAuthz != "" {
		t.Errorf("expected no Authorization header when token file is missing, got %q", receivedAuthz)
	}
}

func TestPolicyPuller_PullOnce_TokenSentAsBearer(t *testing.T) {
	var receivedAuthz string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthz = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/access/v3/config/policySets":
			_, _ = w.Write([]byte(emptyPolicySetsResponse))
		case "/access/v3/config/pips":
			_, _ = w.Write([]byte(emptyPIPsResponse))
		}
	}))
	defer srv.Close()

	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer opaSrv.Close()

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("my-service-account-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	puller := NewPolicyPuller(PullConfig{
		SourceURL:      srv.URL,
		Interval:       time.Second,
		TokenFile:      tokenFile,
		PolicyFile:     filepath.Join(dir, "policies.json"),
		PIPFile:        filepath.Join(dir, "pips.json"),
		OPAPoliciesURL: opaSrv.URL + "/v1/data/policies",
		OPAPIPsURL:     opaSrv.URL + "/v1/data/pips",
		Logger:         log.New(os.Stderr, "[test] ", 0),
	})

	if err := puller.PullOnce(context.Background()); err != nil {
		t.Fatalf("PullOnce: %v", err)
	}
	if receivedAuthz != "Bearer my-service-account-token" {
		t.Errorf("Authorization = %q, want %q", receivedAuthz, "Bearer my-service-account-token")
	}
}

func TestPolicyPuller_RunDisabledWhenNoSourceURL(t *testing.T) {
	var called bool
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer opaSrv.Close()

	dir := t.TempDir()
	puller := NewPolicyPuller(PullConfig{
		SourceURL:      "", // disabled
		Interval:       time.Millisecond,
		PolicyFile:     filepath.Join(dir, "policies.json"),
		PIPFile:        filepath.Join(dir, "pips.json"),
		OPAPoliciesURL: opaSrv.URL + "/v1/data/policies",
		OPAPIPsURL:     opaSrv.URL + "/v1/data/pips",
		Logger:         log.New(os.Stderr, "[test] ", 0),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	puller.Run(ctx) // should return immediately

	if called {
		t.Error("OPA was called despite no SourceURL configured")
	}
}

// TestPolicyPuller_WritesConversionCounts covers the wiring from the converter
// through to the status file: the counts have to survive a pull, and a second
// pull of the same data has to report the same counts rather than clear them.
func TestPolicyPuller_WritesConversionCounts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/access/v3/config/policySets":
			_, _ = w.Write([]byte(minimalPolicySetsResponse))
		case "/access/v3/config/pips":
			_, _ = w.Write([]byte(minimalPIPsResponse))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer opaSrv.Close()

	dir := t.TempDir()
	statusFile := filepath.Join(dir, "pull-status.json")
	puller := NewPolicyPuller(PullConfig{
		SourceURL:      srv.URL,
		Interval:       time.Second,
		PolicyFile:     filepath.Join(dir, "policies.json"),
		PIPFile:        filepath.Join(dir, "pips.json"),
		OPAPoliciesURL: opaSrv.URL + "/v1/data/policies",
		OPAPIPsURL:     opaSrv.URL + "/v1/data/pips",
		PullStatusFile: statusFile,
		Logger:         log.New(os.Stderr, "[test] ", 0),
	})

	if err := puller.PullOnce(context.Background()); err != nil {
		t.Fatalf("PullOnce: %v", err)
	}
	puller.recordPullSuccess()

	status, err := LoadPullStatus(statusFile)
	if err != nil {
		t.Fatalf("LoadPullStatus: %v", err)
	}
	if status.Conversion == nil {
		t.Fatal("expected conversion counts in the pull status file")
	}
	// One SIMPLIFIED set with one rule; the DEFAULT set is not counted.
	want := ConversionStats{PolicySets: 1, Rules: 1, Policies: 1}
	if *status.Conversion != want {
		t.Errorf("conversion: want %+v got %+v", want, *status.Conversion)
	}

	// Second pull: the same data is converted again — the counts must stay
	// consistent rather than drift or disappear from the status file.
	if err := puller.PullOnce(context.Background()); err != nil {
		t.Fatalf("second PullOnce: %v", err)
	}
	puller.recordPullSuccess()

	status, err = LoadPullStatus(statusFile)
	if err != nil {
		t.Fatalf("LoadPullStatus after repeat pull: %v", err)
	}
	if status.Conversion == nil || *status.Conversion != want {
		t.Errorf("counts changed on a repeat pull of identical data: %+v", status.Conversion)
	}
}

// TestPolicyPuller_OPASecretDoesNotReachPullURL is a security regression test.
// When OPAAuthToken is set and the authz-policy-admin/access-control token file is absent,
// the OPA write secret must NOT be forwarded to the policy-source server.
// Before the client split (pullClient vs opaClient) the shared OPAAuthTransport
// would inject the OPA secret into any request that had no Authorization header,
// including the access-control/authz-policy-admin pull requests made when no token file
// exists. An adversary with read access to authz-policy-admin logs or TLS termination could
// harvest the OPA write secret and bypass system_authz.rego. See ADR-0077.
func TestPolicyPuller_OPASecretDoesNotReachPullURL(t *testing.T) {
	const opaSecret = "super-secret-opa-write-token"
	var receivedAuthz string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthz = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/access/v3/config/policySets":
			_, _ = w.Write([]byte(emptyPolicySetsResponse))
		case "/access/v3/config/pips":
			_, _ = w.Write([]byte(emptyPIPsResponse))
		}
	}))
	defer srv.Close()

	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer opaSrv.Close()

	dir := t.TempDir()
	puller := NewPolicyPuller(PullConfig{
		SourceURL:      srv.URL,
		Interval:       time.Second,
		TokenFile:      filepath.Join(dir, "nonexistent-token"), // no token file
		OPAAuthToken:   opaSecret,
		PolicyFile:     filepath.Join(dir, "policies.json"),
		PIPFile:        filepath.Join(dir, "pips.json"),
		OPAPoliciesURL: opaSrv.URL + "/v1/data/policies",
		OPAPIPsURL:     opaSrv.URL + "/v1/data/pips",
		Logger:         log.New(os.Stderr, "[test] ", 0),
	})

	if err := puller.PullOnce(context.Background()); err != nil {
		t.Fatalf("PullOnce: %v", err)
	}
	if receivedAuthz != "" {
		t.Errorf("OPA secret leaked to policy-source server: Authorization = %q", receivedAuthz)
	}
}

// TestPolicyPuller_UpdateLogReportsPolicyCount pins the count in the "policies
// updated" line. It first reported len(normalizedPolicies) — the normalised OPA
// document, which has a handful of top-level keys regardless of input — so a
// successful pull of 2207 policies logged "4 policies" on the stand and read as
// catastrophic data loss.
func TestPolicyPuller_UpdateLogReportsPolicyCount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/access/v3/config/policySets":
			_, _ = w.Write([]byte(minimalPolicySetsResponse))
		case "/access/v3/config/pips":
			_, _ = w.Write([]byte(minimalPIPsResponse))
		}
	}))
	defer srv.Close()

	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer opaSrv.Close()

	var buf bytes.Buffer
	dir := t.TempDir()
	puller := NewPolicyPuller(PullConfig{
		SourceURL:      srv.URL,
		Interval:       time.Second,
		PolicyFile:     filepath.Join(dir, "policies.json"),
		PIPFile:        filepath.Join(dir, "pips.json"),
		OPAPoliciesURL: opaSrv.URL + "/v1/data/policies",
		OPAPIPsURL:     opaSrv.URL + "/v1/data/pips",
		Logger:         log.New(&buf, "", 0),
	})

	if err := puller.PullOnce(context.Background()); err != nil {
		t.Fatalf("PullOnce: %v", err)
	}

	// The fixture has one SIMPLIFIED policy set with one rule ⇒ one policy,
	// and one TOKEN PIP (the FILTERED one is dropped).
	if want := "policies updated (1 policies, 1 PIPs)"; !strings.Contains(buf.String(), want) {
		t.Errorf("want log to contain %q; got %q", want, buf.String())
	}
}
