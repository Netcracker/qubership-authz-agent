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
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// simplePoliciesJSON is a minimal simplified-policy array accepted by
// simplifiedpolicies.Normalize.
const simplePoliciesJSON = `[
  {
    "component": "TestDomain",
    "resourceType": "TestResource",
    "operation": "READ",
    "roles": ["ROLE_TEST"]
  }
]`

// simplePIPsJSON is a minimal simplified-PIP array accepted by pips.Normalize.
const simplePIPsJSON = `[
  {
    "name": "subject.azp",
    "pipType": "TOKEN",
    "claim": "azp"
  }
]`

func TestMountWatcher_WatchOnce_BasicSuccess(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "policies.json"), simplePoliciesJSON)
	writeFile(t, filepath.Join(dir, "pips.json"), simplePIPsJSON)

	var gotPolicies, gotPIPs []byte
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		switch r.URL.Path {
		case "/v1/data/policies":
			gotPolicies = body
		case "/v1/data/pips":
			gotPIPs = body
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer opaSrv.Close()

	outDir := t.TempDir()
	w := NewMountWatcher(MountWatchConfig{
		MountDir:       dir,
		Interval:       time.Second,
		PolicyFile:     filepath.Join(outDir, "policies.json"),
		PIPFile:        filepath.Join(outDir, "pips.json"),
		OPAPoliciesURL: opaSrv.URL + "/v1/data/policies",
		OPAPIPsURL:     opaSrv.URL + "/v1/data/pips",
		Logger:         log.New(os.Stderr, "[test] ", 0),
	})

	changed, err := w.WatchOnce(context.Background())
	if err != nil {
		t.Fatalf("WatchOnce: %v", err)
	}
	if !changed {
		t.Error("expected changed=true on first call")
	}

	// Policy file must be written with {"policies": …} wrapper.
	raw, err := os.ReadFile(filepath.Join(outDir, "policies.json"))
	if err != nil {
		t.Fatalf("policy file not written: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("policy file not valid JSON: %v", err)
	}
	if _, ok := doc["policies"]; !ok {
		t.Error("policy file missing 'policies' key")
	}

	// OPA must have received policy and PIP pushes.
	if len(gotPolicies) == 0 {
		t.Error("no policies pushed to OPA")
	}
	if len(gotPIPs) == 0 {
		t.Error("no PIPs pushed to OPA")
	}

	// The PIP must be present in the pushed data.
	var pipMap map[string]any
	if err := json.Unmarshal(gotPIPs, &pipMap); err != nil {
		t.Fatalf("pushed PIPs not valid JSON: %v", err)
	}
	local, _ := pipMap["local"].(map[string]any)
	token, _ := local["token"].(map[string]any)
	if _, ok := token["subject.azp"]; !ok {
		t.Error("subject.azp not in pushed PIPs")
	}
}

func TestMountWatcher_WatchOnce_NoChangeOnSameContent(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "policies.json"), simplePoliciesJSON)
	writeFile(t, filepath.Join(dir, "pips.json"), simplePIPsJSON)

	opaCalls := 0
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		opaCalls++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer opaSrv.Close()

	outDir := t.TempDir()
	w := NewMountWatcher(MountWatchConfig{
		MountDir:       dir,
		Interval:       time.Second,
		PolicyFile:     filepath.Join(outDir, "policies.json"),
		PIPFile:        filepath.Join(outDir, "pips.json"),
		OPAPoliciesURL: opaSrv.URL + "/v1/data/policies",
		OPAPIPsURL:     opaSrv.URL + "/v1/data/pips",
		Logger:         log.New(os.Stderr, "[test] ", 0),
	})

	// First call: apply.
	if changed, err := w.WatchOnce(context.Background()); err != nil || !changed {
		t.Fatalf("first WatchOnce: changed=%v err=%v", changed, err)
	}
	firstCalls := opaCalls

	// Second call: same files → no change, no OPA push.
	if changed, err := w.WatchOnce(context.Background()); err != nil {
		t.Fatalf("second WatchOnce: %v", err)
	} else if changed {
		t.Error("expected changed=false when files are unchanged")
	}
	if opaCalls != firstCalls {
		t.Errorf("OPA was called on unchanged files (%d additional calls)", opaCalls-firstCalls)
	}
}

func TestMountWatcher_WatchOnce_ReloadsOnContentChange(t *testing.T) {
	// This is the "dedicated test that a mount-only Pod re-applies on change"
	// required by the handover.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "policies.json"), simplePoliciesJSON)
	writeFile(t, filepath.Join(dir, "pips.json"), simplePIPsJSON)

	var lastPoliciesBody []byte
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		if r.URL.Path == "/v1/data/policies" {
			lastPoliciesBody = body
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer opaSrv.Close()

	outDir := t.TempDir()
	w := NewMountWatcher(MountWatchConfig{
		MountDir:       dir,
		Interval:       time.Second,
		PolicyFile:     filepath.Join(outDir, "policies.json"),
		PIPFile:        filepath.Join(outDir, "pips.json"),
		OPAPoliciesURL: opaSrv.URL + "/v1/data/policies",
		OPAPIPsURL:     opaSrv.URL + "/v1/data/pips",
		Logger:         log.New(os.Stderr, "[test] ", 0),
	})

	// First load.
	if _, err := w.WatchOnce(context.Background()); err != nil {
		t.Fatalf("first WatchOnce: %v", err)
	}

	// Simulate a ConfigMap update: add a second policy.
	const updatedPolicies = `[
  {"component": "TestDomain", "resourceType": "TestResource", "operation": "READ", "roles": ["ROLE_TEST"]},
  {"component": "OrderDomain", "resourceType": "Order", "operation": "DELETE", "roles": ["ROLE_MANAGER"]}
]`
	writeFile(t, filepath.Join(dir, "policies.json"), updatedPolicies)

	// Second call: changed file → must re-apply.
	changed, err := w.WatchOnce(context.Background())
	if err != nil {
		t.Fatalf("second WatchOnce: %v", err)
	}
	if !changed {
		t.Error("expected changed=true after file update")
	}

	// The pushed policies must now include the Order resource type under ols
	// (the policy has no condition/predicate, so it lands in OLS).
	if len(lastPoliciesBody) == 0 {
		t.Fatal("no policies pushed after update")
	}
	var updated map[string]any
	if err := json.Unmarshal(lastPoliciesBody, &updated); err != nil {
		t.Fatalf("pushed body not valid JSON: %v", err)
	}
	// The simplifiedpolicies normalizer uppercases resource types.
	ols, _ := updated["ols"].(map[string]any)
	if _, ok := ols["ORDER"]; !ok {
		t.Errorf("updated push must include ORDER in ols; got ols keys: %v", mapKeys(ols))
	}
}

func TestMountWatcher_WatchOnce_MissingFileIsError(t *testing.T) {
	dir := t.TempDir()
	// policies.json exists but pips.json does not.
	writeFile(t, filepath.Join(dir, "policies.json"), simplePoliciesJSON)

	outDir := t.TempDir()
	w := NewMountWatcher(MountWatchConfig{
		MountDir:   dir,
		Interval:   time.Second,
		PolicyFile: filepath.Join(outDir, "policies.json"),
		PIPFile:    filepath.Join(outDir, "pips.json"),
		Logger:     log.New(os.Stderr, "[test] ", 0),
	})

	_, err := w.WatchOnce(context.Background())
	if err == nil {
		t.Error("expected error when pips.json is missing")
	}
}

// writeFile is a test helper.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writeFile %s: %v", path, err)
	}
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
