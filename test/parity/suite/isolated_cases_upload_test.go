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

package paritysuite

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// runIsolatedCasesAgainstStub runs cases through runIsolatedCases on the
// authz-agent profile, against one server that stands in for both
// authz-policy-admin and the agent, and returns the requests the server
// received. The server answers the n-th PUT to domainPoliciesPath or
// domainPIPsPath, counted from 1 over the whole run, with refuse[n] when that
// is set, a check with false, and everything else with 200. uploadGoldens holds
// the upload golden of each case that has one.
func runIsolatedCasesAgainstStub(t *testing.T, refuse map[int]int, uploadGoldens map[string]int, cases ...isolatedCase) []string {
	t.Helper()
	t.Setenv("PARITY_PULL_SETTLE_SECONDS", "0")
	var mu sync.Mutex
	var sent []string
	domainPUTs := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case domainPoliciesPath, domainPIPsPath:
			domainPUTs++
			if status, ok := refuse[domainPUTs]; ok {
				w.WriteHeader(status)
			}
		case "/access/v1/check/resource":
			_, _ = w.Write([]byte("false"))
			return
		}
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)

	goldenRoot := t.TempDir()
	for id, status := range uploadGoldens {
		golden := filepath.Join(goldenRoot, "load-simplified-policies-v1", "isolated", id+".json")
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(fmt.Sprintf(`{"status": %d}`, status)), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cfg := Config{ACBaseURL: srv.URL, ACStubBaseURL: srv.URL, TenantID: "t", Profile: "authz-agent"}
	s := &ParitySuite{
		cfg:        cfg,
		tokens:     &TokenFactory{cfg: cfg, cache: map[string]tokenEntry{"m2m": {accessToken: "m2m-token", expiresAt: time.Now().Add(time.Hour)}}},
		comparator: &GoldenComparator{goldenRoot: goldenRoot},
	}
	s.SetS(s)
	t.Run("run", func(t *testing.T) {
		s.SetT(t)
		s.runIsolatedCases(cases)
	})
	mu.Lock()
	defer mu.Unlock()
	return sent
}

// A case that authz-policy-admin refuses, as the PAP did, passes its upload
// golden and sends no request; the next case runs in full.
func TestRunIsolatedCases_AStubRefusalTheGoldenRecordsEndsOnlyItsOwnCase(t *testing.T) {
	refused := isolatedCase{id: "refused", resourceType: "RT", condition: "x", requests: []isolatedRequest{{name: "read", m2mOnly: true}}}
	next := isolatedCase{id: "next", resourceType: "RT", requests: []isolatedRequest{{name: "read", m2mOnly: true}}}
	want := []string{
		"PUT " + domainPoliciesPath,
		"PUT " + domainPIPsPath,
		"PUT " + domainPoliciesPath,
		"PUT " + domainPoliciesPath,
		"PUT " + domainPIPsPath,
		"PUT " + domainPoliciesPath,
		"POST /access/v1/check/resource",
		// the cleanup of the test
		"PUT " + domainPoliciesPath,
		"PUT " + domainPIPsPath,
		"PUT " + domainPoliciesPath,
	}
	got := runIsolatedCasesAgainstStub(t,
		map[int]int{3: http.StatusBadRequest},
		map[string]int{"refused": http.StatusBadRequest, "next": http.StatusOK},
		refused, next)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("requests with the first case refused mismatch (-want +got):\n%s", diff)
	}
}
