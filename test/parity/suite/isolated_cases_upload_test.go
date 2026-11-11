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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
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
// is set, a check with false, and everything else with 200. With pulls not
// nil, the suite asks the server to pull, and the server answers the n-th pull
// with pulls[n] when that is set, else with 204. uploadGoldens holds the upload
// golden of each case that has one.
func runIsolatedCasesAgainstStub(t *testing.T, refuse, pulls map[int]int, uploadGoldens map[string]int, cases ...isolatedCase) []string {
	t.Helper()
	t.Setenv("PARITY_PULL_SETTLE_SECONDS", "0")
	t.Setenv("PARITY_AGENT_PULL_URL", "")
	var mu sync.Mutex
	var sent []string
	domainPUTs, pullsSeen := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case agentPullPath:
			pullsSeen++
			status, ok := pulls[pullsSeen]
			if !ok {
				status = http.StatusNoContent
			}
			w.WriteHeader(status)
			return
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
	if pulls != nil {
		t.Setenv("PARITY_AGENT_PULL_URL", srv.URL+agentPullPath)
	}

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
		map[int]int{3: http.StatusBadRequest}, nil,
		map[string]int{"refused": http.StatusBadRequest, "next": http.StatusOK},
		refused, next)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("requests with the first case refused mismatch (-want +got):\n%s", diff)
	}
}

const agentPullPath = "/internal/v1/pull"

// An upload legacy refused, which authz-policy-admin accepts and the agent
// does not load, matches its golden: the agent refused it too. The case sends
// no request, as on legacy.
func TestRunIsolatedCases_AnUploadLegacyRefusedAndTheAgentDidNotLoadMatches(t *testing.T) {
	refused := isolatedCase{id: "refused", resourceType: "RT", condition: "x", requests: []isolatedRequest{{name: "read", m2mOnly: true}}}
	next := isolatedCase{id: "next", resourceType: "RT", requests: []isolatedRequest{{name: "read", m2mOnly: true}}}
	want := []string{
		"PUT " + domainPoliciesPath,
		"PUT " + domainPIPsPath,
		"PUT " + domainPoliciesPath,
		"POST " + agentPullPath,
		"PUT " + domainPoliciesPath,
		"PUT " + domainPIPsPath,
		"PUT " + domainPoliciesPath,
		"POST " + agentPullPath,
		"POST /access/v1/check/resource",
		// the cleanup of the test
		"PUT " + domainPoliciesPath,
		"PUT " + domainPIPsPath,
		"PUT " + domainPoliciesPath,
		"POST " + agentPullPath,
	}
	got := runIsolatedCasesAgainstStub(t, nil,
		map[int]int{1: http.StatusBadGateway},
		map[string]int{"refused": http.StatusBadRequest, "next": http.StatusOK},
		refused, next)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("requests with the first upload not loaded mismatch (-want +got):\n%s", diff)
	}
}

// brokenSetupChild selects the child run of a test that reads the go test
// output of a run that fails on purpose (childOutput).
const brokenSetupChild = "PARITY_TEST_BROKEN_SETUP_CHILD"

// childOutput runs the test t again in a child process with brokenSetupChild
// set, and returns its verbose output. The test does its work only in the
// child, where os.Getenv(brokenSetupChild) is "1".
func childOutput(t *testing.T) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(), brokenSetupChild+"=1")
	raw, _ := cmd.CombinedOutput()
	return string(raw)
}

// requireOutput reports each pattern of wants that out does not match.
func requireOutput(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !regexp.MustCompile(want).MatchString(out) {
			t.Errorf("the child run's output does not match %q:\n%s", want, out)
		}
	}
}

// An upload legacy accepted, which the agent does not load, fails the subtest
// "setup" of its case with SETUP BROKEN and skips its requests with the same
// report, so the go test output tells it from a wrong answer. The next case,
// which the agent loads, sends its request. The test reads that output from a child
// run of itself, since the child fails on purpose.
func TestRunIsolatedCases_AnUploadLegacyAcceptedAndTheAgentDidNotLoadIsABrokenSetup(t *testing.T) {
	if os.Getenv(brokenSetupChild) == "1" {
		accepted := isolatedCase{id: "accepted", resourceType: "RT", requests: []isolatedRequest{{name: "read", m2mOnly: true}}}
		next := isolatedCase{id: "next", resourceType: "RT", requests: []isolatedRequest{{name: "read", m2mOnly: true}}}
		sent := runIsolatedCasesAgainstStub(t, nil,
			map[int]int{1: http.StatusBadGateway},
			map[string]int{"accepted": http.StatusOK, "next": http.StatusOK},
			accepted, next)
		t.Logf("checks sent: %d", strings.Count(strings.Join(sent, "\n"), "/access/v1/check/resource"))
		return
	}
	run := regexp.QuoteMeta(t.Name() + "/run/")
	requireOutput(t, childOutput(t),
		`--- PASS: `+run+`accepted/upload `,
		`=== RUN   `+run+`accepted/setup\n.*: SETUP BROKEN: the agent did not load the policies: POST .*: HTTP 502`,
		`--- FAIL: `+run+`accepted/setup `,
		`=== RUN   `+run+`accepted/read\n.*: SETUP BROKEN: .*; not compared`,
		`--- SKIP: `+run+`accepted/read `,
		`--- PASS: `+run+`next/upload `,
		`checks sent: 1\n`)
}

// Only a pull the agent refused (502) is a refusal that can match a refused
// upload of legacy. A pull that failed otherwise, here with 500, says nothing
// about the upload, so the case is a broken setup even where the golden
// records a refusal.
func TestRunIsolatedCases_AnUploadLegacyRefusedThatTheAgentFailedToPullIsABrokenSetup(t *testing.T) {
	if os.Getenv(brokenSetupChild) == "1" {
		refused := isolatedCase{id: "refused", resourceType: "RT", condition: "x", requests: []isolatedRequest{{name: "read", m2mOnly: true}}}
		runIsolatedCasesAgainstStub(t, nil,
			map[int]int{1: http.StatusInternalServerError},
			map[string]int{"refused": http.StatusBadRequest},
			refused)
		return
	}
	run := regexp.QuoteMeta(t.Name() + "/run/")
	requireOutput(t, childOutput(t),
		`=== RUN   `+run+`refused/setup\n.*: SETUP BROKEN: the agent did not load the policies: POST .*: HTTP 500`,
		`--- FAIL: `+run+`refused/setup `,
		`--- SKIP: `+run+`refused/read `)
}

// runSetup reports a setup that returned an error, and one that stopped its
// subtest with t.Fatal, both as a broken setup, and the check after it is
// skipped with that report.
func TestRunSetup_BreaksTheChecksAfterAFailedSetup(t *testing.T) {
	if os.Getenv(brokenSetupChild) == "1" {
		t.Run("returned", func(t *testing.T) {
			broken := runSetup(t, func(*testing.T) error { return errors.New("HTTP 502") })
			t.Run("decision", func(t *testing.T) { skipIfBroken(t, broken) })
		})
		t.Run("fatal", func(t *testing.T) {
			broken := runSetup(t, func(t *testing.T) error {
				t.Fatal("pip-mock is unreachable")
				return nil
			})
			t.Run("decision", func(t *testing.T) { skipIfBroken(t, broken) })
		})
		t.Run("loaded", func(t *testing.T) {
			broken := runSetup(t, func(*testing.T) error { return nil })
			t.Run("decision", func(t *testing.T) { skipIfBroken(t, broken) })
		})
		return
	}
	name := regexp.QuoteMeta(t.Name())
	requireOutput(t, childOutput(t),
		`=== RUN   `+name+`/returned/setup\n.*: SETUP BROKEN: HTTP 502\n`,
		`=== RUN   `+name+`/returned/decision\n.*: SETUP BROKEN: HTTP 502; not compared\n`,
		`--- SKIP: `+name+`/returned/decision `,
		`--- FAIL: `+name+`/fatal/setup `,
		`=== RUN   `+name+`/fatal/decision\n.*: SETUP BROKEN: the setup subtest failed, see its output; not compared\n`,
		`--- PASS: `+name+`/loaded/setup `,
		`--- PASS: `+name+`/loaded/decision `)
}
