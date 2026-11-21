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
		// the domain emptied after the upload the agent did not load
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

// An upload the agent did not load would otherwise stay in the configuration
// every later pull reads, whatever domain the later case uploads into. The
// domain of that upload is therefore emptied before the next case, which here
// uploads into a domain of its own.
func TestRunIsolatedCases_EmptiesTheDomainOfAnUploadTheAgentDidNotLoad(t *testing.T) {
	refused := isolatedCase{id: "refused", resourceType: "RT", condition: "x", requests: []isolatedRequest{{name: "read", m2mOnly: true}}}
	next := isolatedCase{id: "next", domain: "PARITY_OWN", resourceType: "RT", requests: []isolatedRequest{{name: "read", m2mOnly: true}}}
	own := []string{
		"PUT /access/v1/simplifiedPolicies/domainPolicies/PARITY_OWN",
		"PUT /access/v1/simplifiedPolicies/domainPIPs/PARITY_OWN",
		"PUT /access/v1/simplifiedPolicies/domainPolicies/PARITY_OWN",
		"POST " + agentPullPath,
	}
	want := []string{
		"PUT " + domainPoliciesPath,
		"PUT " + domainPIPsPath,
		"PUT " + domainPoliciesPath,
		"POST " + agentPullPath,
		// the domain emptied after the upload the agent did not load
		"PUT " + domainPoliciesPath,
		"PUT " + domainPIPsPath,
		"PUT " + domainPoliciesPath,
		"POST " + agentPullPath,
	}
	want = append(want, own...)
	want = append(want, "POST /access/v1/check/resource")
	// the cleanup of the test
	want = append(want, "PUT "+domainPoliciesPath, "PUT "+domainPIPsPath, "PUT "+domainPoliciesPath, "POST "+agentPullPath)
	want = append(want, own...)
	got := runIsolatedCasesAgainstStub(t, nil,
		map[int]int{1: http.StatusBadGateway},
		map[string]int{"refused": http.StatusBadRequest, "next": http.StatusOK},
		refused, next)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("requests mismatch (-want +got):\n%s", diff)
	}
}

// When emptying the domain fails, the upload the agent did not load stays in
// the stand, so a later case uploads nothing: its subtest "setup" fails with
// SETUP BROKEN and its requests are skipped. Emptying fails when its pull is
// refused, or when authz-policy-admin refuses one of its uploads. The test
// reads that output from a child run of itself, since the child fails on
// purpose.
func TestRunIsolatedCases_AfterADomainTheAgentDidNotEmptyTheLaterCasesAreABrokenSetup(t *testing.T) {
	if os.Getenv(brokenSetupChild) == "1" {
		refused := isolatedCase{id: "refused", resourceType: "RT", condition: "x", requests: []isolatedRequest{{name: "read", m2mOnly: true}}}
		next := isolatedCase{id: "next", domain: "PARITY_OWN", resourceType: "RT", requests: []isolatedRequest{{name: "read", m2mOnly: true}}}
		goldens := map[string]int{"refused": http.StatusBadRequest, "next": http.StatusOK}
		for _, tc := range []struct {
			name          string
			refuse, pulls map[int]int
		}{
			{"pull-refused", nil, map[int]int{1: http.StatusBadGateway, 2: http.StatusBadGateway}},
			// the uploads 1 to 3 are the case's, 4 to 6 empty the domain
			{"upload-refused", map[int]int{5: http.StatusInternalServerError}, map[int]int{1: http.StatusBadGateway}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				sent := runIsolatedCasesAgainstStub(t, tc.refuse, tc.pulls, goldens, refused, next)
				t.Logf("uploads into PARITY_OWN: %d", strings.Count(strings.Join(sent, "\n"), "/PARITY_OWN"))
			})
		}
		return
	}
	name := regexp.QuoteMeta(t.Name())
	out := childOutput(t)
	if strings.Contains(out, "did not load: "+setupBrokenPrefix) {
		t.Errorf("the child run's output repeats %s inside a report:\n%s", setupBrokenPrefix, out)
	}
	requireOutput(t, out,
		`--- PASS: `+name+`/pull-refused/run/refused/upload `,
		`=== RUN   `+name+`/pull-refused/run/next/setup\n.*: SETUP BROKEN: empty domain PARITY_ISOLATED after case refused, `+
			`which the agent did not load: .*HTTP 502`,
		`--- FAIL: `+name+`/pull-refused/run/next/setup `,
		`--- SKIP: `+name+`/pull-refused/run/next/read `,
		`=== RUN   `+name+`/upload-refused/run/next/setup\n.*: SETUP BROKEN: empty domain PARITY_ISOLATED after case refused, `+
			`which the agent did not load: HTTP 500\n`,
		`--- SKIP: `+name+`/upload-refused/run/next/read `,
		// the cleanup of the test empties PARITY_OWN; the case uploaded nothing
		`(?s)pull-refused.*uploads into PARITY_OWN: 3\n.*upload-refused.*uploads into PARITY_OWN: 3\n`)
}

// brokenSetupChild selects the child run of a test that reads the go test
// output of a run that fails on purpose (childOutput).
const brokenSetupChild = "PARITY_TEST_BROKEN_SETUP_CHILD"

// childOutput runs the test t again in a child process with brokenSetupChild
// set, and returns its verbose output. The test does its work only in the
// child, where os.Getenv(brokenSetupChild) is "1".
func childOutput(t *testing.T) string {
	t.Helper()
	return childOutputRun(t, "^"+t.Name()+"$")
}

// childOutputRun is childOutput with the child's -test.run pattern run.
func childOutputRun(t *testing.T, run string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run="+run, "-test.v")
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

// A -run pattern that selects a check and not the setup it waits on leaves the
// setup unrun: the check is skipped with a report that names the setup, and its
// parent fails. The setup here stops with t.Fatal, which would end the parent
// before the check if the setup ran there. The test reads the go test output
// from a child run of itself, since the child fails on purpose.
func TestRunSetup_SkipsTheChecksOfASetupThatRunLeavesOut(t *testing.T) {
	if os.Getenv(brokenSetupChild) == "1" {
		t.Run("point", func(t *testing.T) {
			broken := runSetup(t, func(t *testing.T) error {
				t.Fatal("the setup ran")
				return nil
			})
			t.Run("decision", func(t *testing.T) { skipIfBroken(t, broken) })
		})
		return
	}
	name := regexp.QuoteMeta(t.Name())
	out := childOutputRun(t, "^"+t.Name()+"$/^point$/^decision$")
	if strings.Contains(out, "the setup ran") {
		t.Errorf("the child run ran the setup that -run leaves out:\n%s", out)
	}
	requireOutput(t, out,
		`=== RUN   `+name+`/point\n.*: SETUP BROKEN: -run or -skip left out the subtest setup this check waits on; `+
			`select it too\n`,
		`=== RUN   `+name+`/point/decision\n.*: SETUP BROKEN: -run or -skip left out the subtest setup .*; not compared\n`,
		`--- SKIP: `+name+`/point/decision `,
		`--- FAIL: `+name+`/point `)
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
