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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"
	"time"
)

// runRequestAgainstStub sends req through runRequest on profile, against one
// server that stands in for the service under test and for pip-mock. The
// server answers a check with the body answer, and pip-mock's call log holds
// reads calls to req.classifyBy. goldens maps a sub-case under
// check-resource-v1-outcome to its recorded answer.
func runRequestAgainstStub(t *testing.T, profile, answer string, reads int, goldens map[string]string, req isolatedRequest) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/access/v1/check/resource":
			_, _ = w.Write([]byte(answer))
		case "/pip-stub/calls":
			calls := make([]PipStubCall, reads)
			for i := range calls {
				calls[i] = PipStubCall{Path: req.classifyBy}
			}
			_ = json.NewEncoder(w).Encode(calls)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	root := t.TempDir()
	for subCase, golden := range goldens {
		writeGolden(t, root, Meta(PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME).GoldenDir+"/"+subCase, golden)
	}
	cfg := Config{ACBaseURL: srv.URL, ACStubBaseURL: srv.URL, TenantID: "t", Profile: profile}
	s := &ParitySuite{
		cfg:        cfg,
		tokens:     &TokenFactory{cfg: cfg, cache: map[string]tokenEntry{"m2m": {accessToken: "m2m-token", expiresAt: time.Now().Add(time.Hour)}}},
		comparator: &GoldenComparator{goldenRoot: root},
		pipMock:    NewPipController(srv.URL),
	}
	s.SetS(s)
	s.SetT(t)
	s.runRequest("regular/c/r", "parity-type", req)
}

// runRequest compares the answer with the golden its class names, and a
// request classed by classifyBy finds that golden by profile: on the legacy
// profile the call log picks the one class, on the authz-agent profile any
// recorded class may match. Each case runs as a subtest of a child run, since
// the failing ones fail on purpose, and the parent reads the verdict of each.
func TestRunRequest_ComparesTheAnswerWithTheGoldenOfItsClass(t *testing.T) {
	const allow, deny = `{"status":200,"decision":true}`, `{"status":200,"decision":false}`
	plain := isolatedRequest{name: "r", operation: "READ", m2mOnly: true}
	classed := plain
	classed.classifyBy = "/route"
	cases := []struct {
		name, profile, answer string
		reads                 int
		goldens               map[string]string
		req                   isolatedRequest
		verdict               string
	}{
		{"a-matching-answer", "authz-agent", "true", 0, map[string]string{"regular/c/r": allow}, plain, "PASS"},
		{"a-different-answer", "authz-agent", "true", 0, map[string]string{"regular/c/r": deny}, plain, "FAIL"},
		{"legacy-the-class-the-call-log-shows", "legacy", "true", 1,
			map[string]string{"regular/c/r-when-the-pip-was-read": allow, "regular/c/r-when-the-pip-was-skipped": deny}, classed, "PASS"},
		{"legacy-not-the-other-class", "legacy", "true", 0,
			map[string]string{"regular/c/r-when-the-pip-was-read": allow, "regular/c/r-when-the-pip-was-skipped": deny}, classed, "FAIL"},
		{"agent-any-recorded-class", "authz-agent", "false", 1,
			map[string]string{"regular/c/r-when-the-pip-was-read": allow, "regular/c/r-when-the-pip-was-skipped": deny}, classed, "PASS"},
		{"agent-the-unclassified-golden", "authz-agent", "true", 0, map[string]string{"regular/c/r": allow}, classed, "PASS"},
		{"agent-no-recorded-class-matches", "authz-agent", "true", 0,
			map[string]string{"regular/c/r-when-the-pip-was-read": deny}, classed, "FAIL"},
		{"agent-nothing-recorded", "authz-agent", "true", 0, nil, classed, "SKIP"},
	}
	if os.Getenv(brokenSetupChild) == "1" {
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				runRequestAgainstStub(t, tc.profile, tc.answer, tc.reads, tc.goldens, tc.req)
			})
		}
		return
	}
	out := childOutput(t)
	for _, tc := range cases {
		verdict := regexp.MustCompile(`--- (PASS|FAIL|SKIP): ` + regexp.QuoteMeta(t.Name()+"/"+tc.name) + ` `).FindStringSubmatch(out)
		if verdict == nil {
			t.Errorf("%s: the child run reports no verdict:\n%s", tc.name, out)
			continue
		}
		if verdict[1] != tc.verdict {
			t.Errorf("%s: %s, want %s; child output:\n%s", tc.name, verdict[1], tc.verdict, out)
		}
	}
}
