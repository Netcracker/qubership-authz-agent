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

package runtimetest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func pullRouteAnswering(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/internal/v1/pull"
}

func TestRequestAgentPull_ReportsALoadOn204(t *testing.T) {
	loaded, err := RequestAgentPull(pullRouteAnswering(t, http.StatusNoContent, ""))

	if !loaded || err != nil {
		t.Errorf("RequestAgentPull() = %v, %v; want true, nil", loaded, err)
	}
}

// waitForACPull sleeps for the pull interval when RequestAgentPull reports
// neither a load nor an error.
func TestRequestAgentPull_ReportsNothingWithoutAPullRoute(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
	}{
		{"404 from a build without the paritytest tag", pullRouteAnswering(t, http.StatusNotFound, "")},
		{"AGENT_PULL_URL empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loaded, err := RequestAgentPull(tc.url)

			if loaded || err != nil {
				t.Errorf("RequestAgentPull(%q) = %v, %v; want false, nil", tc.url, loaded, err)
			}
		})
	}
}

func TestRequestAgentPull_ReportsAFailedLoadWithTheAgentsAnswer(t *testing.T) {
	loaded, err := RequestAgentPull(pullRouteAnswering(t, http.StatusBadGateway, `{"error":"fetch policySets: HTTP 500"}`))

	if loaded || err == nil || !strings.Contains(err.Error(), "HTTP 502") || !strings.Contains(err.Error(), "fetch policySets: HTTP 500") {
		t.Errorf("RequestAgentPull() = %v, %v; want false and an error with the agent's status and body", loaded, err)
	}
}

func TestRequestAgentPull_ReportsAnUnreachableAgent(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()

	if loaded, err := RequestAgentPull(url); loaded || err == nil {
		t.Errorf("RequestAgentPull(%q) = %v, %v with the server closed; want false and an error", url, loaded, err)
	}
}
