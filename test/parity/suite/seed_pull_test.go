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

package paritysuite

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// wipeWithAgent runs WipeDomain of the authz-agent seeder against a stub that
// accepts every write and an agent whose pull route answers with agent, and
// returns how long WipeDomain took and its error.
func wipeWithAgent(t *testing.T, agent http.HandlerFunc) (time.Duration, error) {
	t.Helper()
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(stub.Close)
	if agent != nil {
		srv := httptest.NewServer(agent)
		t.Cleanup(srv.Close)
		t.Setenv("PARITY_AGENT_PULL_URL", srv.URL+"/internal/v1/pull")
	} else {
		t.Setenv("PARITY_AGENT_PULL_URL", "")
	}
	t.Setenv("PARITY_PULL_SETTLE_SECONDS", "1")
	seeder := &authzAgentInternalSeeder{cfg: Config{ACStubBaseURL: stub.URL}}
	start := time.Now()
	err := seeder.WipeDomain(context.Background(), "PARITY_DOMAIN")
	return time.Since(start), err
}

func answering(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func TestAwaitPull_ReturnsAtOnceWhenTheAgentLoaded(t *testing.T) {
	took, err := wipeWithAgent(t, answering(http.StatusNoContent, ""))

	if err != nil || took >= time.Second {
		t.Errorf("WipeDomain() = %v after %s, want nil before the 1s settle delay", err, took)
	}
}

func TestAwaitPull_FailsTheSeedWhenTheAgentLoadFails(t *testing.T) {
	_, err := wipeWithAgent(t, answering(http.StatusBadGateway, `{"error":"fetch policySets: HTTP 500"}`))

	if err == nil || !strings.Contains(err.Error(), "HTTP 502") || !strings.Contains(err.Error(), "fetch policySets: HTTP 500") {
		t.Errorf("WipeDomain() = %v, want an error with the agent's status and body", err)
	}
}

func TestAwaitPull_FailsTheSeedWhenTheAgentIsUnreachable(t *testing.T) {
	_, err := wipeWithAgent(t, func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	})

	if err == nil {
		t.Error("WipeDomain() = nil with the agent's connection aborted, want an error")
	}
}

func TestAwaitPull_WaitsTheSettleDelayWithoutAPullRoute(t *testing.T) {
	for _, tc := range []struct {
		name  string
		agent http.HandlerFunc
	}{
		{"404 from a build without the paritytest tag", answering(http.StatusNotFound, "")},
		{"PARITY_AGENT_PULL_URL empty", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			took, err := wipeWithAgent(t, tc.agent)

			if err != nil || took < time.Second {
				t.Errorf("WipeDomain() = %v after %s, want nil after the 1s settle delay", err, took)
			}
		})
	}
}
