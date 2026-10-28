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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// callsServer serves one /pip-stub/calls response that lists one call and,
// unless dropped is empty, carries it as the Pip-Stub-Calls-Dropped header.
func callsServer(t *testing.T, dropped string) *PipController {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dropped != "" {
			w.Header().Set("Pip-Stub-Calls-Dropped", dropped)
		}
		_, _ = io.WriteString(w, `[{"path":"/api/v1/pip/allowed","method":"GET"}]`)
	}))
	t.Cleanup(srv.Close)
	return NewPipController(srv.URL)
}

// A log the stub truncated would yield wrong call counts, so GetCalls refuses it.
func TestGetCalls_RefusesALogWithDroppedCalls(t *testing.T) {
	calls, err := callsServer(t, "3").GetCalls(context.Background())
	if err == nil || !strings.Contains(err.Error(), "dropped 3 calls") {
		t.Errorf("GetCalls() = %v, %v, want an error that names 3 dropped calls", calls, err)
	}
}

// A stub that dropped nothing, or an older stub that sends no header, yields
// the calls it lists.
func TestGetCalls_ReturnsACompleteLog(t *testing.T) {
	for _, tc := range []struct{ name, dropped string }{
		{"a stub that dropped nothing", "0"},
		{"a stub that sends no dropped count", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, err := callsServer(t, tc.dropped).GetCalls(context.Background())
			if err != nil || len(calls) != 1 || calls[0].Path != "/api/v1/pip/allowed" {
				t.Errorf("GetCalls() = %+v, %v, want the one call to /api/v1/pip/allowed", calls, err)
			}
		})
	}
}
