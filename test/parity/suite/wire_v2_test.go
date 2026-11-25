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
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"authz-agent/test/parity/suite/model"
)

// HelperCheckResourceV2 reads the plain row 7 answer the way outcomeOf reads
// the outcome row: a 200 answer without a boolean decision is an error, not a
// denial, and a refusal is not read for a decision.
func TestHelperCheckResourceV2_ADecisionThatIsNotABooleanIsAnError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr bool
	}{
		{"a boolean decision", http.StatusOK, `{"decision":false}`, false},
		{"no decision", http.StatusOK, `{}`, true},
		{"a string decision", http.StatusOK, `{"decision":"true"}`, true},
		{"a refusal", http.StatusBadRequest, `{"error":"bad"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			cfg := Config{ACBaseURL: srv.URL, TenantID: "t"}
			status, _, _, err := HelperCheckResourceV2(context.Background(), cfg, model.CheckResourceRequest{}, TokenBundle{}, PerCallOptions{})
			if (err != nil) != tc.wantErr {
				t.Errorf("HelperCheckResourceV2 on %d %s: status %d, error %v, want an error: %t", tc.status, tc.body, status, err, tc.wantErr)
			}
		})
	}
}
