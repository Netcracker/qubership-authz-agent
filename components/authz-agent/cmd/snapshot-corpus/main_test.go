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

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The bundle records an answer by path alone, so a recorded path is answered
// whatever the method of the call.
func TestReplay_AnswersARecordedPathWhateverTheMethod(t *testing.T) {
	tr := &replay{}
	tr.paths.Store(&map[string][2]json.RawMessage{"/ent/u1": {json.RawMessage("200"), json.RawMessage(`"granted"`)}})
	for _, tc := range []struct{ method, path, want string }{
		{http.MethodGet, "/ent/u1", "200 granted"},
		{http.MethodPost, "/ent/u1", "200 granted"},
		{http.MethodGet, "/other", "200 null"},
	} {
		resp, err := tr.RoundTrip(httptest.NewRequest(tc.method, "http://pip"+tc.path, nil))
		if err != nil {
			t.Errorf("RoundTrip(%s %s): %v", tc.method, tc.path, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		if got := fmt.Sprintf("%d %s", resp.StatusCode, body); got != tc.want {
			t.Errorf("RoundTrip(%s %s) = %s, want %s", tc.method, tc.path, got, tc.want)
		}
	}
}
