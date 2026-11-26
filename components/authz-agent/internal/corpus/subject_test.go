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

package corpus

import (
	"maps"
	"testing"

	"authz-agent/internal/jsonvalue"
)

func TestSubject_ARecordedRequestIsProjectedAsTheServerProjectsIt(t *testing.T) {
	headers := map[string]string{"Authorization": "Bearer m2m", "Incoming-Token": "eyJ.user.jwt", "X-Corr": "c"}
	claims := `{"sub": "u1", "n": 12345678901234567890}`
	sub, err := Subject("a", headers, &claims, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"x-corr": "c"}; !maps.Equal(sub.Headers, want) {
		t.Errorf("Headers = %v, want %v", sub.Headers, want)
	}
	if sub.IncomingToken != "eyJ.user.jwt" {
		t.Errorf("IncomingToken = %q, want eyJ.user.jwt", sub.IncomingToken)
	}
	if n, _ := sub.Claims.Get("n"); n != jsonvalue.Number("12345678901234567890") {
		t.Errorf("claim n = %#v, want jsonvalue.Number(\"12345678901234567890\")", n)
	}
}

func TestSubject_TheRecordedAnonymityMustMatchTheHeaders(t *testing.T) {
	for _, tc := range []struct {
		name      string
		headers   map[string]string
		anonymous bool
		wantErr   bool
	}{
		{"a token, recorded as a user", map[string]string{"Authorization": "Bearer a"}, false, false},
		{"no token, recorded as a user", map[string]string{"X-Corr": "c"}, false, true},
		{"Authorization-Type anonymous, recorded as anonymous",
			map[string]string{"Authorization": "Bearer a", "Authorization-Type": "anonymous"}, true, false},
		{"a token, recorded as anonymous", map[string]string{"Authorization": "Bearer a"}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Subject("a", tc.headers, nil, tc.anonymous)
			if (err != nil) != tc.wantErr {
				t.Errorf("Subject(%v, anonymous=%v) error = %v, want an error: %v", tc.headers, tc.anonymous, err, tc.wantErr)
			}
		})
	}
}
