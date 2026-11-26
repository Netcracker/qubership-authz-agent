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

package snapshot

import (
	"encoding/json"
	"maps"
	"reflect"
	"testing"

	"authz-agent/internal/jsonvalue"
)

func TestNewSubject_ThePIPsGetNoTokenOfTheCaller(t *testing.T) {
	headers := map[string][]string{"Authorization": {"Bearer m2m"}, "Incoming-Token": {"eyJ.user.jwt"},
		"X-Request-Id": {"abc"}, "X-Corr": {"c0", "c1"}, "Host": {"agent"}}
	sub, err := NewSubject("a", headers, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"x-corr": "c1", "host": "agent"}; !maps.Equal(sub.Headers, want) {
		t.Errorf("Headers = %v, want %v", sub.Headers, want)
	}
	if sub.IncomingToken != "eyJ.user.jwt" {
		t.Errorf("IncomingToken = %q, want eyJ.user.jwt", sub.IncomingToken)
	}
	if sub.RequestID != "abc" {
		t.Errorf("RequestID = %q, want abc", sub.RequestID)
	}
}

func TestNewSubject_ARequestWithoutASubjectTokenIsAnonymous(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers map[string][]string
		want    bool
	}{
		{"Authorization alone", map[string][]string{"Authorization": {"Bearer a"}}, false},
		{"Incoming-Token alone", map[string][]string{"Incoming-Token": {"Bearer u"}}, false},
		{"no token", map[string][]string{"Host": {"agent"}}, true},
		{"Authorization-Type anonymous", map[string][]string{"Authorization": {"Bearer a"},
			"Incoming-Token": {"Bearer u"}, "Authorization-Type": {" Anonymous "}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sub, err := NewSubject("a", tc.headers, nil)
			if err != nil {
				t.Fatal(err)
			}
			if sub.Anonymous != tc.want {
				t.Errorf("NewSubject(%v).Anonymous = %v, want %v", tc.headers, sub.Anonymous, tc.want)
			}
		})
	}
}

func TestNewSubject_TheClaimsAreThePayloadObject(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload any
		want    string
	}{
		{"an object", map[string]any{"sub": "u1", "n": json.Number("12345678901234567890")},
			`{"n":12345678901234567890,"sub":"u1"}`},
		{"a string", "u1", `{}`},
		{"none", nil, `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sub, err := NewSubject("a", nil, tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			want, err := jsonvalue.Decode([]byte(tc.want))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(any(sub.Claims), want) {
				t.Errorf("NewSubject(payload %v).Claims = %v, want %s", tc.payload, sub.Claims, tc.want)
			}
		})
	}
}
