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
	"regexp"
	"strings"
	"testing"
)

const (
	jwtHeader    = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	jwtPayload   = "eyJzdWIiOiJ1c2VyIiwiZXhwIjoxfQ"
	jwtSignature = "c2lnbmF0dXJlLXRoYXQtbXVzdC1nbw"
)

var (
	fullJWT     = jwtHeader + "." + jwtPayload + "." + jwtSignature
	strippedJWT = jwtHeader + "." + jwtPayload
	// anyFullJWT is the shape the runtime suite rejects in a downloaded log.
	anyFullJWT = regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
)

func TestSanitizeString(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"bearer value", "Bearer " + fullJWT, "Bearer " + strippedJWT},
		{"naked token", fullJWT, strippedJWT},
		{
			"embedded in serialised arguments",
			`[{"headers":{"authorization":"Bearer ` + fullJWT + `"},"method":"GET"}]`,
			`[{"headers":{"authorization":"Bearer ` + strippedJWT + `"},"method":"GET"}]`,
		},
		{"two tokens in one string", fullJWT + " and " + fullJWT, strippedJWT + " and " + strippedJWT},
		{"already stripped", "Bearer " + strippedJWT, "Bearer " + strippedJWT},
		{"not a jwt", "Bearer invalid.jwt", "Bearer invalid.jwt"},
		{"dotted but no jwt header", "a.b.c", "a.b.c"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeString(c.in); got != c.want {
				t.Fatalf("sanitizeString(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// The event shape follows what OPA ships with nd_builtin_cache enabled: the
// token sits in input fields, and in the keys of the cached io.jwt.decode_verify
// and http.send calls, which are their serialised arguments.
func TestSanitizeValueWalksKeysAndNesting(t *testing.T) {
	event := map[string]any{
		"input": map[string]any{
			"authorizationToken": "Bearer " + fullJWT,
			"subject":            fullJWT,
			"resources":          []any{map[string]any{"note": "ref " + fullJWT}},
		},
		"nd_builtin_cache": map[string]any{
			"io.jwt.decode_verify": map[string]any{
				`["` + fullJWT + `",{"cert":"x"}]`: []any{true, map[string]any{}, map[string]any{}},
			},
			"http.send": map[string]any{
				`[{"headers":{"authorization":"Bearer ` + fullJWT + `"},"url":"http://pip"}]`: map[string]any{
					"status_code": float64(200),
				},
			},
		},
		"decision_id": "d1",
		"count":       float64(3),
	}

	out, ok := sanitizeValue(event).(map[string]any)
	if !ok {
		t.Fatal("sanitized event is not a map")
	}

	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if anyFullJWT.Match(raw) {
		t.Fatalf("a full JWT survived sanitisation: %s", raw)
	}
	if !strings.Contains(string(raw), strippedJWT) {
		t.Fatalf("header and payload must survive: %s", raw)
	}

	// Keys are rewritten rather than dropped, and the values under them stay.
	cache := out["nd_builtin_cache"].(map[string]any)
	verify := cache["io.jwt.decode_verify"].(map[string]any)
	if _, found := verify[`["`+strippedJWT+`",{"cert":"x"}]`]; !found {
		t.Fatalf("io.jwt.decode_verify key not rewritten: %v", verify)
	}
	send := cache["http.send"].(map[string]any)
	wantKey := `[{"headers":{"authorization":"Bearer ` + strippedJWT + `"},"url":"http://pip"}]`
	if v, found := send[wantKey]; !found || v.(map[string]any)["status_code"] != float64(200) {
		t.Fatalf("http.send key not rewritten or its value lost: %v", send)
	}
	if out["decision_id"] != "d1" || out["count"] != float64(3) {
		t.Fatalf("fields without tokens changed: %v", out)
	}
}
