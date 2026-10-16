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

package keys

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseConfig_ReadsBothAddressForms(t *testing.T) {
	doc := `{"providers": [
		{"id": "cloud-common", "issuer": "https://idp.example/auth/realms/cloud-common",
		 "audiences": ["account"], "allowMissingAud": true},
		{"id": "kubernetes", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks",
		 "caFile": "/var/run/ca.crt", "tokenFile": "/var/run/token", "audiences": ["netcracker"]}
	]}`
	want := Config{Providers: []Provider{
		{ID: "cloud-common", Issuer: "https://idp.example/auth/realms/cloud-common", Audiences: []string{"account"}, AllowMissingAud: true},
		{ID: "kubernetes", JWKSURI: "https://kubernetes.default.svc/openid/v1/jwks", CAFile: "/var/run/ca.crt", TokenFile: "/var/run/token", Audiences: []string{"netcracker"}},
	}}
	got, err := ParseConfig([]byte(doc))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseConfig() = %+v, want %+v", got, want)
	}
}

// Every document puts a valid provider first and breaks one rule in the
// second, so an error that names providers[1] blames the entry at fault.
func TestParseConfig_AcceptsAnIDOfLettersDigitsDotsUnderscoresAndHyphens(t *testing.T) {
	doc := `{"providers": [{"id": "Cloud_common.v2-x", "issuer": "https://idp.example/realms/a"}]}`
	if _, err := ParseConfig([]byte(doc)); err != nil {
		t.Errorf("ParseConfig(%s) error = %v, want none", doc, err)
	}
}

func TestParseConfig_RejectsAnEntryThatBreaksARule(t *testing.T) {
	tests := []struct {
		name  string
		entry map[string]any
	}{
		{"empty id", map[string]any{"id": "", "issuer": "https://idp.example/realms/b"}},
		{"id with a space", map[string]any{"id": "realm b", "issuer": "https://idp.example/realms/b"}},
		{"duplicate id", map[string]any{"id": "a", "issuer": "https://idp.example/realms/b"}},
		{"neither issuer nor jwksUri", map[string]any{"id": "b"}},
		{"both issuer and jwksUri", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "jwksUri": "https://idp.example/realms/b/certs"}},
		{"allowMissingAud without audiences", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "allowMissingAud": true}},
		{"empty audience", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "audiences": []string{""}}},
		{"issuer that is not http", map[string]any{"id": "b", "issuer": "ftp://idp.example/realms/b"}},
		{"issuer without a host", map[string]any{"id": "b", "issuer": "https:///realms/b"}},
		{"jwksUri that is not http", map[string]any{"id": "b", "jwksUri": "file:///etc/jwks.json"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := json.Marshal(map[string]any{"providers": []any{
				map[string]any{"id": "a", "issuer": "https://idp.example/realms/a"},
				tt.entry,
			}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = ParseConfig(doc)
			if err == nil || !strings.Contains(err.Error(), "providers[1]") {
				t.Errorf("ParseConfig(%s) error = %v, want an error naming providers[1]", doc, err)
			}
		})
	}
}

func TestParseConfig_RejectsADocumentThatBreaksARule(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{"empty providers", `{"providers": []}`},
		{"no providers member", `{}`},
		{"unknown provider field", `{"providers": [{"id": "a", "issuer": "https://idp.example/realms/a", "required": true}]}`},
		{"unknown top-level field", `{"providers": [{"id": "a", "issuer": "https://idp.example/realms/a"}], "mode": "strict"}`},
		{"second JSON value", `{"providers": [{"id": "a", "issuer": "https://idp.example/realms/a"}]} {}`},
		{"not JSON", `providers: []`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(tt.doc)); err == nil {
				t.Errorf("ParseConfig(%s) error = nil, want an error", tt.doc)
			}
		})
	}
}

func TestReadConfig_ParsesTheFile(t *testing.T) {
	path := writeFile(t, "trusted-providers.json", `{"providers": [{"id": "a", "issuer": "https://idp.example/realms/a"}]}`)
	want := Config{Providers: []Provider{{ID: "a", Issuer: "https://idp.example/realms/a"}}}
	got, err := ReadConfig(path)
	if err != nil {
		t.Fatalf("ReadConfig(%s) error = %v", path, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ReadConfig(%s) = %+v, want %+v", path, got, want)
	}
}

func TestReadConfig_AMissingFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.json")
	if _, err := ReadConfig(path); err == nil {
		t.Errorf("ReadConfig(%s) error = nil, want an error", path)
	}
}
