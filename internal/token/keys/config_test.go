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
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseConfig_ReadsKeycloakAndProviders(t *testing.T) {
	doc := `{"keycloak": {"url": "https://kc.example", "requiredRealms": ["cloud-common"], "caFile": "/var/run/kc-ca.crt"},
	 "providers": [
		{"id": "external", "issuer": "https://idp.example/oidc", "audiences": ["account"], "allowMissingAud": true},
		{"id": "kubernetes", "issuer": "https://kubernetes.default.svc", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks",
		 "caFile": "/var/run/ca.crt", "tokenFile": "/var/run/token", "audiences": ["netcracker"], "kubernetes": true}
	]}`
	want := Config{
		Keycloak: &Keycloak{URL: "https://kc.example", RequiredRealms: []string{"cloud-common"}, CAFile: "/var/run/kc-ca.crt"},
		Providers: []Provider{
			{ID: "external", Issuer: "https://idp.example/oidc", Audiences: []string{"account"}, AllowMissingAud: true},
			{ID: "kubernetes", Issuer: "https://kubernetes.default.svc", JWKSURI: "https://kubernetes.default.svc/openid/v1/jwks", CAFile: "/var/run/ca.crt", TokenFile: "/var/run/token", Audiences: []string{"netcracker"}, Kubernetes: true},
		},
	}
	got, err := ParseConfig([]byte(doc))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseConfig() = %+v, want %+v", got, want)
	}
}

// The marked provider is not named kubernetes, so a mark taken from the id
// fails the test.
func TestParseConfig_ReadsTheKubernetesMark(t *testing.T) {
	doc := `{"providers": [
		{"id": "k8s", "issuer": "https://kubernetes.default.svc", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks",
		 "audiences": ["netcracker"], "kubernetes": true},
		{"id": "idp", "issuer": "https://idp.example", "jwksUri": "https://idp.example/openid/v1/jwks", "audiences": ["netcracker"]}
	]}`
	want := Config{Providers: []Provider{
		{ID: "k8s", Issuer: "https://kubernetes.default.svc", JWKSURI: "https://kubernetes.default.svc/openid/v1/jwks", Audiences: []string{"netcracker"}, Kubernetes: true},
		{ID: "idp", Issuer: "https://idp.example", JWKSURI: "https://idp.example/openid/v1/jwks", Audiences: []string{"netcracker"}},
	}}
	got, err := ParseConfig([]byte(doc))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseConfig() = %+v, want %+v", got, want)
	}
}

func TestParseConfig_AcceptsAKeycloakWithoutProviders(t *testing.T) {
	doc := `{"keycloak": {"url": "https://kc.example"}}`
	if _, err := ParseConfig([]byte(doc)); err != nil {
		t.Errorf("ParseConfig(%s) error = %v, want none", doc, err)
	}
}

func TestParseConfig_RejectsAKeycloakThatBreaksARule(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{"no url", `{"keycloak": {}}`},
		{"url that is not http", `{"keycloak": {"url": "ftp://kc.example"}}`},
		{"url without a host", `{"keycloak": {"url": "https:///auth"}}`},
		{"empty required realm", `{"keycloak": {"url": "https://kc.example", "requiredRealms": [""]}}`},
		{"required realm that is a dot segment", `{"keycloak": {"url": "https://kc.example", "requiredRealms": [".."]}}`},
		{"unknown field", `{"keycloak": {"url": "https://kc.example", "realm": "a"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(tt.doc))
			if err == nil || !strings.Contains(err.Error(), "keycloak") && !strings.Contains(err.Error(), `"realm"`) {
				t.Errorf("ParseConfig(%s) error = %v, want an error about the keycloak object", tt.doc, err)
			}
		})
	}
}

func TestParseConfig_AcceptsATokenFileWithDiscoveryOfTheClusterAPIServer(t *testing.T) {
	for _, issuer := range []string{
		"https://kubernetes.default.svc",
		"https://kubernetes.default.svc.cluster.local",
		"https://KUBERNETES.default.svc:443",
	} {
		t.Run(issuer, func(t *testing.T) {
			entry, err := json.Marshal(map[string]any{"id": "k8s", "issuer": issuer, "caFile": "/var/run/ca.crt",
				"tokenFile": "/var/run/token", "audiences": []string{"netcracker"}, "kubernetes": true})
			if err != nil {
				t.Fatal(err)
			}
			doc := `{"providers": [` + string(entry) + `]}`
			if _, err := ParseConfig([]byte(doc)); err != nil {
				t.Errorf("ParseConfig(%s) error = %v, want none", doc, err)
			}
		})
	}
}

// New validates the configuration too, so a caller that builds a Config in code
// and never parses a file gets the same refusal.
func TestNew_RefusesAnUnmarkedProviderThatLooksLikeKubernetes(t *testing.T) {
	_, err := New(Config{Providers: []Provider{{ID: "kubernetes", Issuer: "https://idp.example"}}}, testOptions())
	if err == nil || !strings.Contains(err.Error(), `provider "kubernetes" looks like a Kubernetes API server`) {
		t.Errorf("New() error = %v, want the refusal of the unmarked provider", err)
	}
}

// The reader holds only this text, so it names the setting that repairs the
// file and the way out for a provider that is not the API server.
func TestParseConfig_SaysHowToRepairAnUnmarkedProvider(t *testing.T) {
	_, err := ParseConfig([]byte(`{"providers": [{"id": "kubernetes", "issuer": "https://idp.example"}]}`))
	if err == nil {
		t.Fatal("ParseConfig() error = nil, want one for the unmarked provider")
	}
	for _, part := range []string{`provider "kubernetes"`, `"kubernetes": true`, "no namespace check", "another id"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("ParseConfig() error = %q, want it to name %q", err, part)
		}
	}
}

func TestParseConfig_AcceptsAnIDOfLettersDigitsDotsUnderscoresAndHyphens(t *testing.T) {
	doc := `{"providers": [{"id": "Cloud_common.v2-x", "issuer": "https://idp.example/realms/a"}]}`
	if _, err := ParseConfig([]byte(doc)); err != nil {
		t.Errorf("ParseConfig(%s) error = %v, want none", doc, err)
	}
}

// Every document puts a valid provider first and breaks one rule in the
// second, so an error that names providers[1] blames the entry at fault.
func TestParseConfig_RejectsAnEntryThatBreaksARule(t *testing.T) {
	tests := []struct {
		name  string
		entry map[string]any
	}{
		{"empty id", map[string]any{"id": "", "issuer": "https://idp.example/realms/b"}},
		{"id with a space", map[string]any{"id": "realm b", "issuer": "https://idp.example/realms/b"}},
		{"duplicate id", map[string]any{"id": "a", "issuer": "https://idp.example/realms/b"}},
		{"no issuer", map[string]any{"id": "b"}},
		{"jwksUri without issuer", map[string]any{"id": "b", "jwksUri": "https://idp.example/realms/b/certs"}},
		{"duplicate issuer", map[string]any{"id": "b", "issuer": "https://idp.example/realms/a"}},
		{"tokenFile without jwksUri", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "tokenFile": "/var/run/token"}},
		{"tokenFile without jwksUri on another host, with a CA", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "caFile": "/var/run/ca.crt", "tokenFile": "/var/run/token"}},
		{"tokenFile without jwksUri, on an in-cluster name over http", map[string]any{"id": "b", "issuer": "http://kubernetes.default.svc", "caFile": "/var/run/ca.crt", "tokenFile": "/var/run/token", "audiences": []string{"netcracker"}, "kubernetes": true}},
		{"tokenFile without jwksUri, on an in-cluster name without a CA", map[string]any{"id": "b", "issuer": "https://kubernetes.default.svc", "tokenFile": "/var/run/token", "audiences": []string{"netcracker"}, "kubernetes": true}},
		{"unmarked provider named kubernetes", map[string]any{"id": "kubernetes", "issuer": "https://idp.example/realms/b"}},
		{"unmarked issuer on an in-cluster name", map[string]any{"id": "b", "issuer": "https://kubernetes.default.svc"}},
		{"unmarked jwksUri on an in-cluster name", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks"}},
		{"unmarked jwksUri on the full in-cluster name, in capitals, with a port", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "jwksUri": "https://KUBERNETES.default.svc.cluster.local:443/openid/v1/jwks"}},
		{"allowMissingAud without audiences", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "allowMissingAud": true}},
		{"kubernetes without audiences", map[string]any{"id": "b", "issuer": "https://kubernetes.default.svc", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks", "kubernetes": true}},
		{"kubernetes with allowMissingAud", map[string]any{"id": "b", "issuer": "https://kubernetes.default.svc", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks", "kubernetes": true, "audiences": []string{"netcracker"}, "allowMissingAud": true}},
		{"empty audience", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "audiences": []string{""}}},
		{"issuer that is not http", map[string]any{"id": "b", "issuer": "ftp://idp.example/realms/b"}},
		{"issuer without a host", map[string]any{"id": "b", "issuer": "https:///realms/b"}},
		{"jwksUri that is not http", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "jwksUri": "file:///etc/jwks.json"}},
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

// jwtWith returns a compact JWT whose payload is the JSON text payload. The
// header and the signature are placeholders, since nothing checks them.
func jwtWith(payload string) string {
	return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln"
}

func TestIssuerOfTokenFile_ReturnsTheIssOfTheToken(t *testing.T) {
	const want = "https://kubernetes.default.svc.cluster.local"
	path := writeFile(t, "token", jwtWith(`{"iss": "`+want+`", "sub": "system:serviceaccount:ns:app"}`)+"\n")
	got, err := IssuerOfTokenFile(path)
	if err != nil {
		t.Fatalf("IssuerOfTokenFile() error = %v", err)
	}
	if got != want {
		t.Errorf("IssuerOfTokenFile() = %q, want %q", got, want)
	}
}

func TestIssuerOfTokenFile_RefusesAFileWithoutAnIssuer(t *testing.T) {
	tests := []struct {
		name, path string
	}{
		{"missing file", filepath.Join(t.TempDir(), "absent")},
		{"empty file", writeFile(t, "token", "\n")},
		{"two parts", writeFile(t, "token", strings.TrimSuffix(jwtWith(`{"iss": "https://a.example"}`), ".c2ln"))},
		{"four parts", writeFile(t, "token", jwtWith(`{"iss": "https://a.example"}`)+".c2ln")},
		{"payload that is not base64url", writeFile(t, "token", "e30.%%%.c2ln")},
		{"payload that is not JSON", writeFile(t, "token", jwtWith("not json"))},
		{"payload without iss", writeFile(t, "token", jwtWith(`{"sub": "a"}`))},
		{"ISS in place of iss", writeFile(t, "token", jwtWith(`{"ISS": "https://a.example"}`))},
		{"iss that is a number", writeFile(t, "token", jwtWith(`{"iss": 5}`))},
		{"empty iss", writeFile(t, "token", jwtWith(`{"iss": ""}`))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IssuerOfTokenFile(tt.path)
			if err == nil {
				t.Errorf("IssuerOfTokenFile(%s) = %q, want an error", tt.path, got)
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
