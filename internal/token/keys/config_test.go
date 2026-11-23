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
	"errors"
	"io/fs"
	"maps"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// identityProvider returns the provider identity-provider of the example of
// ADR-0104, as the JSON members of a provider file.
func identityProvider() map[string]any {
	return map[string]any{
		"id":              "identity-provider",
		"issuer":          map[string]any{"type": "realm-template", "value": "http://identity-provider:8080/auth/realms/{realm}"},
		"jwksUri":         "http://identity-provider:8080/auth/realms/{realm}/protocol/openid-connect/certs",
		"readinessRealms": []any{"cloud-common"},
		"audience":        map[string]any{"mode": "skipValidation"},
	}
}

// kubernetesProvider returns the provider kubernetes of the example of
// ADR-0104, as the JSON members of a provider file.
func kubernetesProvider() map[string]any {
	return map[string]any{
		"id":                  "kubernetes",
		"issuer":              map[string]any{"type": "exact", "value": "https://kubernetes.default.svc.cluster.local"},
		"jwksUri":             "https://kubernetes.default.svc/openid/v1/jwks",
		"jwksBearerTokenFile": "/var/run/secrets/tokens/kubernetes/token",
		"audience":            map[string]any{"mode": "matchAny", "values": []any{"netcracker"}},
	}
}

// with returns a copy of provider with the member name set to value, or
// removed when value is nil.
func with(provider map[string]any, name string, value any) map[string]any {
	out := maps.Clone(provider)
	if value == nil {
		delete(out, name)
	} else {
		out[name] = value
	}
	return out
}

// providerFile returns the content of a provider file that holds providers.
func providerFile(t *testing.T, providers ...map[string]any) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{"providers": providers})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// kubernetesFileWithAudience returns the content of a provider file that holds
// a provider kubernetes whose one audience value is value, written into the
// file as it is, so value may hold bytes that are not UTF-8.
func kubernetesFileWithAudience(value string) string {
	return `{"providers": [{"id": "kubernetes", "issuer": {"type": "exact", "value": "https://k8s"}, "jwksUri": "https://k8s/jwks", "audience": {"mode": "matchAny", "values": ["` + value + `"]}}]}`
}

// providerDir returns a new directory that holds a file of each name in files
// with its content.
func providerDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The file of the provider kubernetes sorts after the file of the provider
// identity-provider, and comes first in the map.
func TestReadDir_ReadsTheProvidersOfEveryFileInTheOrderOfTheirNames(t *testing.T) {
	dir := providerDir(t, map[string]string{
		"b.json": providerFile(t, kubernetesProvider()),
		"a.json": providerFile(t, identityProvider()),
	})
	want := Config{Providers: []Provider{
		{
			ID:              IdentityProviderID,
			Issuer:          Issuer{Type: RealmTemplate, Value: "http://identity-provider:8080/auth/realms/{realm}"},
			JWKSURI:         "http://identity-provider:8080/auth/realms/{realm}/protocol/openid-connect/certs",
			ReadinessRealms: []string{"cloud-common"},
			Audience:        Audience{Mode: SkipValidation},
			file:            filepath.Join(dir, "a.json"),
		},
		{
			ID:                  KubernetesID,
			Issuer:              Issuer{Type: Exact, Value: "https://kubernetes.default.svc.cluster.local"},
			JWKSURI:             "https://kubernetes.default.svc/openid/v1/jwks",
			JWKSBearerTokenFile: "/var/run/secrets/tokens/kubernetes/token",
			Audience:            Audience{Mode: MatchAny, Values: []string{"netcracker"}},
			file:                filepath.Join(dir, "b.json"),
		},
	}}
	got, err := ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ReadDir() = %+v, want %+v", got, want)
	}
}

// Every skipped entry holds text that is not a provider file, so reading it
// fails the call.
func TestReadDir_SkipsEveryEntryThatIsNotAProviderFile(t *testing.T) {
	dir := providerDir(t, map[string]string{
		"idp.json":     providerFile(t, identityProvider()),
		".hidden.json": "not JSON",
		"notes.txt":    "not JSON",
		"json":         "not JSON",
	})
	if err := os.Mkdir(filepath.Join(dir, "nested.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "nested.json"), filepath.Join(dir, "link-to-a-directory.json")); err != nil {
		t.Fatal(err)
	}
	got, err := ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v, want the provider of idp.json alone", err)
	}
	if len(got.Providers) != 1 || got.Providers[0].ID != IdentityProviderID {
		t.Errorf("ReadDir() = %+v, want the provider of idp.json alone", got)
	}
}

// The layout is the one the kubelet writes for a ConfigMap mounted as a
// directory: the data in a hidden directory, ..data a link to it, and each key
// a link through ..data.
func TestReadDir_ReadsAProviderFileThroughTheLinksOfAMountedConfigMap(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "..2026_11_23_10_00_00.000000001")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "kubernetes.json"), []byte(providerFile(t, kubernetesProvider())), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(data), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..data", "kubernetes.json"), filepath.Join(dir, "kubernetes.json")); err != nil {
		t.Fatal(err)
	}
	got, err := ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(got.Providers) != 1 || got.Providers[0].ID != KubernetesID {
		t.Errorf("ReadDir() = %+v, want the provider kubernetes once", got)
	}
}

func TestReadDir_RefusesADirectoryWithoutAProvider(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
	}{
		{"empty directory", nil},
		{"file with an empty providers array", map[string]string{"empty.json": `{"providers": []}`}},
		{"provider in a hidden file only", map[string]string{".idp.json": providerFile(t, identityProvider())}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := providerDir(t, tt.files)
			_, err := ReadDir(dir)
			if err == nil || !containsAll(err.Error(), "provider directory "+dir, "holds no provider") {
				t.Errorf("ReadDir(%s) error = %v, want an error saying the directory holds no provider", dir, err)
			}
		})
	}
}

func TestReadDir_RefusesADirectoryThatDoesNotExist(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "providers")
	if _, err := ReadDir(dir); !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "provider directory "+dir) {
		t.Errorf("ReadDir(%s) error = %v, want an fs.ErrNotExist error naming the directory", dir, err)
	}
}

// Each file is the only one in its directory, so an error that names it blames
// the file at fault.
func TestReadDir_RefusesAFileThatIsNotAProviderFile(t *testing.T) {
	tests := []struct {
		name, content string
		want          []string
	}{
		{"text that is not JSON", "providers: []", []string{"not a JSON object"}},
		{"JSON array", `[]`, []string{"not a JSON object"}},
		{"second JSON value", `{"providers": []} {}`, []string{"data after the JSON object"}},
		{"object without its closing brace", `{"providers": []`, []string{"not a JSON object: unexpected end of JSON input"}},
		{"member providers twice", `{"providers": [], "providers": []}`, []string{`member "providers" appears twice`}},
		{"no member providers", `{}`, []string{`holds no array "providers"`}},
		{"providers that is null", `{"providers": null}`, []string{`holds no array "providers"`}},
		{"providers that is an object", `{"providers": {}}`, []string{`holds no array "providers"`}},
		{"section keycloak and a member mode beside providers", `{"keycloak": {"url": "http://kc"}, "providers": [], "mode": "strict"}`, []string{`"keycloak", "mode"`}},
		{"provider that is not an object", `{"providers": ["identity-provider"]}`, []string{"providers[0]: not a JSON object"}},
		{"provider with its id twice", `{"providers": [{"id": "kubernetes", "id": "kubernetes"}]}`, []string{`providers[0]: member "id" appears twice`}},
		{"provider with another member twice", `{"providers": [{"id": "kubernetes", "jwksUri": "https://k8s/a", "jwksUri": "https://k8s/b"}]}`, []string{`provider "kubernetes": member "jwksUri" appears twice`}},
		{"byte that is not UTF-8", kubernetesFileWithAudience("caf\xe9"), []string{"holds 0xE9 at byte 168, which is not UTF-8; save the file in UTF-8"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := providerDir(t, map[string]string{"providers.json": tt.content})
			_, err := ReadDir(dir)
			want := append([]string{"provider file " + filepath.Join(dir, "providers.json") + ": "}, tt.want...)
			if err == nil || !containsAll(err.Error(), want...) {
				t.Errorf("ReadDir() of %s error = %v, want an error that contains %q", tt.content, err, want)
			}
		})
	}
}

// U+FFFD is the character that encoding/json puts in place of a byte in a
// string that is not UTF-8.
func TestReadDir_ReadsAValueOutsideASCIIAsTheFileHoldsIt(t *testing.T) {
	for _, value := range []string{"caf\u00e9", "\ufffd"} {
		dir := providerDir(t, map[string]string{"k8s.json": kubernetesFileWithAudience(value)})
		got, err := ReadDir(dir)
		if err != nil {
			t.Errorf("ReadDir() with the audience value %q error = %v, want none", value, err)
			continue
		}
		if values := got.Providers[0].Audience.Values; len(values) != 1 || values[0] != value {
			t.Errorf("ReadDir() with the audience value %q read the audience values %q", value, values)
		}
	}
}

func TestReadDir_RefusesAProviderFileThatLinksToNoFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "idp.json")
	if err := os.Symlink(filepath.Join(dir, "absent"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDir(dir); !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "provider file "+path) {
		t.Errorf("ReadDir() with a link to no file error = %v, want an fs.ErrNotExist error naming %s", err, path)
	}
}

// The file has no read permission, which root ignores.
func TestReadDir_RefusesAProviderFileItCannotRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file without read permission")
	}
	dir := providerDir(t, map[string]string{"idp.json": providerFile(t, identityProvider())})
	path := filepath.Join(dir, "idp.json")
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDir(dir); !errors.Is(err, fs.ErrPermission) || !strings.Contains(err.Error(), "provider file "+path) {
		t.Errorf("ReadDir() with an unreadable file error = %v, want an fs.ErrPermission error naming %s", err, path)
	}
}

// A socket named like a provider file is neither a directory nor a file to
// read. The directory is short, because a socket path is limited to about 100
// bytes.
func TestReadDir_RefusesAProviderFileThatIsNotARegularFile(t *testing.T) {
	dir, err := os.MkdirTemp("", "p")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.json")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if _, err := ReadDir(dir); err == nil || !strings.Contains(err.Error(), "provider file "+path+": is not a regular file") {
		t.Errorf("ReadDir() with a socket error = %v, want an error saying %s is not a regular file", err, path)
	}
}

// Each provider is the provider identity-provider or kubernetes of the example
// of ADR-0104 with one member changed, alone in its file. A row named "removed
// member" adds a member of the format that ADR-0104 replaced.
func TestReadDir_RefusesAProviderThatBreaksAMemberRule(t *testing.T) {
	idp, k8s := identityProvider(), kubernetesProvider()
	tests := []struct {
		name     string
		provider map[string]any
		want     []string
	}{
		{"id of another provider", with(idp, "id", "keycloak"), []string{`provider "keycloak"`, `the id "keycloak" is neither`}},
		{"no id", with(idp, "id", nil), []string{"providers[0]", `has no member "id"`}},
		{"id that is a number", with(idp, "id", 1), []string{"providers[0]", `has no member "id"`}},
		{"id that is null", with(idp, "id", json.RawMessage("null")), []string{"providers[0]", `has no member "id"`}},
		{"unknown member", with(idp, "issuerPattern", "http://kc/{realm}"), []string{`provider "identity-provider"`, `member "issuerPattern" is not allowed`}},
		{"member jwksUri in another case", with(with(k8s, "jwksUri", nil), "jwksURI", "https://k8s/jwks"), []string{`provider "kubernetes"`, `member "jwksURI" is not allowed`}},
		{"removed member audiences", with(k8s, "audiences", []any{"netcracker"}), []string{`provider "kubernetes"`, `member "audiences" is not allowed`}},
		{"removed member allowMissingAud", with(k8s, "allowMissingAud", true), []string{`member "allowMissingAud" is not allowed`}},
		{"removed member caFile", with(k8s, "caFile", "/var/run/ca.crt"), []string{`member "caFile" is not allowed`}},
		{"removed member tokenFile", with(k8s, "tokenFile", "/var/run/token"), []string{`member "tokenFile" is not allowed`}},
		{"removed member kubernetes", with(k8s, "kubernetes", true), []string{`member "kubernetes" is not allowed`}},
		{"removed member required", with(idp, "required", true), []string{`member "required" is not allowed`}},
		{"member that is null", with(idp, "readinessRealms", json.RawMessage("null")), []string{`member "readinessRealms" is null`}},
		{"no issuer", with(idp, "issuer", nil), []string{`has no member "issuer"`}},
		{"no jwksUri", with(k8s, "jwksUri", nil), []string{`has no member "jwksUri"`}},
		{"no audience", with(idp, "audience", nil), []string{`has no member "audience"`}},
		{"jwksBearerTokenFile in identity-provider", with(idp, "jwksBearerTokenFile", "/var/run/token"), []string{`member "jwksBearerTokenFile" is not allowed`, `the provider of Kubernetes tokens has the id "kubernetes"`}},
		{"readinessRealms in kubernetes", with(k8s, "readinessRealms", []any{"cloud-common"}), []string{`provider "kubernetes"`, `member "readinessRealms" is not allowed`}},
		{"readinessRealms in an exact identity-provider", with(with(idp, "issuer", map[string]any{"type": "exact", "value": "http://kc/auth/realms/a"}), "jwksUri", "http://kc/auth/realms/a/certs"), []string{`member "readinessRealms" is not allowed in an exact provider`}},
		{"issuer that is a string", with(k8s, "issuer", "https://kubernetes.default.svc.cluster.local"), []string{`member "issuer": not a JSON object`}},
		{"issuer with a member twice", with(k8s, "issuer", json.RawMessage(`{"type": "exact", "value": "https://k8s", "type": "realm-template"}`)), []string{`member "issuer": member "type" appears twice`}},
		{"issuer with a member pattern", with(k8s, "issuer", map[string]any{"type": "exact", "value": "https://k8s", "pattern": "x"}), []string{`member "issuer" holds "pattern"`}},
		{"issuer without a value", with(k8s, "issuer", map[string]any{"type": "exact"}), []string{`member "value" of "issuer" is not a string`}},
		{"issuer type of another kind", with(k8s, "issuer", map[string]any{"type": "regex", "value": "https://k8s"}), []string{`issuer.type is "regex"`}},
		{"empty issuer value", with(k8s, "issuer", map[string]any{"type": "exact", "value": ""}), []string{"issuer.value is empty"}},
		{"jwksUri that is not http", with(k8s, "jwksUri", "file:///etc/jwks.json"), []string{`jwksUri "file:///etc/jwks.json" is not an http or https URL`}},
		{"jwksUri without a host", with(k8s, "jwksUri", "https:///openid/v1/jwks"), []string{`jwksUri "https:///openid/v1/jwks" has no host`}},
		{"jwksUri with a user and no host", with(k8s, "jwksUri", "https://user@/jwks"), []string{`jwksUri "https://user@/jwks" has no host`}},
		{"jwksUri with a port that is not a number", with(k8s, "jwksUri", "https://k8s:x/jwks"), []string{`jwksUri "https://k8s:x/jwks" is not a URL`}},
		{"jwksUri with a space", with(k8s, "jwksUri", "https://k8s/open id/jwks"), []string{`jwksUri "https://k8s/open id/jwks" holds " " at byte 16`, "percent-encode it as %20"}},
		{"jwksUri with a leading no-break space", with(k8s, "jwksUri", "\u00a0https://k8s/jwks"), []string{`jwksUri "\u00a0https://k8s/jwks" holds "\u00a0" at byte 0`, "percent-encode it as %C2%A0"}},
		{"jwksUri with DEL", with(k8s, "jwksUri", "https://k8s/\x7fjwks"), []string{`jwksUri "https://k8s/\x7fjwks" holds "\x7f" at byte 12`, "percent-encode it as %7F"}},
		{"realm-template jwksUri with a no-break space", with(idp, "jwksUri", "http://kc/\u00a0/{realm}/certs"), []string{`jwksUri "http://kc/\u00a0/{realm}/certs" holds "\u00a0" at byte 10`, "percent-encode it as %C2%A0"}},
		{"realm-template issuer with a leading space", with(idp, "issuer", map[string]any{"type": "realm-template", "value": " http://kc/auth/realms/{realm}"}), []string{`issuer.value " http://kc/auth/realms/{realm}" holds " " at byte 0`, "percent-encode it as %20"}},
		{"realm-template issuer with a trailing line feed", with(idp, "issuer", map[string]any{"type": "realm-template", "value": "http://kc/auth/realms/{realm}\n"}), []string{`issuer.value "http://kc/auth/realms/{realm}\n" holds "\n" at byte 29`, "percent-encode it as %0A"}},
		{"realm-template issuer with a letter outside ASCII", with(idp, "issuer", map[string]any{"type": "realm-template", "value": "http://kc/äuth/realms/{realm}"}), []string{`issuer.value "http://kc/äuth/realms/{realm}" holds "\u00e4" at byte 10`, "percent-encode it as %C3%A4"}},
		{"jwksUri with a fragment", with(k8s, "jwksUri", "https://k8s/jwks#keys"), []string{`jwksUri "https://k8s/jwks#keys" holds a fragment`}},
		{"realm-template jwksUri with a fragment", with(idp, "jwksUri", "http://kc/auth/realms/{realm}/certs#keys"), []string{`jwksUri "http://kc/auth/realms/{realm}/certs#keys" holds a fragment`}},
		{"realm-template issuer with an empty fragment", with(idp, "issuer", map[string]any{"type": "realm-template", "value": "http://kc/auth/realms/{realm}#"}), []string{`issuer.value "http://kc/auth/realms/{realm}#" holds a fragment`}},
		{"jwksUri with a placeholder", with(k8s, "jwksUri", "https://k8s/{namespace}/jwks"), []string{`jwksUri "https://k8s/{namespace}/jwks" holds '{' or '}'; percent-encode them as %7B and %7D`}},
		{"realm-template jwksUri with a second placeholder", with(idp, "jwksUri", "http://kc/{tenant}/{realm}/certs"), []string{`jwksUri "http://kc/{tenant}/{realm}/certs" holds '{' or '}' outside its {realm}`}},
		{"realm-template issuer with a closing brace", with(idp, "issuer", map[string]any{"type": "realm-template", "value": "http://kc/auth/realms/{realm}/}"}), []string{`issuer.value "http://kc/auth/realms/{realm}/}" holds '{' or '}' outside its {realm}`}},
		{"jwksUri that is a number", with(k8s, "jwksUri", 1), []string{`member "jwksUri" has the wrong type`}},
		{"jwksBearerTokenFile that is a number", with(k8s, "jwksBearerTokenFile", 1), []string{`member "jwksBearerTokenFile" is not a string`}},
		{"issuer type that is a number", with(k8s, "issuer", map[string]any{"type": 1, "value": "https://k8s"}), []string{`member "type" of "issuer" is not a string`}},
		{"issuer type that is null", with(k8s, "issuer", map[string]any{"type": json.RawMessage("null"), "value": "https://k8s"}), []string{`member "type" of "issuer" is not a string`}},
		{"relative jwksBearerTokenFile", with(k8s, "jwksBearerTokenFile", "token"), []string{`jwksBearerTokenFile "token" is not an absolute path`}},
		{"empty jwksBearerTokenFile", with(k8s, "jwksBearerTokenFile", ""), []string{`jwksBearerTokenFile "" is not an absolute path`}},
		{"audience that is a string", with(k8s, "audience", "netcracker"), []string{`member "audience": not a JSON object`}},
		{"audience with a member twice", with(k8s, "audience", json.RawMessage(`{"mode": "matchAny", "mode": "skipValidation"}`)), []string{`member "audience": member "mode" appears twice`}},
		{"audience mode of another kind", with(k8s, "audience", map[string]any{"mode": "exact", "values": []any{"netcracker"}}), []string{`audience.mode is "exact"`}},
		{"audience without a mode", with(k8s, "audience", map[string]any{"values": []any{"netcracker"}}), []string{`member "mode" of "audience" is not a string`}},
		{"audience with a member allowMissing", with(k8s, "audience", map[string]any{"mode": "matchAny", "values": []any{"a"}, "allowMissing": true}), []string{`member "audience" holds "allowMissing"`}},
		{"matchAny without values", with(k8s, "audience", map[string]any{"mode": "matchAny"}), []string{"audience.values is empty"}},
		{"matchAny with an empty array", with(k8s, "audience", map[string]any{"mode": "matchAny", "values": []any{}}), []string{"audience.values is empty"}},
		{"matchAny with an empty value", with(k8s, "audience", map[string]any{"mode": "matchAny", "values": []any{"netcracker", ""}}), []string{"audience.values holds an empty string"}},
		{"matchAny with a value that is a number", with(k8s, "audience", map[string]any{"mode": "matchAny", "values": []any{1}}), []string{`member "values" of "audience" is not an array of strings`}},
		{"skipValidation with values", with(idp, "audience", map[string]any{"mode": "skipValidation", "values": []any{"account"}}), []string{`audience.values is set with the mode "skipValidation"`}},
		{"skipValidation with an empty array", with(idp, "audience", map[string]any{"mode": "skipValidation", "values": []any{}}), []string{`audience.values is set with the mode "skipValidation"`}},
		{"skipValidation with values that are null", with(idp, "audience", map[string]any{"mode": "skipValidation", "values": json.RawMessage("null")}), []string{`member "values" of "audience" is not an array of strings`}},
		{"readinessRealms that is a string", with(idp, "readinessRealms", "cloud-common"), []string{`member "readinessRealms" has the wrong type`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := providerDir(t, map[string]string{"provider.json": providerFile(t, tt.provider)})
			_, err := ReadDir(dir)
			want := append([]string{filepath.Join(dir, "provider.json")}, tt.want...)
			if err == nil || !containsAll(err.Error(), want...) {
				t.Errorf("ReadDir() error = %v, want an error that contains %q", err, want)
			}
		})
	}
}

func TestReadDir_ListsTheMembersOfTheProviderBesideAMemberItDoesNotAllow(t *testing.T) {
	dir := providerDir(t, map[string]string{"k8s.json": providerFile(t, with(kubernetesProvider(), "caFile", "/var/run/ca.crt"))})
	want := "provider file " + filepath.Join(dir, "k8s.json") + `: provider "kubernetes": member "caFile" is not allowed; ` +
		`a provider "kubernetes" holds id, issuer, jwksUri, audience, and may hold jwksBearerTokenFile`
	if _, err := ReadDir(dir); err == nil || err.Error() != want {
		t.Errorf("ReadDir() error = %v, want %s", err, want)
	}
}

// The names are those that a realm name in iss may not decode to.
func TestReadDir_RefusesAReadinessRealmThatIsNotARealmName(t *testing.T) {
	tests := []struct {
		name, realm, want string
	}{
		{"empty name", "", "is empty"},
		{"dot", ".", "is a dot segment"},
		{"dot dot", "..", "is a dot segment"},
		{"slash", "a/b", "holds '/', '?', or '#'"},
		{"question mark", "a?b", "holds '/', '?', or '#'"},
		{"hash", "a#b", "holds '/', '?', or '#'"},
		{"control character", "a\x01b", "holds a control character"},
		{"C1 control character", "a\u0085b", "holds a control character"},
		{"name of 256 bytes", strings.Repeat("x", 256), "is 256 bytes long"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := providerDir(t, map[string]string{"idp.json": providerFile(t, with(identityProvider(), "readinessRealms", []any{"cloud-common", tt.realm}))})
			if _, err := ReadDir(dir); err == nil || !containsAll(err.Error(), "readinessRealms: ", tt.want) {
				t.Errorf("ReadDir() with the readiness realm %q error = %v, want an error that contains %q", tt.realm, err, tt.want)
			}
		})
	}
}

func TestReadDir_AcceptsAReadinessRealmOf255BytesAndAnyOtherCharacter(t *testing.T) {
	realms := []any{strings.Repeat("x", 255), "a b", "tenant%20ü"}
	dir := providerDir(t, map[string]string{"idp.json": providerFile(t, with(identityProvider(), "readinessRealms", realms))})
	if _, err := ReadDir(dir); err != nil {
		t.Errorf("ReadDir() with the readiness realms %q error = %v, want none", realms, err)
	}
}

// The provider identity-provider is the one of the example of ADR-0104 with its
// issuer.value or its jwksUri changed.
func TestReadDir_RefusesARealmPlaceholderOutsideOneWholePathSegment(t *testing.T) {
	const jwks = "http://kc/auth/realms/{realm}/protocol/openid-connect/certs"
	tests := []struct {
		name, issuer, jwksURI, want string
	}{
		{"{realm} in the host", "http://{realm}.kc/auth", jwks, "outside a whole segment of its path"},
		{"{realm} as the host", "http://{realm}/auth", jwks, "outside a whole segment of its path"},
		{"{realm} as the host of a URL without a path", "http://{realm}", jwks, "outside a whole segment of its path"},
		{"{realm} after a slash in the query", "http://kc/auth?/{realm}", jwks, "outside a whole segment of its path"},
		{"{realm} after a slash in a query without a path", "http://kc?/{realm}", jwks, "outside a whole segment of its path"},
		{"{realm} after a slash in the fragment", "http://kc/auth#/{realm}", jwks, "outside a whole segment of its path"},
		{"{realm} in part of a segment", "http://kc/auth/realms/t-{realm}", jwks, "outside a whole segment of its path"},
		{"{realm} before more text in its segment", "http://kc/auth/realms/{realm}x", jwks, "outside a whole segment of its path"},
		{"{realm} in the query", "http://kc/auth?realm={realm}", jwks, "outside a whole segment of its path"},
		{"{realm} twice", "http://kc/{realm}/realms/{realm}", jwks, "holds {realm} 2 times"},
		{"no {realm} in the issuer", "http://kc/auth/realms/a", jwks, "holds {realm} 0 times"},
		{"no {realm} in the jwksUri", "http://kc/auth/realms/{realm}", "http://kc/certs", `jwksUri "http://kc/certs" holds {realm} 0 times`},
		{"issuer that is no absolute URL", "/auth/realms/{realm}", jwks, "is not an absolute URL"},
		{"issuer without a scheme", "://kc/auth/realms/{realm}", jwks, "is not an absolute URL"},
		{"issuer that starts with a host", "//proxy/https://kc/auth/realms/{realm}", jwks, "is not an absolute URL"},
		{"issuer that starts with a host and a port", "//kc:8080/x://y/{realm}", jwks, "is not an absolute URL"},
		{"issuer without a host", "http:///auth/realms/{realm}", jwks, "has no host"},
		{"issuer with a scheme of one letter and no host", "a:///auth/realms/{realm}", jwks, "has no host"},
		{"issuer with a broken escape in the host", "http://kc%zz/auth/realms/{realm}", jwks, "is not a URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := with(with(identityProvider(), "issuer", map[string]any{"type": "realm-template", "value": tt.issuer}), "jwksUri", tt.jwksURI)
			dir := providerDir(t, map[string]string{"idp.json": providerFile(t, provider)})
			if _, err := ReadDir(dir); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ReadDir() with the issuer %q and the jwksUri %q error = %v, want an error that contains %q", tt.issuer, tt.jwksURI, err, tt.want)
			}
		})
	}
}

func TestReadDir_RefusesARealmPlaceholderInAnExactProvider(t *testing.T) {
	tests := []struct {
		name, issuer, jwksURI, want string
	}{
		{"in the issuer", "https://k8s/{realm}", "https://k8s/jwks", `issuer.value "https://k8s/{realm}" holds {realm}`},
		{"in the jwksUri", "https://k8s", "https://k8s/{realm}/jwks", `jwksUri "https://k8s/{realm}/jwks" holds {realm}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := with(with(kubernetesProvider(), "issuer", map[string]any{"type": "exact", "value": tt.issuer}), "jwksUri", tt.jwksURI)
			dir := providerDir(t, map[string]string{"k8s.json": providerFile(t, provider)})
			if _, err := ReadDir(dir); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ReadDir() error = %v, want an error that contains %q", err, tt.want)
			}
		})
	}
}

func TestReadDir_AcceptsARealmPlaceholderAsOneWholePathSegment(t *testing.T) {
	tests := []struct {
		name, issuer string
	}{
		{"last segment", "http://kc/auth/realms/{realm}"},
		{"segment before another", "http://kc/realms/{realm}/issuer"},
		{"last segment before a query", "http://kc/realms/{realm}?v=1"},
		{"only segment", "http://kc/{realm}"},
		{"scheme with a digit, a dot, a plus, and a hyphen", "x-1.a+b://kc/realms/{realm}"},
		{"scheme of one letter", "a://kc/{realm}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := with(identityProvider(), "issuer", map[string]any{"type": "realm-template", "value": tt.issuer})
			dir := providerDir(t, map[string]string{"idp.json": providerFile(t, provider)})
			if _, err := ReadDir(dir); err != nil {
				t.Errorf("ReadDir() with the issuer %q error = %v, want none", tt.issuer, err)
			}
		})
	}
}

// '!' and '~' are the lowest and the highest printable ASCII characters other
// than the space.
func TestReadDir_AcceptsAURLOfPrintableASCIIWithTheSchemeInUpperOrLowerCase(t *testing.T) {
	idp, k8s := identityProvider(), kubernetesProvider()
	tests := []struct {
		name     string
		provider map[string]any
	}{
		{"jwksUri with the scheme in upper case", with(k8s, "jwksUri", "HTTPS://kubernetes.default.svc/openid/v1/jwks")},
		{"realm-template jwksUri with the scheme in mixed case", with(idp, "jwksUri", "Http://identity-provider:8080/auth/realms/{realm}/protocol/openid-connect/certs")},
		{"jwksUri with ! and ~", with(k8s, "jwksUri", "https://k8s/!openid~/jwks")},
		{"realm-template issuer with ! and ~", with(idp, "issuer", map[string]any{"type": "realm-template", "value": "http://kc/!auth~/realms/{realm}"})},
		{"jwksUri with a query", with(k8s, "jwksUri", "https://k8s/openid/v1/jwks?format=jwks")},
		{"jwksUri with a percent-encoded space, brace, hash, and no-break space", with(k8s, "jwksUri", "https://k8s/a%20b%7Bc%7D%23d%C2%A0/jwks")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := providerDir(t, map[string]string{"provider.json": providerFile(t, tt.provider)})
			if _, err := ReadDir(dir); err != nil {
				t.Errorf("ReadDir() of %s error = %v, want none", providerFile(t, tt.provider), err)
			}
		})
	}
}

// The checks of a URL apply to the issuer.value of a realm-template provider,
// and an exact one is compared with iss as text.
func TestReadDir_AcceptsAnExactIssuerThatIsNotAURL(t *testing.T) {
	const issuer = "iss with a space, #x, {y}, and \u00e4"
	dir := providerDir(t, map[string]string{"k8s.json": providerFile(t, with(kubernetesProvider(), "issuer", map[string]any{"type": "exact", "value": issuer}))})
	if _, err := ReadDir(dir); err != nil {
		t.Errorf("ReadDir() with the exact issuer.value %q error = %v, want none", issuer, err)
	}
}

func TestReadDir_RefusesTwoProvidersWithOneIDInTwoFiles(t *testing.T) {
	dir := providerDir(t, map[string]string{
		"a.json": providerFile(t, identityProvider()),
		"b.json": providerFile(t, with(identityProvider(), "issuer", map[string]any{"type": "realm-template", "value": "http://other/auth/realms/{realm}"})),
	})
	want := []string{
		`provider "identity-provider" in ` + filepath.Join(dir, "a.json"),
		`provider "identity-provider" in ` + filepath.Join(dir, "b.json"),
		"have one id",
	}
	if _, err := ReadDir(dir); err == nil || !containsAll(err.Error(), want...) {
		t.Errorf("ReadDir() error = %v, want an error that contains %q", err, want)
	}
}

// The provider kubernetes takes an issuer of each type here, beside the
// realm-template http://kc/auth/realms/{realm} of identity-provider. Each row
// that does not overlap differs from a row that does in one respect.
func TestReadDir_RefusesTwoProvidersOneIssCanMatch(t *testing.T) {
	tests := []struct {
		name     string
		issuer   map[string]any
		overlaps bool
	}{
		{"exact issuer that the realm-template matches", map[string]any{"type": "exact", "value": "http://kc/auth/realms/k8s"}, true},
		{"exact issuer with a slash after the realm", map[string]any{"type": "exact", "value": "http://kc/auth/realms/k8s/"}, false},
		{"exact issuer with no realm name", map[string]any{"type": "exact", "value": "http://kc/auth/realms/"}, false},
		{"realm-template with {realm} in another segment", map[string]any{"type": "realm-template", "value": "http://kc/auth/{realm}/k8s"}, true},
		{"realm-template with another fixed segment", map[string]any{"type": "realm-template", "value": "http://kc/auth/tenants/{realm}"}, false},
		{"realm-template with another port", map[string]any{"type": "realm-template", "value": "http://kc:8080/auth/realms/{realm}"}, false},
		{"realm-template with one more segment", map[string]any{"type": "realm-template", "value": "http://kc/auth/realms/{realm}/k8s"}, false},
	}
	idp := with(with(identityProvider(), "issuer", map[string]any{"type": "realm-template", "value": "http://kc/auth/realms/{realm}"}), "readinessRealms", nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8s := with(kubernetesProvider(), "issuer", tt.issuer)
			if tt.issuer["type"] == "realm-template" {
				k8s = with(k8s, "jwksUri", "https://kubernetes.default.svc/{realm}/jwks")
			}
			// Validate compares each provider with the providers before it, so
			// the two orders give the realm-template to either side of the
			// comparison.
			for _, names := range [][2]string{{"1.json", "2.json"}, {"2.json", "1.json"}} {
				dir := providerDir(t, map[string]string{names[0]: providerFile(t, idp), names[1]: providerFile(t, k8s)})
				_, err := ReadDir(dir)
				want := []string{
					`provider "identity-provider" in ` + filepath.Join(dir, names[0]),
					`provider "kubernetes" in ` + filepath.Join(dir, names[1]),
					"can match one iss",
				}
				switch {
				case tt.overlaps && (err == nil || !containsAll(err.Error(), want...)):
					t.Errorf("ReadDir() with the kubernetes issuer %v in %s error = %v, want an error that contains %q", tt.issuer, names[1], err, want)
				case !tt.overlaps && err != nil:
					t.Errorf("ReadDir() with the kubernetes issuer %v in %s error = %v, want none", tt.issuer, names[1], err)
				}
			}
		})
	}
}

// An exact issuer need not be a URL, so the issuers here are plain text too.
func TestReadDir_RefusesTwoExactProvidersWithOneIssuer(t *testing.T) {
	tests := []struct {
		name, idp, k8s string
		overlaps       bool
	}{
		{"one URL", "https://kubernetes.default.svc.cluster.local", "https://kubernetes.default.svc.cluster.local", true},
		{"one text", "issuer-a", "issuer-a", true},
		{"two texts", "issuer-a", "issuer-b", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := with(with(with(identityProvider(), "issuer", map[string]any{"type": "exact", "value": tt.idp}), "jwksUri", "http://kc/certs"), "readinessRealms", nil)
			k8s := with(kubernetesProvider(), "issuer", map[string]any{"type": "exact", "value": tt.k8s})
			dir := providerDir(t, map[string]string{"idp.json": providerFile(t, idp), "k8s.json": providerFile(t, k8s)})
			_, err := ReadDir(dir)
			switch {
			case tt.overlaps && (err == nil || !strings.Contains(err.Error(), "can match one iss")):
				t.Errorf("ReadDir() with the issuers %q and %q error = %v, want an error saying that one iss can match both providers", tt.idp, tt.k8s, err)
			case !tt.overlaps && err != nil:
				t.Errorf("ReadDir() with the issuers %q and %q error = %v, want none", tt.idp, tt.k8s, err)
			}
		})
	}
}

// Each provider is built in code with one value a provider file could not
// hold, so only the checks of New refuse it, and no file names it.
func TestNew_RefusesAProviderBuiltWithAValueThatBreaksARule(t *testing.T) {
	k8s := Provider{
		ID:       KubernetesID,
		Issuer:   Issuer{Type: Exact, Value: "https://k8s"},
		JWKSURI:  "https://k8s/jwks",
		Audience: Audience{Mode: MatchAny, Values: []string{"netcracker"}},
	}
	idp := keycloakProvider()
	tests := []struct {
		name     string
		provider func() Provider
		want     string
	}{
		{"id of another provider", func() Provider { p := k8s; p.ID = "keycloak"; return p }, `provider "keycloak": the id "keycloak" is neither`},
		{"jwksBearerTokenFile in identity-provider", func() Provider { p := idp; p.JWKSBearerTokenFile = "/var/run/token"; return p },
			`provider "identity-provider": member "jwksBearerTokenFile" is not allowed`},
		{"relative jwksBearerTokenFile", func() Provider { p := k8s; p.JWKSBearerTokenFile = "token"; return p },
			`provider "kubernetes": jwksBearerTokenFile "token" is not an absolute path`},
		{"readinessRealms in an exact kubernetes", func() Provider { p := k8s; p.ReadinessRealms = []string{"cloud-common"}; return p },
			`provider "kubernetes": member "readinessRealms" is not allowed; a provider "kubernetes" holds`},
		{"readinessRealms in a realm-template kubernetes", func() Provider {
			p := keycloakProvider("cloud-common")
			p.ID = KubernetesID
			return p
		}, `provider "kubernetes": member "readinessRealms" is not allowed; a provider "kubernetes" holds`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(Config{Providers: []Provider{tt.provider()}}, testOptions()); err == nil || !strings.HasPrefix(err.Error(), tt.want) {
				t.Errorf("New() error = %v, want an error that starts with %q", err, tt.want)
			}
		})
	}
}

func TestNew_RefusesAConfigWithoutAProvider(t *testing.T) {
	if _, err := New(Config{}, testOptions()); err == nil || err.Error() != "no provider is configured" {
		t.Errorf("New(Config{}) error = %v, want no provider is configured", err)
	}
}
