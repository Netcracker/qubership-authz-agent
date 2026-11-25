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
		"type":            "realms",
		"issuerTemplate":  "http://identity-provider:8080/auth/realms/{realm}",
		"jwksUri":         "http://identity-provider:8080/auth/realms/{realm}/protocol/openid-connect/certs",
		"readinessRealms": []any{"cloud-common"},
		"audience":        map[string]any{"mode": "ignore"},
	}
}

// singleIdentityProvider returns a provider identity-provider of the type
// single, as the JSON members of a provider file.
func singleIdentityProvider() map[string]any {
	return map[string]any{
		"type":     "single",
		"issuer":   "http://kc/auth/realms/a",
		"jwksUri":  "http://kc/auth/realms/a/certs",
		"audience": map[string]any{"mode": "ignore"},
	}
}

// kubernetesProvider returns the provider kubernetes of the example of
// ADR-0104, as the JSON members of a provider file.
func kubernetesProvider() map[string]any {
	return map[string]any{
		"type":                "single",
		"issuer":              "https://kubernetes.default.svc.cluster.local",
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

// providerFile returns the content of a provider file that holds provider
// under key.
func providerFile(t *testing.T, key string, provider map[string]any) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{"providers": map[string]any{key: provider}})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// kubernetesFileWithAudience returns the content of a provider file that holds
// a provider kubernetes whose one audience value is value, written into the
// file as it is, so value may hold bytes that are not UTF-8.
func kubernetesFileWithAudience(value string) string {
	return `{"providers": {"kubernetes": {"type": "single", "issuer": "https://k8s", "jwksUri": "https://k8s/jwks", "audience": {"mode": "matchAny", "values": ["` + value + `"]}}}}`
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

// The two files are those of the example of ADR-0104, $schema included, and
// the file of the provider kubernetes sorts first.
func TestReadDir_ReadsTheProvidersOfEveryFileInTheOrderOfTheirNames(t *testing.T) {
	dir := providerDir(t, map[string]string{
		"b-identity-provider.json": `{
  "$schema": "https://raw.githubusercontent.com/Netcracker/qubership-authz-agent/main/api/provider-file.v1.schema.json",
  "providers": {
    "identity-provider": {
      "type": "realms",
      "issuerTemplate": "http://identity-provider:8080/auth/realms/{realm}",
      "jwksUri": "http://identity-provider:8080/auth/realms/{realm}/protocol/openid-connect/certs",
      "readinessRealms": ["cloud-common"],
      "audience": {"mode": "ignore"}
    }
  }
}`,
		"a-kubernetes.json": `{
  "$schema": "https://raw.githubusercontent.com/Netcracker/qubership-authz-agent/main/api/provider-file.v1.schema.json",
  "providers": {
    "kubernetes": {
      "type": "single",
      "issuer": "https://kubernetes.default.svc.cluster.local",
      "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks",
      "jwksBearerTokenFile": "/var/run/secrets/tokens/kubernetes/token",
      "audience": {"mode": "matchAny", "values": ["netcracker"]}
    }
  }
}`,
	})
	want := Config{Providers: []Provider{
		{
			ID:                  KubernetesID,
			Type:                Single,
			Issuer:              "https://kubernetes.default.svc.cluster.local",
			JWKSURI:             "https://kubernetes.default.svc/openid/v1/jwks",
			JWKSBearerTokenFile: "/var/run/secrets/tokens/kubernetes/token",
			Audience:            Audience{Mode: MatchAny, Values: []string{"netcracker"}},
			file:                filepath.Join(dir, "a-kubernetes.json"),
		},
		{
			ID:              IdentityProviderID,
			Type:            Realms,
			IssuerTemplate:  "http://identity-provider:8080/auth/realms/{realm}",
			JWKSURI:         "http://identity-provider:8080/auth/realms/{realm}/protocol/openid-connect/certs",
			ReadinessRealms: []string{"cloud-common"},
			Audience:        Audience{Mode: Ignore},
			file:            filepath.Join(dir, "b-identity-provider.json"),
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

// The key kubernetes comes first in the file and sorts last.
func TestReadDir_ReadsTheProvidersOfOneFileInTheOrderOfTheirKeys(t *testing.T) {
	dir := providerDir(t, map[string]string{"providers.json": `{"providers": {
  "kubernetes": {"type": "single", "issuer": "https://k8s", "jwksUri": "https://k8s/jwks", "audience": {"mode": "matchAny", "values": ["netcracker"]}},
  "identity-provider": {"type": "single", "issuer": "http://kc/auth/realms/a", "jwksUri": "http://kc/auth/realms/a/certs", "audience": {"mode": "ignore"}}
}}`})
	got, err := ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	var keys []string
	for _, p := range got.Providers {
		keys = append(keys, p.ID)
	}
	if want := []string{KubernetesID, IdentityProviderID}; !reflect.DeepEqual(keys, want) {
		t.Errorf("ReadDir() read the keys %q, want %q", keys, want)
	}
}

// Every skipped entry holds text that is not a provider file, so reading it
// fails the call.
func TestReadDir_SkipsEveryEntryThatIsNotAProviderFile(t *testing.T) {
	dir := providerDir(t, map[string]string{
		"idp.json":     providerFile(t, IdentityProviderID, identityProvider()),
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
	if err := os.WriteFile(filepath.Join(data, "kubernetes.json"), []byte(providerFile(t, KubernetesID, kubernetesProvider())), 0o600); err != nil {
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
		{"file with an empty providers object", map[string]string{"empty.json": `{"providers": {}}`}},
		{"provider in a hidden file only", map[string]string{".idp.json": providerFile(t, IdentityProviderID, identityProvider())}},
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
		{"text that is not JSON", "providers: {}", []string{"not a JSON object"}},
		{"JSON array", `[]`, []string{"not a JSON object"}},
		{"second JSON value", `{"providers": {}} {}`, []string{"data after the JSON object"}},
		{"object without its closing brace", `{"providers": {}`, []string{"not a JSON object: unexpected end of JSON input"}},
		{"member providers twice", `{"providers": {}, "providers": {}}`, []string{`member "providers" appears twice`}},
		{"no member providers", `{}`, []string{`has no member "providers"`}},
		{"no member providers beside $schema", `{"$schema": "provider-file.v1.schema.json"}`, []string{`has no member "providers"`}},
		{"providers that is null", `{"providers": null}`, []string{`member "providers": not a JSON object`}},
		{"providers that is an array, as in the former format", `{"providers": []}`, []string{`member "providers": not a JSON object`}},
		{"section keycloak and a member mode beside providers", `{"keycloak": {"url": "http://kc"}, "providers": {}, "mode": "strict"}`, []string{`holds "keycloak", "mode" beside "providers"`}},
		{"$schema that is a number", `{"$schema": 1, "providers": {}}`, []string{`member "$schema" is not a string`}},
		{"$schema that is null", `{"$schema": null, "providers": {}}`, []string{`member "$schema" is not a string`}},
		{"provider that is not an object", `{"providers": {"identity-provider": "http://kc"}}`, []string{`provider "identity-provider": not a JSON object`}},
		{"provider that is null", `{"providers": {"identity-provider": null}}`, []string{`provider "identity-provider": not a JSON object`}},
		{"provider twice", `{"providers": {"kubernetes": {}, "kubernetes": {}}}`, []string{`member "providers": member "kubernetes" appears twice`}},
		{"provider with a member twice", `{"providers": {"kubernetes": {"type": "single", "jwksUri": "https://k8s/a", "jwksUri": "https://k8s/b"}}}`, []string{`provider "kubernetes": member "jwksUri" appears twice`}},
		{"byte that is not UTF-8", kubernetesFileWithAudience("caf\xe9"), []string{"holds 0xE9 at byte 152, which is not UTF-8; save the file in UTF-8"}},
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
	dir := providerDir(t, map[string]string{"idp.json": providerFile(t, IdentityProviderID, identityProvider())})
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
// of ADR-0104, or the single identity-provider, with one member changed, alone
// in its file under the key it is listed with. A row named "removed member"
// adds a member of the format that ADR-0104 replaced.
func TestReadDir_RefusesAProviderThatBreaksAMemberRule(t *testing.T) {
	const idpKey, k8sKey = IdentityProviderID, KubernetesID
	idp, single, k8s := identityProvider(), singleIdentityProvider(), kubernetesProvider()
	tests := []struct {
		name     string
		key      string
		provider map[string]any
		want     []string
	}{
		{"key of another provider", "keycloak", idp, []string{`provider "keycloak": the key "keycloak" is neither "identity-provider" nor "kubernetes"`}},
		{"key in another case", "Kubernetes", k8s, []string{`provider "Kubernetes": the key "Kubernetes" is neither`}},
		{"no type", idpKey, with(idp, "type", nil), []string{`provider "identity-provider": has no member "type" that is a string; a provider "identity-provider" has the type "realms" or "single"`}},
		{"type that is a number", k8sKey, with(k8s, "type", 1), []string{`provider "kubernetes": has no member "type" that is a string; a provider "kubernetes" has the type "single"`}},
		{"type that is null", k8sKey, with(k8s, "type", json.RawMessage("null")), []string{`has no member "type" that is a string`}},
		{"type of another kind", idpKey, with(idp, "type", "exact"), []string{`provider "identity-provider": the type "exact" is not allowed; a provider "identity-provider" has the type "realms" or "single"`}},
		{"type realms in kubernetes", k8sKey, with(k8s, "type", "realms"), []string{`provider "kubernetes": the type "realms" is not allowed; a provider "kubernetes" has the type "single"`}},
		{"unknown member", idpKey, with(idp, "issuerPattern", "http://kc/{realm}"), []string{`provider "identity-provider": member "issuerPattern" is not allowed`}},
		{"member jwksUri in another case", k8sKey, with(with(k8s, "jwksUri", nil), "jwksURI", "https://k8s/jwks"), []string{`provider "kubernetes": member "jwksURI" is not allowed`}},
		{"removed member id", k8sKey, with(k8s, "id", "kubernetes"), []string{`member "id" is not allowed`}},
		{"removed member audiences", k8sKey, with(k8s, "audiences", []any{"netcracker"}), []string{`member "audiences" is not allowed`}},
		{"removed member allowMissingAud", k8sKey, with(k8s, "allowMissingAud", true), []string{`member "allowMissingAud" is not allowed`}},
		{"removed member caFile", k8sKey, with(k8s, "caFile", "/var/run/ca.crt"), []string{`member "caFile" is not allowed`}},
		{"removed member tokenFile", k8sKey, with(k8s, "tokenFile", "/var/run/token"), []string{`member "tokenFile" is not allowed`}},
		{"removed member kubernetes", k8sKey, with(k8s, "kubernetes", true), []string{`member "kubernetes" is not allowed`}},
		{"removed member required", idpKey, with(idp, "required", true), []string{`member "required" is not allowed`}},
		{"member that is null", idpKey, with(idp, "readinessRealms", json.RawMessage("null")), []string{`member "readinessRealms" is null`}},
		{"no issuerTemplate in a realms provider", idpKey, with(idp, "issuerTemplate", nil), []string{`has no member "issuerTemplate"`}},
		{"no issuer in a single provider", k8sKey, with(k8s, "issuer", nil), []string{`has no member "issuer"`}},
		{"no jwksUri", k8sKey, with(k8s, "jwksUri", nil), []string{`has no member "jwksUri"`}},
		{"no audience", idpKey, with(idp, "audience", nil), []string{`has no member "audience"`}},
		{"issuer in a realms provider", idpKey, with(idp, "issuer", "http://identity-provider:8080/auth/realms/a"), []string{`member "issuer" is not allowed; a provider "identity-provider" of the type "realms" holds`}},
		{"issuerTemplate in a single provider", idpKey, with(single, "issuerTemplate", "http://kc/auth/realms/{realm}"), []string{`member "issuerTemplate" is not allowed; a provider "identity-provider" of the type "single" holds`}},
		{"jwksBearerTokenFile in identity-provider", idpKey, with(idp, "jwksBearerTokenFile", "/var/run/token"), []string{`member "jwksBearerTokenFile" is not allowed`, `the provider of Kubernetes tokens has the key "kubernetes"`}},
		{"readinessRealms in kubernetes", k8sKey, with(k8s, "readinessRealms", []any{"cloud-common"}), []string{`provider "kubernetes": member "readinessRealms" is not allowed`, `the agent waits for the keys of a provider of the type "single" at start in any case`}},
		{"readinessRealms in a single identity-provider", idpKey, with(single, "readinessRealms", []any{"a"}), []string{`member "readinessRealms" is not allowed`, `the agent waits for the keys of a provider of the type "single" at start in any case`}},
		{"issuer in the former format", k8sKey, with(k8s, "issuer", map[string]any{"type": "exact", "value": "https://k8s"}), []string{`member "issuer" is not a string`}},
		{"issuer that is not a URL", k8sKey, with(k8s, "issuer", "kubernetes"), []string{`issuer "kubernetes" is not an absolute URL`}},
		{"empty issuer", k8sKey, with(k8s, "issuer", ""), []string{`issuer "" is not an absolute URL`}},
		{"issuer with a space", idpKey, with(single, "issuer", "http://kc/auth/realms/a b"), []string{`issuer "http://kc/auth/realms/a b" holds " " at byte 23`, "percent-encode it as %20"}},
		{"issuer with a fragment", k8sKey, with(k8s, "issuer", "https://k8s#x"), []string{`issuer "https://k8s#x" holds a fragment`}},
		{"issuer with a brace", k8sKey, with(k8s, "issuer", "https://k8s/{x}"), []string{`issuer "https://k8s/{x}" holds '{' or '}'; percent-encode them as %7B and %7D`}},
		{"jwksUri that is not http", k8sKey, with(k8s, "jwksUri", "file:///etc/jwks.json"), []string{`jwksUri "file:///etc/jwks.json" is not an http or https URL`}},
		{"jwksUri without a host", k8sKey, with(k8s, "jwksUri", "https:///openid/v1/jwks"), []string{`jwksUri "https:///openid/v1/jwks" has no host`}},
		{"jwksUri with a user and no host", k8sKey, with(k8s, "jwksUri", "https://user@/jwks"), []string{`jwksUri "https://user@/jwks" has no host`}},
		{"jwksUri with a port and no host", k8sKey, with(k8s, "jwksUri", "https://:8443/jwks"), []string{`jwksUri "https://:8443/jwks" has no host`}},
		{"jwksUri with a port that is not a number", k8sKey, with(k8s, "jwksUri", "https://k8s:x/jwks"), []string{`jwksUri "https://k8s:x/jwks" is not a URL`}},
		{"jwksUri with a space", k8sKey, with(k8s, "jwksUri", "https://k8s/open id/jwks"), []string{`jwksUri "https://k8s/open id/jwks" holds " " at byte 16`, "percent-encode it as %20"}},
		{"jwksUri with a leading no-break space", k8sKey, with(k8s, "jwksUri", "\u00a0https://k8s/jwks"), []string{`jwksUri "\u00a0https://k8s/jwks" holds "\u00a0" at byte 0`, "percent-encode it as %C2%A0"}},
		{"jwksUri with DEL", k8sKey, with(k8s, "jwksUri", "https://k8s/\x7fjwks"), []string{`jwksUri "https://k8s/\x7fjwks" holds "\x7f" at byte 12`, "percent-encode it as %7F"}},
		{"realms jwksUri with a no-break space", idpKey, with(idp, "jwksUri", "http://kc/\u00a0/{realm}/certs"), []string{`jwksUri "http://kc/\u00a0/{realm}/certs" holds "\u00a0" at byte 10`, "percent-encode it as %C2%A0"}},
		{"issuerTemplate with a leading space", idpKey, with(idp, "issuerTemplate", " http://kc/auth/realms/{realm}"), []string{`issuerTemplate " http://kc/auth/realms/{realm}" holds " " at byte 0`, "percent-encode it as %20"}},
		{"issuerTemplate with a trailing line feed", idpKey, with(idp, "issuerTemplate", "http://kc/auth/realms/{realm}\n"), []string{`issuerTemplate "http://kc/auth/realms/{realm}\n" holds "\n" at byte 29`, "percent-encode it as %0A"}},
		{"issuerTemplate with a letter outside ASCII", idpKey, with(idp, "issuerTemplate", "http://kc/äuth/realms/{realm}"), []string{`issuerTemplate "http://kc/äuth/realms/{realm}" holds "\u00e4" at byte 10`, "percent-encode it as %C3%A4"}},
		{"jwksUri with a fragment", k8sKey, with(k8s, "jwksUri", "https://k8s/jwks#keys"), []string{`jwksUri "https://k8s/jwks#keys" holds a fragment`}},
		{"realms jwksUri with a fragment", idpKey, with(idp, "jwksUri", "http://kc/auth/realms/{realm}/certs#keys"), []string{`jwksUri "http://kc/auth/realms/{realm}/certs#keys" holds a fragment`}},
		{"issuerTemplate with an empty fragment", idpKey, with(idp, "issuerTemplate", "http://kc/auth/realms/{realm}#"), []string{`issuerTemplate "http://kc/auth/realms/{realm}#" holds a fragment`}},
		{"jwksUri with a placeholder", k8sKey, with(k8s, "jwksUri", "https://k8s/{namespace}/jwks"), []string{`jwksUri "https://k8s/{namespace}/jwks" holds '{' or '}'; percent-encode them as %7B and %7D`}},
		{"realms jwksUri with a second placeholder", idpKey, with(idp, "jwksUri", "http://kc/{tenant}/{realm}/certs"), []string{`jwksUri "http://kc/{tenant}/{realm}/certs" holds '{' or '}' outside its {realm}`}},
		{"issuerTemplate with a closing brace", idpKey, with(idp, "issuerTemplate", "http://kc/auth/realms/{realm}/}"), []string{`issuerTemplate "http://kc/auth/realms/{realm}/}" holds '{' or '}' outside its {realm}`}},
		{"jwksUri that is a number", k8sKey, with(k8s, "jwksUri", 1), []string{`member "jwksUri" is not a string`}},
		{"issuerTemplate that is a number", idpKey, with(idp, "issuerTemplate", 1), []string{`member "issuerTemplate" is not a string`}},
		{"jwksBearerTokenFile that is a number", k8sKey, with(k8s, "jwksBearerTokenFile", 1), []string{`member "jwksBearerTokenFile" is not a string`}},
		{"relative jwksBearerTokenFile", k8sKey, with(k8s, "jwksBearerTokenFile", "token"), []string{`jwksBearerTokenFile "token" is not an absolute path`}},
		{"empty jwksBearerTokenFile", k8sKey, with(k8s, "jwksBearerTokenFile", ""), []string{`jwksBearerTokenFile "" is not an absolute path`}},
		{"audience that is a string", k8sKey, with(k8s, "audience", "netcracker"), []string{`member "audience": not a JSON object`}},
		{"audience with a member twice", k8sKey, with(k8s, "audience", json.RawMessage(`{"mode": "matchAny", "mode": "ignore"}`)), []string{`member "audience": member "mode" appears twice`}},
		{"audience mode of another kind", k8sKey, with(k8s, "audience", map[string]any{"mode": "exact", "values": []any{"netcracker"}}), []string{`audience.mode is "exact"; it is "matchAny" or "ignore"`}},
		{"audience mode of the former format", idpKey, with(idp, "audience", map[string]any{"mode": "skipValidation"}), []string{`audience.mode is "skipValidation"; it is "matchAny" or "ignore"`}},
		{"audience without a mode", k8sKey, with(k8s, "audience", map[string]any{"values": []any{"netcracker"}}), []string{`member "mode" of "audience" is not a string`}},
		{"audience mode that is a number", k8sKey, with(k8s, "audience", map[string]any{"mode": 1, "values": []any{"netcracker"}}), []string{`member "mode" of "audience" is not a string`}},
		{"audience mode that is null", k8sKey, with(k8s, "audience", map[string]any{"mode": json.RawMessage("null"), "values": []any{"netcracker"}}), []string{`member "mode" of "audience" is not a string`}},
		{"audience with a member allowMissing", k8sKey, with(k8s, "audience", map[string]any{"mode": "matchAny", "values": []any{"a"}, "allowMissing": true}), []string{`member "audience" holds "allowMissing"`}},
		{"matchAny without values", k8sKey, with(k8s, "audience", map[string]any{"mode": "matchAny"}), []string{"audience.values is empty"}},
		{"matchAny with an empty array", k8sKey, with(k8s, "audience", map[string]any{"mode": "matchAny", "values": []any{}}), []string{"audience.values is empty"}},
		{"matchAny with an empty value", k8sKey, with(k8s, "audience", map[string]any{"mode": "matchAny", "values": []any{"netcracker", ""}}), []string{"audience.values holds an empty string"}},
		{"matchAny with a value that is a number", k8sKey, with(k8s, "audience", map[string]any{"mode": "matchAny", "values": []any{1}}), []string{`member "values" of "audience" is not an array of strings`}},
		{"matchAny with a value that is null", k8sKey, with(k8s, "audience", map[string]any{"mode": "matchAny", "values": []any{"netcracker", nil}}), []string{`member "values" of "audience" is not an array of strings`}},
		{"ignore with values", idpKey, with(idp, "audience", map[string]any{"mode": "ignore", "values": []any{"account"}}), []string{`audience.values is set with the mode "ignore", which checks no value; remove it, or set the mode to "matchAny"`}},
		{"ignore with an empty array", idpKey, with(idp, "audience", map[string]any{"mode": "ignore", "values": []any{}}), []string{`audience.values is set with the mode "ignore"`}},
		{"ignore with values that are null", idpKey, with(idp, "audience", map[string]any{"mode": "ignore", "values": json.RawMessage("null")}), []string{`member "values" of "audience" is not an array of strings`}},
		{"readinessRealms that is a string", idpKey, with(idp, "readinessRealms", "cloud-common"), []string{`member "readinessRealms" is not an array of strings`}},
		{"readinessRealms with a name that is null", idpKey, with(idp, "readinessRealms", []any{"cloud-common", nil}), []string{`member "readinessRealms" is not an array of strings`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := providerDir(t, map[string]string{"provider.json": providerFile(t, tt.key, tt.provider)})
			_, err := ReadDir(dir)
			want := append([]string{filepath.Join(dir, "provider.json")}, tt.want...)
			if err == nil || !containsAll(err.Error(), want...) {
				t.Errorf("ReadDir() error = %v, want an error that contains %q", err, want)
			}
		})
	}
}

// A single identity-provider is the provider with no optional member.
func TestReadDir_ListsTheMembersOfTheProviderBesideAMemberItDoesNotAllow(t *testing.T) {
	tests := []struct {
		name, key string
		provider  map[string]any
		want      string
	}{
		{"kubernetes", KubernetesID, kubernetesProvider(), `provider "kubernetes": member "caFile" is not allowed; ` +
			`a provider "kubernetes" of the type "single" holds type, issuer, jwksUri, audience, and may hold jwksBearerTokenFile`},
		{"realms identity-provider", IdentityProviderID, identityProvider(), `provider "identity-provider": member "caFile" is not allowed; ` +
			`a provider "identity-provider" of the type "realms" holds type, issuerTemplate, jwksUri, audience, and may hold readinessRealms`},
		{"single identity-provider", IdentityProviderID, singleIdentityProvider(), `provider "identity-provider": member "caFile" is not allowed; ` +
			`a provider "identity-provider" of the type "single" holds type, issuer, jwksUri, audience`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := providerDir(t, map[string]string{"p.json": providerFile(t, tt.key, with(tt.provider, "caFile", "/var/run/ca.crt"))})
			want := "provider file " + filepath.Join(dir, "p.json") + ": " + tt.want
			if _, err := ReadDir(dir); err == nil || err.Error() != want {
				t.Errorf("ReadDir() error = %v, want %s", err, want)
			}
		})
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
			dir := providerDir(t, map[string]string{"idp.json": providerFile(t, IdentityProviderID, with(identityProvider(), "readinessRealms", []any{"cloud-common", tt.realm}))})
			if _, err := ReadDir(dir); err == nil || !containsAll(err.Error(), "readinessRealms: ", tt.want) {
				t.Errorf("ReadDir() with the readiness realm %q error = %v, want an error that contains %q", tt.realm, err, tt.want)
			}
		})
	}
}

func TestReadDir_AcceptsAReadinessRealmOf255BytesAndAnyOtherCharacter(t *testing.T) {
	realms := []any{strings.Repeat("x", 255), "a b", "tenant%20ü"}
	dir := providerDir(t, map[string]string{"idp.json": providerFile(t, IdentityProviderID, with(identityProvider(), "readinessRealms", realms))})
	if _, err := ReadDir(dir); err != nil {
		t.Errorf("ReadDir() with the readiness realms %q error = %v, want none", realms, err)
	}
}

// The provider identity-provider is the one of the example of ADR-0104 with its
// issuerTemplate or its jwksUri changed.
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
		{"no {realm} in the issuerTemplate", "http://kc/auth/realms/a", jwks, "holds {realm} 0 times"},
		{"no {realm} in the jwksUri", "http://kc/auth/realms/{realm}", "http://kc/certs", `jwksUri "http://kc/certs" holds {realm} 0 times`},
		{"issuerTemplate that is no absolute URL", "/auth/realms/{realm}", jwks, "is not an absolute URL"},
		{"issuerTemplate without a scheme", "://kc/auth/realms/{realm}", jwks, "is not an absolute URL"},
		{"issuerTemplate that starts with a host", "//proxy/https://kc/auth/realms/{realm}", jwks, "is not an absolute URL"},
		{"issuerTemplate that starts with a host and a port", "//kc:8080/x://y/{realm}", jwks, "is not an absolute URL"},
		{"issuerTemplate without a host", "http:///auth/realms/{realm}", jwks, "has no host"},
		{"issuerTemplate with a scheme of one letter and no host", "a:///auth/realms/{realm}", jwks, "has no host"},
		{"issuerTemplate with a broken escape in the host", "http://kc%zz/auth/realms/{realm}", jwks, "is not a URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := with(with(identityProvider(), "issuerTemplate", tt.issuer), "jwksUri", tt.jwksURI)
			dir := providerDir(t, map[string]string{"idp.json": providerFile(t, IdentityProviderID, provider)})
			if _, err := ReadDir(dir); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ReadDir() with the issuerTemplate %q and the jwksUri %q error = %v, want an error that contains %q", tt.issuer, tt.jwksURI, err, tt.want)
			}
		})
	}
}

// Only the key identity-provider has the type realms, so only its error offers
// that type.
func TestReadDir_RefusesARealmPlaceholderInASingleProvider(t *testing.T) {
	tests := []struct {
		name, key string
		provider  map[string]any
		want      string
	}{
		{"in the issuer of kubernetes", KubernetesID, with(kubernetesProvider(), "issuer", "https://k8s/{realm}"),
			`issuer "https://k8s/{realm}" holds {realm}, which a provider of the type "single" does not; remove {realm}`},
		{"in the jwksUri of kubernetes", KubernetesID, with(kubernetesProvider(), "jwksUri", "https://k8s/{realm}/jwks"),
			`jwksUri "https://k8s/{realm}/jwks" holds {realm}, which a provider of the type "single" does not; remove {realm}`},
		{"in the issuer of identity-provider", IdentityProviderID, with(singleIdentityProvider(), "issuer", "http://kc/auth/realms/{realm}"),
			`issuer "http://kc/auth/realms/{realm}" holds {realm}, which a provider of the type "single" does not; set type to "realms" and name the iss in issuerTemplate, or remove {realm}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := providerDir(t, map[string]string{"p.json": providerFile(t, tt.key, tt.provider)})
			if _, err := ReadDir(dir); err == nil || !strings.HasSuffix(err.Error(), tt.want) {
				t.Errorf("ReadDir() error = %v, want an error that ends with %q", err, tt.want)
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
			provider := with(identityProvider(), "issuerTemplate", tt.issuer)
			dir := providerDir(t, map[string]string{"idp.json": providerFile(t, IdentityProviderID, provider)})
			if _, err := ReadDir(dir); err != nil {
				t.Errorf("ReadDir() with the issuerTemplate %q error = %v, want none", tt.issuer, err)
			}
		})
	}
}

// '!' and '~' are the lowest and the highest printable ASCII characters other
// than the space.
func TestReadDir_AcceptsAURLOfPrintableASCIIWithTheSchemeInUpperOrLowerCase(t *testing.T) {
	idp, single, k8s := identityProvider(), singleIdentityProvider(), kubernetesProvider()
	tests := []struct {
		name, key string
		provider  map[string]any
	}{
		{"jwksUri with the scheme in upper case", KubernetesID, with(k8s, "jwksUri", "HTTPS://kubernetes.default.svc/openid/v1/jwks")},
		{"realms jwksUri with the scheme in mixed case", IdentityProviderID, with(idp, "jwksUri", "Http://identity-provider:8080/auth/realms/{realm}/protocol/openid-connect/certs")},
		{"jwksUri with ! and ~", KubernetesID, with(k8s, "jwksUri", "https://k8s/!openid~/jwks")},
		{"issuerTemplate with ! and ~", IdentityProviderID, with(idp, "issuerTemplate", "http://kc/!auth~/realms/{realm}")},
		{"issuer with ! and ~ and a scheme other than http", IdentityProviderID, with(single, "issuer", "urn+x://kc/!a~")},
		{"jwksUri with a query", KubernetesID, with(k8s, "jwksUri", "https://k8s/openid/v1/jwks?format=jwks")},
		{"jwksUri with a percent-encoded space, brace, hash, and no-break space", KubernetesID, with(k8s, "jwksUri", "https://k8s/a%20b%7Bc%7D%23d%C2%A0/jwks")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := providerDir(t, map[string]string{"provider.json": providerFile(t, tt.key, tt.provider)})
			if _, err := ReadDir(dir); err != nil {
				t.Errorf("ReadDir() of %s error = %v, want none", providerFile(t, tt.key, tt.provider), err)
			}
		})
	}
}

func TestReadDir_RefusesTwoProvidersWithOneKeyInTwoFiles(t *testing.T) {
	dir := providerDir(t, map[string]string{
		"a.json": providerFile(t, IdentityProviderID, identityProvider()),
		"b.json": providerFile(t, IdentityProviderID, with(identityProvider(), "issuerTemplate", "http://other/auth/realms/{realm}")),
	})
	want := []string{
		`provider "identity-provider" in ` + filepath.Join(dir, "a.json"),
		`provider "identity-provider" in ` + filepath.Join(dir, "b.json"),
		"have the same key; each key names one provider",
	}
	if _, err := ReadDir(dir); err == nil || !containsAll(err.Error(), want...) {
		t.Errorf("ReadDir() error = %v, want an error that contains %q", err, want)
	}
}

// The provider kubernetes takes an issuer here beside the issuerTemplate
// http://kc/auth/realms/{realm} of identity-provider. Each row that does not
// overlap differs from the row that does in one respect.
func TestReadDir_RefusesASingleProviderThatARealmsProviderMatches(t *testing.T) {
	tests := []struct {
		name     string
		issuer   string
		overlaps bool
	}{
		{"issuer that the issuerTemplate matches", "http://kc/auth/realms/k8s", true},
		{"issuer with a slash after the realm", "http://kc/auth/realms/k8s/", false},
		{"issuer with no realm name", "http://kc/auth/realms/", false},
	}
	idp := with(with(identityProvider(), "issuerTemplate", "http://kc/auth/realms/{realm}"), "readinessRealms", nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8s := with(kubernetesProvider(), "issuer", tt.issuer)
			// Validate compares each provider with the providers before it, so
			// the two orders give the realms provider to either side of the
			// comparison.
			for _, names := range [][2]string{{"1.json", "2.json"}, {"2.json", "1.json"}} {
				dir := providerDir(t, map[string]string{names[0]: providerFile(t, IdentityProviderID, idp), names[1]: providerFile(t, KubernetesID, k8s)})
				_, err := ReadDir(dir)
				want := []string{
					`issuerTemplate "http://kc/auth/realms/{realm}" of provider "identity-provider" in ` + filepath.Join(dir, names[0]),
					`issuer "` + tt.issuer + `" of provider "kubernetes" in ` + filepath.Join(dir, names[1]),
					"can match one iss",
				}
				switch {
				case tt.overlaps && (err == nil || !containsAll(err.Error(), want...)):
					t.Errorf("ReadDir() with the kubernetes issuer %q in %s error = %v, want an error that contains %q", tt.issuer, names[1], err, want)
				case !tt.overlaps && err != nil:
					t.Errorf("ReadDir() with the kubernetes issuer %q in %s error = %v, want none", tt.issuer, names[1], err)
				}
			}
		})
	}
}

func TestReadDir_RefusesTwoSingleProvidersWithOneIssuer(t *testing.T) {
	tests := []struct {
		name, idp, k8s string
		overlaps       bool
	}{
		{"one URL", "https://kubernetes.default.svc.cluster.local", "https://kubernetes.default.svc.cluster.local", true},
		{"two URLs that differ in case", "https://Kubernetes.default.svc.cluster.local", "https://kubernetes.default.svc.cluster.local", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := with(singleIdentityProvider(), "issuer", tt.idp)
			k8s := with(kubernetesProvider(), "issuer", tt.k8s)
			dir := providerDir(t, map[string]string{"idp.json": providerFile(t, IdentityProviderID, idp), "k8s.json": providerFile(t, KubernetesID, k8s)})
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

// Only the key identity-provider takes the type realms, so no provider file
// holds two realms providers, and overlap compares two issuerTemplates for a
// key that takes the type realms in a later format.
func TestOverlap_ComparesTwoIssuerTemplatesByTheirFixedSegments(t *testing.T) {
	const base = "http://kc/auth/realms/{realm}"
	tests := []struct {
		name, template string
		overlaps       bool
	}{
		{"{realm} in another segment", "http://kc/auth/{realm}/k8s", true},
		{"another fixed segment", "http://kc/auth/tenants/{realm}", false},
		{"another port", "http://kc:8080/auth/realms/{realm}", false},
		{"one more segment", "http://kc/auth/realms/{realm}/k8s", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Provider{Type: Realms, IssuerTemplate: base}
			b := Provider{Type: Realms, IssuerTemplate: tt.template}
			if got := overlap(a, b); got != tt.overlaps {
				t.Errorf("overlap(%q, %q) = %t, want %t", base, tt.template, got, tt.overlaps)
			}
			if got := overlap(b, a); got != tt.overlaps {
				t.Errorf("overlap(%q, %q) = %t, want %t", tt.template, base, got, tt.overlaps)
			}
		})
	}
}

// Each provider is built in code with one value that breaks a rule, so New
// refuses it and the error names no file. Most of these values are ones that
// the parser of a provider file refuses before Validate sees them.
func TestNew_RefusesAProviderBuiltWithAValueThatBreaksARule(t *testing.T) {
	k8s := Provider{
		ID:       KubernetesID,
		Type:     Single,
		Issuer:   "https://k8s",
		JWKSURI:  "https://k8s/jwks",
		Audience: Audience{Mode: MatchAny, Values: []string{"netcracker"}},
	}
	idp := keycloakProvider()
	tests := []struct {
		name     string
		provider func() Provider
		want     string
	}{
		{"key of another provider", func() Provider { p := k8s; p.ID = "keycloak"; return p }, `provider "keycloak": the key "keycloak" is neither`},
		{"no type", func() Provider { p := k8s; p.Type = ""; return p }, `provider "kubernetes": the type "" is not allowed; a provider "kubernetes" has the type "single"`},
		{"type realms in kubernetes", func() Provider { p := keycloakProvider("cloud-common"); p.ID = KubernetesID; return p },
			`provider "kubernetes": the type "realms" is not allowed`},
		{"issuer in a realms provider", func() Provider { p := idp; p.Issuer = "https://public.example/auth/realms/a"; return p },
			`provider "identity-provider": member "issuer" is not allowed; a provider "identity-provider" of the type "realms" holds`},
		{"issuerTemplate in a single provider", func() Provider { p := k8s; p.IssuerTemplate = "https://k8s/{realm}"; return p },
			`provider "kubernetes": member "issuerTemplate" is not allowed; a provider "kubernetes" of the type "single" holds`},
		{"jwksBearerTokenFile in identity-provider", func() Provider { p := idp; p.JWKSBearerTokenFile = "/var/run/token"; return p },
			`provider "identity-provider": member "jwksBearerTokenFile" is not allowed`},
		{"relative jwksBearerTokenFile", func() Provider { p := k8s; p.JWKSBearerTokenFile = "token"; return p },
			`provider "kubernetes": jwksBearerTokenFile "token" is not an absolute path`},
		{"readinessRealms in kubernetes", func() Provider { p := k8s; p.ReadinessRealms = []string{"cloud-common"}; return p },
			`provider "kubernetes": member "readinessRealms" is not allowed; a provider "kubernetes" of the type "single" holds`},
		{"readiness realm that is not a realm name", func() Provider { return keycloakProvider("a/b") },
			`provider "identity-provider": readinessRealms: "a/b" holds '/', '?', or '#'`},
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
