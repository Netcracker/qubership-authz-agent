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

package policyadmin

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── loadTrustedProviders ──────────────────────────────────────────────────

func TestLoadTrustedProviders_MissingFile(t *testing.T) {
	_, err := loadTrustedProviders("/nonexistent/path/trusted-providers.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadTrustedProviders_MalformedJSON(t *testing.T) {
	f := writeTempFile(t, []byte("not-json"))
	_, err := loadTrustedProviders(f)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestLoadTrustedProviders_Valid(t *testing.T) {
	raw := `{"providers":[{"id":"kc","issuer":"http://kc:8080/realms/test","audiences":["app"],"required":true}]}`
	f := writeTempFile(t, []byte(raw))
	doc, err := loadTrustedProviders(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(doc.Providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(doc.Providers))
	}
	if doc.Providers[0].ID != "kc" {
		t.Errorf("expected id 'kc', got %q", doc.Providers[0].ID)
	}
}

// A config still carrying the removed `algorithms` field must fail loudly
// rather than lose its meaning silently — authz-agent-ADR-0075 buys a strict
// schema with the absence of backward compatibility, so the strictness has to
// be real.
func TestLoadTrustedProviders_RejectsRemovedAlgorithmsField(t *testing.T) {
	raw := `{"providers":[{"id":"kc","issuer":"http://kc:8080/realms/test","algorithms":["RS256"]}]}`
	f := writeTempFile(t, []byte(raw))
	_, err := loadTrustedProviders(f)
	if err == nil {
		t.Fatal("expected an error for the removed 'algorithms' field")
	}
	if !strings.Contains(err.Error(), "algorithms") {
		t.Errorf("error should name the offending field, got: %v", err)
	}
}

func TestLoadTrustedProviders_EmptyProviders(t *testing.T) {
	raw := `{"providers":[]}`
	f := writeTempFile(t, []byte(raw))
	doc, err := loadTrustedProviders(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(doc.Providers) != 0 {
		t.Fatalf("expected 0 providers, got %d", len(doc.Providers))
	}
}

// ── entry forms ──────────────────────────────────────────────────────────

func TestTrustedProvider_Validate(t *testing.T) {
	cases := []struct {
		name     string
		provider TrustedProvider
		wantErr  string
	}{
		{"discovery form", TrustedProvider{ID: "kc", Issuer: "http://kc:8080/realms/test"}, ""},
		{"explicit form", TrustedProvider{ID: "kc", JWKSURI: "http://kc:8080/certs"}, ""},
		{"no id", TrustedProvider{Issuer: "http://kc:8080/realms/test"}, "'id'"},
		{"unsafe id", TrustedProvider{ID: "kc/../etc", Issuer: "http://kc:8080/x"}, "unsupported characters"},
		{"neither address", TrustedProvider{ID: "kc"}, "neither"},
		{"both addresses", TrustedProvider{ID: "kc", Issuer: "http://kc:8080/x", JWKSURI: "http://kc:8080/certs"}, "both"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.provider.validate(0)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("expected no error, got %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("expected an error mentioning %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("expected error mentioning %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// ── buildIndexedTrustedProviders ─────────────────────────────────────────

func TestBuildIndexedTrustedProviders_KeyedById(t *testing.T) {
	providers := []TrustedProvider{
		{ID: "kc", Issuer: "http://kc:8080/realms/test", Audiences: []string{"app"}, Required: true},
	}

	raw, _ := json.Marshal(buildIndexedTrustedProviders(providers))
	var parsed map[string]interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	tp, ok := parsed["trustedProviders"].(map[string]interface{})
	if !ok {
		t.Fatal("missing trustedProviders key")
	}
	byID, ok := tp["byId"].(map[string]interface{})
	if !ok {
		t.Fatal("missing byId key")
	}
	provider, ok := byID["kc"].(map[string]interface{})
	if !ok {
		t.Fatal("missing provider entry 'kc'")
	}
	if provider["id"] != "kc" {
		t.Errorf("expected id 'kc', got %v", provider["id"])
	}
	if provider["required"] != true {
		t.Errorf("expected required=true, got %v", provider["required"])
	}
	// The fetch address must not be published: no policy rule may key off it,
	// and publishing it would invite one to.
	if _, ok := provider["issuer"]; ok {
		t.Error("issuer must not be published into the provider index")
	}
}

// ── indexProviderKeys ────────────────────────────────────────────────────

func TestIndexProviderKeys(t *testing.T) {
	logger := log.New(os.Stdout, "", 0)
	keys := []map[string]interface{}{
		{"kid": "k1", "kty": "RSA", "alg": "RS256", "use": "sig", "n": "abc", "e": "AQAB"},
		{"kid": "k2", "kty": "RSA", "n": "def", "e": "AQAB"},
		{"kty": "RSA", "n": "no-kid", "e": "AQAB"},
		{"kid": "enc-1", "kty": "RSA", "use": "enc", "alg": "RSA-OAEP", "n": "ghi", "e": "AQAB"},
	}

	indexed, skipped := indexProviderKeys("kc", keys, logger)

	if len(indexed) != 2 {
		t.Fatalf("expected 2 usable keys, got %d", len(indexed))
	}
	if skipped != 2 {
		t.Errorf("expected 2 skipped keys (no kid, encryption), got %d", skipped)
	}
	if indexed[0].kid != "k1" || indexed[1].kid != "k2" {
		t.Errorf("expected keys in JWKS order, got %q and %q", indexed[0].kid, indexed[1].kid)
	}
	if indexed[0].candidate.Alg != "RS256" || indexed[1].candidate.Alg != "" {
		t.Errorf("alg should be lifted from the JWK verbatim, got %q and %q",
			indexed[0].candidate.Alg, indexed[1].candidate.Alg)
	}

	// Each candidate carries a JWKS narrowed to its own key: that is how
	// "try this one candidate" is expressed to io.jwt.decode_verify.
	var doc JWKSDocument
	if err := json.Unmarshal([]byte(indexed[0].candidate.JWKSJSON), &doc); err != nil {
		t.Fatalf("candidate jwksJson is not a JWKS: %v", err)
	}
	if len(doc.Keys) != 1 || doc.Keys[0]["kid"] != "k1" {
		t.Errorf("expected a one-key JWKS for k1, got %s", indexed[0].candidate.JWKSJSON)
	}
}

// ── RunBootstrap integration ─────────────────────────────────────────────

func TestRunBootstrap_MissingProvidersFile(t *testing.T) {
	dir := t.TempDir()
	statusFile := filepath.Join(dir, "status.json")

	RunBootstrap(BootstrapConfig{
		TrustedProvidersFile: filepath.Join(dir, "nonexistent.json"),
		JWKSBootstrapDir:     filepath.Join(dir, "jwks"),
		BootstrapRequired:    true,
		HTTPTimeout:          2 * time.Second,
		HTTPRetries:          1,
		StatusFile:           statusFile,
		Logger:               log.New(os.Stderr, "[test] ", 0),
	})

	status := readStatus(t, statusFile)
	if status.Mode != "strict" {
		t.Errorf("expected mode strict, got %q", status.Mode)
	}
	if status.ConfiguredCount != 0 {
		t.Errorf("expected configuredCount 0, got %d", status.ConfiguredCount)
	}
}

func TestRunBootstrap_EmptyProviders(t *testing.T) {
	dir := t.TempDir()
	providersFile := writeTempFile(t, []byte(`{"providers":[]}`))
	statusFile := filepath.Join(dir, "status.json")

	RunBootstrap(BootstrapConfig{
		TrustedProvidersFile: providersFile,
		JWKSBootstrapDir:     filepath.Join(dir, "jwks"),
		BootstrapRequired:    false,
		HTTPTimeout:          2 * time.Second,
		HTTPRetries:          1,
		StatusFile:           statusFile,
		Logger:               log.New(os.Stderr, "[test] ", 0),
	})

	status := readStatus(t, statusFile)
	if status.Mode != "permissive" {
		t.Errorf("expected mode permissive, got %q", status.Mode)
	}
	if status.ConfiguredCount != 0 {
		t.Errorf("expected configuredCount 0, got %d", status.ConfiguredCount)
	}
}

func TestRunBootstrap_SuccessfulProvider(t *testing.T) {
	jwksJSON := `{"keys":[{"kty":"RSA","kid":"test-key","n":"abc","e":"AQAB"}]}`

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			discoveryJSON := fmt.Sprintf(`{"issuer":"%s","jwks_uri":"%s/protocol/openid-connect/certs"}`, serverURL, serverURL)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, discoveryJSON)
			return
		}
		if r.URL.Path == "/protocol/openid-connect/certs" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, jwksJSON)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	serverURL = server.URL

	dir := t.TempDir()
	providersJSON := fmt.Sprintf(`{"providers":[{"id":"test-idp","issuer":"%s","audiences":["app"],"required":true}]}`, server.URL)
	providersFile := writeTempFile(t, []byte(providersJSON))
	statusFile := filepath.Join(dir, "status.json")
	jwksDir := filepath.Join(dir, "authn", "jwks")

	RunBootstrap(BootstrapConfig{
		TrustedProvidersFile: providersFile,
		JWKSBootstrapDir:     jwksDir,
		BootstrapRequired:    true,
		HTTPTimeout:          5 * time.Second,
		HTTPRetries:          3,
		StatusFile:           statusFile,
		Logger:               log.New(os.Stderr, "[test] ", 0),
	})

	// Verify status.
	status := readStatus(t, statusFile)
	if status.Mode != "strict" {
		t.Errorf("expected mode strict, got %q", status.Mode)
	}
	if status.ConfiguredCount != 1 {
		t.Errorf("expected configuredCount 1, got %d", status.ConfiguredCount)
	}
	if status.SuccessCount != 1 {
		t.Errorf("expected successCount 1, got %d", status.SuccessCount)
	}
	if status.FailureCount != 0 {
		t.Errorf("expected failureCount 0, got %d", status.FailureCount)
	}
	if status.CompletedAt == "" {
		t.Error("expected non-empty completedAt")
	}
	if len(status.Providers) != 1 || status.Providers[0].Result != "success" {
		t.Errorf("expected provider success result, got %+v", status.Providers)
	}

	if !status.Providers[0].Required {
		t.Error("required flag must reach the status artifact; readiness counts it")
	}

	// Verify trustedProviders.json artifact.
	authnDir := filepath.Dir(jwksDir)
	trustedProvidersPath := filepath.Join(authnDir, "trustedProviders.json")
	tpRaw, err := os.ReadFile(trustedProvidersPath)
	if err != nil {
		t.Fatalf("failed to read trustedProviders.json: %v", err)
	}
	var tpDoc map[string]interface{}
	if err := json.Unmarshal(tpRaw, &tpDoc); err != nil {
		t.Fatalf("trustedProviders.json is invalid JSON: %v", err)
	}
	tp := tpDoc["trustedProviders"].(map[string]interface{})
	byID := tp["byId"].(map[string]interface{})
	if _, ok := byID["test-idp"]; !ok {
		t.Errorf("expected provider key 'test-idp' in byId, got %v", byID)
	}

	// Verify the kid index artifact.
	indexPath := filepath.Join(authnDir, "jwksByKid.json")
	indexRaw, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("failed to read jwksByKid.json: %v", err)
	}
	var indexDoc struct {
		JWKSByKid map[string][]jwksCandidate `json:"jwksByKid"`
	}
	if err := json.Unmarshal(indexRaw, &indexDoc); err != nil {
		t.Fatalf("jwksByKid.json is invalid JSON: %v", err)
	}
	candidates, ok := indexDoc.JWKSByKid["test-key"]
	if !ok || len(candidates) != 1 {
		t.Fatalf("expected one candidate under kid 'test-key-1', got %v", indexDoc.JWKSByKid)
	}
	if candidates[0].ProviderID != "test-idp" {
		t.Errorf("expected providerId 'test-idp', got %q", candidates[0].ProviderID)
	}
	var jwksFromStr JWKSDocument
	if err := json.Unmarshal([]byte(candidates[0].JWKSJSON), &jwksFromStr); err != nil {
		t.Errorf("candidate jwksJson is not valid JSON: %v", err)
	}
	if len(jwksFromStr.Keys) != 1 {
		t.Errorf("expected a one-key JWKS per candidate, got %d keys", len(jwksFromStr.Keys))
	}
}

// The discovery document no longer has to echo the configured issuer: Keycloak
// reports the host the request arrived through, so that comparison rejected
// healthy realms reached by a second hostname (authz-agent-ADR-0075).
func TestRunBootstrap_DiscoveryIssuerMismatchIsAccepted(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = fmt.Fprintf(w, `{"issuer":"https://public-gateway/auth/realms/x","jwks_uri":"%s/certs"}`, serverURL)
		case "/certs":
			_, _ = fmt.Fprint(w, `{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"k1","n":"abc","e":"AQAB"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	serverURL = server.URL

	dir := t.TempDir()
	providersFile := writeTempFile(t, []byte(fmt.Sprintf(`{"providers":[{"id":"kc","issuer":"%s"}]}`, server.URL)))
	statusFile := filepath.Join(dir, "status.json")

	RunBootstrap(BootstrapConfig{
		TrustedProvidersFile: providersFile,
		JWKSBootstrapDir:     filepath.Join(dir, "authn", "jwks"),
		BootstrapRequired:    true,
		HTTPTimeout:          5 * time.Second,
		HTTPRetries:          1,
		StatusFile:           statusFile,
		Logger:               log.New(os.Stderr, "[test] ", 0),
	})

	status := readStatus(t, statusFile)
	if status.SuccessCount != 1 {
		t.Errorf("expected the provider to bootstrap, got %+v", status.Providers)
	}
}

// The explicit entry form fetches the JWKS directly, with no discovery request.
func TestRunBootstrap_ExplicitJWKSURIFormSkipsDiscovery(t *testing.T) {
	var discoveryCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			discoveryCalls++
			http.NotFound(w, r)
		case "/certs":
			_, _ = fmt.Fprint(w, `{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"k1","n":"abc","e":"AQAB"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	providersFile := writeTempFile(t, []byte(fmt.Sprintf(`{"providers":[{"id":"kc","jwksUri":"%s/certs"}]}`, server.URL)))
	statusFile := filepath.Join(dir, "status.json")

	RunBootstrap(BootstrapConfig{
		TrustedProvidersFile: providersFile,
		JWKSBootstrapDir:     filepath.Join(dir, "authn", "jwks"),
		BootstrapRequired:    true,
		HTTPTimeout:          5 * time.Second,
		HTTPRetries:          1,
		StatusFile:           statusFile,
		Logger:               log.New(os.Stderr, "[test] ", 0),
	})

	status := readStatus(t, statusFile)
	if status.SuccessCount != 1 {
		t.Errorf("expected the provider to bootstrap, got %+v", status.Providers)
	}
	if discoveryCalls != 0 {
		t.Errorf("explicit form must not perform discovery, got %d calls", discoveryCalls)
	}
}

func TestRunBootstrap_ProviderDiscoveryFailure(t *testing.T) {
	// Unreachable issuer.
	dir := t.TempDir()
	providersJSON := `{"providers":[{"id":"broken","issuer":"http://127.0.0.1:1/realms/broken"}]}`
	providersFile := writeTempFile(t, []byte(providersJSON))
	statusFile := filepath.Join(dir, "status.json")

	RunBootstrap(BootstrapConfig{
		TrustedProvidersFile: providersFile,
		JWKSBootstrapDir:     filepath.Join(dir, "authn", "jwks"),
		BootstrapRequired:    true,
		HTTPTimeout:          1 * time.Second,
		HTTPRetries:          1,
		StatusFile:           statusFile,
		Logger:               log.New(os.Stderr, "[test] ", 0),
	})

	status := readStatus(t, statusFile)
	if status.SuccessCount != 0 {
		t.Errorf("expected successCount 0, got %d", status.SuccessCount)
	}
	if status.FailureCount != 1 {
		t.Errorf("expected failureCount 1, got %d", status.FailureCount)
	}
	if len(status.Providers) != 1 {
		t.Fatalf("expected 1 provider result, got %d", len(status.Providers))
	}
	if status.Providers[0].Result != "failure" {
		t.Errorf("expected failure result, got %q", status.Providers[0].Result)
	}
	if status.Providers[0].FailureReason == "" {
		t.Error("expected non-empty failure reason")
	}
}

func TestRunBootstrap_InvalidJWKSStructure(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = fmt.Fprintf(w, `{"issuer":"%s","jwks_uri":"%s/certs"}`, serverURL, serverURL)
		case "/certs":
			_, _ = fmt.Fprint(w, `{"notKeys":"invalid"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	serverURL = server.URL

	dir := t.TempDir()
	providersJSON := fmt.Sprintf(`{"providers":[{"id":"bad-jwks","issuer":"%s"}]}`, server.URL)
	providersFile := writeTempFile(t, []byte(providersJSON))
	statusFile := filepath.Join(dir, "status.json")

	RunBootstrap(BootstrapConfig{
		TrustedProvidersFile: providersFile,
		JWKSBootstrapDir:     filepath.Join(dir, "authn", "jwks"),
		BootstrapRequired:    true,
		HTTPTimeout:          5 * time.Second,
		HTTPRetries:          1,
		StatusFile:           statusFile,
		Logger:               log.New(os.Stderr, "[test] ", 0),
	})

	status := readStatus(t, statusFile)
	if status.FailureCount != 1 {
		t.Errorf("expected failureCount 1, got %d", status.FailureCount)
	}
}

func TestRunBootstrap_InvalidProviderID(t *testing.T) {
	dir := t.TempDir()
	providersJSON := `{"providers":[{"id":"bad id!","issuer":"http://kc:8080"}]}`
	providersFile := writeTempFile(t, []byte(providersJSON))
	statusFile := filepath.Join(dir, "status.json")

	RunBootstrap(BootstrapConfig{
		TrustedProvidersFile: providersFile,
		JWKSBootstrapDir:     filepath.Join(dir, "authn", "jwks"),
		BootstrapRequired:    true,
		HTTPTimeout:          2 * time.Second,
		HTTPRetries:          1,
		StatusFile:           statusFile,
		Logger:               log.New(os.Stderr, "[test] ", 0),
	})

	status := readStatus(t, statusFile)
	if status.FailureCount != 1 {
		t.Errorf("expected failureCount 1, got %d", status.FailureCount)
	}
	if len(status.Providers) != 1 || !strings.Contains(status.Providers[0].FailureReason, "unsupported characters") {
		t.Errorf("expected unsupported characters reason, got %+v", status.Providers)
	}
}

func TestRunBootstrap_MixedProviders(t *testing.T) {
	jwksJSON := `{"keys":[{"kty":"RSA","kid":"k1","n":"abc","e":"AQAB"}]}`

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_, _ = fmt.Fprintf(w, `{"issuer":"%s","jwks_uri":"%s/certs"}`, serverURL, serverURL)
			return
		}
		if r.URL.Path == "/certs" {
			_, _ = fmt.Fprint(w, jwksJSON)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	serverURL = server.URL

	dir := t.TempDir()
	providersJSON := fmt.Sprintf(`{"providers":[
		{"id":"good","issuer":"%s"},
		{"id":"broken","issuer":"http://127.0.0.1:1/realms/broken"}
	]}`, server.URL)
	providersFile := writeTempFile(t, []byte(providersJSON))
	statusFile := filepath.Join(dir, "status.json")

	RunBootstrap(BootstrapConfig{
		TrustedProvidersFile: providersFile,
		JWKSBootstrapDir:     filepath.Join(dir, "authn", "jwks"),
		BootstrapRequired:    false,
		HTTPTimeout:          2 * time.Second,
		HTTPRetries:          1,
		StatusFile:           statusFile,
		Logger:               log.New(os.Stderr, "[test] ", 0),
	})

	status := readStatus(t, statusFile)
	if status.Mode != "permissive" {
		t.Errorf("expected mode permissive, got %q", status.Mode)
	}
	if status.ConfiguredCount != 2 {
		t.Errorf("expected configuredCount 2, got %d", status.ConfiguredCount)
	}
	if status.SuccessCount != 1 {
		t.Errorf("expected successCount 1, got %d", status.SuccessCount)
	}
	if status.FailureCount != 1 {
		t.Errorf("expected failureCount 1, got %d", status.FailureCount)
	}
}

func TestRunBootstrap_LegacyFileCleanup(t *testing.T) {
	dir := t.TempDir()
	authnDir := filepath.Join(dir, "authn")
	jwksDir := filepath.Join(authnDir, "jwks")
	_ = os.MkdirAll(jwksDir, 0o755)

	// Create legacy files.
	_ = os.WriteFile(filepath.Join(authnDir, "trusted_providers.json"), []byte("{}"), 0o644)
	_ = os.WriteFile(filepath.Join(authnDir, "verified_tokens.json"), []byte("{}"), 0o644)
	_ = os.WriteFile(filepath.Join(authnDir, "internal.json"), []byte("{}"), 0o644)
	_ = os.WriteFile(filepath.Join(jwksDir, "keycloak-svt.json"), []byte(`{"keys":[{"kid":"stale"}]}`), 0o644)

	providersFile := writeTempFile(t, []byte(`{"providers":[]}`))
	statusFile := filepath.Join(dir, "status.json")

	RunBootstrap(BootstrapConfig{
		TrustedProvidersFile: providersFile,
		JWKSBootstrapDir:     jwksDir,
		BootstrapRequired:    true,
		HTTPTimeout:          2 * time.Second,
		HTTPRetries:          1,
		StatusFile:           statusFile,
		Logger:               log.New(os.Stderr, "[test] ", 0),
	})

	// Verify legacy files are removed.
	for _, name := range []string{"trusted_providers.json", "verified_tokens.json", "internal.json"} {
		path := filepath.Join(authnDir, name)
		if _, err := os.Stat(path); err == nil {
			t.Errorf("expected legacy file %s to be removed", name)
		}
	}
	entries, err := os.ReadDir(jwksDir)
	if err != nil {
		t.Fatalf("failed to read jwks dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected jwks dir to be emptied, found %d entries", len(entries))
	}
}

func TestRunBootstrap_StaleArtifactCleanup_EmptyProviders(t *testing.T) {
	dir := t.TempDir()
	authnDir := filepath.Join(dir, "authn")
	jwksDir := filepath.Join(authnDir, "jwks")
	_ = os.MkdirAll(jwksDir, 0o755)

	// Simulate artifacts from a previous successful run.
	for _, name := range []string{"trustedProviders.json", "jwks.json", "jwksJson.json", "internal.json"} {
		_ = os.WriteFile(filepath.Join(authnDir, name), []byte(`{"stale":true}`), 0o644)
	}
	_ = os.WriteFile(filepath.Join(jwksDir, "stale-provider.json"), []byte(`{"keys":[{"kid":"stale"}]}`), 0o644)

	providersFile := writeTempFile(t, []byte(`{"providers":[]}`))
	statusFile := filepath.Join(dir, "status.json")

	RunBootstrap(BootstrapConfig{
		TrustedProvidersFile: providersFile,
		JWKSBootstrapDir:     jwksDir,
		BootstrapRequired:    true,
		HTTPTimeout:          2 * time.Second,
		HTTPRetries:          1,
		StatusFile:           statusFile,
		Logger:               log.New(os.Stderr, "[test] ", 0),
	})

	for _, name := range []string{"trustedProviders.json", "jwks.json", "jwksJson.json", "internal.json"} {
		path := filepath.Join(authnDir, name)
		if _, err := os.Stat(path); err == nil {
			t.Errorf("expected stale artifact %s to be removed", name)
		}
	}
	entries, err := os.ReadDir(jwksDir)
	if err != nil {
		t.Fatalf("failed to read jwks dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected jwks dir to be emptied, found %d entries", len(entries))
	}
}

func TestRunBootstrap_StaleArtifactCleanup_MissingProvidersFile(t *testing.T) {
	dir := t.TempDir()
	authnDir := filepath.Join(dir, "authn")
	jwksDir := filepath.Join(authnDir, "jwks")
	_ = os.MkdirAll(jwksDir, 0o755)

	// Simulate artifacts from a previous successful run.
	for _, name := range []string{"trustedProviders.json", "jwks.json", "jwksJson.json", "internal.json"} {
		_ = os.WriteFile(filepath.Join(authnDir, name), []byte(`{"stale":true}`), 0o644)
	}
	_ = os.WriteFile(filepath.Join(jwksDir, "stale-provider.json"), []byte(`{"keys":[{"kid":"stale"}]}`), 0o644)

	statusFile := filepath.Join(dir, "status.json")

	RunBootstrap(BootstrapConfig{
		TrustedProvidersFile: filepath.Join(dir, "nonexistent.json"),
		JWKSBootstrapDir:     jwksDir,
		BootstrapRequired:    true,
		HTTPTimeout:          2 * time.Second,
		HTTPRetries:          1,
		StatusFile:           statusFile,
		Logger:               log.New(os.Stderr, "[test] ", 0),
	})

	for _, name := range []string{"trustedProviders.json", "jwks.json", "jwksJson.json", "internal.json"} {
		path := filepath.Join(authnDir, name)
		if _, err := os.Stat(path); err == nil {
			t.Errorf("expected stale artifact %s to be removed", name)
		}
	}
	entries, err := os.ReadDir(jwksDir)
	if err != nil {
		t.Fatalf("failed to read jwks dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected jwks dir to be emptied, found %d entries", len(entries))
	}
}

// ── Health integration with Go-generated bootstrap status ────────────────

func TestHealthWithGoBootstrapStatus_Strict(t *testing.T) {
	jwksJSON := `{"keys":[{"kty":"RSA","kid":"k1","n":"abc","e":"AQAB"}]}`
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_, _ = fmt.Fprintf(w, `{"issuer":"%s","jwks_uri":"%s/certs"}`, serverURL, serverURL)
			return
		}
		if r.URL.Path == "/certs" {
			_, _ = fmt.Fprint(w, jwksJSON)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	serverURL = server.URL

	dir := t.TempDir()
	providersJSON := fmt.Sprintf(`{"providers":[{"id":"test","issuer":"%s","required":true}]}`, server.URL)
	providersFile := writeTempFile(t, []byte(providersJSON))
	statusFile := filepath.Join(dir, "status.json")

	RunBootstrap(BootstrapConfig{
		TrustedProvidersFile: providersFile,
		JWKSBootstrapDir:     filepath.Join(dir, "authn", "jwks"),
		BootstrapRequired:    true,
		HTTPTimeout:          5 * time.Second,
		HTTPRetries:          1,
		StatusFile:           statusFile,
		Logger:               log.New(os.Stderr, "[test] ", 0),
	})

	// Load the status and verify health evaluation.
	status, err := loadBootstrapStatus(statusFile)
	if err != nil {
		t.Fatalf("failed to load bootstrap status: %v", err)
	}
	healthy, msg, _ := evaluateHealth(true, status)
	if !healthy {
		t.Fatalf("expected healthy, got unhealthy: %s", msg)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────

func readStatus(t *testing.T, path string) BootstrapStatus {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read status file: %v", err)
	}
	var status BootstrapStatus
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatalf("failed to parse status file: %v; content: %s", err, string(raw))
	}
	return status
}

// Two entries sharing an id would collapse into one slot of the published
// byId map, and the survivor's audience policy would then silently apply to
// the other realm's keys — which are indexed under the same providerId.
func TestLoadTrustedProviders_RejectsDuplicateProviderID(t *testing.T) {
	raw := `{"providers":[
		{"id":"same","issuer":"http://a:8080/realms/x","audiences":["internal"]},
		{"id":"same","issuer":"http://b:8080/realms/y"}
	]}`
	f := writeTempFile(t, []byte(raw))

	_, err := loadTrustedProviders(f)
	if err == nil {
		t.Fatal("expected an error for a duplicate provider id")
	}
	if !strings.Contains(err.Error(), "same") {
		t.Errorf("error should name the duplicated id, got: %v", err)
	}
}

// The status artifact must distinguish "config rejected" from "nothing
// configured"; health.go keys the readiness decision off exactly that.
func TestRunBootstrap_RejectedConfigIsRecordedAsAConfigError(t *testing.T) {
	dir := t.TempDir()
	providersFile := writeTempFile(t, []byte(`{"providers":[{"id":"kc","issuer":"http://kc:8080/x","algorithms":["RS256"]}]}`))
	statusFile := filepath.Join(dir, "status.json")

	RunBootstrap(BootstrapConfig{
		TrustedProvidersFile: providersFile,
		JWKSBootstrapDir:     filepath.Join(dir, "authn", "jwks"),
		BootstrapRequired:    true,
		HTTPTimeout:          time.Second,
		HTTPRetries:          1,
		StatusFile:           statusFile,
		Logger:               log.New(os.Stderr, "[test] ", 0),
	})

	status := readStatus(t, statusFile)
	if status.ConfigError == "" {
		t.Fatal("a rejected config must be recorded as such, not as zero providers")
	}
	if healthy, _, _ := evaluateHealth(true, &status); healthy {
		t.Error("a Pod with a rejected provider config must not be Ready")
	}
}
