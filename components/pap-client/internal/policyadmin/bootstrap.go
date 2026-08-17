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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Default bootstrap configuration values.
const (
	DefaultTrustedProvidersFile = "/etc/authz/trusted-providers.json"
	DefaultJWKSBootstrapDir     = "/etc/opa/data/authn/jwks"
	DefaultBootstrapRequired    = true
	DefaultJWKSHTTPTimeout      = 5
	DefaultJWKSHTTPRetries      = 3
)

// BootstrapConfig holds all settings for the bootstrap subcommand.
type BootstrapConfig struct {
	TrustedProvidersFile string
	JWKSBootstrapDir     string
	// OPAAuthTokenFile is the path to the file containing the OPA write-path
	// bearer token (authz-agent-ADR-0077).  When non-empty, bootstrap reads the
	// file and writes {"opa_auth_secret":"<token>"} to
	// <opaDataDir>/opa-auth-secret.json so system_authz.rego can load it as
	// data.opa_auth_secret at OPA startup.  OPA data dir is derived from
	// JWKSBootstrapDir (two directory levels up).
	// An empty file is treated as absent.
	OPAAuthTokenFile  string
	BootstrapRequired bool
	HTTPTimeout       time.Duration
	HTTPRetries       int
	StatusFile        string
	// TenantManagerURL enables display-name resolution for realms that are not
	// addressable by the name an operator wrote. Empty disables it entirely.
	TenantManagerURL string
	Logger           *log.Logger
}

// TrustedProvidersFile is the top-level JSON structure.
type TrustedProvidersDoc struct {
	Providers []TrustedProvider `json:"providers"`
}

// TrustedProvider is a single provider entry from the config.
//
// An entry takes one of two forms, and never both (authz-agent-ADR-0075):
//
//   - discovery — `issuer` names the address to fetch from; bootstrap resolves
//     `<issuer>/.well-known/openid-configuration` to a `jwks_uri`. Since the
//     `iss` claim is not validated any more, `issuer` here is an address and
//     NOT a matching rule.
//   - explicit — `jwksUri` is fetched directly and no discovery happens. An
//     entry that sets `jwksUri` must leave `issuer` empty: two addresses in one
//     entry can only drift apart, and one of them would be silently ignored.
type TrustedProvider struct {
	ID        string   `json:"id"`
	Issuer    string   `json:"issuer,omitempty"`
	JWKSURI   string   `json:"jwksUri,omitempty"`
	Audiences []string `json:"audiences,omitempty"`
	Required  bool     `json:"required,omitempty"`
	// AllowMissingAud opts this provider into identity.rego's "token has
	// no aud claim" verification path (ADR-0049's legacy-ingress relay
	// contract). It only means anything for an entry that also sets
	// Audiences: with no audiences configured the aud claim is not checked
	// at all. Tokens carrying a WRONG aud still fail either way.
	AllowMissingAud bool `json:"allowMissingAud,omitempty"`
}

// validate reports whether the entry is one of the two accepted forms.
// A half-filled entry is rejected loudly rather than bootstrapped into a
// provider that can never match anything.
func (p TrustedProvider) validate(idx int) error {
	if p.ID == "" {
		return fmt.Errorf("provider[%d] is missing required field 'id'", idx)
	}
	if !validProviderIDRe.MatchString(p.ID) {
		return fmt.Errorf("provider[%d] id contains unsupported characters: %s", idx, p.ID)
	}
	switch {
	case p.Issuer == "" && p.JWKSURI == "":
		return fmt.Errorf("provider '%s' sets neither 'issuer' (discovery form) nor 'jwksUri' (explicit form)", p.ID)
	case p.Issuer != "" && p.JWKSURI != "":
		return fmt.Errorf("provider '%s' sets both 'issuer' and 'jwksUri'; use one form or the other", p.ID)
	}
	return nil
}

// OIDCDiscovery is the subset of the OIDC discovery document we need.
//
// The issuer reported here is deliberately not compared with the configured
// one. Keycloak echoes the host the request arrived through, so the comparison
// used to reject a healthy realm reached by a second hostname — see
// authz-agent-ADR-0075.
type OIDCDiscovery struct {
	JWKSURI string `json:"jwks_uri"`
}

// JWKSDocument represents a fetched JWKS with keys.
type JWKSDocument struct {
	Keys []map[string]interface{} `json:"keys"`
}

// jwksCandidate is one indexed key: a single-key JWKS document plus the
// provider it came from. identity.rego hands `jwksJson` straight to
// io.jwt.decode_verify, so narrowing the document to one key is how "try this
// candidate" is expressed.
type jwksCandidate struct {
	ProviderID string `json:"providerId"`
	Alg        string `json:"alg,omitempty"`
	Kty        string `json:"kty"`
	JWKSJSON   string `json:"jwksJson"`
}

// indexedKey pairs a candidate with the kid it is filed under. The kid lives
// outside the candidate because it is the map key in the published document,
// and carrying it in both places would only invite the two to disagree.
type indexedKey struct {
	kid       string
	candidate jwksCandidate
}

// providerBootstrapResult tracks one provider's outcome.
type providerBootstrapResult struct {
	ID            string `json:"id"`
	Result        string `json:"result"` // "success" | "failure"
	Required      bool   `json:"required,omitempty"`
	FailureReason string `json:"failureReason,omitempty"`
}

// validProviderIDRe matches safe provider IDs: alphanumeric, dot, dash, underscore.
var validProviderIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// RunBootstrap executes the JWKS bootstrap process.
// It never returns an error; provider failures are recorded in the status artifact.
func RunBootstrap(cfg BootstrapConfig) {
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(os.Stdout, "[bootstrap] ", log.LstdFlags)
	}

	mode := "strict"
	if !cfg.BootstrapRequired {
		mode = "permissive"
	}

	statusFile := cfg.StatusFile
	if statusFile == "" {
		statusFile = DefaultBootstrapStatusFile
	}

	// Prepare output directories early so cleanup runs on all paths.
	authnDir := filepath.Dir(cfg.JWKSBootstrapDir)
	if err := os.MkdirAll(cfg.JWKSBootstrapDir, 0o755); err != nil {
		logger.Printf("warn: failed to create JWKS dir: %v", err)
		writeBootstrapStatus(statusFile, mode, 0, 0, 0, err.Error(), nil, logger)
		return
	}

	// Remove legacy/stale runtime docs from pre-cutover volumes before loading authn data.
	removeLegacyAuthnArtifacts(authnDir, cfg.JWKSBootstrapDir, logger)

	// Pre-flight: read trusted providers file.
	providersDoc, err := loadTrustedProviders(cfg.TrustedProvidersFile)
	if err != nil {
		// A config that cannot be read or parsed is NOT "no providers
		// configured": zero configured providers clears every count threshold,
		// so without the explicit marker the Pod would report Ready and then
		// reject every token it is handed.
		logger.Printf("warn: %v", err)
		removeStaleAuthnArtifacts(authnDir, logger)
		writeBootstrapStatus(statusFile, mode, 0, 0, 0, err.Error(), nil, logger)
		return
	}

	configuredCount := len(providersDoc.Providers)

	if configuredCount == 0 {
		logger.Printf("no providers configured")
		removeStaleAuthnArtifacts(authnDir, logger)
		writeBootstrapStatus(statusFile, mode, 0, 0, 0, "", nil, logger)
		return
	}

	// Build indexed trusted providers.
	indexed := buildIndexedTrustedProviders(providersDoc.Providers)
	trustedOutFile := filepath.Join(authnDir, "trustedProviders.json")
	if err := writeJSONFile(trustedOutFile, indexed); err != nil {
		logger.Printf("warn: failed to write indexed trusted providers: %v", err)
		writeBootstrapStatus(statusFile, mode, configuredCount, 0, 0, err.Error(), nil, logger)
		return
	}
	logger.Printf("indexed trusted providers written to %s", trustedOutFile)
	logger.Printf("providers count: %d", configuredCount)

	// HTTP client for fetching.
	client := &http.Client{Timeout: cfg.HTTPTimeout}

	// Per-provider JWKS fetch.
	resolver := newRealmResolver(cfg.TenantManagerURL, client, logger)
	artifacts := fetchProviderArtifacts(providersDoc.Providers, client, cfg.HTTPRetries, resolver, logger)

	// Write the kid index.
	jwksOutFile := filepath.Join(authnDir, "jwksByKid.json")
	if err := writeJSONFile(jwksOutFile, map[string]interface{}{"jwksByKid": artifacts.jwksByKid}); err != nil {
		logger.Printf("warn: failed to write jwksByKid.json: %v", err)
	}

	writeBootstrapStatus(statusFile, mode, configuredCount, artifacts.successCount, artifacts.failureCount, "", artifacts.results, logger)

	// Write OPA write-path auth secret (authz-agent-ADR-0077).
	// Done last so the JWKS bootstrap artifacts are already present: the
	// auth secret is not required for JWKS loading, but it must exist before
	// OPA starts serving requests that require authenticated writes.
	if cfg.OPAAuthTokenFile != "" {
		opaDataDir := filepath.Dir(filepath.Dir(cfg.JWKSBootstrapDir))
		if err := writeOPAAuthSecret(opaDataDir, cfg.OPAAuthTokenFile, logger); err != nil {
			logger.Printf("warn: failed to write OPA auth secret: %v", err)
		}
	}

	logger.Printf("bootstrap completed")
}

// writeOPAAuthSecret reads the bearer token from tokenFile and writes
// {"opa_auth_secret":"<token>"} to <opaDataDir>/opa-auth-secret.json.
// An empty or missing token file is silently skipped.
func writeOPAAuthSecret(opaDataDir, tokenFile string, logger *log.Logger) error {
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Printf("warn: AUTHZ_OPA_AUTH_TOKEN_FILE=%s not found — OPA write paths will deny all callers (ADR-0077)", tokenFile)
			return nil
		}
		return fmt.Errorf("read %s: %w", tokenFile, err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		logger.Printf("warn: AUTHZ_OPA_AUTH_TOKEN_FILE=%s is empty — OPA write paths will deny all callers (ADR-0077)", tokenFile)
		return nil
	}

	type opaAuthSecret struct {
		OPAAuthSecret string `json:"opa_auth_secret"`
	}
	// json.Marshal handles all JSON string escaping, including backslashes and
	// double-quotes.
	content, err := json.Marshal(opaAuthSecret{OPAAuthSecret: token})
	if err != nil {
		return fmt.Errorf("marshal opa_auth_secret: %w", err)
	}

	outPath := filepath.Join(opaDataDir, "opa-auth-secret.json")
	if err := os.MkdirAll(opaDataDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", opaDataDir, err)
	}
	// 0o600: both OPA and pap-client run as uid 1000 (OPA's default; pap-client's
	// Dockerfile sets USER 1000 explicitly). The opa-data volume is an emptyDir
	// in Kubernetes and a named Docker volume in Compose; in either case only
	// uid-1000 processes can read this file, which is the desired access boundary
	// for the OPA write-path auth secret (ADR-0077).
	if err := os.WriteFile(outPath, append(content, '\n'), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	logger.Printf("OPA auth secret written to %s (ADR-0077)", outPath)
	return nil
}

type providerResult struct {
	status providerBootstrapResult
	keys   []indexedKey
}

// providerArtifacts is everything a full pass over the configured providers
// produces: the per-provider outcome plus the kid index that gets published
// under `data.authn`. Shared by the startup bootstrap and by the reloader in
// providers_reload.go, so both compute the same thing from the same input.
type providerArtifacts struct {
	results      []providerBootstrapResult
	jwksByKid    map[string][]jwksCandidate
	successCount int
	failureCount int
}

// fetchProviderArtifacts runs the discovery + JWKS fetch for every provider.
// It performs no writes: callers decide whether the outcome is good enough to
// publish, which is what lets a reload keep the previous keys when a new
// configuration cannot be fetched.
func fetchProviderArtifacts(providers []TrustedProvider, client *http.Client, retries int, resolver *realmResolver, logger *log.Logger) providerArtifacts {
	artifacts := providerArtifacts{jwksByKid: make(map[string][]jwksCandidate)}

	for i, provider := range providers {
		result := bootstrapProvider(provider, i, client, retries, resolver, logger)
		artifacts.results = append(artifacts.results, result.status)

		if result.status.Result != "success" {
			artifacts.failureCount++
			continue
		}

		artifacts.successCount++
		// Providers are walked in configuration order and keys in JWKS
		// order, so the candidate list for a shared kid is deterministic.
		for _, key := range result.keys {
			artifacts.jwksByKid[key.kid] = append(artifacts.jwksByKid[key.kid], key.candidate)
		}
	}

	return artifacts
}

func bootstrapProvider(provider TrustedProvider, idx int, client *http.Client, retries int, resolver *realmResolver, logger *log.Logger) providerResult {
	fail := func(reason string) providerResult {
		logger.Printf("warn: %s", reason)
		id := provider.ID
		if id == "" {
			id = fmt.Sprintf("provider-%d", idx)
		}
		return providerResult{status: providerBootstrapResult{
			ID: id, Result: "failure", Required: provider.Required, FailureReason: reason,
		}}
	}

	if err := provider.validate(idx); err != nil {
		return fail(err.Error())
	}

	jwksURI := provider.JWKSURI
	if jwksURI == "" {
		// Discovery form: resolve the issuer address to a jwks_uri.
		issuer := provider.Issuer
		discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
		discoveryBody, err := fetchWithRetry(client, discoveryURL, retries)
		if err != nil {
			// The realm may be addressed by a tenant DISPLAY name. A tenant
			// realm is created with a generated UUID as its name and keeps the
			// readable name only in `displayName`, so `default` never resolves
			// directly. Ask tenant-manager for the real name and try once more.
			//
			// Deliberately only after a failed discovery: a name that works is
			// never second-guessed, so this costs nothing on the normal path and
			// cannot change the meaning of a working configuration.
			if resolved, ok := resolver.resolveIssuer(issuer); ok {
				retryURL := strings.TrimRight(resolved, "/") + "/.well-known/openid-configuration"
				if body, retryErr := fetchWithRetry(client, retryURL, retries); retryErr == nil {
					_, discoveryBody, err = resolved, body, nil
				}
			}
		}
		if err != nil {
			return fail(fmt.Sprintf("unable to fetch OIDC discovery document for provider '%s' from %s", provider.ID, discoveryURL))
		}

		var discovery OIDCDiscovery
		if err := json.Unmarshal(discoveryBody, &discovery); err != nil {
			return fail(fmt.Sprintf("OIDC discovery document for provider '%s' is not valid JSON", provider.ID))
		}
		if discovery.JWKSURI == "" {
			return fail(fmt.Sprintf("OIDC discovery document for provider '%s' is missing jwks_uri", provider.ID))
		}
		jwksURI = discovery.JWKSURI
	}

	jwksBody, err := fetchWithRetry(client, jwksURI, retries)
	if err != nil {
		return fail(fmt.Sprintf("unable to fetch JWKS for provider '%s' from %s", provider.ID, jwksURI))
	}

	var jwksDoc JWKSDocument
	if err := json.Unmarshal(jwksBody, &jwksDoc); err != nil {
		return fail(fmt.Sprintf("unable to validate JWKS document for provider '%s'", provider.ID))
	}
	if jwksDoc.Keys == nil {
		return fail(fmt.Sprintf("invalid JWKS structure for provider '%s'", provider.ID))
	}

	candidates, skipped := indexProviderKeys(provider.ID, jwksDoc.Keys, logger)
	if len(candidates) == 0 {
		return fail(fmt.Sprintf("JWKS for provider '%s' contains no usable signing key with a kid (%d skipped)", provider.ID, skipped))
	}

	logger.Printf("provider '%s' contributed %d signing key(s) to the kid index", provider.ID, len(candidates))

	return providerResult{
		status: providerBootstrapResult{ID: provider.ID, Result: "success", Required: provider.Required},
		keys:   candidates,
	}
}

// indexProviderKeys turns a JWKS into one candidate per usable signing key.
//
// A key without a `kid` is dropped: the whole lookup is by kid, so such a key
// could never be selected and keeping it would only make the index look fuller
// than it is. Encryption keys (`use: "enc"`, which Keycloak realms publish
// alongside signing keys) are dropped for the same reason.
func indexProviderKeys(providerID string, keys []map[string]interface{}, logger *log.Logger) ([]indexedKey, int) {
	var (
		candidates []indexedKey
		skipped    int
	)

	for _, key := range keys {
		kid, _ := key["kid"].(string)
		if kid == "" {
			skipped++
			logger.Printf("warn: provider '%s' publishes a key without a kid; it cannot be looked up and is skipped", providerID)
			continue
		}
		if use, _ := key["use"].(string); use != "" && use != "sig" {
			skipped++
			continue
		}

		single, err := json.Marshal(map[string]interface{}{"keys": []map[string]interface{}{key}})
		if err != nil {
			skipped++
			logger.Printf("warn: provider '%s' key '%s' could not be serialized: %v", providerID, kid, err)
			continue
		}

		alg, _ := key["alg"].(string)
		kty, _ := key["kty"].(string)
		candidates = append(candidates, indexedKey{kid: kid, candidate: jwksCandidate{
			ProviderID: providerID,
			Alg:        alg,
			Kty:        kty,
			JWKSJSON:   string(single),
		}})
	}

	return candidates, skipped
}

// buildIndexedTrustedProviders creates the byId layout that identity.rego reads
// once a candidate key has selected a provider.
func buildIndexedTrustedProviders(providers []TrustedProvider) map[string]interface{} {
	byID := make(map[string]interface{}, len(providers))

	for _, p := range providers {
		byID[p.ID] = providerToMap(p)
	}

	return map[string]interface{}{
		"trustedProviders": map[string]interface{}{
			"byId": byID,
		},
	}
}

// providerToMap converts a TrustedProvider to the map form stored in the index.
// The fetch address — issuer or jwksUri — is deliberately not published: no
// policy rule may key off it any more, and publishing it would invite one to.
func providerToMap(p TrustedProvider) map[string]interface{} {
	m := map[string]interface{}{"id": p.ID}
	if p.Audiences != nil {
		m["audiences"] = p.Audiences
	}
	if p.Required {
		m["required"] = true
	}
	if p.AllowMissingAud {
		m["allowMissingAud"] = true
	}
	return m
}

// loadTrustedProviders reads and parses the trusted providers config file.
//
// Parsing is strict: an unknown field is an error rather than a warning, so a
// config still carrying the removed `algorithms` field fails loudly at startup
// instead of quietly losing its meaning (authz-agent-ADR-0075).
func loadTrustedProviders(path string) (*TrustedProvidersDoc, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("missing file: %s", path)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	var doc TrustedProvidersDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to parse trusted providers file %s: %v", path, err)
	}

	// The published index is keyed by id, so two entries sharing one would
	// collapse into a single map slot — the survivor's audience policy would
	// then silently apply to the other realm's keys, which are indexed under
	// the same providerId. Cheaper to reject than to explain.
	seen := make(map[string]struct{}, len(doc.Providers))
	for _, p := range doc.Providers {
		if _, dup := seen[p.ID]; dup {
			return nil, fmt.Errorf("trusted providers file %s declares provider id %q more than once", path, p.ID)
		}
		seen[p.ID] = struct{}{}
	}

	return &doc, nil
}

// fetchWithRetry fetches a URL with retry logic.
func fetchWithRetry(client *http.Client, url string, retries int) ([]byte, error) {
	// Support file:// scheme for testing.
	if strings.HasPrefix(url, "file://") {
		path := strings.TrimPrefix(url, "file://")
		return os.ReadFile(path)
	}

	var lastErr error
	for attempt := 1; attempt <= retries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}

		resp, err := client.Do(req)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB limit
		_ = resp.Body.Close()

		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return body, nil
		}

		lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return nil, lastErr
}

// removeLegacyAuthnArtifacts removes pre-cutover runtime leftovers that can corrupt merged OPA authn data.
func removeLegacyAuthnArtifacts(authnDir, jwksBootstrapDir string, logger *log.Logger) {
	// jwks.json / jwksJson.json are the pre-ADR-0075 provider-keyed documents.
	// Nothing reads them any more, but a persisted volume still holds them and
	// OPA would merge them back into `data.authn` alongside the kid index.
	for _, name := range []string{"trusted_providers.json", "verified_tokens.json", "internal.json", "jwks.json", "jwksJson.json"} {
		path := filepath.Join(authnDir, name)
		if _, err := os.Stat(path); err == nil {
			if err := os.Remove(path); err == nil {
				logger.Printf("removed legacy authn runtime artifact %s", path)
			}
		}
	}

	entries, err := os.ReadDir(jwksBootstrapDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		path := filepath.Join(jwksBootstrapDir, entry.Name())
		if err := os.RemoveAll(path); err == nil {
			logger.Printf("removed stale JWKS bootstrap artifact %s", path)
		}
	}
}

// removeStaleAuthnArtifacts removes authn artifacts from a previous successful bootstrap run.
// Called when the current run has no valid providers so stale data does not leak into OPA.
func removeStaleAuthnArtifacts(authnDir string, logger *log.Logger) {
	for _, name := range []string{"trustedProviders.json", "jwksByKid.json", "jwks.json", "jwksJson.json", "internal.json"} {
		path := filepath.Join(authnDir, name)
		if _, err := os.Stat(path); err == nil {
			if err := os.Remove(path); err == nil {
				logger.Printf("removed stale authn artifact %s", path)
			}
		}
	}

	jwksDir := filepath.Join(authnDir, "jwks")
	entries, err := os.ReadDir(jwksDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		path := filepath.Join(jwksDir, entry.Name())
		if err := os.RemoveAll(path); err == nil {
			logger.Printf("removed stale authn artifact %s", path)
		}
	}
}

// writeBootstrapStatus writes the deterministic JSON status artifact.
func writeBootstrapStatus(path, mode string, configured, success, failure int, configErr string, providers []providerBootstrapResult, logger *log.Logger) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logger.Printf("warn: failed to create status dir: %v", err)
		return
	}

	if providers == nil {
		providers = []providerBootstrapResult{}
	}

	status := BootstrapStatus{
		Mode:            mode,
		ConfiguredCount: configured,
		SuccessCount:    success,
		FailureCount:    failure,
		ConfigError:     configErr,
		Providers:       make([]BootstrapProviderResult, len(providers)),
		CompletedAt:     time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}

	for i, p := range providers {
		status.Providers[i] = BootstrapProviderResult(p)
	}

	if err := writeJSONFile(path, status); err != nil {
		logger.Printf("warn: failed to write bootstrap status: %v", err)
		return
	}

	logger.Printf("bootstrap status written to %s", path)
}

// writeJSONFile atomically writes a JSON file via temp+rename.
func writeJSONFile(path string, data interface{}) error {
	content, err := json.Marshal(data)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}

	if err := os.Chmod(tmpName, 0o644); err != nil {
		_ = os.Remove(tmpName)
		return err
	}

	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}

	return nil
}
