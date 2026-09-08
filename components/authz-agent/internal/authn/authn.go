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

// Package authn keeps data.authn, the document identity.rego verifies
// tokens against, in step with the trusted providers file: the signing keys
// of every provider indexed by kid, and the providers themselves indexed by
// id. [Manager.Bootstrap] builds the document at start, [Manager.Run]
// rebuilds it when the file changes, and [Manager.Status] reports the
// outcome the health rules of [Evaluate] read.
package authn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Defaults of Config.
const (
	DefaultFile           = "/etc/authz/trusted-providers.json"
	DefaultHTTPTimeout    = 5 * time.Second
	DefaultHTTPRetries    = 3
	DefaultReloadInterval = 30 * time.Second
)

// Config tells the manager where the providers are and how to fetch them.
type Config struct {
	// File is the trusted providers document, a JSON object with a
	// providers array.
	File string
	// Required selects strict mode, where every configured provider has to
	// bootstrap; otherwise one is enough, and the providers marked required
	// have to.
	Required bool
	// HTTPTimeout bounds one discovery or JWKS request; HTTPRetries is how
	// many times each is attempted.
	HTTPTimeout time.Duration
	HTTPRetries int
	// TenantManagerURL resolves a realm written by its tenant display name
	// to the realm name Keycloak serves; empty disables the lookup.
	TenantManagerURL string
	// ReloadInterval is how often the file is checked for a change; zero
	// disables the reload.
	ReloadInterval time.Duration
}

// Store receives the authn document.
type Store interface {
	Put(ctx context.Context, path []string, value any) error
}

// Logger receives the diagnostics.
type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}

// Provider is one entry of the trusted providers file. An entry names the
// address to fetch keys from in one of two forms and never both: issuer,
// resolved through OIDC discovery to a jwks_uri, or jwksUri, fetched as it
// is.
type Provider struct {
	ID        string   `json:"id"`
	Issuer    string   `json:"issuer,omitempty"`
	JWKSURI   string   `json:"jwksUri,omitempty"`
	Audiences []string `json:"audiences,omitempty"`
	Required  bool     `json:"required,omitempty"`
	// AllowMissingAud lets a token without an aud claim pass this
	// provider's audience check; it means nothing when Audiences is empty.
	AllowMissingAud bool `json:"allowMissingAud,omitempty"`
}

// Document is the trusted providers file.
type Document struct {
	Providers []Provider `json:"providers"`
}

// ProviderResult is the outcome of one provider's bootstrap.
type ProviderResult struct {
	ID            string `json:"id"`
	Result        string `json:"result"`
	Required      bool   `json:"required,omitempty"`
	FailureReason string `json:"failureReason,omitempty"`
}

// Status is the outcome of the last bootstrap or reload, in the shape the
// pap-client wrote to its status file. ConfigError is set when the file
// itself could not be read or parsed, which is not the same as a file with
// no providers: a rejected file must keep the service unhealthy.
type Status struct {
	Mode            string           `json:"mode"`
	ConfiguredCount int              `json:"configuredCount"`
	SuccessCount    int              `json:"successCount"`
	FailureCount    int              `json:"failureCount"`
	ConfigError     string           `json:"configError,omitempty"`
	Providers       []ProviderResult `json:"providers"`
	CompletedAt     string           `json:"completedAt"`
}

// validProviderID bounds the characters of a provider id, which becomes a
// key of the published index.
var validProviderID = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// Manager owns the authn document of one store.
type Manager struct {
	cfg      Config
	store    Store
	log      Logger
	client   *http.Client
	resolver *realmResolver

	mu          sync.Mutex
	status      Status
	appliedHash string
}

// New returns a manager for cfg; zero timeouts and retries take the
// defaults.
func New(cfg Config, store Store, log Logger) *Manager {
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = DefaultHTTPTimeout
	}
	if cfg.HTTPRetries <= 0 {
		cfg.HTTPRetries = DefaultHTTPRetries
	}
	client := &http.Client{Timeout: cfg.HTTPTimeout}
	return &Manager{
		cfg:      cfg,
		store:    store,
		log:      log,
		client:   client,
		resolver: newRealmResolver(cfg.TenantManagerURL, client, log),
	}
}

// Mode names the threshold the manager applies.
func (m *Manager) Mode() string {
	if m.cfg.Required {
		return "strict"
	}
	return "permissive"
}

// Status is the outcome of the last bootstrap or reload.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

// Bootstrap reads the file, fetches every provider's keys, and publishes
// the document with whatever was fetched: a provider that failed leaves its
// keys out and its failure in the status, and the health rules decide
// whether that is acceptable. A file that cannot be read or parsed is
// recorded as a configuration error and publishes nothing.
func (m *Manager) Bootstrap(ctx context.Context) Status {
	mode := m.Mode()
	hash, _ := hashFile(m.cfg.File)
	doc, err := Load(m.cfg.File)
	if err != nil {
		m.log.Warnf("trusted providers: %v", err)
		return m.record(hash, Status{Mode: mode, ConfigError: err.Error()})
	}
	if len(doc.Providers) == 0 {
		m.log.Infof("trusted providers: no providers configured")
		if err := m.publish(ctx, doc, artifacts{jwksByKid: map[string][]candidate{}}); err != nil {
			m.log.Warnf("trusted providers: publish: %v", err)
		}
		return m.record(hash, Status{Mode: mode})
	}
	fetched := m.fetch(doc.Providers)
	if err := m.publish(ctx, doc, fetched); err != nil {
		m.log.Warnf("trusted providers: publish: %v", err)
	}
	m.log.Infof("trusted providers: %d of %d providers bootstrapped in %s mode", fetched.successCount, len(doc.Providers), mode)
	return m.record(hash, fetched.status(mode, len(doc.Providers)))
}

// Run rebuilds the document whenever the file changes, until ctx ends. A
// change that does not meet the threshold, or leaves a required provider
// out, is not published and is retried on the next tick, so an edit that
// breaks the configuration never takes the previous keys away.
func (m *Manager) Run(ctx context.Context) {
	if m.cfg.ReloadInterval <= 0 {
		m.log.Infof("trusted providers: reload disabled")
		return
	}
	ticker := time.NewTicker(m.cfg.ReloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			changed, err := m.Reload(ctx)
			switch {
			case err != nil:
				m.log.Warnf("trusted providers: reload failed, keeping the previous keys: %v", err)
			case changed:
				m.log.Infof("trusted providers: reloaded")
			}
		}
	}
}

// Reload checks the file once. It returns true when a new configuration
// was published, false when the file is unchanged, and an error when a
// changed file could not be applied.
func (m *Manager) Reload(ctx context.Context) (bool, error) {
	hash, err := hashFile(m.cfg.File)
	if err != nil {
		return false, err
	}
	m.mu.Lock()
	unchanged := hash == m.appliedHash
	m.mu.Unlock()
	if unchanged {
		return false, nil
	}
	doc, err := Load(m.cfg.File)
	if err != nil {
		return false, err
	}
	mode := m.Mode()
	configured := len(doc.Providers)
	fetched := m.fetch(doc.Providers)
	if required := threshold(mode, configured); fetched.successCount < required {
		return false, fmt.Errorf("%d of %d providers fetched, %s mode requires %d", fetched.successCount, configured, mode, required)
	}
	if missing := missingRequired(fetched.results); len(missing) > 0 {
		return false, fmt.Errorf("required providers %s did not bootstrap", strings.Join(missing, ", "))
	}
	if err := m.publish(ctx, doc, fetched); err != nil {
		return false, err
	}
	m.record(hash, fetched.status(mode, configured))
	return true, nil
}

func (m *Manager) record(hash string, status Status) Status {
	status.CompletedAt = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	if status.Providers == nil {
		status.Providers = []ProviderResult{}
	}
	m.mu.Lock()
	m.status = status
	m.appliedHash = hash
	m.mu.Unlock()
	return status
}

// publish writes data.authn: the providers by id, without their fetch
// addresses, and the keys by kid.
func (m *Manager) publish(ctx context.Context, doc *Document, fetched artifacts) error {
	byID := map[string]any{}
	for _, p := range doc.Providers {
		entry := map[string]any{"id": p.ID}
		if p.Audiences != nil {
			entry["audiences"] = p.Audiences
		}
		if p.Required {
			entry["required"] = true
		}
		if p.AllowMissingAud {
			entry["allowMissingAud"] = true
		}
		byID[p.ID] = entry
	}
	value := map[string]any{
		"trustedProviders": map[string]any{"byId": byID},
		"jwksByKid":        fetched.jwksByKid,
	}
	return m.store.Put(ctx, []string{"authn"}, value)
}

// Load reads and parses the trusted providers file. An unknown field and a
// provider id used twice are errors, so a file that lost its meaning fails
// at start instead of trusting nobody.
func Load(path string) (*Document, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("missing file: %s", path)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to parse trusted providers file %s: %v", path, err)
	}
	seen := make(map[string]struct{}, len(doc.Providers))
	for _, p := range doc.Providers {
		if _, dup := seen[p.ID]; dup {
			return nil, fmt.Errorf("trusted providers file %s declares provider id %q more than once", path, p.ID)
		}
		seen[p.ID] = struct{}{}
	}
	return &doc, nil
}

// validate reports whether the entry is one of the two accepted forms.
func (p Provider) validate(idx int) error {
	if p.ID == "" {
		return fmt.Errorf("provider[%d] is missing required field 'id'", idx)
	}
	if !validProviderID.MatchString(p.ID) {
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

// candidate is one signing key as identity.rego tries it: a JWKS document
// narrowed to that key, with the provider it came from.
type candidate struct {
	ProviderID string `json:"providerId"`
	Alg        string `json:"alg,omitempty"`
	Kty        string `json:"kty"`
	JWKSJSON   string `json:"jwksJson"`
}

type indexedKey struct {
	kid       string
	candidate candidate
}

// artifacts is what one pass over the providers produces.
type artifacts struct {
	results      []ProviderResult
	jwksByKid    map[string][]candidate
	successCount int
	failureCount int
}

func (a artifacts) status(mode string, configured int) Status {
	return Status{
		Mode:            mode,
		ConfiguredCount: configured,
		SuccessCount:    a.successCount,
		FailureCount:    a.failureCount,
		Providers:       a.results,
	}
}

// fetch runs the discovery and the JWKS fetch for every provider, in
// configuration order, so the candidates of a kid shared by two providers
// keep a fixed order.
func (m *Manager) fetch(providers []Provider) artifacts {
	out := artifacts{jwksByKid: map[string][]candidate{}}
	for i, p := range providers {
		result, keys := m.fetchProvider(p, i)
		out.results = append(out.results, result)
		if result.Result != "success" {
			out.failureCount++
			continue
		}
		out.successCount++
		for _, key := range keys {
			out.jwksByKid[key.kid] = append(out.jwksByKid[key.kid], key.candidate)
		}
	}
	return out
}

func (m *Manager) fetchProvider(p Provider, idx int) (ProviderResult, []indexedKey) {
	fail := func(reason string) (ProviderResult, []indexedKey) {
		m.log.Warnf("trusted providers: %s", reason)
		id := p.ID
		if id == "" {
			id = fmt.Sprintf("provider-%d", idx)
		}
		return ProviderResult{ID: id, Result: "failure", Required: p.Required, FailureReason: reason}, nil
	}
	if err := p.validate(idx); err != nil {
		return fail(err.Error())
	}
	jwksURI := p.JWKSURI
	if jwksURI == "" {
		discoveryURL := strings.TrimRight(p.Issuer, "/") + "/.well-known/openid-configuration"
		body, err := fetchWithRetry(m.client, discoveryURL, m.cfg.HTTPRetries)
		if err != nil {
			// The realm may be written by its tenant display name; the
			// resolver is asked only once discovery under the written name
			// failed, so a working configuration is never second-guessed.
			if resolved, ok := m.resolver.resolveIssuer(p.Issuer); ok {
				if retried, retryErr := fetchWithRetry(m.client, strings.TrimRight(resolved, "/")+"/.well-known/openid-configuration", m.cfg.HTTPRetries); retryErr == nil {
					body, err = retried, nil
				}
			}
		}
		if err != nil {
			return fail(fmt.Sprintf("unable to fetch OIDC discovery document for provider '%s' from %s", p.ID, discoveryURL))
		}
		var discovery struct {
			JWKSURI string `json:"jwks_uri"`
		}
		if err := json.Unmarshal(body, &discovery); err != nil {
			return fail(fmt.Sprintf("OIDC discovery document for provider '%s' is not valid JSON", p.ID))
		}
		if discovery.JWKSURI == "" {
			return fail(fmt.Sprintf("OIDC discovery document for provider '%s' is missing jwks_uri", p.ID))
		}
		jwksURI = discovery.JWKSURI
	}
	body, err := fetchWithRetry(m.client, jwksURI, m.cfg.HTTPRetries)
	if err != nil {
		return fail(fmt.Sprintf("unable to fetch JWKS for provider '%s' from %s", p.ID, jwksURI))
	}
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fail(fmt.Sprintf("unable to validate JWKS document for provider '%s'", p.ID))
	}
	if jwks.Keys == nil {
		return fail(fmt.Sprintf("invalid JWKS structure for provider '%s'", p.ID))
	}
	keys, skipped := m.indexKeys(p.ID, jwks.Keys)
	if len(keys) == 0 {
		return fail(fmt.Sprintf("JWKS for provider '%s' contains no usable signing key with a kid (%d skipped)", p.ID, skipped))
	}
	m.log.Infof("trusted providers: provider '%s' contributed %d signing key(s)", p.ID, len(keys))
	return ProviderResult{ID: p.ID, Result: "success", Required: p.Required}, keys
}

// indexKeys turns a JWKS into one candidate per signing key that has a
// kid. A key without one could never be looked up, and an encryption key
// (use other than sig) never signs a token, so both are left out.
func (m *Manager) indexKeys(providerID string, keys []map[string]any) ([]indexedKey, int) {
	var out []indexedKey
	skipped := 0
	for _, key := range keys {
		kid, _ := key["kid"].(string)
		if kid == "" {
			skipped++
			m.log.Warnf("trusted providers: provider '%s' publishes a key without a kid; it cannot be looked up and is skipped", providerID)
			continue
		}
		if use, _ := key["use"].(string); use != "" && use != "sig" {
			skipped++
			continue
		}
		single, err := json.Marshal(map[string]any{"keys": []map[string]any{key}})
		if err != nil {
			skipped++
			m.log.Warnf("trusted providers: provider '%s' key '%s' could not be serialized: %v", providerID, kid, err)
			continue
		}
		alg, _ := key["alg"].(string)
		kty, _ := key["kty"].(string)
		out = append(out, indexedKey{kid: kid, candidate: candidate{ProviderID: providerID, Alg: alg, Kty: kty, JWKSJSON: string(single)}})
	}
	return out, skipped
}

// fetchWithRetry gets url up to retries times and returns the first 2xx
// body. A file:// URL is read from disk.
func fetchWithRetry(client *http.Client, url string, retries int) ([]byte, error) {
	if strings.HasPrefix(url, "file://") {
		return os.ReadFile(strings.TrimPrefix(url, "file://"))
	}
	var lastErr error
	for attempt := 1; attempt <= retries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			cancel()
			return nil, err
		}
		resp, err := client.Do(req)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
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

// threshold is the number of providers that must bootstrap for the
// configuration to count as healthy: every one in strict mode, one in
// permissive mode, none for an empty list.
func threshold(mode string, configured int) int {
	if configured == 0 {
		return 0
	}
	if mode == "strict" {
		return configured
	}
	return 1
}

// missingRequired names the providers marked required that did not
// bootstrap, in configuration order.
func missingRequired(results []ProviderResult) []string {
	var missing []string
	for _, r := range results {
		if r.Required && r.Result != "success" {
			missing = append(missing, r.ID)
		}
	}
	return missing
}

// hashFile digests the file content. Kubernetes republishes a ConfigMap by
// swapping a symlink, so the content is read rather than the file stat-ed.
func hashFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Details are the mode, the counts, and the missing providers behind an
// unhealthy verdict on the bootstrap.
type Details struct {
	Mode            string   `json:"mode"`
	SuccessCount    int      `json:"successCount"`
	RequiredCount   int      `json:"requiredCount"`
	MissingRequired []string `json:"missingRequired,omitempty"`
}

// Evaluate applies the readiness rules to a status: a configuration error
// is unhealthy; a provider marked required that did not bootstrap is
// unhealthy whatever the mode; and fewer successes than the mode's
// threshold is unhealthy, where an empty list wants none. message names
// the reason and details carry the counts; both are empty when the status
// is healthy.
func Evaluate(status Status) (healthy bool, message string, configError string, details *Details) {
	if status.ConfigError != "" {
		return false, "trusted providers configuration is invalid", status.ConfigError, nil
	}
	required := threshold(status.Mode, status.ConfiguredCount)
	if missing := missingRequired(status.Providers); len(missing) > 0 {
		return false, "required identity providers did not bootstrap", "", &Details{
			Mode: status.Mode, SuccessCount: status.SuccessCount, RequiredCount: required, MissingRequired: missing,
		}
	}
	if status.SuccessCount < required {
		return false, "bootstrap threshold not met", "", &Details{
			Mode: status.Mode, SuccessCount: status.SuccessCount, RequiredCount: required,
		}
	}
	return true, "", "", nil
}
