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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Defaults for the trusted-providers reloader.
const (
	// DefaultProvidersReloadInterval is the poll period for the trusted
	// providers file. A Kubernetes ConfigMap update reaches the container's
	// volume within roughly 60-90 s anyway, so polling faster buys nothing;
	// polling is used rather than inotify because the kubelet publishes an
	// update by swapping the `..data` symlink, which file-level watches miss.
	DefaultProvidersReloadInterval = 30 * time.Second

	// DefaultOPAAuthnDataPath is the OPA data document the reloader keeps in
	// sync with the file. identity.rego reads the whole subtree as
	// `data.authn` (see files/opa/policies/identity.rego).
	DefaultOPAAuthnDataPath = "/v1/data/authn"
)

// ProvidersReloader watches the trusted providers file and republishes the
// authn data into a running OPA when it changes, so an operator can edit the
// ConfigMap without restarting the Pod.
//
// Failure policy: a reload that cannot satisfy the bootstrap threshold changes
// nothing — the previously published keys stay in OPA, the bootstrap status
// file is left alone (so `pap-client healthcheck` does not flip a serving Pod
// to NotReady over a bad edit), and the attempt is retried on the next tick.
// See authz-agent-ADR-0070.
type ProvidersReloader struct {
	cfg BootstrapConfig

	// OPAAuthnURL is the absolute URL of OPA's authn data document.
	OPAAuthnURL string

	// Interval is the poll period. Zero disables the reloader.
	Interval time.Duration

	fetchClient *http.Client
	opaClient   *http.Client
	resolver    *realmResolver
	logger      *log.Logger

	// appliedHash is the digest of the file content currently published.
	// Seeded from the file at construction time because the startup bootstrap
	// has already applied it — only later edits are reloads.
	appliedHash string
}

// NewProvidersReloader builds a reloader for cfg. The initial file digest is
// recorded as already applied, so a Pod that just bootstrapped does not
// immediately re-fetch every JWKS.
//
// opaAuthToken is the bearer token sent to OPA when updating the authn data
// document (PATCH or PUT /v1/data/authn). Empty disables auth injection.
// See authz-agent-ADR-0077.
func NewProvidersReloader(cfg BootstrapConfig, opaAuthnURL string, interval time.Duration, opaAuthToken string) *ProvidersReloader {
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(os.Stdout, "[providers-reload] ", log.LstdFlags)
	}

	httpTimeout := cfg.HTTPTimeout
	if httpTimeout <= 0 {
		httpTimeout = DefaultJWKSHTTPTimeout * time.Second
	}

	r := &ProvidersReloader{
		cfg:         cfg,
		OPAAuthnURL: opaAuthnURL,
		Interval:    interval,
		fetchClient: &http.Client{Timeout: httpTimeout},
		opaClient:   NewOPAClient(opaAuthToken, 10*time.Second),
		logger:      logger,
	}
	r.resolver = newRealmResolver(cfg.TenantManagerURL, r.fetchClient, logger)

	if hash, err := hashFile(cfg.TrustedProvidersFile); err == nil {
		r.appliedHash = hash
	}

	return r
}

// Run polls until ctx is cancelled. Intended to be started as a goroutine next
// to the pap-client HTTP server.
func (r *ProvidersReloader) Run(ctx context.Context) {
	if r.Interval <= 0 {
		r.logger.Printf("trusted providers reload disabled")
		return
	}

	r.logger.Printf("watching %s every %s", r.cfg.TrustedProvidersFile, r.Interval)

	ticker := time.NewTicker(r.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			changed, err := r.ReloadOnce(ctx)
			switch {
			case err != nil:
				// Deliberately not fatal and deliberately not reflected in the
				// bootstrap status: the previous configuration is still live.
				r.logger.Printf("warn: trusted providers reload failed, keeping previous authn data: %v", err)
			case changed:
				r.logger.Printf("trusted providers reloaded")
			}
		}
	}
}

// ReloadOnce performs a single check. It returns true when a new configuration
// was published, false when the file is unchanged, and an error when a changed
// file could not be applied (in which case nothing was published).
func (r *ProvidersReloader) ReloadOnce(ctx context.Context) (bool, error) {
	hash, err := hashFile(r.cfg.TrustedProvidersFile)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", r.cfg.TrustedProvidersFile, err)
	}

	if hash == r.appliedHash {
		return false, nil
	}

	doc, err := loadTrustedProviders(r.cfg.TrustedProvidersFile)
	if err != nil {
		return false, err
	}

	configured := len(doc.Providers)
	artifacts := fetchProviderArtifacts(doc.Providers, r.fetchClient, r.cfg.HTTPRetries, r.resolver, r.logger)

	mode := "strict"
	if !r.cfg.BootstrapRequired {
		mode = "permissive"
	}

	if required := bootstrapThreshold(mode, configured); artifacts.successCount < required {
		return false, fmt.Errorf(
			"%d of %d providers fetched, %s mode requires %d — not published",
			artifacts.successCount, configured, mode, required,
		)
	}

	// The same gate readiness applies, applied here too. Without it a reload
	// could publish a configuration whose `required` provider is down and then
	// write a status that immediately takes the Pod out of the Service — the
	// opposite of the failure policy above, which promises that a reload never
	// flips a serving Pod to NotReady over a bad edit.
	if missing := missingRequired(artifacts.results); len(missing) > 0 {
		return false, fmt.Errorf(
			"required provider(s) %s did not bootstrap — not published",
			strings.Join(missing, ", "),
		)
	}

	if err := r.publish(ctx, doc, artifacts, configured); err != nil {
		return false, err
	}

	// Only now is the new content the applied content; a failure above leaves
	// appliedHash pointing at the last good configuration, so the next tick
	// retries the same edit.
	r.appliedHash = hash
	writeBootstrapStatus(r.statusFile(), mode, configured, artifacts.successCount, artifacts.failureCount, "", artifacts.results, r.logger)

	return true, nil
}

// publish writes the authn artifacts to disk (so an OPA restart reloads the
// same state) and pushes them into the running OPA.
func (r *ProvidersReloader) publish(ctx context.Context, doc *TrustedProvidersDoc, artifacts providerArtifacts, configured int) error {
	authnDir := filepath.Dir(r.cfg.JWKSBootstrapDir)

	if configured == 0 {
		// An operator emptying the list means "trust nobody": drop the files
		// instead of leaving the previous keys behind on disk.
		removeStaleAuthnArtifacts(authnDir, r.logger)
	} else {
		indexed := buildIndexedTrustedProviders(doc.Providers)
		if err := writeJSONFile(filepath.Join(authnDir, "trustedProviders.json"), indexed); err != nil {
			return fmt.Errorf("write trustedProviders.json: %w", err)
		}
		if err := writeJSONFile(filepath.Join(authnDir, "jwksByKid.json"), map[string]interface{}{"jwksByKid": artifacts.jwksByKid}); err != nil {
			return fmt.Errorf("write jwksByKid.json: %w", err)
		}
	}

	return r.pushToOPA(ctx, doc, artifacts, configured)
}

// pushToOPA replaces both authn sub-documents in one request.
//
// A JSON Patch is used rather than `PUT /v1/data/authn` so that anything else
// living under `data.authn` (identity.rego also reads `verifiedTokens`) is not
// wiped by a reload, and so the provider index and the key index change
// together rather than in two separately-visible steps. When `data.authn` does not exist yet OPA
// answers 404 to the patch; then — and only then — a PUT of the whole subtree
// is correct, because there is nothing to preserve.
func (r *ProvidersReloader) pushToOPA(ctx context.Context, doc *TrustedProvidersDoc, artifacts providerArtifacts, configured int) error {
	if r.OPAAuthnURL == "" {
		return nil
	}

	trusted := map[string]interface{}{"byId": map[string]interface{}{}}
	if configured > 0 {
		if indexed, ok := buildIndexedTrustedProviders(doc.Providers)["trustedProviders"].(map[string]interface{}); ok {
			trusted = indexed
		}
	}

	patch := []map[string]interface{}{
		{"op": "add", "path": "/trustedProviders", "value": trusted},
		{"op": "add", "path": "/jwksByKid", "value": artifacts.jwksByKid},
	}

	status, err := r.sendToOPA(ctx, http.MethodPatch, r.OPAAuthnURL, "application/json-patch+json", patch)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		full := map[string]interface{}{
			"trustedProviders": trusted,
			"jwksByKid":        artifacts.jwksByKid,
		}
		if status, err = r.sendToOPA(ctx, http.MethodPut, r.OPAAuthnURL, "application/json", full); err != nil {
			return err
		}
	}

	if status < 200 || status >= 300 {
		return fmt.Errorf("OPA rejected the authn update: HTTP %d", status)
	}

	return nil
}

func (r *ProvidersReloader) sendToOPA(ctx context.Context, method, url, contentType string, payload interface{}) (int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := r.opaClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	return resp.StatusCode, nil
}

func (r *ProvidersReloader) statusFile() string {
	if r.cfg.StatusFile != "" {
		return r.cfg.StatusFile
	}
	return DefaultBootstrapStatusFile
}

// missingRequired names the providers marked `required` that did not fetch.
// Mirrors missingRequiredProviders in health.go, which reads the same outcome
// back out of the status artifact.
func missingRequired(results []providerBootstrapResult) []string {
	var missing []string
	for _, r := range results {
		if r.Required && r.Result != "success" {
			missing = append(missing, r.ID)
		}
	}
	return missing
}

// bootstrapThreshold is the number of providers that must be fetched for the
// configuration to count as healthy. It mirrors evaluateHealth in health.go:
// strict wants every configured provider, permissive wants one, and an empty
// list wants none.
func bootstrapThreshold(mode string, configured int) int {
	if configured == 0 {
		return 0
	}
	if mode == "strict" {
		return configured
	}
	return 1
}

// hashFile digests the file content. Kubernetes republishes a ConfigMap by
// swapping a symlink, so the path is re-read in full rather than stat-ed.
func hashFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(raw)

	return hex.EncodeToString(sum[:]), nil
}
