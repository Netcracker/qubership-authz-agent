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
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"authz-agent/internal/atomicfile"
)

const (
	// DefaultTokenWatchInterval is the poll period for AUTHZ_PAP_CLIENT_TOKEN_FILE.
	// The kubelet rotates a projected SA token roughly every 5 minutes; the
	// token-fetcher sidecar writes a fresh Keycloak token before expiry.
	// 15 s is fast enough to pick up a rotation well before the old token
	// expires, and inexpensive enough to run continuously.
	DefaultTokenWatchInterval = 15 * time.Second
)

// TokenWatcherConfig holds the configuration for the token file watcher.
type TokenWatcherConfig struct {
	// TokenFile is the path to AUTHZ_PAP_CLIENT_TOKEN_FILE.
	TokenFile string

	// OPAM2MURL is the OPA data API URL for the M2M credential document.
	// Example: "http://127.0.0.1:8181/v1/data/m2m"
	//
	// This MUST be a document root that no other writer touches. OPA's Data
	// API PUT replaces the document at the given path, so any writer sharing
	// this root would erase the token (and be erased by it) on every write.
	// See the "one writer per document root" note on TokenWatcher.
	OPAM2MURL string

	// M2MFile is the path to write the M2M bearer token disk copy.
	// OPA reads this file at startup when recovering from a restart, so it
	// must be on the shared opa-data volume and contain {"m2m":{"bearerToken":"..."}}
	// — the "m2m" wrapper key makes OPA produce data.m2m on load, matching
	// the /v1/data/m2m document root this watcher pushes to.
	// Empty → no disk write (file-only restart recovery disabled).
	M2MFile string

	// Interval is how often to check the file. Zero uses DefaultTokenWatchInterval.
	Interval time.Duration

	// Logger receives diagnostic output.
	Logger *log.Logger

	// HTTPClient is optional; a default client with a 10 s timeout is used when nil.
	HTTPClient *http.Client
}

// TokenWatcher polls AUTHZ_PAP_CLIENT_TOKEN_FILE and, on any content change, publishes
// the new token to OPA as {"bearerToken": "<token>"} via PUT /v1/data/m2m.
// This works uniformly for both KUBERNETES_M2M_ENABLED modes:
//
//   - true:  the kubelet rotates the projected SA token in-place.
//   - false: the token-fetcher sidecar writes a fresh Keycloak token atomically.
//
// Publishing happens on every detected change, not just at startup, so a
// token rotation is propagated to OPA within one poll interval.
//
// One writer per document root.  The token lives under its own root, data.m2m,
// and not under data.pips beside the PIP configuration it is used with.  OPA's
// Data API PUT *replaces* the document at the target path rather than merging
// into it, so two writers sharing a root erase each other: an earlier version
// of this code published {"m2mBearerToken": ...} to /v1/data/pips, which the
// PolicyPuller then overwrote on its next 30 s tick with a NormalizedPIPs
// document that has no such field — and vice versa.  Because pip.rego treats an
// absent token as "add no header" (ADR-0076), that failed silently: PIP calls
// simply went out unauthenticated.  Keep this root exclusive.  If the token
// ever has to share a document with another writer, both writers must move to
// JSON Patch, as ProvidersReloader.pushToOPA does.
type TokenWatcher struct {
	cfg         TokenWatcherConfig
	client      *http.Client
	logger      *log.Logger
	appliedHash string
}

// NewTokenWatcher constructs a TokenWatcher.
func NewTokenWatcher(cfg TokenWatcherConfig) *TokenWatcher {
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(os.Stdout, "[token-watcher] ", log.LstdFlags)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &TokenWatcher{
		cfg:    cfg,
		client: client,
		logger: logger,
	}
}

// Run polls the token file until ctx is cancelled.  Should be started as a
// goroutine alongside the pull loop and providers reloader.
func (w *TokenWatcher) Run(ctx context.Context) {
	if strings.TrimSpace(w.cfg.TokenFile) == "" {
		w.logger.Printf("token watcher disabled: TokenFile not set")
		return
	}
	if strings.TrimSpace(w.cfg.OPAM2MURL) == "" {
		w.logger.Printf("token watcher disabled: OPAM2MURL not set")
		return
	}

	interval := w.cfg.Interval
	if interval <= 0 {
		interval = DefaultTokenWatchInterval
	}

	w.logger.Printf("watching %s every %s", w.cfg.TokenFile, interval)

	// Publish immediately at startup.
	if err := w.checkAndPublish(ctx); err != nil {
		w.logger.Printf("warn: initial token publish: %v", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.checkAndPublish(ctx); err != nil {
				w.logger.Printf("warn: token publish: %v", err)
			}
		}
	}
}

// checkAndPublish reads the token file, computes its content hash, and PUTs
// the token to OPA when the hash has changed.
func (w *TokenWatcher) checkAndPublish(ctx context.Context) error {
	raw, err := os.ReadFile(w.cfg.TokenFile)
	if err != nil {
		if os.IsNotExist(err) {
			// Not yet written (first boot, sidecar not ready). Skip silently.
			return nil
		}
		return fmt.Errorf("read %s: %w", w.cfg.TokenFile, err)
	}

	token := strings.TrimSpace(string(raw))
	if token == "" {
		return nil
	}

	h := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(h[:])
	if hash == w.appliedHash {
		return nil // unchanged
	}

	if err := w.publish(ctx, token); err != nil {
		return err
	}
	w.appliedHash = hash
	w.logger.Printf("m2m bearer token updated in OPA (hash=%s)", hash[:8])
	return nil
}

// publish PUTs {"bearerToken": token} to OPA /v1/data/m2m, replacing whatever
// was there, AND writes the same document to disk so OPA can reload data.m2m
// from the shared volume after a restart.
//
// Disk write happens BEFORE the push so that a crash between the two leaves the
// file in a consistent state for the next OPA startup.
// The replace is safe only because this watcher is the sole writer of that
// document root — see the note on TokenWatcher.
func (w *TokenWatcher) publish(ctx context.Context, token string) error {
	tokenDoc := map[string]string{"bearerToken": token}

	// Disk write: wrap in {"m2m": ...} so OPA loads the file as data.m2m.
	// The top-level key in a data directory file maps to a key under data;
	// "m2m" here matches the /v1/data/m2m document root the push targets.
	if w.cfg.M2MFile != "" {
		opaDoc := map[string]any{"m2m": tokenDoc}
		content, err := json.Marshal(opaDoc)
		if err != nil {
			return fmt.Errorf("marshal m2m disk doc: %w", err)
		}
		if err := atomicfile.WriteFile(w.cfg.M2MFile, append(content, '\n')); err != nil {
			// Non-fatal: log and continue — the in-memory push is still valid.
			// A failed disk write means restart recovery is degraded, not that
			// the current token is unavailable.
			w.logger.Printf("warn: failed to write m2m disk file %s: %v", w.cfg.M2MFile, err)
		}
	}

	body, err := json.Marshal(tokenDoc)
	if err != nil {
		return fmt.Errorf("marshal token body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, w.cfg.OPAM2MURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build OPA request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("PUT %s: %w", w.cfg.OPAM2MURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("PUT %s: HTTP %d", w.cfg.OPAM2MURL, resp.StatusCode)
	}
	return nil
}
