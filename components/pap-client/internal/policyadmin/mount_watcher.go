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
	"time"

	"authz-agent/internal/atomicfile"
	"authz-agent/internal/pips"
	"authz-agent/internal/simplifiedpolicies"
)

const (
	// DefaultMountWatchInterval is the poll interval for changes to the
	// policy ConfigMap mount.  The kubelet propagates a ConfigMap edit into a
	// directory-mounted volume by swapping the `..data` symlink (not by
	// updating the files in-place), so an inotify/fsnotify watch on the leaf
	// files would miss the swap — polling is intentional here, same as in
	// ProvidersReloader for trusted providers.
	DefaultMountWatchInterval = 30 * time.Second

	// MountPoliciesFile is the filename inside the mount directory that
	// carries the simplified policies (JSON array of SimplifiedPolicy).
	MountPoliciesFile = "policies.json"

	// MountPIPsFile is the filename inside the mount directory that
	// carries the simplified PIPs (JSON array of SimplifiedPIP).
	MountPIPsFile = "pips.json"
)

// MountWatchConfig holds all configuration for the MountWatcher.
type MountWatchConfig struct {
	// MountDir is the path of the mounted ConfigMap directory.
	// Must contain MountPoliciesFile and MountPIPsFile.
	MountDir string

	// Interval is how often to poll the files. 0 → disabled.
	Interval time.Duration

	// PolicyFile is the path to write the normalised policy document on disk.
	PolicyFile string

	// PIPFile is the path to write the normalised PIP document on disk.
	PIPFile string

	// OPAPoliciesURL is the OPA data API URL for policies.
	OPAPoliciesURL string

	// OPAPIPsURL is the OPA data API URL for PIPs.
	OPAPIPsURL string

	// Entitlements is the container-pinned entitlements PIP config (ADR-0054).
	Entitlements *pips.EntitlementsConfig

	// OPAAuthToken is the bearer token sent to OPA on write requests
	// (PUT /v1/data/*). Empty → no Authorization header. See ADR-0077.
	OPAAuthToken string

	// PullStatusFile is the path where MountWatcher records the first-apply
	// latch (PullStatus JSON).  Written immediately with policiesLoaded=true
	// when the interval is 0 (watcher disabled) so that the readiness probe
	// does not wait indefinitely.  Written after the first successful
	// WatchOnce otherwise.  Empty → status not written.
	PullStatusFile string

	// Logger receives all diagnostic output.
	Logger *log.Logger
}

// MountWatcher watches a mounted-ConfigMap directory for changes to policies
// and PIPs in simplified form, normalises them, and republishes the result to
// OPA without restarting the Pod.
//
// This is the offline-delivery counterpart to PolicyPuller: when the cluster
// cannot reach access-control (air-gapped, test environments), an operator
// mounts a ConfigMap that carries the simplified format and MountWatcher
// applies the same normalisation pipeline.  Presence of the mount directory at
// startup causes pap-client to start a MountWatcher instead of a
// PolicyPuller.
type MountWatcher struct {
	cfg    MountWatchConfig
	client *http.Client
	logger *log.Logger

	// Last SHA-256 digests of the files that were successfully applied.
	appliedPoliciesHash string
	appliedPIPsHash     string

	// firstSuccessAt is the time of the first successful WatchOnce call.
	// Zero value means no successful apply yet.
	firstSuccessAt time.Time
}

// NewMountWatcher builds a MountWatcher.
func NewMountWatcher(cfg MountWatchConfig) *MountWatcher {
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(os.Stdout, "[mount-watch] ", log.LstdFlags)
	}
	return &MountWatcher{
		cfg:    cfg,
		client: NewOPAClient(cfg.OPAAuthToken, 10*time.Second),
		logger: logger,
	}
}

// Run polls until ctx is cancelled.  Returns immediately when Interval is 0.
//
// Pull status (PullStatus JSON at cfg.PullStatusFile) is written immediately
// with policiesLoaded=true when the interval is 0 (watcher disabled), or after
// the first successful WatchOnce otherwise.  The policiesLoaded flag is a latch
// that is never reset to false.
func (w *MountWatcher) Run(ctx context.Context) {
	if w.cfg.Interval <= 0 {
		w.logger.Printf("mount watcher disabled: interval is 0")
		w.writeMountStatusDisabled("mount watcher disabled: interval is 0")
		return
	}
	w.logger.Printf("watching mount %s every %s", w.cfg.MountDir, w.cfg.Interval)

	// Apply immediately at startup so policies are live before the first tick.
	if changed, err := w.WatchOnce(ctx); err != nil {
		w.logger.Printf("warn: initial mount apply failed: %v", err)
	} else if changed {
		w.logger.Printf("policies loaded from mount %s", w.cfg.MountDir)
		w.recordMountSuccess()
	}

	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			changed, err := w.WatchOnce(ctx)
			switch {
			case err != nil:
				w.logger.Printf("warn: mount reload failed, keeping previous data: %v", err)
			case changed:
				w.logger.Printf("policies reloaded from mount %s", w.cfg.MountDir)
				w.recordMountSuccess()
			}
		}
	}
}

// recordMountSuccess is called after a successful WatchOnce.  It writes the
// pull status file on the first call (setting firstSuccessAt) and updates
// lastSuccessAt on subsequent calls.  policiesLoaded is never reset to false.
func (w *MountWatcher) recordMountSuccess() {
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)
	if w.firstSuccessAt.IsZero() {
		w.firstSuccessAt = now
	}
	status := PullStatus{
		PoliciesLoaded: true,
		FirstSuccessAt: w.firstSuccessAt.UTC().Format(time.RFC3339),
		LastSuccessAt:  nowStr,
	}
	if err := WritePullStatus(w.cfg.PullStatusFile, status); err != nil {
		w.logger.Printf("warn: failed to write pull status: %v", err)
	}
}

// writeMountStatusDisabled writes policiesLoaded=true when the mount watcher
// exits early (interval is 0).  This prevents the readiness probe from
// blocking a Pod that was never expected to watch a ConfigMap.
func (w *MountWatcher) writeMountStatusDisabled(reason string) {
	status := PullStatus{
		PoliciesLoaded: true,
		Reason:         reason,
	}
	if err := WritePullStatus(w.cfg.PullStatusFile, status); err != nil {
		w.logger.Printf("warn: failed to write pull status: %v", err)
	}
}

// WatchOnce checks the mounted files and republishes if either changed.
// Returns (true, nil) when a new configuration was published, (false, nil) when
// the files are unchanged, and (false, err) when a changed file could not be
// applied (previous data still live in OPA).
func (w *MountWatcher) WatchOnce(ctx context.Context) (bool, error) {
	psFile := filepath.Join(w.cfg.MountDir, MountPoliciesFile)
	pipFile := filepath.Join(w.cfg.MountDir, MountPIPsFile)

	psHash, err := hashFile(psFile)
	if err != nil {
		return false, fmt.Errorf("hash %s: %w", psFile, err)
	}
	pipHash, err := hashFile(pipFile)
	if err != nil {
		return false, fmt.Errorf("hash %s: %w", pipFile, err)
	}

	if psHash == w.appliedPoliciesHash && pipHash == w.appliedPIPsHash {
		return false, nil
	}

	psRaw, err := os.ReadFile(psFile)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", psFile, err)
	}
	pipRaw, err := os.ReadFile(pipFile)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", pipFile, err)
	}

	if err := w.applyAndPublish(ctx, psRaw, pipRaw); err != nil {
		return false, err
	}

	// Record hashes only after successful publish.
	w.appliedPoliciesHash = psHash
	w.appliedPIPsHash = pipHash
	return true, nil
}

// applyAndPublish normalises the simplified-format file contents and pushes
// them to OPA.  The files use the same JSON format that the upload endpoint
// used to accept: a plain JSON array of simplified policies / PIPs.
func (w *MountWatcher) applyAndPublish(ctx context.Context, psRaw, pipRaw []byte) error {
	// Normalise policies.
	normalizedPolicies, err := simplifiedpolicies.Normalize(psRaw)
	if err != nil {
		return fmt.Errorf("normalize policies from mount: %w", err)
	}

	// Normalise PIPs.
	pipDoc, _, err := pips.Normalize(pipRaw)
	if err != nil {
		return fmt.Errorf("normalize pips from mount: %w", err)
	}

	// Apply container-pinned entitlements (ADR-0054).
	pips.ApplyEntitlementsOverride(pipDoc, w.cfg.Entitlements)

	// Persist policies first so BuildActivationIndex reads the new file.
	policyRoot := map[string]any{"policies": normalizedPolicies}
	policyContent, err := json.MarshalIndent(policyRoot, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicfile.WriteFile(w.cfg.PolicyFile, append(policyContent, '\n')); err != nil {
		return fmt.Errorf("persist policies: %w", err)
	}

	// Build GENERAL-PIP activation index from the freshly-written policy file.
	activation := pips.BuildActivationIndex(pipDoc.Normalized.Remote.General, w.cfg.PolicyFile)
	pipDoc.Normalized.Activation.GeneralByResourceTypeOperation = activation

	// Persist PIPs in OPA data-directory format: {"pips": <NormalizedPIPs>}.
	// The "pips" wrapper key makes OPA produce data.pips on startup load,
	// matching the /v1/data/pips document root the push below targets.
	opaDoc := map[string]any{"pips": pipDoc.Normalized}
	pipContent, err := json.MarshalIndent(opaDoc, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicfile.WriteFile(w.cfg.PIPFile, append(pipContent, '\n')); err != nil {
		return fmt.Errorf("persist pips: %w", err)
	}

	// Push policies to OPA.
	if w.cfg.OPAPoliciesURL != "" {
		body, err := json.Marshal(normalizedPolicies)
		if err != nil {
			return err
		}
		if err := w.mountOPARequest(ctx, w.cfg.OPAPoliciesURL, body); err != nil {
			return fmt.Errorf("push policies to OPA: %w", err)
		}
	}

	// Push PIPs to OPA.
	if w.cfg.OPAPIPsURL != "" {
		body, err := json.Marshal(pipDoc.Normalized)
		if err != nil {
			return err
		}
		if err := w.mountOPARequest(ctx, w.cfg.OPAPIPsURL, body); err != nil {
			return fmt.Errorf("push pips to OPA: %w", err)
		}
	}

	return nil
}

func (w *MountWatcher) mountOPARequest(ctx context.Context, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("OPA PUT %s: HTTP %d", url, resp.StatusCode)
	}
	return nil
}
