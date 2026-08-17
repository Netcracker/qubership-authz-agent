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
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"authz-agent/internal/pips"
)

// replacingOPA models the one property of OPA's Data API that matters here: PUT
// REPLACES the document at the target path, it does not merge into it.
//
// The per-writer stubs used elsewhere in this package cannot express that —
// each sees only its own request — which is exactly why the collision this
// file guards against went unnoticed until it was found on a live stand.
type replacingOPA struct {
	mu   sync.Mutex
	docs map[string]map[string]any
}

func newReplacingOPA() *replacingOPA {
	return &replacingOPA{docs: map[string]map[string]any{}}
}

func (f *replacingOPA) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "bad method", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.docs[r.URL.Path] = doc // replace, never merge
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
}

func (f *replacingOPA) doc(path string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.docs[path]
}

// TestTokenAndPIPsLiveInSeparateDocumentRoots is a regression test for the
// defect where the M2M bearer token and the PIP configuration shared
// /v1/data/pips: whichever of TokenWatcher and PolicyPuller wrote last erased
// the other, so pip.rego saw no token for all but ~30 s in every 5 h rotation
// window and PIP calls silently went out unauthenticated.
//
// The invariant under test is not "the token is published" — the old code did
// that too — but "publishing the token and pulling policies do not destroy each
// other's document". Both writers run against ONE fake OPA here; a future
// change that points them back at a shared root fails this test.
func TestTokenAndPIPsLiveInSeparateDocumentRoots(t *testing.T) {
	t.Parallel()

	opa := newReplacingOPA()
	opaSrv := httptest.NewServer(opa.handler())
	defer opaSrv.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/access/v3/config/policySets":
			_, _ = w.Write([]byte(minimalPolicySetsResponse))
		case "/access/v3/config/pips":
			_, _ = w.Write([]byte(minimalPIPsResponse))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("m2m-token-v1"), 0o600); err != nil {
		t.Fatal(err)
	}

	const (
		pipsPath = "/v1/data/pips"
		m2mPath  = "/v1/data/m2m"
	)

	watcher := NewTokenWatcher(TokenWatcherConfig{
		TokenFile: tokenFile,
		OPAM2MURL: opaSrv.URL + m2mPath,
		Interval:  10 * time.Millisecond,
		Logger:    silentLogger(),
	})
	puller := NewPolicyPuller(PullConfig{
		SourceURL:      srv.URL,
		Interval:       time.Second,
		PolicyFile:     filepath.Join(dir, "policies.json"),
		PIPFile:        filepath.Join(dir, "pips.json"),
		OPAPoliciesURL: opaSrv.URL + "/v1/data/policies",
		OPAPIPsURL:     opaSrv.URL + pipsPath,
		Logger:         log.New(io.Discard, "", 0),
	})

	ctx := context.Background()

	// Interleave in both orders: the original defect was order-dependent only
	// in which document was lost, never in whether one was.
	if err := watcher.checkAndPublish(ctx); err != nil {
		t.Fatalf("initial token publish: %v", err)
	}
	if err := puller.PullOnce(ctx); err != nil {
		t.Fatalf("first pull: %v", err)
	}

	if got := opa.doc(m2mPath)["bearerToken"]; got != "m2m-token-v1" {
		t.Errorf("after a pull, data.m2m.bearerToken = %v, want %q — the pull erased the token", got, "m2m-token-v1")
	}
	if opa.doc(pipsPath) == nil {
		t.Fatalf("after a pull, data.pips is absent")
	}

	// Now a token rotation on top of a populated data.pips.
	if err := os.WriteFile(tokenFile, []byte("m2m-token-v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := watcher.checkAndPublish(ctx); err != nil {
		t.Fatalf("rotation publish: %v", err)
	}

	if got := opa.doc(m2mPath)["bearerToken"]; got != "m2m-token-v2" {
		t.Errorf("after rotation, data.m2m.bearerToken = %v, want %q", got, "m2m-token-v2")
	}
	pipsDoc := opa.doc(pipsPath)
	if pipsDoc == nil {
		t.Fatalf("after a token rotation, data.pips is gone — the token write erased the PIP configuration")
	}
	// The PIP document must still carry its own structure, not just exist.
	if _, ok := pipsDoc["byName"]; !ok {
		t.Errorf("after a token rotation, data.pips lost its byName index: %v", pipsDoc)
	}

	// The token must never appear inside the PIP document: that co-location is
	// the defect itself, and it is also what made GET /v1/data/pips leak it.
	if _, ok := pipsDoc["m2mBearerToken"]; ok {
		t.Errorf("data.pips carries m2mBearerToken again; the token must live under data.m2m only")
	}
}

// TestDiskLayoutMatchesPushTargets verifies the three-way invariant required for
// OPA restart recovery:
//
//  1. The disk file path (relative to the OPA data directory) and the top-level
//     key inside each file together produce a data document path that is identical
//     to the OPA Data API path the push targets.
//  2. The disk writer (persistPolicies / persistPIPs / TokenWatcher.publish) and
//     the OPA push use the same data structure.
//
// A mismatch means startup-from-disk and runtime-push disagree: OPA loads one
// thing at startup and pap-client overwrites it with another on the first tick.
// That was how the pre-Phase-4 `persistPIPs` bug was obscured — the push always
// won, so the disk representation (which OPA only reads at startup) was never
// exercised.
//
// The test belongs here, next to the collision test, because adding a third writer
// to the same document roots is what triggered the original defect. "Third writer"
// is the disk writer itself; if it targets the wrong root it becomes the fourth
// cause of silent failure in this neighbourhood.
func TestDiskLayoutMatchesPushTargets(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// ── Policy file ─────────────────────────────────────────────────────────
	// Push URL:  /v1/data/policies  → data.policies = <map>
	// Disk file: policies.json at OPA data dir root with {"policies": <map>}
	// OPA data dir convention: top-level key in the file = sub-key under data.
	policyFile := filepath.Join(dir, "policies.json")
	puller := NewPolicyPuller(PullConfig{
		PolicyFile: policyFile,
		PIPFile:    filepath.Join(dir, "pips_unused.json"),
		Logger:     log.New(io.Discard, "", 0),
	})

	normalizedPolicies := map[string]any{"test-policy": map[string]any{"allow": true}}
	if err := puller.persistPolicies(normalizedPolicies); err != nil {
		t.Fatalf("persistPolicies: %v", err)
	}
	diskKey := topLevelKeyFromFile(t, policyFile)
	pushRoot := "policies" // from /v1/data/policies → path component after /v1/data/
	if diskKey != pushRoot {
		t.Errorf("policies.json disk top-level key = %q, push path last component = %q; they must match for OPA restart recovery to work", diskKey, pushRoot)
	}

	// ── PIP file ─────────────────────────────────────────────────────────────
	// Push URL:  /v1/data/pips  → data.pips = NormalizedPIPs
	// Disk file: pips.json at OPA data dir root with {"pips": NormalizedPIPs}
	pipFile := filepath.Join(dir, "pips.json")
	pipPuller := NewPolicyPuller(PullConfig{
		PolicyFile: policyFile,
		PIPFile:    pipFile,
		Logger:     log.New(io.Discard, "", 0),
	})

	// Build a minimal PIPDocument to persist.
	minimalPipDoc := minimalPIPDocumentForTest(t)
	if err := pipPuller.persistPIPs(minimalPipDoc); err != nil {
		t.Fatalf("persistPIPs: %v", err)
	}
	diskKey = topLevelKeyFromFile(t, pipFile)
	pushRoot = "pips" // from /v1/data/pips
	if diskKey != pushRoot {
		t.Errorf("pips.json disk top-level key = %q, push path last component = %q; they must match for OPA restart recovery to work", diskKey, pushRoot)
	}

	// ── M2M file ──────────────────────────────────────────────────────────────
	// Push URL:  /v1/data/m2m  → data.m2m = {"bearerToken": "..."}
	// Disk file: m2m.json at OPA data dir root with {"m2m": {"bearerToken": "..."}}
	m2mFile := filepath.Join(dir, "m2m.json")

	opa := newReplacingOPA()
	opaSrv := httptest.NewServer(opa.handler())
	defer opaSrv.Close()

	watcher := NewTokenWatcher(TokenWatcherConfig{
		TokenFile: filepath.Join(dir, "token"),
		OPAM2MURL: opaSrv.URL + "/v1/data/m2m",
		M2MFile:   m2mFile,
		Logger:    log.New(io.Discard, "", 0),
	})
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("restart-test-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := watcher.checkAndPublish(context.Background()); err != nil {
		t.Fatalf("initial token publish: %v", err)
	}

	diskKey = topLevelKeyFromFile(t, m2mFile)
	pushRoot = "m2m" // from /v1/data/m2m
	if diskKey != pushRoot {
		t.Errorf("m2m.json disk top-level key = %q, push path last component = %q; they must match for OPA restart recovery to work", diskKey, pushRoot)
	}

	// Also assert that the value under the disk key matches what was pushed to OPA.
	// This verifies that startup-from-disk and runtime-push use the same structure.
	m2mPushed := opa.doc("/v1/data/m2m")
	if m2mPushed == nil {
		t.Fatal("nothing was pushed to OPA /v1/data/m2m")
	}
	m2mDisk := fileDoc(t, m2mFile)["m2m"]
	m2mDiskBytes, _ := json.Marshal(m2mDisk)
	m2mPushedBytes, _ := json.Marshal(m2mPushed)
	if string(m2mDiskBytes) != string(m2mPushedBytes) {
		t.Errorf("m2m disk doc (%s) != m2m pushed doc (%s); restart recovery would serve a different token than the live push", m2mDiskBytes, m2mPushedBytes)
	}
}

// TestMountWatcherDiskLayoutMatchesPushTargets verifies that the MountWatcher's
// inline disk-persist logic (inside applyAndPublish) writes pips.json and
// policies.json in the same OPA data-dir format that PolicyPuller.persistPIPs
// and persistPolicies use: a single top-level key whose name equals the last
// component of the OPA Data API path the push targets.
//
// Mount mode shares the fix with the pull mode:
// the old code wrote the full PIPDocument struct ({"raw":…,"normalized":…})
// which does not produce data.pips on OPA startup.  The fix writes
// {"pips": pipDoc.Normalized}, matching the /v1/data/pips push target.
//
// This is the mount-mode counterpart of TestDiskLayoutMatchesPushTargets.
func TestMountWatcherDiskLayoutMatchesPushTargets(t *testing.T) {
	t.Parallel()

	// mount dir: source files (simplified-format JSON arrays).
	mountDir := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(mountDir, MountPoliciesFile), []byte("[]"), 0o644,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(mountDir, MountPIPsFile), []byte("[]"), 0o644,
	); err != nil {
		t.Fatal(err)
	}

	// output dir: where MountWatcher writes normalised disk files.
	dataDir := t.TempDir()
	policyFile := filepath.Join(dataDir, "policies.json")
	pipFile := filepath.Join(dataDir, "pips.json")

	// Empty OPA URLs: push is skipped (if-non-empty guard in applyAndPublish),
	// but disk persist still runs. We only need to verify the on-disk layout.
	w := NewMountWatcher(MountWatchConfig{
		MountDir:   mountDir,
		PolicyFile: policyFile,
		PIPFile:    pipFile,
		Logger:     log.New(io.Discard, "", 0),
	})

	applied, err := w.WatchOnce(context.Background())
	if err != nil {
		t.Fatalf("WatchOnce: %v", err)
	}
	if !applied {
		t.Fatal("WatchOnce returned applied=false on first call; expected files to be processed")
	}

	// policies.json: top-level key must be "policies" to match /v1/data/policies.
	if diskKey := topLevelKeyFromFile(t, policyFile); diskKey != "policies" {
		t.Errorf("MountWatcher policies.json disk top-level key = %q; want %q "+
			"(must match OPA /v1/data/policies push target for restart recovery)",
			diskKey, "policies")
	}

	// pips.json: top-level key must be "pips" to match /v1/data/pips.
	if diskKey := topLevelKeyFromFile(t, pipFile); diskKey != "pips" {
		t.Errorf("MountWatcher pips.json disk top-level key = %q; want %q "+
			"(must match OPA /v1/data/pips push target for restart recovery)",
			diskKey, "pips")
	}
}

// topLevelKeyFromFile reads a JSON file and returns its single top-level key.
// It fails the test if the file does not exist, cannot be parsed, or has more
// than one top-level key (since OPA's data merge uses each key as a data path
// component and multiple keys would pollute unrelated document roots).
func topLevelKeyFromFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(doc) != 1 {
		keys := make([]string, 0, len(doc))
		for k := range doc {
			keys = append(keys, k)
		}
		t.Fatalf("%s has %d top-level keys (%s); expected exactly 1 so OPA's data merge targets one document root", path, len(doc), strings.Join(keys, ", "))
	}
	for k := range doc {
		return k
	}
	return "" // unreachable
}

// fileDoc reads a JSON file and returns its contents as a map.
func fileDoc(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return doc
}

// minimalPIPDocumentForTest builds a PIPDocument with the minimum structure
// required for persistPIPs to write a valid disk file.
func minimalPIPDocumentForTest(t *testing.T) *pips.PIPDocument {
	t.Helper()
	doc := &pips.PIPDocument{
		Normalized: pips.NormalizedPIPs{
			ByName: map[string]pips.NormalizedEntry{},
			Local: pips.LocalPIPs{
				Token:  map[string]pips.TokenPIPConfig{},
				Header: map[string]pips.HeaderPIPConfig{},
			},
			Remote: pips.RemotePIPs{
				General: map[string]pips.GeneralPIPConfig{},
			},
		},
	}
	return doc
}
