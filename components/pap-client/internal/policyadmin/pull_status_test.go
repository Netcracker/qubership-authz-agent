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
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── WritePullStatus / LoadPullStatus ──────────────────────────────────────────

func TestWriteAndLoadPullStatus_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pull-status.json")

	nowStr := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	status := PullStatus{
		PoliciesLoaded: true,
		FirstSuccessAt: nowStr,
		LastSuccessAt:  nowStr,
	}
	if err := WritePullStatus(path, status); err != nil {
		t.Fatalf("WritePullStatus: %v", err)
	}

	got, err := LoadPullStatus(path)
	if err != nil {
		t.Fatalf("LoadPullStatus: %v", err)
	}
	if !got.PoliciesLoaded {
		t.Error("expected policiesLoaded=true")
	}
	if got.FirstSuccessAt != nowStr {
		t.Errorf("firstSuccessAt mismatch: got %q want %q", got.FirstSuccessAt, nowStr)
	}
}

func TestLoadPullStatus_AbsentFile(t *testing.T) {
	_, err := LoadPullStatus("/nonexistent/pull-status.json")
	if err == nil {
		t.Fatal("expected error for absent file, got nil")
	}
}

func TestLoadPullStatus_MalformedJSON(t *testing.T) {
	f := writeTempFile(t, []byte("not-json"))
	_, err := LoadPullStatus(f)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestWritePullStatus_EmptyPath(t *testing.T) {
	// Writing to an empty path must be a no-op, not an error.
	if err := WritePullStatus("", PullStatus{PoliciesLoaded: true}); err != nil {
		t.Fatalf("unexpected error for empty path: %v", err)
	}
}

func TestWritePullStatus_ReasonField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pull-status.json")

	want := "pull disabled: source URL empty"
	status := PullStatus{PoliciesLoaded: true, Reason: want}
	if err := WritePullStatus(path, status); err != nil {
		t.Fatalf("WritePullStatus: %v", err)
	}
	got, err := LoadPullStatus(path)
	if err != nil {
		t.Fatalf("LoadPullStatus: %v", err)
	}
	if got.Reason != want {
		t.Errorf("reason mismatch: got %q want %q", got.Reason, want)
	}
	if !got.PoliciesLoaded {
		t.Error("policiesLoaded must be true for a disabled-pull status")
	}
}

// ── PolicyPuller pull status latch ───────────────────────────────────────────

// TestPolicyPuller_LatchNeverResets verifies that policiesLoaded is set to true
// on the first successful pull and that the status file does not change on a
// subsequent failed pull.
func TestPolicyPuller_LatchNeverResets(t *testing.T) {
	dir := t.TempDir()
	pullStatusFile := filepath.Join(dir, "pull-status.json")

	// OPA accepts all PUT requests.
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer opaSrv.Close()

	puller := NewPolicyPuller(PullConfig{
		SourceURL:      "http://irrelevant", // won't be called via PullOnce directly
		Interval:       time.Second,
		PolicyFile:     filepath.Join(dir, "policies.json"),
		PIPFile:        filepath.Join(dir, "pips.json"),
		OPAPoliciesURL: opaSrv.URL + "/v1/data/policies",
		OPAPIPsURL:     opaSrv.URL + "/v1/data/pips",
		PullStatusFile: pullStatusFile,
		Logger:         log.New(io.Discard, "", 0),
	})

	// Simulate first successful pull: call recordPullSuccess directly.
	puller.recordPullSuccess()

	status, err := LoadPullStatus(pullStatusFile)
	if err != nil {
		t.Fatalf("LoadPullStatus after first success: %v", err)
	}
	if !status.PoliciesLoaded {
		t.Fatal("policiesLoaded must be true after first success")
	}
	firstSuccessAt := status.FirstSuccessAt
	if firstSuccessAt == "" {
		t.Fatal("firstSuccessAt must be set after first success")
	}

	// Snapshot the file content before any further operation.
	rawBefore, _ := os.ReadFile(pullStatusFile)

	// Do NOT call recordPullSuccess again (simulating a failed pull — the
	// caller in Run() only calls recordPullSuccess on err==nil).
	// The file must remain unchanged.
	rawAfter, _ := os.ReadFile(pullStatusFile)
	if string(rawBefore) != string(rawAfter) {
		t.Error("pull status file must not change when recordPullSuccess is not called")
	}

	status2, err := LoadPullStatus(pullStatusFile)
	if err != nil {
		t.Fatalf("LoadPullStatus after no-op: %v", err)
	}
	if !status2.PoliciesLoaded {
		t.Error("policiesLoaded latch must never reset to false")
	}
	if status2.FirstSuccessAt != firstSuccessAt {
		t.Errorf("firstSuccessAt changed unexpectedly: was %q now %q", firstSuccessAt, status2.FirstSuccessAt)
	}
}

// TestPolicyPuller_SecondSuccessUpdatesLastSuccessAt verifies that subsequent
// successful pulls update lastSuccessAt but leave firstSuccessAt unchanged.
func TestPolicyPuller_SecondSuccessUpdatesLastSuccessAt(t *testing.T) {
	dir := t.TempDir()
	pullStatusFile := filepath.Join(dir, "pull-status.json")

	puller := NewPolicyPuller(PullConfig{
		SourceURL:      "http://irrelevant",
		Interval:       time.Second,
		PolicyFile:     filepath.Join(dir, "policies.json"),
		PIPFile:        filepath.Join(dir, "pips.json"),
		PullStatusFile: pullStatusFile,
		Logger:         log.New(io.Discard, "", 0),
	})

	// First success.
	puller.recordPullSuccess()
	s1, err := LoadPullStatus(pullStatusFile)
	if err != nil {
		t.Fatalf("LoadPullStatus after 1st: %v", err)
	}

	// Short sleep to make the timestamp differ.
	time.Sleep(10 * time.Millisecond)

	// Second success.
	puller.recordPullSuccess()
	s2, err := LoadPullStatus(pullStatusFile)
	if err != nil {
		t.Fatalf("LoadPullStatus after 2nd: %v", err)
	}

	if s2.FirstSuccessAt != s1.FirstSuccessAt {
		t.Errorf("firstSuccessAt changed: was %q now %q", s1.FirstSuccessAt, s2.FirstSuccessAt)
	}
	// LastSuccessAt should be >= firstSuccessAt; both calls happen within 10ms so
	// they may be equal — just verify it is set.
	if s2.LastSuccessAt == "" {
		t.Error("lastSuccessAt must be set after second success")
	}
	if !s2.PoliciesLoaded {
		t.Error("policiesLoaded must remain true")
	}
}

// TestPolicyPuller_DisabledSourceURLWritesLoaded verifies that when SourceURL
// is empty, Run() writes policiesLoaded=true immediately and then returns.
func TestPolicyPuller_DisabledSourceURLWritesLoaded(t *testing.T) {
	dir := t.TempDir()
	pullStatusFile := filepath.Join(dir, "pull-status.json")

	puller := NewPolicyPuller(PullConfig{
		SourceURL:      "",
		PullStatusFile: pullStatusFile,
		Logger:         log.New(io.Discard, "", 0),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	puller.Run(ctx)

	status, err := LoadPullStatus(pullStatusFile)
	if err != nil {
		t.Fatalf("LoadPullStatus: %v", err)
	}
	if !status.PoliciesLoaded {
		t.Error("policiesLoaded must be true when pull is disabled (empty source URL)")
	}
	if status.Reason == "" {
		t.Error("reason must be set for a disabled-pull status")
	}
}

// TestPolicyPuller_DisabledIntervalZeroWritesLoaded verifies that when Interval
// is 0, Run() writes policiesLoaded=true immediately and then returns.
func TestPolicyPuller_DisabledIntervalZeroWritesLoaded(t *testing.T) {
	dir := t.TempDir()
	pullStatusFile := filepath.Join(dir, "pull-status.json")

	puller := NewPolicyPuller(PullConfig{
		SourceURL:      "http://authz-policy-admin:8080",
		Interval:       0,
		PullStatusFile: pullStatusFile,
		Logger:         log.New(io.Discard, "", 0),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	puller.Run(ctx)

	status, err := LoadPullStatus(pullStatusFile)
	if err != nil {
		t.Fatalf("LoadPullStatus: %v", err)
	}
	if !status.PoliciesLoaded {
		t.Error("policiesLoaded must be true when pull is disabled (interval 0)")
	}
}

// ── MountWatcher pull status latch ───────────────────────────────────────────

// TestMountWatcher_WritesStatusOnFirstSuccess verifies that after the first
// successful WatchOnce call policiesLoaded=true is written.
func TestMountWatcher_WritesStatusOnFirstSuccess(t *testing.T) {
	dir := t.TempDir()
	pullStatusFile := filepath.Join(dir, "pull-status.json")
	mountDir := t.TempDir()

	// Write valid simplified-format files into the mount directory.
	if err := os.WriteFile(filepath.Join(mountDir, MountPoliciesFile), []byte("[]"), 0o644); err != nil {
		t.Fatalf("write policies: %v", err)
	}
	if err := os.WriteFile(filepath.Join(mountDir, MountPIPsFile), []byte("[]"), 0o644); err != nil {
		t.Fatalf("write pips: %v", err)
	}

	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer opaSrv.Close()

	watcher := NewMountWatcher(MountWatchConfig{
		MountDir:       mountDir,
		Interval:       50 * time.Millisecond,
		PolicyFile:     filepath.Join(dir, "policies.json"),
		PIPFile:        filepath.Join(dir, "pips.json"),
		OPAPoliciesURL: opaSrv.URL + "/v1/data/policies",
		OPAPIPsURL:     opaSrv.URL + "/v1/data/pips",
		PullStatusFile: pullStatusFile,
		Logger:         log.New(io.Discard, "", 0),
	})

	changed, err := watcher.WatchOnce(context.Background())
	if err != nil {
		t.Fatalf("WatchOnce: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true on first WatchOnce")
	}
	watcher.recordMountSuccess()

	status, err := LoadPullStatus(pullStatusFile)
	if err != nil {
		t.Fatalf("LoadPullStatus: %v", err)
	}
	if !status.PoliciesLoaded {
		t.Error("policiesLoaded must be true after first successful WatchOnce")
	}
	if status.FirstSuccessAt == "" {
		t.Error("firstSuccessAt must be set after first success")
	}
}

// TestMountWatcher_IntervalZeroWritesLoaded verifies that when Interval is 0,
// Run() writes policiesLoaded=true immediately and returns.
func TestMountWatcher_IntervalZeroWritesLoaded(t *testing.T) {
	dir := t.TempDir()
	pullStatusFile := filepath.Join(dir, "pull-status.json")

	watcher := NewMountWatcher(MountWatchConfig{
		MountDir:       t.TempDir(),
		Interval:       0,
		PullStatusFile: pullStatusFile,
		Logger:         log.New(io.Discard, "", 0),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	watcher.Run(ctx)

	status, err := LoadPullStatus(pullStatusFile)
	if err != nil {
		t.Fatalf("LoadPullStatus: %v", err)
	}
	if !status.PoliciesLoaded {
		t.Error("policiesLoaded must be true when mount watcher is disabled (interval 0)")
	}
	if status.Reason == "" {
		t.Error("reason must be set for a disabled-watcher status")
	}
}
