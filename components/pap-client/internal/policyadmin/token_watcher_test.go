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
	"sync/atomic"
	"testing"
	"time"
)

func silentLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

// TestTokenWatcher_PublishesOnChange verifies that a content change in the
// token file triggers a PUT to OPA within the poll interval.
func TestTokenWatcher_PublishesOnChange(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")

	var putCount int32
	var lastToken string

	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || !strings.HasPrefix(r.URL.Path, "/v1/data/m2m") {
			t.Errorf("unexpected OPA request: %s %s", r.Method, r.URL.Path)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var payload map[string]string
		_ = json.Unmarshal(body, &payload)
		lastToken = payload["bearerToken"]
		atomic.AddInt32(&putCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer opaSrv.Close()

	// Write the initial token.
	if err := os.WriteFile(tokenFile, []byte("initial-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := TokenWatcherConfig{
		TokenFile: tokenFile,
		OPAM2MURL: opaSrv.URL + "/v1/data/m2m",
		Interval:  20 * time.Millisecond,
		Logger:    silentLogger(),
	}
	w := NewTokenWatcher(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go w.Run(ctx)

	// The initial publish should have happened within the first few ticks.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&putCount) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if atomic.LoadInt32(&putCount) == 0 {
		t.Fatal("expected at least one PUT within 500 ms")
	}
	if lastToken != "initial-token" {
		t.Errorf("expected initial-token, got %q", lastToken)
	}

	// Overwrite token — must trigger a second PUT.
	before := atomic.LoadInt32(&putCount)
	if err := os.WriteFile(tokenFile, []byte("refreshed-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&putCount) > before {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if atomic.LoadInt32(&putCount) <= before {
		t.Fatal("expected PUT after token file change")
	}
	if lastToken != "refreshed-token" {
		t.Errorf("expected refreshed-token, got %q", lastToken)
	}
}

// TestTokenWatcher_NoPublishWhenUnchanged verifies that an unchanged token file
// does not trigger repeated PUTs after the initial publish.
func TestTokenWatcher_NoPublishWhenUnchanged(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("stable-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	var putCount int32
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&putCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer opaSrv.Close()

	cfg := TokenWatcherConfig{
		TokenFile: tokenFile,
		OPAM2MURL: opaSrv.URL + "/v1/data/m2m",
		Interval:  20 * time.Millisecond,
		Logger:    silentLogger(),
	}
	watcher := NewTokenWatcher(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	go watcher.Run(ctx)
	<-ctx.Done()

	// Should have published exactly once (initial), not on every tick.
	count := atomic.LoadInt32(&putCount)
	if count != 1 {
		t.Errorf("expected exactly 1 PUT (initial), got %d", count)
	}
}

// TestTokenWatcher_ToleratesAbsentFile verifies that a missing token file does
// not cause the watcher to error out before the sidecar has written it.
func TestTokenWatcher_ToleratesAbsentFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "missing-token")

	var putCount int32
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&putCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer opaSrv.Close()

	cfg := TokenWatcherConfig{
		TokenFile: tokenFile,
		OPAM2MURL: opaSrv.URL + "/v1/data/m2m",
		Interval:  20 * time.Millisecond,
		Logger:    silentLogger(),
	}
	watcher := NewTokenWatcher(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go watcher.Run(ctx)
	<-ctx.Done()

	// Missing file: no PUT expected.
	if c := atomic.LoadInt32(&putCount); c != 0 {
		t.Errorf("expected 0 PUTs for missing file, got %d", c)
	}
}
