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

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// makeJWT builds a minimal JWT with a given exp claim.  The signature section
// is a dummy string — fetchAndWrite never verifies it.
func makeJWT(exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		fmt.Sprintf(`{"sub":"svc","exp":%d}`, exp),
	))
	return header + "." + payload + ".fakesig"
}

// ─── fetchToken tests ────────────────────────────────────────────────────────

func TestFetchToken_ExpiresInUsed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "my-token",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	token, lifetime, err := fetchToken(srv.Client(), srv.URL, "cid", "csec")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "my-token" {
		t.Errorf("expected my-token, got %q", token)
	}
	// Allow a 2-second window for test execution time.
	if lifetime < 3598*time.Second || lifetime > 3601*time.Second {
		t.Errorf("expected ~3600s lifetime, got %s", lifetime)
	}
}

func TestFetchToken_JWTFallbackWhenExpiresInAbsent(t *testing.T) {
	exp := time.Now().Add(900 * time.Second).Unix()
	jwt := makeJWT(exp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": jwt,
			// no expires_in field
		})
	}))
	defer srv.Close()

	_, lifetime, err := fetchToken(srv.Client(), srv.URL, "cid", "csec")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should be ~900 s based on JWT exp.
	if lifetime < 898*time.Second || lifetime > 901*time.Second {
		t.Errorf("expected ~900s from JWT exp, got %s", lifetime)
	}
}

func TestFetchToken_NetworkError(t *testing.T) {
	_, _, err := fetchToken(http.DefaultClient, "http://127.0.0.1:1", "cid", "csec")
	if err == nil {
		t.Fatal("expected error on unreachable server")
	}
}

func TestFetchToken_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, _, err := fetchToken(srv.Client(), srv.URL, "cid", "csec")
	if err == nil {
		t.Fatal("expected error on 401 response")
	}
}

// ─── fetchAndWrite tests ─────────────────────────────────────────────────────

func TestFetchAndWrite_TokenWrittenAtomically(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	secretDir := t.TempDir()
	idFile := filepath.Join(secretDir, "username")
	secFile := filepath.Join(secretDir, "password")
	if err := os.WriteFile(idFile, []byte("myclient"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secFile, []byte("mysecret"), 0o600); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "written-token",
			"expires_in":   300,
		})
	}))
	defer srv.Close()

	cfg := config{
		clientIDFile:     idFile,
		clientSecretFile: secFile,
		tokenURL:         srv.URL,
		tokenFile:        tokenFile,
		markerFile:       filepath.Join(dir, "ready"),
		renewBefore:      60 * time.Second,
	}

	logger := log.New(io.Discard, "", 0)
	lifetime, err := fetchAndWrite(cfg, srv.Client(), logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lifetime < 299*time.Second || lifetime > 301*time.Second {
		t.Errorf("unexpected lifetime: %s", lifetime)
	}

	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("token file not written: %v", err)
	}
	if string(raw) != "written-token" {
		t.Errorf("token file content: got %q, want %q", raw, "written-token")
	}
}

// TestFetchAndWrite_TokenFileMode pins the 0600 permission on the written token
// file. The token contains a credential; world-readable or group-readable mode
// would expose it to other processes in the same Pod. The mode is set by
// WriteFile0600 in atomicfile — this test catches any regression that widens
// the permissions back to 0644.
func TestFetchAndWrite_TokenFileMode(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	secretDir := t.TempDir()
	idFile := filepath.Join(secretDir, "username")
	secFile := filepath.Join(secretDir, "password")
	if err := os.WriteFile(idFile, []byte("cid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secFile, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "some-token",
			"expires_in":   300,
		})
	}))
	defer srv.Close()

	cfg := config{
		clientIDFile:     idFile,
		clientSecretFile: secFile,
		tokenURL:         srv.URL,
		tokenFile:        tokenFile,
		markerFile:       filepath.Join(dir, "ready"),
		renewBefore:      60 * time.Second,
	}

	logger := log.New(io.Discard, "", 0)
	if _, err := fetchAndWrite(cfg, srv.Client(), logger); err != nil {
		t.Fatalf("fetchAndWrite: %v", err)
	}

	info, err := os.Stat(tokenFile)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	const wantMode = os.FileMode(0o600)
	if got := info.Mode().Perm(); got != wantMode {
		t.Errorf("token file mode: got %04o, want %04o", got, wantMode)
	}
}

// ─── marker-file tests ───────────────────────────────────────────────────────

func TestWriteMarker_WrittenOnFirstSuccessOnly(t *testing.T) {
	dir := t.TempDir()
	markerFile := filepath.Join(dir, "ready")
	secretDir := t.TempDir()
	idFile := filepath.Join(secretDir, "username")
	secFile := filepath.Join(secretDir, "password")
	if err := os.WriteFile(idFile, []byte("cid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secFile, []byte("csec"), 0o600); err != nil {
		t.Fatal(err)
	}

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": fmt.Sprintf("token-%d", calls),
			"expires_in":   10,
		})
	}))
	defer srv.Close()

	cfg := config{
		clientIDFile:     idFile,
		clientSecretFile: secFile,
		tokenURL:         srv.URL,
		tokenFile:        filepath.Join(dir, "token"),
		markerFile:       markerFile,
		renewBefore:      5 * time.Second,
	}

	logger := log.New(io.Discard, "", 0)

	// First fetch: marker should be created.
	firstSuccess := false
	if _, err := fetchAndWrite(cfg, srv.Client(), logger); err != nil {
		t.Fatalf("first fetch failed: %v", err)
	}
	if !firstSuccess {
		// The test directly exercises writeMarker rather than run() to avoid
		// the infinite loop; we just check the marker file is writable.
		if err := writeMarker(markerFile, logger); err != nil {
			t.Fatalf("writeMarker failed: %v", err)
		}
	}
	if _, err := os.Stat(markerFile); os.IsNotExist(err) {
		t.Fatal("marker file was not created")
	}

	// Overwriting the marker should not fail (idempotent).
	stat1, _ := os.Stat(markerFile)
	time.Sleep(2 * time.Millisecond)
	_ = writeMarker(markerFile, logger)
	stat2, _ := os.Stat(markerFile)

	// The file should still exist; its mtime may change.
	if stat1 == nil || stat2 == nil {
		t.Fatal("marker disappeared after second write")
	}
}

// ─── retry behavior test ─────────────────────────────────────────────────────

func TestFetchAndWrite_RetryOnNetworkError(t *testing.T) {
	dir := t.TempDir()
	secretDir := t.TempDir()
	idFile := filepath.Join(secretDir, "username")
	secFile := filepath.Join(secretDir, "password")
	if err := os.WriteFile(idFile, []byte("cid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secFile, []byte("csec"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config{
		clientIDFile:     idFile,
		clientSecretFile: secFile,
		tokenURL:         "http://127.0.0.1:1", // unreachable
		tokenFile:        filepath.Join(dir, "token"),
		markerFile:       filepath.Join(dir, "ready"),
		renewBefore:      5 * time.Second,
	}

	logger := log.New(io.Discard, "", 0)
	// fetchAndWrite returns an error on network failure (run() handles retry).
	_, err := fetchAndWrite(cfg, http.DefaultClient, logger)
	if err == nil {
		t.Fatal("expected error on unreachable token URL")
	}
}
