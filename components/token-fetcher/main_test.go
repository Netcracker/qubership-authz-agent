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
	"strings"
	"testing"
	"time"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// discard is shared by tests that do not assert on log output.
var discard = log.New(io.Discard, "", 0)

// makeJWT builds a minimal JWT with a given exp claim.  The signature section
// is a dummy string — jwtExp never verifies it.
func makeJWT(exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		fmt.Sprintf(`{"sub":"svc","exp":%d}`, exp),
	))
	return header + "." + payload + ".fakesig"
}

// writeSecretFiles creates clientId and clientSecret files in a temp dir and
// returns their paths.
func writeSecretFiles(t *testing.T) (idFile, secretFile string) {
	t.Helper()
	dir := t.TempDir()
	idFile = filepath.Join(dir, "username")
	secretFile = filepath.Join(dir, "password")
	if err := os.WriteFile(idFile, []byte("cid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretFile, []byte("csec"), 0o600); err != nil {
		t.Fatal(err)
	}
	return idFile, secretFile
}

// tokenServer starts an httptest server that answers every request with the
// given access token; expiresIn > 0 adds the expires_in field, 0 omits it to
// exercise the JWT-exp fallback.
func tokenServer(t *testing.T, accessToken string, expiresIn int) *httptest.Server {
	t.Helper()
	body := map[string]any{"access_token": accessToken}
	if expiresIn > 0 {
		body["expires_in"] = expiresIn
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// testConfig returns a config that points at tokenURL, with fresh secret
// files and token/marker paths in a temp dir.
func testConfig(t *testing.T, tokenURL string) config {
	t.Helper()
	idFile, secretFile := writeSecretFiles(t)
	dir := t.TempDir()
	return config{
		clientIDFile:     idFile,
		clientSecretFile: secretFile,
		tokenURL:         tokenURL,
		tokenFile:        filepath.Join(dir, "token"),
		markerFile:       filepath.Join(dir, "ready"),
		renewBefore:      60 * time.Second,
	}
}

// ─── fetchToken tests ────────────────────────────────────────────────────────

func TestFetchToken_ExpiresInUsed(t *testing.T) {
	srv := tokenServer(t, "my-token", 3600)

	token, lifetime, err := fetchToken(srv.Client(), srv.URL, "cid", "csec")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "my-token" {
		t.Errorf("expected my-token, got %q", token)
	}
	if lifetime != 3600*time.Second {
		t.Errorf("expected 3600s lifetime, got %s", lifetime)
	}
}

func TestFetchToken_JWTFallbackWhenExpiresInAbsent(t *testing.T) {
	exp := time.Now().Add(900 * time.Second).Unix()
	srv := tokenServer(t, makeJWT(exp), 0)

	_, lifetime, err := fetchToken(srv.Client(), srv.URL, "cid", "csec")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The fallback computes time.Until(exp); allow a small execution window.
	if lifetime < 898*time.Second || lifetime > 901*time.Second {
		t.Errorf("expected ~900s from JWT exp, got %s", lifetime)
	}
}

func TestFetchToken_JWTFallbackExpInPast(t *testing.T) {
	srv := tokenServer(t, makeJWT(time.Now().Add(-time.Hour).Unix()), 0)

	if _, _, err := fetchToken(srv.Client(), srv.URL, "cid", "csec"); err == nil {
		t.Fatal("expected error when the JWT exp is in the past")
	}
}

func TestFetchToken_EmptyAccessToken(t *testing.T) {
	srv := tokenServer(t, "", 300)

	if _, _, err := fetchToken(srv.Client(), srv.URL, "cid", "csec"); err == nil {
		t.Fatal("expected error on empty access_token")
	}
}

func TestFetchToken_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	t.Cleanup(srv.Close)

	if _, _, err := fetchToken(srv.Client(), srv.URL, "cid", "csec"); err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}

func TestFetchToken_NetworkError(t *testing.T) {
	if _, _, err := fetchToken(http.DefaultClient, "http://127.0.0.1:1", "cid", "csec"); err == nil {
		t.Fatal("expected error on unreachable server")
	}
}

func TestFetchToken_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	if _, _, err := fetchToken(srv.Client(), srv.URL, "cid", "csec"); err == nil {
		t.Fatal("expected error on 401 response")
	}
}

// ─── jwtExp tests ────────────────────────────────────────────────────────────

func TestJWTExp(t *testing.T) {
	const exp = int64(1900000000)

	t.Run("unpadded payload", func(t *testing.T) {
		got, err := jwtExp(makeJWT(exp))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := time.Unix(exp, 0); !got.Equal(want) {
			t.Errorf("exp: got %v, want %v", got, want)
		}
	})

	t.Run("padded payload", func(t *testing.T) {
		// 19000000000 makes the JSON 19 bytes long, so the padded base64url
		// encoding ends in "=" — the branch that pads before decoding.
		const paddedExp = int64(19000000000)
		payload := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, paddedExp)))
		if !strings.Contains(payload, "=") {
			t.Fatal("test fixture must produce a padded payload")
		}
		got, err := jwtExp("h." + payload + ".s")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := time.Unix(paddedExp, 0); !got.Equal(want) {
			t.Errorf("exp: got %v, want %v", got, want)
		}
	})

	t.Run("not a JWT", func(t *testing.T) {
		if _, err := jwtExp("opaque-token"); err == nil {
			t.Error("expected error for a token without dots")
		}
	})

	t.Run("missing exp claim", func(t *testing.T) {
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"svc"}`))
		if _, err := jwtExp("h." + payload + ".s"); err == nil {
			t.Error("expected error when exp is absent")
		}
	})

	t.Run("payload is not base64", func(t *testing.T) {
		if _, err := jwtExp("h.!!!!.s"); err == nil {
			t.Error("expected error on undecodable payload")
		}
	})
}

// ─── loadConfig tests ────────────────────────────────────────────────────────

func TestLoadConfig_Defaults(t *testing.T) {
	for _, key := range []string{
		"AUTHZ_M2M_CLIENT_ID_FILE",
		"AUTHZ_M2M_CLIENT_SECRET_FILE",
		"AUTHZ_M2M_TOKEN_URL",
		"AUTHZ_PAP_CLIENT_TOKEN_FILE",
		"AUTHZ_M2M_MARKER_FILE",
		"AUTHZ_M2M_RENEW_BEFORE_SECONDS",
	} {
		t.Setenv(key, "")
	}

	cfg := loadConfig(discard)
	want := config{
		clientIDFile:     defaultClientIDFile,
		clientSecretFile: defaultClientSecretFile,
		tokenURL:         defaultTokenURL,
		tokenFile:        defaultTokenFile,
		markerFile:       defaultMarkerFile,
		renewBefore:      defaultRenewBefore,
	}
	if cfg != want {
		t.Errorf("defaults: got %+v, want %+v", cfg, want)
	}
}

func TestLoadConfig_RenewBefore(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want time.Duration
	}{
		{"valid", "120", 120 * time.Second},
		{"zero disables the margin", "0", 0},
		{"trailing garbage rejected", "60abc", defaultRenewBefore},
		{"negative rejected", "-5", defaultRenewBefore},
		{"not a number rejected", "abc", defaultRenewBefore},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AUTHZ_M2M_RENEW_BEFORE_SECONDS", tc.env)
			if got := loadConfig(discard).renewBefore; got != tc.want {
				t.Errorf("renewBefore: got %s, want %s", got, tc.want)
			}
		})
	}
}

// ─── fetchAndWrite tests ─────────────────────────────────────────────────────

func TestFetchAndWrite_TokenWritten(t *testing.T) {
	srv := tokenServer(t, "written-token", 300)
	cfg := testConfig(t, srv.URL)

	lifetime, err := fetchAndWrite(cfg, srv.Client(), discard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lifetime != 300*time.Second {
		t.Errorf("lifetime: got %s, want 300s", lifetime)
	}

	raw, err := os.ReadFile(cfg.tokenFile)
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
	srv := tokenServer(t, "some-token", 300)
	cfg := testConfig(t, srv.URL)

	if _, err := fetchAndWrite(cfg, srv.Client(), discard); err != nil {
		t.Fatalf("fetchAndWrite: %v", err)
	}

	info, err := os.Stat(cfg.tokenFile)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	const wantMode = os.FileMode(0o600)
	if got := info.Mode().Perm(); got != wantMode {
		t.Errorf("token file mode: got %04o, want %04o", got, wantMode)
	}
}

func TestFetchAndWrite_ErrorOnUnreachableURL(t *testing.T) {
	cfg := testConfig(t, "http://127.0.0.1:1")

	if _, err := fetchAndWrite(cfg, http.DefaultClient, discard); err == nil {
		t.Fatal("expected error on unreachable token URL")
	}
}

// ─── step tests ──────────────────────────────────────────────────────────────

func TestStep_SuccessWritesMarkerAndResetsBackoff(t *testing.T) {
	srv := tokenServer(t, "tok", 300)
	cfg := testConfig(t, srv.URL)

	sleep, next := step(cfg, srv.Client(), discard, maxBackoff)
	if sleep != 240*time.Second {
		t.Errorf("sleep: got %s, want 240s", sleep)
	}
	if next != initialBackoff {
		t.Errorf("backoff after success: got %s, want %s", next, initialBackoff)
	}
	if _, err := os.Stat(cfg.markerFile); err != nil {
		t.Errorf("marker file not written: %v", err)
	}
}

func TestStep_MarkerRewrittenOnEverySuccess(t *testing.T) {
	srv := tokenServer(t, "tok", 300)
	cfg := testConfig(t, srv.URL)

	if _, next := step(cfg, srv.Client(), discard, initialBackoff); next != initialBackoff {
		t.Fatalf("first step did not succeed (next backoff %s)", next)
	}
	// Losing the marker (an operator cleanup, a probe mishap) must not stick:
	// every successful refresh rewrites it.
	if err := os.Remove(cfg.markerFile); err != nil {
		t.Fatalf("remove marker: %v", err)
	}
	step(cfg, srv.Client(), discard, initialBackoff)
	if _, err := os.Stat(cfg.markerFile); err != nil {
		t.Errorf("marker not rewritten on second success: %v", err)
	}
}

func TestStep_FailureDoublesBackoffAndSkipsMarker(t *testing.T) {
	cfg := testConfig(t, "http://127.0.0.1:1")
	client := &http.Client{Timeout: time.Second}

	sleep, next := step(cfg, client, discard, initialBackoff)
	if sleep != initialBackoff {
		t.Errorf("sleep on failure: got %s, want the current backoff %s", sleep, initialBackoff)
	}
	if next != 2*initialBackoff {
		t.Errorf("next backoff: got %s, want %s", next, 2*initialBackoff)
	}
	if _, err := os.Stat(cfg.markerFile); !os.IsNotExist(err) {
		t.Errorf("marker must not appear on failure; stat err: %v", err)
	}
}

func TestStep_BackoffCapped(t *testing.T) {
	cfg := testConfig(t, "http://127.0.0.1:1")
	client := &http.Client{Timeout: time.Second}

	if _, next := step(cfg, client, discard, maxBackoff); next != maxBackoff {
		t.Errorf("backoff: got %s, want it capped at %s", next, maxBackoff)
	}
}

func TestStep_RefreshSchedule(t *testing.T) {
	cases := []struct {
		name        string
		expiresIn   int
		renewBefore time.Duration
		want        time.Duration
	}{
		{"normal margin", 300, 60 * time.Second, 240 * time.Second},
		{"margin equals lifetime: half-life", 60, 60 * time.Second, 30 * time.Second},
		{"margin exceeds lifetime: half-life", 30, 60 * time.Second, 15 * time.Second},
		{"tiny lifetime floors at one second", 1, 60 * time.Second, time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := tokenServer(t, "tok", tc.expiresIn)
			cfg := testConfig(t, srv.URL)
			cfg.renewBefore = tc.renewBefore

			sleep, _ := step(cfg, srv.Client(), discard, initialBackoff)
			if sleep != tc.want {
				t.Errorf("sleep: got %s, want %s", sleep, tc.want)
			}
		})
	}
}
