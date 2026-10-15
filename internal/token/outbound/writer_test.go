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

package outbound

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// tokenEndpoint is a fake token endpoint. It records the path and the form
// of the last request and counts the requests. It answers the first
// failures requests with 503 and every later one with status and body.
type tokenEndpoint struct {
	srv *httptest.Server

	mu       sync.Mutex
	status   int
	body     string
	failures int
	lastPath string
	lastForm url.Values
	requests int
}

func newTokenEndpoint(t *testing.T, body string) *tokenEndpoint {
	t.Helper()
	e := &tokenEndpoint{status: http.StatusOK, body: body}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		e.mu.Lock()
		defer e.mu.Unlock()
		e.requests++
		e.lastPath = r.URL.Path
		e.lastForm = r.PostForm
		if e.failures > 0 {
			e.failures--
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(e.status)
		_, _ = w.Write([]byte(e.body))
	}))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *tokenEndpoint) form() url.Values {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastForm
}

func (e *tokenEndpoint) path() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastPath
}

func (e *tokenEndpoint) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.requests
}

// newTestWriter returns a writer for e at the path /token with the
// credentials agent and s3cret and the token file path, and the path of
// the secret file. Its first pause after a failure is 10 ms rather than two
// seconds, so a retry fits in a test.
func newTestWriter(t *testing.T, e *tokenEndpoint, path string) (*Writer, string) {
	t.Helper()
	dir := t.TempDir()
	idFile, secretFile := filepath.Join(dir, "username"), filepath.Join(dir, "password")
	writeFile(t, idFile, "agent\n")
	writeFile(t, secretFile, "s3cret\n")
	w, err := NewWriter(WriterConfig{TokenURL: e.srv.URL + "/token", ClientIDFile: idFile, ClientSecretFile: secretFile, Path: path}, nil)
	if err != nil {
		t.Fatalf("NewWriter() error = %v", err)
	}
	w.firstBackoff = 10 * time.Millisecond
	return w, secretFile
}

func TestWriter_RefreshWritesTheTokenItObtains(t *testing.T) {
	e := newTokenEndpoint(t, `{"access_token": "tok-1", "expires_in": 300}`)
	path := inTempDir(t, "token")
	w, _ := newTestWriter(t, e, path)

	lifetime, err := w.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if lifetime != 300*time.Second {
		t.Errorf("Refresh() lifetime = %s, want 5m0s", lifetime)
	}
	if got := readFile(t, path); got != "tok-1" {
		t.Errorf("token file = %q, want %q", got, "tok-1")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("token file mode = %o, want 600", mode)
	}
	want := url.Values{"grant_type": {"client_credentials"}, "client_id": {"agent"}, "client_secret": {"s3cret"}}
	if got := e.form(); got.Encode() != want.Encode() {
		t.Errorf("token request form = %s, want %s", got.Encode(), want.Encode())
	}
	if got := e.path(); got != "/token" {
		t.Errorf("token request path = %q, want %q", got, "/token")
	}
}

func TestWriter_TakesTheLifetimeFromExpWithoutExpiresIn(t *testing.T) {
	e := newTokenEndpoint(t, `{"access_token": "`+jwtExpiringAt(t, time.Now().Add(10*time.Minute))+`"}`)
	w, _ := newTestWriter(t, e, inTempDir(t, "token"))
	lifetime, err := w.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if lifetime <= 9*time.Minute || lifetime > 10*time.Minute {
		t.Errorf("Refresh() lifetime = %s, want just under 10m0s", lifetime)
	}
}

// The file holds an earlier token, and a failed Refresh leaves it there for
// the reader.
func TestWriter_AFailedRefreshKeepsThePreviousToken(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"HTTP 401", http.StatusUnauthorized, `{"error": "unauthorized_client"}`},
		{"body that is not JSON", http.StatusOK, `<html></html>`},
		{"no access_token", http.StatusOK, `{"expires_in": 300}`},
		{"neither expires_in nor a JWT", http.StatusOK, `{"access_token": "opaque"}`},
		{"JWT without exp", http.StatusOK, `{"access_token": "` + unsignedJWT(t, map[string]any{"sub": "authz-agent"}) + `"}`},
		{"JWT that has expired", http.StatusOK, `{"access_token": "` + jwtExpiringAt(t, time.Now().Add(-time.Minute)) + `"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newTokenEndpoint(t, tt.body)
			e.status = tt.status
			path := inTempDir(t, "token")
			writeFile(t, path, "earlier")
			w, _ := newTestWriter(t, e, path)
			if _, err := w.Refresh(context.Background()); err == nil {
				t.Errorf("Refresh() error = nil, want an error")
			}
			if got := readFile(t, path); got != "earlier" {
				t.Errorf("token file = %q, want %q", got, "earlier")
			}
		})
	}
}

func TestWriter_RefreshFailsWithoutItsFiles(t *testing.T) {
	e := newTokenEndpoint(t, `{"access_token": "tok-1", "expires_in": 300}`)
	dir := t.TempDir()
	present, empty := filepath.Join(dir, "present"), filepath.Join(dir, "empty")
	writeFile(t, present, "agent")
	writeFile(t, empty, "\n")
	tests := []struct {
		name               string
		idFile, secretFile string
		path               string
	}{
		{"missing client id file", filepath.Join(dir, "absent"), present, filepath.Join(dir, "token")},
		{"empty client secret file", present, empty, filepath.Join(dir, "token")},
		{"missing token directory", present, present, filepath.Join(dir, "absent", "token")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := NewWriter(WriterConfig{TokenURL: e.srv.URL + "/token", ClientIDFile: tt.idFile, ClientSecretFile: tt.secretFile, Path: tt.path}, nil)
			if err != nil {
				t.Fatalf("NewWriter() error = %v", err)
			}
			if _, err := w.Refresh(context.Background()); err == nil {
				t.Errorf("Refresh() error = nil, want an error")
			}
		})
	}
}

func TestWriter_LeavesOnlyTheTokenFileBehind(t *testing.T) {
	e := newTokenEndpoint(t, `{"access_token": "tok-1", "expires_in": 300}`)
	path := inTempDir(t, "token")
	w, _ := newTestWriter(t, e, path)
	for range 2 {
		if _, err := w.Refresh(context.Background()); err != nil {
			t.Fatalf("Refresh() error = %v", err)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if len(names) != 1 || names[0] != "token" {
		t.Errorf("files in the token directory = %q, want only %q", names, "token")
	}
}

func TestWriter_ReadsTheCredentialsOnEveryRefresh(t *testing.T) {
	e := newTokenEndpoint(t, `{"access_token": "tok-1", "expires_in": 300}`)
	w, secretFile := newTestWriter(t, e, inTempDir(t, "token"))
	if _, err := w.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	writeFile(t, secretFile, "rotated")
	if _, err := w.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() after the rotation error = %v", err)
	}
	if got := e.form().Get("client_secret"); got != "rotated" {
		t.Errorf("client_secret after the rotation = %q, want %q", got, "rotated")
	}
}

func TestWriter_RunRetriesUntilTheEndpointAnswers(t *testing.T) {
	e := newTokenEndpoint(t, `{"access_token": "tok-1", "expires_in": 300}`)
	e.failures = 2
	path := inTempDir(t, "token")
	w, _ := newTestWriter(t, e, path)
	runInBackground(t, w.Run)
	waitFor(t, "the token after two failures", func() bool {
		raw, err := os.ReadFile(path)
		return err == nil && string(raw) == "tok-1"
	})
}

func TestWriter_AFileSourceReadsWhatItWrites(t *testing.T) {
	e := newTokenEndpoint(t, `{"access_token": "tok-1", "expires_in": 300}`)
	path := inTempDir(t, "token")
	w, _ := newTestWriter(t, e, path)
	if _, err := w.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	s := NewFileSource(path, time.Hour, nil)
	s.read()
	if got := s.Token(); got != "tok-1" {
		t.Errorf("Token() = %q, want %q", got, "tok-1")
	}
}

func TestNewWriter_RefusesAnIncompleteConfig(t *testing.T) {
	valid := WriterConfig{TokenURL: "https://idp.example/token", ClientIDFile: "/etc/secret/username", ClientSecretFile: "/etc/secret/password", Path: "/run/token"}
	tests := []struct {
		name string
		cfg  WriterConfig
	}{
		{"relative token URL", WriterConfig{TokenURL: "/token", ClientIDFile: valid.ClientIDFile, ClientSecretFile: valid.ClientSecretFile, Path: valid.Path}},
		{"token URL that is not http", WriterConfig{TokenURL: "ftp://idp.example/token", ClientIDFile: valid.ClientIDFile, ClientSecretFile: valid.ClientSecretFile, Path: valid.Path}},
		{"token URL without a host", WriterConfig{TokenURL: "https:///token", ClientIDFile: valid.ClientIDFile, ClientSecretFile: valid.ClientSecretFile, Path: valid.Path}},
		{"no client id file", WriterConfig{TokenURL: valid.TokenURL, ClientSecretFile: valid.ClientSecretFile, Path: valid.Path}},
		{"no client secret file", WriterConfig{TokenURL: valid.TokenURL, ClientIDFile: valid.ClientIDFile, Path: valid.Path}},
		{"no token file", WriterConfig{TokenURL: valid.TokenURL, ClientIDFile: valid.ClientIDFile, ClientSecretFile: valid.ClientSecretFile}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewWriter(tt.cfg, nil); err == nil {
				t.Errorf("NewWriter(%+v) error = nil, want an error", tt.cfg)
			}
		})
	}
	if _, err := NewWriter(valid, nil); err != nil {
		t.Errorf("NewWriter(%+v) error = %v, want none", valid, err)
	}
}

func TestNewWriter_DefaultsRenewBeforeToAMinute(t *testing.T) {
	w, err := NewWriter(WriterConfig{TokenURL: "https://idp.example/token", ClientIDFile: "/etc/secret/username", ClientSecretFile: "/etc/secret/password", Path: "/run/token"}, nil)
	if err != nil {
		t.Fatalf("NewWriter() error = %v", err)
	}
	if w.cfg.RenewBefore != DefaultRenewBefore {
		t.Errorf("RenewBefore = %s, want %s", w.cfg.RenewBefore, DefaultRenewBefore)
	}
}

// A token that lives one second is renewed after a second, so Run asks
// again within the test.
func TestWriter_RunRefreshesAgainBeforeTheTokenExpires(t *testing.T) {
	e := newTokenEndpoint(t, `{"access_token": "tok-1", "expires_in": 1}`)
	w, _ := newTestWriter(t, e, inTempDir(t, "token"))
	runInBackground(t, w.Run)
	waitFor(t, "a second token request", func() bool { return e.count() >= 2 })
}

// The secret is posted to TokenURL; a redirect would post it again to
// wherever the response points.
func TestWriter_DoesNotFollowARedirect(t *testing.T) {
	elsewhere := newTokenEndpoint(t, `{"access_token": "tok-1", "expires_in": 300}`)
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.srv.URL+"/token", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirecting.Close)
	w, _ := newTestWriter(t, elsewhere, inTempDir(t, "token"))
	w.cfg.TokenURL = redirecting.URL + "/token"
	if _, err := w.Refresh(context.Background()); err == nil {
		t.Errorf("Refresh() error = nil, want an error for the redirect")
	}
	if got := elsewhere.count(); got != 0 {
		t.Errorf("requests at the redirect target = %d, want 0", got)
	}
}

func TestNextBackoff(t *testing.T) {
	tests := []struct {
		backoff, want time.Duration
	}{
		{2 * time.Second, 4 * time.Second},
		{2 * time.Minute, 4 * time.Minute},
		{4 * time.Minute, maxBackoff},
		{maxBackoff, maxBackoff},
	}
	for _, tt := range tests {
		if got := nextBackoff(tt.backoff); got != tt.want {
			t.Errorf("nextBackoff(%s) = %s, want %s", tt.backoff, got, tt.want)
		}
	}
}

func TestWriter_NeverLogsTheToken(t *testing.T) {
	e := newTokenEndpoint(t, `{"access_token": "tok-secret-1", "expires_in": 300}`)
	w, _ := newTestWriter(t, e, inTempDir(t, "token"))
	log := &recordingLogger{}
	w.log = log
	if _, err := w.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	for _, m := range log.all() {
		if strings.Contains(m, "tok-secret-1") {
			t.Errorf("log message %q carries the token", m)
		}
	}
	if len(log.all()) == 0 {
		t.Errorf("Refresh logged nothing, want the line it writes on success")
	}
}

func TestRenewal(t *testing.T) {
	tests := []struct {
		lifetime, renewBefore, want time.Duration
	}{
		{5 * time.Minute, time.Minute, 4 * time.Minute},
		{100 * time.Second, time.Minute, 50 * time.Second},
		{time.Second, time.Minute, time.Second},
		{time.Second / 2, time.Minute, time.Second},
	}
	for _, tt := range tests {
		if got := renewal(tt.lifetime, tt.renewBefore); got != tt.want {
			t.Errorf("renewal(%s, %s) = %s, want %s", tt.lifetime, tt.renewBefore, got, tt.want)
		}
	}
}
