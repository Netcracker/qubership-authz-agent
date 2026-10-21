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
	"encoding/base64"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// tokenEndpoint is a fake token endpoint. It records the path, the form,
// and the Authorization header of the last request and counts the
// requests. It answers the first failures requests with 503 and every later
// one with status and body.
type tokenEndpoint struct {
	srv *httptest.Server

	mu       sync.Mutex
	status   int
	body     string
	failures int
	lastPath string
	lastForm url.Values
	lastAuth string
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
		e.lastAuth = r.Header.Get("Authorization")
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

func (e *tokenEndpoint) authorization() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastAuth
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
	if got := e.authorization(); got != "" {
		t.Errorf("token request Authorization = %q, want none", got)
	}
}

// The id and the secret hold characters that form encoding changes, a colon
// among them, which would split the header in the wrong place; the Writer
// encodes both values, as RFC 6749, section 2.3.1, requires.
func TestWriter_SendsTheCredentialsInABasicHeaderWhenAsked(t *testing.T) {
	e := newTokenEndpoint(t, `{"access_token": "tok-1", "expires_in": 300}`)
	w, secretFile := newTestWriter(t, e, inTempDir(t, "token"))
	writeFile(t, filepath.Join(filepath.Dir(secretFile), "username"), "agent:1\n")
	writeFile(t, secretFile, "p@ss word:1\n")
	w.cfg.BasicAuth = true

	if _, err := w.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("agent%3A1:p%40ss+word%3A1"))
	if got := e.authorization(); got != want {
		t.Errorf("token request Authorization = %q, want %q", got, want)
	}
	if got, want := e.form().Encode(), "grant_type=client_credentials"; got != want {
		t.Errorf("token request form = %s, want %s", got, want)
	}
}

func TestWriter_ReportsTheErrorTheProviderNames(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"error with a description", `{"error": "invalid_client", "error_description": "Invalid client credentials"}`,
			`HTTP 401, error "invalid_client": "Invalid client credentials"`},
		{"error without a description", `{"error": "invalid_client"}`, `HTTP 401, error "invalid_client"`},
		{"description with a line break", `{"error": "invalid_request", "error_description": "line one\nline two"}`,
			`HTTP 401, error "invalid_request": "line one\nline two"`},
		{"error of 65 runes", `{"error": "` + strings.Repeat("e", 65) + `"}`,
			`HTTP 401, error "` + strings.Repeat("e", 64) + `"...`},
		{"description of 201 runes", `{"error": "invalid_request", "error_description": "` + strings.Repeat("d", 201) + `"}`,
			`HTTP 401, error "invalid_request": "` + strings.Repeat("d", 200) + `"...`},
		{"JSON that is not an OAuth error", `{"message": "Unauthorized"}`, `HTTP 401`},
		{"body that is not JSON", `<html>Unauthorized</html>`, `HTTP 401`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newTokenEndpoint(t, tt.body)
			e.status = http.StatusUnauthorized
			w, _ := newTestWriter(t, e, inTempDir(t, "token"))
			_, err := w.Refresh(context.Background())
			if err == nil || !strings.HasSuffix(err.Error(), tt.want) {
				t.Errorf("Refresh() error = %v, want one that ends with %s", err, tt.want)
			}
		})
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

// A lifetime longer than a Duration can hold, about 292 years, is reported
// as the longest Duration, whichever part of the response gives it.
func TestWriter_ALifetimeBeyondADurationIsTheLongestDuration(t *testing.T) {
	tests := []struct {
		name, body string
	}{
		{"expires_in of 1e10 seconds", `{"access_token": "tok-1", "expires_in": 1e10}`},
		{"exp claim of 1e300", `{"access_token": "` + unsignedJWT(t, map[string]any{"sub": "authz-agent", "exp": 1e300}) + `"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newTokenEndpoint(t, tt.body)
			w, _ := newTestWriter(t, e, inTempDir(t, "token"))
			lifetime, err := w.Refresh(context.Background())
			if err != nil {
				t.Fatalf("Refresh() error = %v", err)
			}
			if lifetime != math.MaxInt64 {
				t.Errorf("Refresh() lifetime = %s, want %s", lifetime, time.Duration(math.MaxInt64))
			}
		})
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

// A token that lives one second is renewed after a second, so Run asks
// again within the test.
func TestWriter_RunRefreshesAgainBeforeTheTokenExpires(t *testing.T) {
	e := newTokenEndpoint(t, `{"access_token": "tok-1", "expires_in": 1}`)
	w, _ := newTestWriter(t, e, inTempDir(t, "token"))
	runInBackground(t, w.Run)
	waitFor(t, "a second token request", func() bool { return e.count() >= 2 })
}

func TestWriter_RunWaits70PercentOfTheLifetimeBeforeTheNextRequest(t *testing.T) {
	e := newTokenEndpoint(t, `{"access_token": "tok-1", "expires_in": 300}`)
	w, _ := newTestWriter(t, e, inTempDir(t, "token"))
	var pauses []time.Duration
	w.wait = func(_ context.Context, d time.Duration) bool {
		pauses = append(pauses, d)
		return false
	}
	w.Run(context.Background())
	if len(pauses) != 1 || pauses[0] != 210*time.Second {
		t.Errorf("Run paused %v after a token that lives 5m0s, want [3m30s]", pauses)
	}
}

func TestWriter_RunDoublesThePauseAfterEachFailedAttempt(t *testing.T) {
	e := newTokenEndpoint(t, `{"access_token": "tok-1", "expires_in": 300}`)
	e.failures = 2
	w, _ := newTestWriter(t, e, inTempDir(t, "token"))
	var pauses []time.Duration
	w.wait = func(_ context.Context, d time.Duration) bool {
		pauses = append(pauses, d)
		return len(pauses) < 2
	}
	w.Run(context.Background())
	want := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond}
	if !slices.Equal(pauses, want) {
		t.Errorf("Run paused %v after two failed attempts, want %v", pauses, want)
	}
}

// The endpoint fails once, answers, and then fails once more.
func TestWriter_RunStartsThePausesOverAfterASuccess(t *testing.T) {
	e := newTokenEndpoint(t, `{"access_token": "tok-1", "expires_in": 300}`)
	e.failures = 1
	w, _ := newTestWriter(t, e, inTempDir(t, "token"))
	var pauses []time.Duration
	w.wait = func(_ context.Context, d time.Duration) bool {
		pauses = append(pauses, d)
		if len(pauses) == 2 {
			e.mu.Lock()
			e.failures = 1
			e.mu.Unlock()
		}
		return len(pauses) < 3
	}
	w.Run(context.Background())
	want := []time.Duration{10 * time.Millisecond, 210 * time.Second, 10 * time.Millisecond}
	if !slices.Equal(pauses, want) {
		t.Errorf("Run paused %v, want %v", pauses, want)
	}
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
		lifetime, want time.Duration
	}{
		{5 * time.Minute, 210 * time.Second},
		{2 * time.Second, 1400 * time.Millisecond},
		{time.Second, time.Second},
		// Fifty years: seven times this lifetime overflows a Duration.
		{438000 * time.Hour, 306600 * time.Hour},
	}
	for _, tt := range tests {
		if got := renewal(tt.lifetime); got != tt.want {
			t.Errorf("renewal(%s) = %s, want %s", tt.lifetime, got, tt.want)
		}
	}
}

func TestFromSeconds(t *testing.T) {
	tests := []struct {
		seconds float64
		want    time.Duration
	}{
		{300, 300 * time.Second},
		{0.25, 250 * time.Millisecond},
		{-60, -time.Minute},
		{9223372036, 9223372036 * time.Second},
		// In float64 arithmetic this count is 2^63 nanoseconds, the first
		// count that does not fit.
		{9223372036.854776, math.MaxInt64},
	}
	for _, tt := range tests {
		if got := fromSeconds(tt.seconds); got != tt.want {
			t.Errorf("fromSeconds(%v) = %s, want %s", tt.seconds, got, tt.want)
		}
	}
}

// waitSignals wraps w.wait so that each wait of Run first sends on the
// returned channel. A Renew sent after that reaches the wait, rather than
// the drain that ends a token request.
func waitSignals(w *Writer) <-chan struct{} {
	waiting := make(chan struct{}, 4)
	w.wait = func(ctx context.Context, d time.Duration) bool {
		waiting <- struct{}{}
		return w.sleep(ctx, d)
	}
	return waiting
}

func TestWriter_RenewMakesRunRequestATokenAtOnce(t *testing.T) {
	e := newTokenEndpoint(t, `{"access_token": "tok-1", "expires_in": 300}`)
	w, _ := newTestWriter(t, e, inTempDir(t, "token"))
	c := newClock()
	w.now = c.Now
	written := make(chan struct{}, 2)
	w.cfg.Written = func() { written <- struct{}{} }
	waiting := waitSignals(w)
	runInBackground(t, w.Run)
	receive(t, written, "the first token")
	receive(t, waiting, "Run to wait after the first token")
	c.advance(30 * time.Second)
	w.Renew()
	receive(t, written, "the token Renew asked for")
	if got := e.count(); got != 2 {
		t.Errorf("token requests = %d, want 2", got)
	}
}

func TestWriter_RenewWaitsUntilTheTokenIs30SecondsOld(t *testing.T) {
	tests := []struct {
		name string
		age  time.Duration
		want int
	}{
		{"29 seconds old", 29 * time.Second, 0},
		{"30 seconds old", 30 * time.Second, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newTokenEndpoint(t, `{"access_token": "tok-1", "expires_in": 300}`)
			w, _ := newTestWriter(t, e, inTempDir(t, "token"))
			c := newClock()
			w.now = c.Now
			if _, err := w.Refresh(context.Background()); err != nil {
				t.Fatalf("Refresh() error = %v", err)
			}
			c.advance(tt.age)
			w.Renew()
			if got := len(w.renew); got != tt.want {
				t.Errorf("pending renewals after Renew of a token %s old = %d, want %d", tt.age, got, tt.want)
			}
		})
	}
}

// The identity provider fails every request. The wait here does not take
// Renew's requests, so a pending one stays visible until the next attempt
// drains it.
func TestWriter_RenewCountsAFailedRequestToo(t *testing.T) {
	e := newTokenEndpoint(t, `{"access_token": "tok-1", "expires_in": 300}`)
	e.failures = 1000
	w, _ := newTestWriter(t, e, inTempDir(t, "token"))
	c := newClock()
	w.now = c.Now
	waiting := make(chan struct{}, 4)
	proceed := make(chan struct{})
	w.wait = func(ctx context.Context, _ time.Duration) bool {
		waiting <- struct{}{}
		select {
		case <-proceed:
			return true
		case <-ctx.Done():
			return false
		}
	}
	runInBackground(t, w.Run)
	receive(t, waiting, "Run to wait after the first failure")
	c.advance(30 * time.Second)
	w.Renew()
	proceed <- struct{}{}
	receive(t, waiting, "Run to wait after the second failure")
	w.Renew()
	if got := len(w.renew); got != 0 {
		t.Errorf("pending renewals after a Renew right after a failed request = %d, want 0", got)
	}
	if got := e.count(); got != 2 {
		t.Errorf("token requests = %d, want 2", got)
	}
}

// The pending renewal stands for a Renew that came while Run was requesting
// a token: the token it asked to replace is the one just replaced.
func TestWriter_RunDropsARenewThatCameDuringTheRequest(t *testing.T) {
	e := newTokenEndpoint(t, `{"access_token": "tok-1", "expires_in": 300}`)
	w, _ := newTestWriter(t, e, inTempDir(t, "token"))
	w.renew <- struct{}{}
	w.wait = func(context.Context, time.Duration) bool { return false }
	w.Run(context.Background())
	if got := len(w.renew); got != 0 {
		t.Errorf("pending renewals after the request = %d, want 0", got)
	}
}

func TestWriter_RunsWrittenAfterEachTokenItWrites(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   int
	}{
		{"token obtained", http.StatusOK, 1},
		{"request refused", http.StatusUnauthorized, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newTokenEndpoint(t, `{"access_token": "tok-1", "expires_in": 300}`)
			e.status = tt.status
			w, _ := newTestWriter(t, e, inTempDir(t, "token"))
			var calls int
			w.cfg.Written = func() { calls++ }
			_, _ = w.Refresh(context.Background())
			if calls != tt.want {
				t.Errorf("Written calls = %d, want %d", calls, tt.want)
			}
		})
	}
}
