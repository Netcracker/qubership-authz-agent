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

package m2m

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type store struct {
	mu     sync.Mutex
	tokens []string
}

func (s *store) Put(_ context.Context, path []string, value any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !reflect.DeepEqual(path, []string{"m2m"}) {
		return fmt.Errorf("unexpected path %v", path)
	}
	s.tokens = append(s.tokens, value.(map[string]any)["bearerToken"].(string))
	return nil
}

func (s *store) published() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.tokens...)
}

type quiet struct{}

func (quiet) Infof(string, ...any) {}
func (quiet) Warnf(string, ...any) {}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// waitFor polls cond for up to two seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out after 2s waiting for %s", what)
}

// TestClientCredentials_PublishesTheToken: the grant is posted with the id
// and secret read from their files, and the token comes back through Token
// and as data.m2m.bearerToken.
func TestClientCredentials_PublishesTheToken(t *testing.T) {
	var form map[string][]string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		form = r.PostForm
		_, _ = w.Write([]byte(`{"access_token":"tok1","expires_in":300}`))
	}))
	defer idp.Close()
	st := &store{}
	src := New(Config{
		TokenURL:         idp.URL + "/token",
		ClientIDFile:     writeFile(t, "username", "agent\n"),
		ClientSecretFile: writeFile(t, "password", "s3cret"),
	}, st, quiet{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go src.Run(ctx)

	select {
	case <-src.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("no token within 2s")
	}
	if got := src.Token(); got != "tok1" {
		t.Errorf("Token() = %q, want tok1", got)
	}
	if got := st.published(); !reflect.DeepEqual(got, []string{"tok1"}) {
		t.Errorf("published %v, want [tok1]", got)
	}
	want := map[string][]string{"grant_type": {"client_credentials"}, "client_id": {"agent"}, "client_secret": {"s3cret"}}
	if !reflect.DeepEqual(form, want) {
		t.Errorf("grant form = %v, want %v", form, want)
	}
}

// TestClientCredentials_RefreshesBeforeExpiry: a token that lives two
// seconds and is renewed one second before its expiry is fetched again
// within that second, and the new token replaces the old one.
func TestClientCredentials_RefreshesBeforeExpiry(t *testing.T) {
	var fetches int
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches++
		_, _ = fmt.Fprintf(w, `{"access_token":"tok%d","expires_in":2}`, fetches)
	}))
	defer idp.Close()
	st := &store{}
	src := New(Config{TokenURL: idp.URL, ClientIDFile: writeFile(t, "id", "a"), ClientSecretFile: writeFile(t, "secret", "b"), RenewBefore: time.Second}, st, quiet{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go src.Run(ctx)

	waitFor(t, "the first token", func() bool { return src.Token() == "tok1" })
	waitFor(t, "the refreshed token", func() bool { return src.Token() == "tok2" })
	if got := st.published(); !reflect.DeepEqual(got, []string{"tok1", "tok2"}) {
		t.Errorf("published %v, want [tok1 tok2]", got)
	}
}

// TestClientCredentials_RetriesAfterAFailure: a fetch the provider refuses
// is retried, and the token arrives once the provider answers.
func TestClientCredentials_RetriesAfterAFailure(t *testing.T) {
	var fetches int
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches++
		if fetches == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
	}))
	defer idp.Close()
	st := &store{}
	src := New(Config{TokenURL: idp.URL, ClientIDFile: writeFile(t, "id", "a"), ClientSecretFile: writeFile(t, "secret", "b")}, st, quiet{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go src.Run(ctx)

	deadline := time.Now().Add(initialBackoff + 2*time.Second)
	for time.Now().Before(deadline) && src.Token() == "" {
		time.Sleep(20 * time.Millisecond)
	}
	if got := src.Token(); got != "tok" || fetches != 2 {
		t.Errorf("Token() = %q after %d fetches, want tok after the retry", got, fetches)
	}
}

func TestRenewal(t *testing.T) {
	cases := []struct {
		name                  string
		lifetime, renewBefore time.Duration
		want                  time.Duration
	}{
		{"the margin before expiry", 300 * time.Second, 60 * time.Second, 240 * time.Second},
		{"no later than half the lifetime", 100 * time.Second, 60 * time.Second, 50 * time.Second},
		{"never sooner than one second", time.Second, 60 * time.Second, time.Second},
		{"at the expiry when RenewBefore is zero", 300 * time.Second, 0, 300 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := renewal(tc.lifetime, tc.renewBefore); got != tc.want {
				t.Errorf("renewal(%s, %s) = %s, want %s", tc.lifetime, tc.renewBefore, got, tc.want)
			}
		})
	}
}

func jwt(claims string) string {
	return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".sig"
}

func TestFetchToken(t *testing.T) {
	future := time.Now().Add(90 * time.Second).Unix()
	cases := []struct {
		name     string
		status   int
		body     string
		token    string
		lifetime time.Duration
		err      string
	}{
		{"expires_in is the lifetime", 200, `{"access_token":"t","expires_in":120}`, "t", 120 * time.Second, ""},
		{"expires_in as a decimal", 200, `{"access_token":"t","expires_in":1.5}`, "t", 1500 * time.Millisecond, ""},
		{"exp of the token when expires_in is absent", 200, fmt.Sprintf(`{"access_token":%q}`, jwt(fmt.Sprintf(`{"exp":%d}`, future))), jwt(fmt.Sprintf(`{"exp":%d}`, future)), 0, ""},
		{"exp in the past", 200, fmt.Sprintf(`{"access_token":%q}`, jwt(`{"exp":1}`)), "", 0, "JWT exp is in the past"},
		{"no exp and no expires_in", 200, fmt.Sprintf(`{"access_token":%q}`, jwt(`{}`)), "", 0, "exp claim absent"},
		{"an empty token", 200, `{"access_token":""}`, "", 0, "empty access_token"},
		{"a body that is not JSON", 200, `nope`, "", 0, "parse token response"},
		{"a refusal", 401, `{"error":"invalid_client"}`, "", 0, "HTTP 401"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer idp.Close()
			token, lifetime, err := fetchToken(context.Background(), idp.Client(), idp.URL, "id", "secret")
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("fetchToken() error = %v, want it to contain %q", err, tc.err)
				}
				return
			}
			if err != nil || token != tc.token {
				t.Fatalf("fetchToken() = %q, %v; want %q", token, err, tc.token)
			}
			if tc.lifetime != 0 && lifetime != tc.lifetime {
				t.Errorf("lifetime = %s, want %s", lifetime, tc.lifetime)
			}
			if tc.lifetime == 0 && (lifetime < 80*time.Second || lifetime > 90*time.Second) {
				t.Errorf("lifetime from exp = %s, want about 90s", lifetime)
			}
		})
	}
}

// TestFile_PublishesEachChange: the file's content is published when it
// appears and whenever it changes, and not otherwise.
func TestFile_PublishesEachChange(t *testing.T) {
	file := filepath.Join(t.TempDir(), "token")
	st := &store{}
	src := New(Config{TokenFile: file, WatchInterval: 20 * time.Millisecond}, st, quiet{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go src.Run(ctx)

	time.Sleep(60 * time.Millisecond)
	if got := src.Token(); got != "" || len(st.published()) != 0 {
		t.Fatalf("before the file exists: Token() = %q and %d published, want none", got, len(st.published()))
	}
	if err := os.WriteFile(file, []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first token", func() bool { return src.Token() == "a" })
	if err := os.WriteFile(file, []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the changed token", func() bool { return src.Token() == "b" })
	time.Sleep(60 * time.Millisecond)
	if got := st.published(); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("published %v, want [a b], once per change", got)
	}
	select {
	case <-src.Ready():
	default:
		t.Error("Ready() is not closed after the first token")
	}
}

func TestJWTExpiry(t *testing.T) {
	cases := []struct {
		name, token string
		want        int64
		err         string
	}{
		{"a token with exp", jwt(`{"exp":1700000000}`), 1700000000, ""},
		{"not a JWT", "abc", 0, "too few parts"},
		{"a payload that is not base64url", "a.@@@.c", 0, "decode JWT payload"},
		{"no exp claim", jwt(`{"sub":"x"}`), 0, "exp claim absent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := jwtExpiry(tc.token)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Errorf("jwtExpiry(%q) error = %v, want it to contain %q", tc.token, err, tc.err)
				}
				return
			}
			if err != nil || got.Unix() != tc.want {
				t.Errorf("jwtExpiry(%q) = %v, %v; want exp %d", tc.token, got, err, tc.want)
			}
		})
	}
}
