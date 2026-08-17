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
	"fmt"
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
)

// ── helpers ───────────────────────────────────────────────────────────────

// fakeIdP serves the OIDC discovery document and a JWKS, i.e. the two
// endpoints the provider bootstrap talks to.
func fakeIdP(t *testing.T, jwksJSON string) *httptest.Server {
	t.Helper()

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"issuer":"%s","jwks_uri":"%s/certs"}`, serverURL, serverURL)
		case "/certs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, jwksJSON)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	serverURL = server.URL

	return server
}

// fakeOPA records every data-API request the reloader makes.
type fakeOPA struct {
	*httptest.Server

	mu       sync.Mutex
	requests []opaRequest
	status   int
}

type opaRequest struct {
	method      string
	contentType string
	body        []byte
}

func newFakeOPA(t *testing.T, status int) *fakeOPA {
	t.Helper()

	f := &fakeOPA{status: status}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		f.mu.Lock()
		f.requests = append(f.requests, opaRequest{
			method:      r.Method,
			contentType: r.Header.Get("Content-Type"),
			body:        body,
		})
		current := f.status
		f.mu.Unlock()

		w.WriteHeader(current)
	}))
	t.Cleanup(f.Close)

	return f
}

func (f *fakeOPA) recorded() []opaRequest {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]opaRequest, len(f.requests))
	copy(out, f.requests)

	return out
}

func (f *fakeOPA) setStatus(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = status
}

// reloaderFixture wires a reloader against a temp providers file, a temp authn
// directory and a fake OPA.
type reloaderFixture struct {
	reloader      *ProvidersReloader
	opa           *fakeOPA
	providersFile string
	authnDir      string
	statusFile    string
}

func newReloaderFixture(t *testing.T, initialProviders string, strict bool, opaStatus int) *reloaderFixture {
	t.Helper()

	dir := t.TempDir()
	providersFile := filepath.Join(dir, "trusted-providers.json")
	if err := os.WriteFile(providersFile, []byte(initialProviders), 0o644); err != nil {
		t.Fatalf("write providers file: %v", err)
	}

	authnDir := filepath.Join(dir, "authn")
	statusFile := filepath.Join(dir, "status.json")
	opa := newFakeOPA(t, opaStatus)

	cfg := BootstrapConfig{
		TrustedProvidersFile: providersFile,
		JWKSBootstrapDir:     filepath.Join(authnDir, "jwks"),
		BootstrapRequired:    strict,
		HTTPTimeout:          2 * time.Second,
		HTTPRetries:          1,
		StatusFile:           statusFile,
		Logger:               log.New(os.Stderr, "[test] ", 0),
	}

	return &reloaderFixture{
		reloader:      NewProvidersReloader(cfg, opa.URL+DefaultOPAAuthnDataPath, DefaultProvidersReloadInterval, ""),
		opa:           opa,
		providersFile: providersFile,
		authnDir:      authnDir,
		statusFile:    statusFile,
	}
}

func (f *reloaderFixture) rewriteProviders(t *testing.T, content string) {
	t.Helper()
	if err := os.WriteFile(f.providersFile, []byte(content), 0o644); err != nil {
		t.Fatalf("rewrite providers file: %v", err)
	}
}

// ── tests ─────────────────────────────────────────────────────────────────

// The startup bootstrap has already applied whatever the file said, so an
// untouched file must not cause a single JWKS fetch or OPA write.
func TestReloadOnce_UnchangedFileIsNoOp(t *testing.T) {
	f := newReloaderFixture(t, `{"providers":[]}`, true, http.StatusNoContent)

	changed, err := f.reloader.ReloadOnce(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Error("expected no reload for an unchanged file")
	}
	if got := len(f.opa.recorded()); got != 0 {
		t.Errorf("expected no OPA requests, got %d", got)
	}
}

func TestReloadOnce_PublishesChangedProviders(t *testing.T) {
	idp := fakeIdP(t, `{"keys":[{"kty":"RSA","kid":"k1","n":"abc","e":"AQAB"}]}`)
	f := newReloaderFixture(t, `{"providers":[]}`, true, http.StatusNoContent)

	f.rewriteProviders(t, fmt.Sprintf(
		`{"providers":[{"id":"kc","issuer":"%s","audiences":["app"],"required":true}]}`,
		idp.URL,
	))

	changed, err := f.reloader.ReloadOnce(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatal("expected the changed file to be published")
	}

	// Artifacts on disk, so an OPA restart comes back with the same data.
	for _, name := range []string{"trustedProviders.json", "jwksByKid.json"} {
		if _, err := os.Stat(filepath.Join(f.authnDir, name)); err != nil {
			t.Errorf("expected %s to be written: %v", name, err)
		}
	}

	// One atomic patch carrying both documents.
	requests := f.opa.recorded()
	if len(requests) != 1 {
		t.Fatalf("expected exactly 1 OPA request, got %d", len(requests))
	}
	if requests[0].method != http.MethodPatch {
		t.Errorf("expected PATCH, got %s", requests[0].method)
	}
	if requests[0].contentType != "application/json-patch+json" {
		t.Errorf("unexpected content type %q", requests[0].contentType)
	}

	var ops []map[string]interface{}
	if err := json.Unmarshal(requests[0].body, &ops); err != nil {
		t.Fatalf("patch body is not a JSON array: %v", err)
	}
	paths := map[string]bool{}
	for _, op := range ops {
		paths[fmt.Sprint(op["path"])] = true
	}
	for _, want := range []string{"/trustedProviders", "/jwksByKid"} {
		if !paths[want] {
			t.Errorf("patch is missing an op for %s", want)
		}
	}

	// Health must now describe the new configuration.
	status := readStatus(t, f.statusFile)
	if status.ConfiguredCount != 1 || status.SuccessCount != 1 {
		t.Errorf("expected 1 configured / 1 successful, got %d / %d", status.ConfiguredCount, status.SuccessCount)
	}
}

// A bad edit must not take a serving Pod down: nothing is written, nothing is
// pushed, the bootstrap status (which readiness reads) is left alone.
func TestReloadOnce_UnreachableIssuerKeepsPreviousState(t *testing.T) {
	f := newReloaderFixture(t, `{"providers":[]}`, true, http.StatusNoContent)

	sentinel := filepath.Join(f.authnDir, "jwks.json")
	if err := os.MkdirAll(f.authnDir, 0o755); err != nil {
		t.Fatalf("mkdir authn: %v", err)
	}
	if err := os.WriteFile(sentinel, []byte(`{"jwks":{"previous":{}}}`), 0o644); err != nil {
		t.Fatalf("seed previous jwks: %v", err)
	}

	f.rewriteProviders(t, `{"providers":[{"id":"gone","issuer":"http://127.0.0.1:1/realms/x"}]}`)

	changed, err := f.reloader.ReloadOnce(context.Background())
	if err == nil {
		t.Fatal("expected an error when no provider can be fetched in strict mode")
	}
	if changed {
		t.Error("expected nothing to be published")
	}

	raw, readErr := os.ReadFile(sentinel)
	if readErr != nil {
		t.Fatalf("previous jwks.json disappeared: %v", readErr)
	}
	if string(raw) != `{"jwks":{"previous":{}}}` {
		t.Errorf("previous jwks.json was overwritten: %s", raw)
	}
	if _, err := os.Stat(f.statusFile); !os.IsNotExist(err) {
		t.Error("bootstrap status must not be rewritten by a failed reload")
	}
	if got := len(f.opa.recorded()); got != 0 {
		t.Errorf("expected no OPA requests, got %d", got)
	}
}

// The failed edit must be retried rather than remembered as applied.
func TestReloadOnce_RetriesAfterFailure(t *testing.T) {
	idp := fakeIdP(t, `{"keys":[{"kty":"RSA","kid":"k1","n":"abc","e":"AQAB"}]}`)
	f := newReloaderFixture(t, `{"providers":[]}`, true, http.StatusInternalServerError)

	providers := fmt.Sprintf(
		`{"providers":[{"id":"kc","issuer":"%s","audiences":["app"]}]}`,
		idp.URL,
	)
	f.rewriteProviders(t, providers)

	if _, err := f.reloader.ReloadOnce(context.Background()); err == nil {
		t.Fatal("expected an error when OPA rejects the update")
	}

	f.opa.setStatus(http.StatusNoContent)

	changed, err := f.reloader.ReloadOnce(context.Background())
	if err != nil {
		t.Fatalf("unexpected error on retry: %v", err)
	}
	if !changed {
		t.Error("expected the same edit to be retried and published")
	}
}

// Emptying the list is a legitimate configuration ("trust nobody"), not a
// failure — it publishes and clears the artifacts.
func TestReloadOnce_EmptyListClearsArtifacts(t *testing.T) {
	idp := fakeIdP(t, `{"keys":[{"kty":"RSA","kid":"k1","n":"abc","e":"AQAB"}]}`)
	initial := fmt.Sprintf(
		`{"providers":[{"id":"kc","issuer":"%s"}]}`,
		idp.URL,
	)
	f := newReloaderFixture(t, initial, true, http.StatusNoContent)

	// Publish the provider first so there is something to clear.
	f.rewriteProviders(t, initial+"\n")
	if _, err := f.reloader.ReloadOnce(context.Background()); err != nil {
		t.Fatalf("seed reload failed: %v", err)
	}

	f.rewriteProviders(t, `{"providers":[]}`)
	changed, err := f.reloader.ReloadOnce(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatal("expected the empty list to be published")
	}

	if _, err := os.Stat(filepath.Join(f.authnDir, "jwks.json")); !os.IsNotExist(err) {
		t.Error("expected jwks.json to be removed for an empty provider list")
	}
}

// OPA answers 404 to a patch when data.authn does not exist yet; the whole
// subtree is then written with a PUT.
func TestPushToOPA_FallsBackToPutWhenAuthnMissing(t *testing.T) {
	idp := fakeIdP(t, `{"keys":[{"kty":"RSA","kid":"k1","n":"abc","e":"AQAB"}]}`)
	f := newReloaderFixture(t, `{"providers":[]}`, true, http.StatusNotFound)

	f.rewriteProviders(t, fmt.Sprintf(
		`{"providers":[{"id":"kc","issuer":"%s"}]}`,
		idp.URL,
	))

	if _, err := f.reloader.ReloadOnce(context.Background()); err == nil {
		t.Fatal("expected an error: the fake OPA answers 404 to the PUT as well")
	}

	requests := f.opa.recorded()
	if len(requests) != 2 {
		t.Fatalf("expected a PATCH followed by a PUT, got %d requests", len(requests))
	}
	if requests[0].method != http.MethodPatch || requests[1].method != http.MethodPut {
		t.Errorf("unexpected method sequence: %s, %s", requests[0].method, requests[1].method)
	}

	var full map[string]interface{}
	if err := json.Unmarshal(requests[1].body, &full); err != nil {
		t.Fatalf("PUT body is not an object: %v", err)
	}
	for _, key := range []string{"trustedProviders", "jwksByKid"} {
		if _, ok := full[key]; !ok {
			t.Errorf("PUT body is missing %s", key)
		}
	}
}

// A reload that satisfies the permissive count threshold but leaves a
// `required` provider down must publish nothing. Before the gate existed it
// published the keys AND wrote a status that immediately took the Pod out of
// the Service — the exact opposite of the documented failure policy, which
// promises a bad edit never flips a serving Pod to NotReady.
func TestReloadOnce_MissingRequiredProviderIsNotPublished(t *testing.T) {
	idp := fakeIdP(t, `{"keys":[{"kty":"RSA","alg":"RS256","kid":"k1","n":"abc","e":"AQAB"}]}`)
	f := newReloaderFixture(t, `{"providers":[]}`, false, http.StatusNoContent)

	f.rewriteProviders(t, fmt.Sprintf(
		`{"providers":[
			{"id":"cloud-common","issuer":"http://127.0.0.1:1/realms/down","required":true},
			{"id":"external","issuer":"%s"}
		]}`, idp.URL))

	changed, err := f.reloader.ReloadOnce(context.Background())
	if err == nil {
		t.Fatal("expected the reload to be refused while a required provider is down")
	}
	if changed {
		t.Error("nothing may be published when a required provider failed")
	}
	if !strings.Contains(err.Error(), "cloud-common") {
		t.Errorf("the error should name the required provider, got: %v", err)
	}
	if len(f.opa.recorded()) != 0 {
		t.Errorf("OPA must not be written to, got %d request(s)", len(f.opa.recorded()))
	}
	if _, statErr := os.Stat(f.statusFile); statErr == nil {
		t.Error("the bootstrap status must be left alone so readiness does not flip")
	}
}
