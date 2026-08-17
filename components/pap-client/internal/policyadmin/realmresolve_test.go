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
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const probeRealmUUID = "44b43b97-db5b-48ab-ad58-365d37920bc0"

// fakeTenantManager answers the one endpoint the resolver uses, with the shape
// the real service uses: the identifier as a bare text body, 404 for a name it
// does not know.
func fakeTenantManager(t *testing.T, names map[string]string, calls *int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			atomic.AddInt32(calls, 1)
		}
		if r.URL.Path != tenantLookupPath {
			http.NotFound(w, r)
			return
		}
		id, ok := names[r.URL.Query().Get("dns")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = fmt.Fprint(w, id)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testResolver(t *testing.T, baseURL string) *realmResolver {
	t.Helper()
	return newRealmResolver(baseURL, &http.Client{Timeout: 2 * time.Second}, log.New(os.Stderr, "[test] ", 0))
}

func TestRealmResolver_ResolvesDisplayName(t *testing.T) {
	tm := fakeTenantManager(t, map[string]string{"default": probeRealmUUID}, nil)
	r := testResolver(t, tm.URL)

	got, ok := r.resolve("default")
	if !ok || got != probeRealmUUID {
		t.Fatalf("expected %q, got %q (ok=%v)", probeRealmUUID, got, ok)
	}
}

// A platform realm like cloud-common is a realm in its own right, not a tenant.
// tenant-manager answers 404 and the configured name must be used as-is — the
// ordinary case, not an error.
func TestRealmResolver_UnknownNameIsNotAnError(t *testing.T) {
	tm := fakeTenantManager(t, map[string]string{"default": probeRealmUUID}, nil)
	r := testResolver(t, tm.URL)

	if got, ok := r.resolve("cloud-common"); ok {
		t.Fatalf("expected no resolution for a non-tenant realm, got %q", got)
	}
}

// tenant-manager is another service; its answer is input, not truth. A body
// that is not a usable realm name must not reach a URL.
func TestRealmResolver_RejectsUnusableAnswer(t *testing.T) {
	for _, answer := range []string{
		"../../etc/passwd",
		"has space",
		"a/b",
		"<html>404 not found</html>",
		strings.Repeat("x", 129),
	} {
		t.Run(answer[:min(len(answer), 20)], func(t *testing.T) {
			tm := fakeTenantManager(t, map[string]string{"default": answer}, nil)
			r := testResolver(t, tm.URL)

			if got, ok := r.resolve("default"); ok {
				t.Fatalf("answer %q must be rejected, got %q", answer, got)
			}
		})
	}
}

// An unreachable tenant-manager must degrade to "use the configured name",
// never to a failed provider.
func TestRealmResolver_UnreachableIsNotFatal(t *testing.T) {
	r := testResolver(t, "http://127.0.0.1:1")

	if _, ok := r.resolve("default"); ok {
		t.Fatal("expected no resolution when tenant-manager is unreachable")
	}
}

func TestRealmResolver_DisabledWhenURLEmpty(t *testing.T) {
	if r := newRealmResolver("", http.DefaultClient, log.New(os.Stderr, "", 0)); r != nil {
		t.Fatal("an empty tenant-manager URL must disable resolution entirely")
	}
	// A nil resolver is the disabled state and must be safe to call.
	var nilResolver *realmResolver
	if _, ok := nilResolver.resolve("default"); ok {
		t.Fatal("nil resolver must not resolve")
	}
	if issuer, ok := nilResolver.resolveIssuer("http://idp:8080/auth/realms/default"); ok || issuer != "http://idp:8080/auth/realms/default" {
		t.Fatal("nil resolver must return the issuer untouched")
	}
}

// Both the bootstrap and every reload tick walk the same provider list; asking
// again each time would put avoidable load on tenant-manager.
func TestRealmResolver_CachesBothOutcomes(t *testing.T) {
	var calls int32
	tm := fakeTenantManager(t, map[string]string{"default": probeRealmUUID}, &calls)
	r := testResolver(t, tm.URL)

	for i := 0; i < 3; i++ {
		r.resolve("default")
		r.resolve("cloud-common")
	}

	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("expected one call per distinct name (2), got %d", got)
	}
}

func TestRealmResolver_ResolveIssuerRewritesOnlyTheRealmSegment(t *testing.T) {
	tm := fakeTenantManager(t, map[string]string{"default": probeRealmUUID}, nil)
	r := testResolver(t, tm.URL)

	got, ok := r.resolveIssuer("https://idp.example:8443/auth/realms/default")
	want := "https://idp.example:8443/auth/realms/" + probeRealmUUID
	if !ok || got != want {
		t.Fatalf("expected %q, got %q (ok=%v)", want, got, ok)
	}

	// Host and path prefix are configuration and must survive verbatim.
	if !strings.HasPrefix(got, "https://idp.example:8443/auth/realms/") {
		t.Errorf("resolver rewrote more than the realm segment: %q", got)
	}
}

func TestRealmResolver_ResolveIssuerLeavesUnresolvableAlone(t *testing.T) {
	tm := fakeTenantManager(t, map[string]string{"default": probeRealmUUID}, nil)
	r := testResolver(t, tm.URL)

	for _, issuer := range []string{
		"http://idp:8080/auth/realms/cloud-common", // not a tenant
		"http://idp:8080/auth/realms/",             // no segment
		"noslash",
	} {
		if got, ok := r.resolveIssuer(issuer); ok || got != issuer {
			t.Errorf("issuer %q must be left alone, got %q (ok=%v)", issuer, got, ok)
		}
	}
}

// End to end through RunBootstrap: a provider whose realm is a display name
// bootstraps because the resolver finds the real realm behind it.
func TestRunBootstrap_ResolvesRealmDisplayName(t *testing.T) {
	var idp *httptest.Server
	idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		// Only the UUID realm exists; `/auth/realms/default` is a 404, exactly
		// as on a real Keycloak.
		case "/auth/realms/" + probeRealmUUID + "/.well-known/openid-configuration":
			_, _ = fmt.Fprintf(w, `{"issuer":"%s/auth/realms/%s","jwks_uri":"%s/certs"}`, idp.URL, probeRealmUUID, idp.URL)
		case "/certs":
			_, _ = fmt.Fprint(w, `{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"k1","n":"abc","e":"AQAB"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idp.Close)

	tm := fakeTenantManager(t, map[string]string{"default": probeRealmUUID}, nil)

	dir := t.TempDir()
	providersFile := writeTempFile(t, []byte(fmt.Sprintf(
		`{"providers":[{"id":"default","issuer":"%s/auth/realms/default"}]}`, idp.URL)))
	statusFile := filepath.Join(dir, "status.json")

	RunBootstrap(BootstrapConfig{
		TrustedProvidersFile: providersFile,
		JWKSBootstrapDir:     filepath.Join(dir, "authn", "jwks"),
		BootstrapRequired:    false,
		HTTPTimeout:          2 * time.Second,
		HTTPRetries:          1,
		StatusFile:           statusFile,
		TenantManagerURL:     tm.URL,
		Logger:               log.New(os.Stderr, "[test] ", 0),
	})

	status := readStatus(t, statusFile)
	if status.SuccessCount != 1 {
		t.Fatalf("provider addressed by display name should have bootstrapped, got %+v", status.Providers)
	}
	// The published provider keeps the id the operator wrote — resolution
	// changes where keys are fetched from, not what the provider is called.
	if len(status.Providers) != 1 || status.Providers[0].ID != "default" {
		t.Errorf("expected the configured provider id to survive resolution, got %+v", status.Providers)
	}
}

// Without a tenant-manager the same configuration simply fails that provider,
// with the original discovery URL in the message rather than a resolver error.
func TestRunBootstrap_UnresolvableRealmFailsWithTheConfiguredURL(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(idp.Close)

	dir := t.TempDir()
	providersFile := writeTempFile(t, []byte(fmt.Sprintf(
		`{"providers":[{"id":"default","issuer":"%s/auth/realms/default"}]}`, idp.URL)))
	statusFile := filepath.Join(dir, "status.json")

	RunBootstrap(BootstrapConfig{
		TrustedProvidersFile: providersFile,
		JWKSBootstrapDir:     filepath.Join(dir, "authn", "jwks"),
		BootstrapRequired:    false,
		HTTPTimeout:          2 * time.Second,
		HTTPRetries:          1,
		StatusFile:           statusFile,
		TenantManagerURL:     "", // resolution disabled
		Logger:               log.New(os.Stderr, "[test] ", 0),
	})

	status := readStatus(t, statusFile)
	if status.FailureCount != 1 {
		t.Fatalf("expected the provider to fail, got %+v", status.Providers)
	}
	if want := "/auth/realms/default/"; !strings.Contains(status.Providers[0].FailureReason, want) {
		t.Errorf("failure should name the configured URL, got %q", status.Providers[0].FailureReason)
	}
}

// The name is a URL query value and must be escaped, not concatenated.
func TestRealmResolver_EscapesTheQueriedName(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Query().Get("dns")
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	r := testResolver(t, srv.URL)
	r.resolve("a b&c=d")

	if seen != "a b&c=d" {
		t.Errorf("name must arrive intact as a single query value, got %q", seen)
	}
	if _, err := url.Parse(srv.URL + tenantLookupPath + "?dns=" + url.QueryEscape("a b&c=d")); err != nil {
		t.Errorf("escaped URL must parse: %v", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
