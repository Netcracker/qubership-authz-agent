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

package keys

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Both providers publish the kid "shared", so only the issuer tells the two
// keys apart.
func TestLookup_FindsTheKeyOfTheIssuerThatTheQueryNames(t *testing.T) {
	a := newIdP(t, ecJWK(t, "shared", nil))
	b := newIdP(t, ecJWK(t, "shared", nil))
	providerA, providerB := issuer("a", a), issuer("b", b)
	set := mustLoad(t, testOptions(), providerA, providerB)
	for _, p := range []Provider{providerA, providerB} {
		key, err := set.Lookup(Query{Issuer: p.Issuer, KID: "shared"})
		if err != nil {
			t.Errorf("Lookup(issuer of %q) error = %v", p.ID, err)
			continue
		}
		if key.Source.Provider == nil || key.Source.Provider.ID != p.ID || key.Source.Realm != "" {
			t.Errorf("Lookup(issuer of %q).Source = %+v, want the provider %q", p.ID, key.Source, p.ID)
		}
	}
}

func TestRefresh_JWKSURISkipsDiscovery(t *testing.T) {
	idp := newIdP(t, ecJWK(t, "k1", nil))
	provider := direct("k8s", idp)
	set := mustLoad(t, testOptions(), provider)
	if !loaded(set, provider, "k1") {
		t.Errorf("Lookup(%q) found nothing, want the key served at jwksUri", "k1")
	}
	if got := idp.discoveries(); got != 0 {
		t.Errorf("discovery requests = %d, want 0", got)
	}
}

// Each case comes first in a JWKS whose next key is usable, so a provider
// that loaded nothing, or stopped at the skipped key, fails the control
// instead of passing the case.
func TestRefresh_SkipsAKeyThatCannotSignAnAcceptedToken(t *testing.T) {
	tests := []struct {
		name string
		key  json.RawMessage
	}{
		{"encryption key", ecJWK(t, "case", map[string]any{"use": "enc"})},
		{"symmetric key", json.RawMessage(`{"kty": "oct", "kid": "case", "k": "c2VjcmV0"}`)},
		{"HMAC algorithm", ecJWK(t, "case", map[string]any{"alg": "HS256"})},
		{"algorithm none", ecJWK(t, "case", map[string]any{"alg": "none"})},
		{"algorithm of another key type", ecJWK(t, "case", map[string]any{"alg": "RS256"})},
		{"algorithm of another curve", ecJWK(t, "case", map[string]any{"alg": "ES384"})},
		{"OKP key on X25519", x25519JWK(t, "case")},
		{"RSA modulus of 1024 bits", rsaJWK(t, 1024, "case", nil)},
		{"RSA key without a modulus", json.RawMessage(`{"kty": "RSA", "kid": "case", "e": "AQAB"}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := issuer("realm", newIdP(t, tt.key, ecJWK(t, "control", nil)))
			set := mustLoad(t, testOptions(), provider)
			if loaded(set, provider, "case") {
				t.Errorf("Lookup(%q) found a key, want it skipped", "case")
			}
			if !loaded(set, provider, "control") {
				t.Errorf("Lookup(%q) found nothing, want the usable key", "control")
			}
		})
	}
}

func TestRefresh_AcceptsEverySigningKeyType(t *testing.T) {
	tests := []struct {
		name string
		key  json.RawMessage
	}{
		{"EC key with ES256", ecJWK(t, "k", nil)},
		{"EC key on P-384 with ES384", curveJWK(t, elliptic.P384(), "ES384", "k", nil)},
		{"EC key on P-521 with ES512", curveJWK(t, elliptic.P521(), "ES512", "k", nil)},
		{"RSA key of 2048 bits with RS256", rsaJWK(t, 2048, "k", nil)},
		{"OKP key with EdDSA", edJWK(t, "k", nil)},
		{"key without use", ecJWK(t, "k", map[string]any{"use": nil})},
		{"key without alg", ecJWK(t, "k", map[string]any{"alg": nil})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := issuer("realm", newIdP(t, tt.key))
			set := mustLoad(t, testOptions(), provider)
			if !loaded(set, provider, "k") {
				t.Errorf("Lookup(%q) found nothing, want the key", "k")
			}
		})
	}
}

// OPA lowers both jwx floors to zero in every binary it is linked into, the
// agent's among them, so the package has to refuse a weak key on its own.
// The control key is 2048 bits with the exponent 65537.
func TestRefresh_SkipsAWeakRSAKeyWithTheJWXFloorsLowered(t *testing.T) {
	jwk.Configure(jwk.WithMinRSAModulusBits(0), jwk.WithMinRSAPublicExponent(0))
	t.Cleanup(func() { jwk.Configure(jwk.WithMinRSAModulusBits(2048), jwk.WithMinRSAPublicExponent(3)) })
	control := rsaJWK(t, 2048, "control", nil)
	tests := []struct {
		name string
		key  json.RawMessage
	}{
		{"modulus of 2047 bits", rsaJWK(t, 2047, "case", nil)},
		{"public exponent of 1", rsaJWK(t, 2048, "case", map[string]any{"e": "AQ"})},
		{"even public exponent 65538", rsaJWK(t, 2048, "case", map[string]any{"e": "AQAC"})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := issuer("realm", newIdP(t, control, tt.key))
			set := mustLoad(t, testOptions(), provider)
			if loaded(set, provider, "case") {
				t.Errorf("Lookup(%q) found a key, want it skipped", "case")
			}
			if !loaded(set, provider, "control") {
				t.Errorf("Lookup(%q) found nothing, want the usable key", "control")
			}
		})
	}
}

func TestRefresh_AcceptsAJWKSOfExactly1MiB(t *testing.T) {
	idp := newIdP(t)
	idp.jwks = paddedJWKS(ecJWK(t, "k1", nil), maxResponseBytes)
	provider := issuer("realm", idp)
	set := mustLoad(t, testOptions(), provider)
	if !loaded(set, provider, "k1") {
		t.Errorf("Lookup(%q) found nothing, want the key of a JWKS of %d bytes", "k1", maxResponseBytes)
	}
}

func TestRefresh_ReportsAProviderWhoseKeysCannotBeRead(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, idp *fakeIdP)
	}{
		{"discovery answers 404", func(t *testing.T, idp *fakeIdP) { idp.status = http.StatusNotFound }},
		{"discovery without jwks_uri", func(t *testing.T, idp *fakeIdP) { idp.discovery = []byte(`{}`) }},
		{"discovery jwks_uri that is not http", func(t *testing.T, idp *fakeIdP) { idp.discovery = []byte(`{"jwks_uri": "file:///etc/jwks.json"}`) }},
		{"discovery that is not JSON", func(t *testing.T, idp *fakeIdP) { idp.discovery = []byte(`<html></html>`) }},
		{"JWKS without a keys array", func(t *testing.T, idp *fakeIdP) { idp.jwks = []byte(`{}`) }},
		{"JWKS whose keys array is empty", func(t *testing.T, idp *fakeIdP) { idp.jwks = []byte(`{"keys": []}`) }},
		{"JWKS whose keys is null", func(t *testing.T, idp *fakeIdP) { idp.jwks = []byte(`{"keys": null}`) }},
		{"JWKS whose keys is an object", func(t *testing.T, idp *fakeIdP) { idp.jwks = []byte(`{"keys": {}}`) }},
		{"usable JWKS one byte over 1 MiB", func(t *testing.T, idp *fakeIdP) {
			idp.jwks = paddedJWKS(ecJWK(t, "k1", nil), maxResponseBytes+1)
		}},
		{"JWKS whose only key has no kid", func(t *testing.T, idp *fakeIdP) {
			idp.keys = []json.RawMessage{ecJWK(t, "", map[string]any{"kid": nil})}
		}},
		{"JWKS with two different keys under one kid", func(t *testing.T, idp *fakeIdP) {
			idp.keys = []json.RawMessage{ecJWK(t, "twin", nil), ecJWK(t, "twin", nil)}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newIdP(t, ecJWK(t, "k1", nil))
			tt.setup(t, idp)
			set := mustNew(t, Config{Providers: []Provider{issuer("realm", idp)}}, testOptions())
			err := set.Refresh(t.Context())
			if err == nil || !strings.Contains(err.Error(), `provider "realm"`) {
				t.Errorf("Refresh() error = %v, want an error naming provider %q", err, "realm")
			}
			if set.Ready() {
				t.Errorf("Ready() = true, want false while the provider has no keys")
			}
		})
	}
}

// k2 is listed after the repeated key, so a load that stops at the repeat
// fails on k2.
func TestRefresh_TheSameKeyListedTwiceLoadsOnce(t *testing.T) {
	key := ecJWK(t, "k1", nil)
	provider := issuer("realm", newIdP(t, key, key, ecJWK(t, "k2", nil)))
	set := mustLoad(t, testOptions(), provider)
	if !loaded(set, provider, "k1") {
		t.Errorf("Lookup(%q) found nothing, want the key listed twice", "k1")
	}
	if !loaded(set, provider, "k2") {
		t.Errorf("Lookup(%q) found nothing, want the key listed after the repeat", "k2")
	}
}

func TestRefresh_NamesEveryProviderThatStaysDown(t *testing.T) {
	up := newIdP(t, ecJWK(t, "k1", nil))
	down1 := newIdP(t)
	down1.setStatus(http.StatusServiceUnavailable)
	down2 := newIdP(t)
	down2.setStatus(http.StatusServiceUnavailable)
	providers := []Provider{issuer("up", up), issuer("down-1", down1), issuer("down-2", down2)}
	err := mustNew(t, Config{Providers: providers}, testOptions()).Refresh(t.Context())
	if err == nil || !containsAll(err.Error(), `provider "down-1"`, `provider "down-2"`, "HTTP 503") || strings.Contains(err.Error(), `provider "up"`) {
		t.Errorf("Refresh() error = %v, want an error naming providers %q and %q with HTTP 503, and not provider %q", err, "down-1", "down-2", "up")
	}
}

func TestRefresh_CAFileTrustsAPrivateCertificate(t *testing.T) {
	idp := newTLSIdP(t, ecJWK(t, "k1", nil))
	provider := issuer("realm", idp)
	provider.CAFile = idp.caFile(t)
	set := mustLoad(t, testOptions(), provider)
	if !loaded(set, provider, "k1") {
		t.Errorf("Lookup(%q) found nothing, want the key served over TLS", "k1")
	}
}

func TestRefresh_TheSystemRootsRejectAPrivateCertificate(t *testing.T) {
	idp := newTLSIdP(t, ecJWK(t, "k1", nil))
	set := mustNew(t, Config{Providers: []Provider{issuer("realm", idp)}}, testOptions())
	var certErr *tls.CertificateVerificationError
	if err := set.Refresh(t.Context()); !errors.As(err, &certErr) {
		t.Errorf("Refresh() error = %v, want a *tls.CertificateVerificationError without caFile", err)
	}
}

func TestNew_RefusesAnUnusableCAFile(t *testing.T) {
	tests := []struct {
		name, caFile string
	}{
		{"file without a PEM certificate", writeFile(t, "ca.pem", "not a certificate")},
		{"missing file", filepath.Join(t.TempDir(), "absent.pem")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := issuer("realm", newTLSIdP(t, ecJWK(t, "k1", nil)))
			provider.CAFile = tt.caFile
			_, err := New(Config{Providers: []Provider{provider}}, testOptions())
			if err == nil || !strings.Contains(err.Error(), "caFile") {
				t.Errorf("New() with caFile %s error = %v, want an error naming caFile", tt.caFile, err)
			}
		})
	}
}

// x509.SystemCertPool fails only when a file of roots exists and cannot be
// read, which a test cannot arrange, so the base pool here is a stand-in.
func TestNewClient_FailsWhenItsBasePoolFails(t *testing.T) {
	errNoRoots := errors.New("no root store")
	base := func() (*x509.CertPool, error) { return nil, errNoRoots }
	caFile := newTLSIdP(t, ecJWK(t, "k1", nil)).caFile(t)
	client, err := newClient("provider \"k8s\" internal CA file", base, caFile, time.Second)
	if client != nil || !errors.Is(err, errNoRoots) {
		t.Errorf("newClient() = %v, %v, want no client and an error that wraps %v", client, err, errNoRoots)
	}
}

// The error keeps the cause, so the operator reads that the file is missing
// rather than that it holds no certificate.
func TestNewClient_ReportsACAFileItCannotRead(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "absent.pem")
	client, err := newClient("provider \"k8s\" caFile", emptyCertPool, caFile, time.Second)
	if client != nil || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("newClient(%s) = %v, %v, want no client and an error that wraps fs.ErrNotExist", caFile, client, err)
	}
}

func TestRefresh_FailsWithoutAUsableTokenFile(t *testing.T) {
	tests := []struct {
		name, tokenFile string
	}{
		{"empty file", writeFile(t, "token", "\n")},
		{"missing file", filepath.Join(t.TempDir(), "absent")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := direct("k8s", newIdP(t, ecJWK(t, "k1", nil)))
			provider.TokenFile = tt.tokenFile
			set := mustNew(t, Config{Providers: []Provider{provider}}, testOptions())
			if err := set.Refresh(t.Context()); err == nil || !strings.Contains(err.Error(), "tokenFile") {
				t.Errorf("Refresh() with tokenFile %s error = %v, want an error naming tokenFile", tt.tokenFile, err)
			}
		})
	}
}

// The token changes between two reloads, as a projected service account token
// does when the kubelet rotates it.
func TestRefresh_TokenFileIsReadOnEveryRequest(t *testing.T) {
	idp := newIdP(t, ecJWK(t, "k1", nil))
	idp.token = "first"
	provider := direct("k8s", idp)
	provider.TokenFile = writeFile(t, "token", "first\n")
	set := mustLoad(t, testOptions(), provider)
	if got := idp.authorization(); got != "Bearer first" {
		t.Errorf("Authorization at the first reload = %q, want %q", got, "Bearer first")
	}
	if err := os.WriteFile(provider.TokenFile, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	idp.mu.Lock()
	idp.token = "second"
	idp.mu.Unlock()
	if err := set.Refresh(context.Background()); err != nil {
		t.Errorf("Refresh() error = %v", err)
	}
	if got := idp.authorization(); got != "Bearer second" {
		t.Errorf("Authorization at the second reload = %q, want %q", got, "Bearer second")
	}
}

// Each redirect target listens on the same host at another port, where an
// HTTP client still forwards an Authorization header.
func TestRefresh_DoesNotFollowARedirect(t *testing.T) {
	tests := []struct {
		name     string
		provider func(t *testing.T, redirecting string) Provider
	}{
		{"discovery request", func(_ *testing.T, redirecting string) Provider {
			return Provider{ID: "k8s", Issuer: redirecting}
		}},
		{"JWKS request with the token", func(t *testing.T, redirecting string) Provider {
			return Provider{ID: "k8s", Issuer: redirecting, JWKSURI: redirecting + "/jwks", TokenFile: writeFile(t, "token", "sa-token")}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := newIdP(t, ecJWK(t, "k1", nil))
			redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.srv.URL+r.URL.Path, http.StatusFound)
			}))
			t.Cleanup(redirecting.Close)
			set := mustNew(t, Config{Providers: []Provider{tt.provider(t, redirecting.URL)}}, testOptions())
			if err := set.Refresh(t.Context()); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
				t.Errorf("Refresh() error = %v, want the HTTP 302 of the redirect", err)
			}
			if got := target.authorization(); got != "" {
				t.Errorf("Authorization at the redirect target = %q, want none", got)
			}
		})
	}
}

// providerFetcher returns the fetcher of p, as a Set builds it for a provider.
func providerFetcher(p *Provider, client *http.Client, log Logger) *fetcher {
	return &fetcher{source: Source{Provider: p}, address: p.Issuer, client: client, log: log}
}

// clusterAPIServer answers discovery and the JWKS in memory, because a test
// server cannot listen on an in-cluster name. It keeps the address and the
// Authorization header of each request.
type clusterAPIServer struct {
	jwksURI string
	jwks    []byte
	// redirect, when set, answers the next request with a 302 to this address.
	redirect string
	urls     []string
	headers  []string
}

func (s *clusterAPIServer) RoundTrip(r *http.Request) (*http.Response, error) {
	s.urls = append(s.urls, r.URL.String())
	s.headers = append(s.headers, r.Header.Get("Authorization"))
	if s.redirect != "" {
		header := http.Header{"Location": {s.redirect}}
		s.redirect = ""
		return &http.Response{StatusCode: http.StatusFound, Header: header, Body: http.NoBody, Request: r}, nil
	}
	body := s.jwks
	if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
		body = []byte(`{"jwks_uri": "` + s.jwksURI + `"}`)
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
}

// The jwks_uri is the address a standard API server names by default, which is
// not an in-cluster name, so a token limited to those names fails the test.
func TestFetch_SendsTheTokenWithDiscoveryOfTheClusterAPIServer(t *testing.T) {
	const issuer = "https://kubernetes.default.svc.cluster.local"
	server := &clusterAPIServer{jwksURI: "https://10.0.0.1:6443/openid/v1/jwks",
		jwks: []byte(`{"keys": [` + string(ecJWK(t, "k1", nil)) + `]}`)}
	f := providerFetcher(&Provider{ID: "k8s", Issuer: issuer, TokenFile: writeFile(t, "token", "sa-token\n")}, &http.Client{Transport: server}, &warnRecorder{})
	keys, err := f.fetch(t.Context())
	if err != nil {
		t.Fatalf("fetch() error = %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("fetch() returned %d keys, want 1", len(keys))
	}
	wantURLs := []string{issuer + "/.well-known/openid-configuration", server.jwksURI}
	if !slices.Equal(server.urls, wantURLs) {
		t.Errorf("requests = %q, want %q", server.urls, wantURLs)
	}
	wantHeaders := []string{"Bearer sa-token", "Bearer sa-token"}
	if !slices.Equal(server.headers, wantHeaders) {
		t.Errorf("Authorization headers = %q, want %q", server.headers, wantHeaders)
	}
}

// The redirect target is on the same host, where an HTTP client still forwards
// an Authorization header, so only the client of newClient keeps the token from
// it.
func TestFetch_DoesNotFollowARedirectOfDiscoveryWithTheToken(t *testing.T) {
	const issuer = "https://kubernetes.default.svc"
	server := &clusterAPIServer{redirect: issuer + ":6443/.well-known/openid-configuration"}
	client, err := newClient("provider \"k8s\" caFile", emptyCertPool, "", time.Second)
	if err != nil {
		t.Fatalf("newClient() error = %v", err)
	}
	client.Transport = server
	f := providerFetcher(&Provider{ID: "k8s", Issuer: issuer, TokenFile: writeFile(t, "token", "sa-token")}, client, &warnRecorder{})
	if _, err := f.fetch(t.Context()); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Errorf("fetch() error = %v, want the HTTP 302 of the redirect", err)
	}
	if want := []string{issuer + "/.well-known/openid-configuration"}; !slices.Equal(server.urls, want) {
		t.Errorf("requests = %q, want %q", server.urls, want)
	}
}

// A jwks_uri over http would put the token on the wire in clear text. The
// control sends no token, so the same answer is accepted there.
func TestFetch_RefusesToSendTheTokenToAnHTTPJWKSURI(t *testing.T) {
	const jwksURI = "http://10.0.0.1:8080/openid/v1/jwks"
	jwks := []byte(`{"keys": [` + string(ecJWK(t, "k1", nil)) + `]}`)
	server := &clusterAPIServer{jwksURI: jwksURI, jwks: jwks}
	f := providerFetcher(&Provider{ID: "k8s", Issuer: "https://kubernetes.default.svc", TokenFile: writeFile(t, "token", "sa-token")}, &http.Client{Transport: server}, &warnRecorder{})
	if _, err := f.fetch(t.Context()); err == nil || !containsAll(err.Error(), "has to be https", "set jwksUri to https://kubernetes.default.svc/openid/v1/jwks") {
		t.Errorf("fetch() error = %v, want one that names https and the jwksUri that avoids discovery", err)
	}
	if slices.Contains(server.urls, jwksURI) {
		t.Errorf("requests = %q, want none to %q", server.urls, jwksURI)
	}

	control := &clusterAPIServer{jwksURI: jwksURI, jwks: jwks}
	withoutToken := providerFetcher(&Provider{ID: "idp", Issuer: "https://idp.example"}, &http.Client{Transport: control}, &warnRecorder{})
	if _, err := withoutToken.fetch(t.Context()); err != nil {
		t.Errorf("fetch() without a token error = %v, want none", err)
	}
	if got := strings.Join(control.headers, ""); got != "" {
		t.Errorf("Authorization headers without a token = %q, want none", got)
	}
}

// The provider took https://kubernetes.default.svc at start, and the kubelet
// then rotates the token through other issuers. A token whose iss cannot be
// read is left to the API server.
func TestFetch_WarnsWhenTheTokenChangesToAnIssuerTheProviderDoesNotAccept(t *testing.T) {
	const own = "https://kubernetes.default.svc"
	server := &clusterAPIServer{jwks: []byte(`{"keys": [` + string(ecJWK(t, "k1", nil)) + `]}`)}
	path := writeFile(t, "token", jwtWith(`{"iss": "`+own+`"}`))
	log := &warnRecorder{}
	f := providerFetcher(&Provider{ID: "k8s", Issuer: own, JWKSURI: own + "/openid/v1/jwks", TokenFile: path, Kubernetes: true},
		&http.Client{Transport: server}, log)
	steps := []struct {
		name, token  string
		wantWarnings int
	}{
		{"the issuer of the provider", jwtWith(`{"iss": "` + own + `"}`), 0},
		{"issuer a", jwtWith(`{"iss": "https://oidc.example/a"}`), 1},
		{"issuer a again", jwtWith(`{"iss": "https://oidc.example/a"}`), 1},
		{"a token that is not a JWT", "sa-token", 1},
		{"issuer b", jwtWith(`{"iss": "https://oidc.example/b"}`), 2},
		{"the issuer of the provider after issuer b", jwtWith(`{"iss": "` + own + `"}`), 2},
		{"issuer b after the issuer of the provider", jwtWith(`{"iss": "https://oidc.example/b"}`), 3},
	}
	for _, step := range steps {
		if err := os.WriteFile(path, []byte(step.token), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := f.fetch(t.Context()); err != nil {
			t.Fatalf("fetch() after %s error = %v", step.name, err)
		}
		if len(log.warnings) != step.wantWarnings {
			t.Errorf("warnings after %s = %q, want %d", step.name, log.warnings, step.wantWarnings)
		}
	}
	for _, w := range log.warnings {
		if !containsAll(w, path, `provider "k8s"`, `the issuer "`+own+`"`, "restarts") {
			t.Errorf("warning %q, want one that names %s, provider \"k8s\", its issuer, and the restart", w, path)
		}
	}
}

// The token of a provider without the mark is a credential for that provider,
// and its iss has nothing to do with the issuer of the provider.
func TestFetch_DoesNotCompareTheIssuerOfTheTokenOfAnUnmarkedProvider(t *testing.T) {
	server := &clusterAPIServer{jwks: []byte(`{"keys": [` + string(ecJWK(t, "k1", nil)) + `]}`)}
	log := &warnRecorder{}
	f := providerFetcher(&Provider{ID: "idp", Issuer: "https://idp.example", JWKSURI: "https://idp.example/jwks",
		TokenFile: writeFile(t, "token", jwtWith(`{"iss": "https://client.example"}`))}, &http.Client{Transport: server}, log)
	if _, err := f.fetch(t.Context()); err != nil {
		t.Fatalf("fetch() error = %v", err)
	}
	if len(log.warnings) != 0 {
		t.Errorf("warnings = %q, want none", log.warnings)
	}
}

func TestAcceptsAlgorithm(t *testing.T) {
	tests := []struct {
		alg  string
		want bool
	}{
		{"RS256", true},
		{"PS512", true},
		{"ES384", true},
		{"EdDSA", true},
		{"HS256", false},
		{"none", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := AcceptsAlgorithm(tt.alg); got != tt.want {
			t.Errorf("AcceptsAlgorithm(%q) = %t, want %t", tt.alg, got, tt.want)
		}
	}
}

func TestKey_Allows(t *testing.T) {
	idp := newIdP(t,
		rsaJWK(t, 2048, "declared", nil),
		rsaJWK(t, 2048, "undeclared", map[string]any{"alg": nil}),
		ecJWK(t, "p256", map[string]any{"alg": nil}),
		curveJWK(t, elliptic.P521(), "ES512", "p521", map[string]any{"alg": nil}),
		edJWK(t, "ed25519", map[string]any{"alg": nil}),
	)
	provider := issuer("realm", idp)
	set := mustLoad(t, testOptions(), provider)
	tests := []struct {
		kid, alg string
		want     bool
	}{
		{"declared", "RS256", true},
		{"declared", "PS256", false},
		{"undeclared", "PS256", true},
		{"undeclared", "ES256", false},
		{"undeclared", "HS256", false},
		{"undeclared", "none", false},
		{"p256", "ES256", true},
		{"p256", "ES512", false},
		{"p521", "ES512", true},
		{"p521", "ES256", false},
		{"ed25519", "EdDSA", true},
	}
	for _, tt := range tests {
		key, err := set.Lookup(Query{Issuer: provider.Issuer, KID: tt.kid})
		if err != nil {
			t.Fatalf("Lookup(%q) error = %v", tt.kid, err)
		}
		if got := key.Allows(tt.alg); got != tt.want {
			t.Errorf("Lookup(%q).Allows(%q) = %t, want %t", tt.kid, tt.alg, got, tt.want)
		}
	}
}

func TestRefresh_AProviderThatFailsKeepsItsKeys(t *testing.T) {
	a := newIdP(t, ecJWK(t, "a-old", nil))
	b := newIdP(t, ecJWK(t, "b-old", nil))
	providerA, providerB := issuer("a", a), issuer("b", b)
	set := mustLoad(t, testOptions(), providerA, providerB)
	a.publish(ecJWK(t, "a-new", nil))
	b.setStatus(http.StatusServiceUnavailable)

	err := set.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), `provider "b"`) {
		t.Errorf("Refresh() error = %v, want an error naming provider %q", err, "b")
	}
	for kid, want := range map[string]bool{"a-new": true, "a-old": false} {
		if got := loaded(set, providerA, kid); got != want {
			t.Errorf("Lookup(%q) found = %t, want %t", kid, got, want)
		}
	}
	if !loaded(set, providerB, "b-old") {
		t.Errorf("Lookup(%q) found nothing, want the key kept", "b-old")
	}
}

// Provider a fails in each of the two ways a reload tells apart: a failed
// fetch and a JWKS without a usable key.
func TestRefresh_AProviderBesideAFailingOneTakesItsNewKeys(t *testing.T) {
	tests := []struct {
		name string
		fail func(t *testing.T, idp *fakeIdP)
	}{
		{"fetch fails", func(t *testing.T, idp *fakeIdP) { idp.setStatus(http.StatusServiceUnavailable) }},
		{"JWKS holds no usable key", func(t *testing.T, idp *fakeIdP) {
			idp.publish(ecJWK(t, "enc", map[string]any{"use": "enc"}))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newIdP(t, ecJWK(t, "a-old", nil))
			b := newIdP(t, ecJWK(t, "b-old", nil))
			providerB := issuer("b", b)
			set := mustLoad(t, testOptions(), issuer("a", a), providerB)
			tt.fail(t, a)
			b.publish(ecJWK(t, "b-new", nil))

			_ = set.Refresh(context.Background())
			for kid, want := range map[string]bool{"b-new": true, "b-old": false} {
				if got := loaded(set, providerB, kid); got != want {
					t.Errorf("Lookup(%q) found = %t, want %t", kid, got, want)
				}
			}
		})
	}
}

// A JWKS that parses and holds no usable signing key removes the provider's
// keys. A JWKS whose keys member is missing or not an array is a failed
// fetch, the control, and the old key stays.
func TestRefresh_AJWKSWithoutAUsableKeyRemovesTheProvidersKeys(t *testing.T) {
	tests := []struct {
		name     string
		serve    func(t *testing.T, idp *fakeIdP)
		wantKept bool
	}{
		{"JWKS whose keys array is empty", func(t *testing.T, idp *fakeIdP) { idp.setJWKS(`{"keys": []}`) }, false},
		{"JWKS whose keys is null", func(t *testing.T, idp *fakeIdP) { idp.setJWKS(`{"keys": null}`) }, false},
		{"JWKS whose only key is an encryption key", func(t *testing.T, idp *fakeIdP) {
			idp.publish(ecJWK(t, "enc", map[string]any{"use": "enc"}))
		}, false},
		{"JWKS without a keys array", func(t *testing.T, idp *fakeIdP) { idp.setJWKS(`{}`) }, true},
		{"JWKS whose keys is an object", func(t *testing.T, idp *fakeIdP) { idp.setJWKS(`{"keys": {}}`) }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newIdP(t, ecJWK(t, "old", nil))
			provider := issuer("realm", idp)
			set := mustLoad(t, testOptions(), provider)
			tt.serve(t, idp)
			if err := set.Refresh(context.Background()); err == nil {
				t.Errorf("Refresh() error = nil, want an error that names what happened to the keys")
			}
			if got := loaded(set, provider, "old"); got != tt.wantKept {
				t.Errorf("Lookup(%q) found = %t, want %t", "old", got, tt.wantKept)
			}
			if !set.Ready() {
				t.Errorf("Ready() = false after the source once loaded, want true")
			}
		})
	}
}

// Keycloak publishes an encryption key beside the signing keys of a realm, so
// skipping it is no news. The weak key is the control: its warning goes out on
// the first load that skips it, and again only when the skipped keys change. A
// skipped key is the same key wherever the JWKS lists it, and two keys without
// a kid are two keys although their reason reads alike. A load that skips no
// key warns about nothing.
func TestRefresh_WarnsAboutSkippedKeysOnlyWhenTheyChange(t *testing.T) {
	signing, rotated, enc := ecJWK(t, "k1", nil), ecJWK(t, "k2", nil), ecJWK(t, "enc", map[string]any{"use": "enc"})
	weak := rsaJWK(t, 1024, "weak", nil)
	noKID, otherNoKID := ecJWK(t, "", map[string]any{"kid": nil}), ecJWK(t, "", map[string]any{"kid": nil})
	idp := newIdP(t, signing, enc)
	log := &warnRecorder{}
	opts := testOptions()
	opts.Log = log
	set := mustLoad(t, opts, issuer("realm", idp))
	steps := []struct {
		name string
		keys []json.RawMessage
		want int
	}{
		{"second load of the encryption key", []json.RawMessage{signing, enc}, 0},
		{"first load of a weak key", []json.RawMessage{signing, enc, weak}, 1},
		{"second load of the weak key", []json.RawMessage{signing, enc, weak}, 1},
		{"load of a new signing key ahead of the weak key", []json.RawMessage{signing, rotated, enc, weak}, 1},
		{"load of a second skipped key", []json.RawMessage{signing, rotated, enc, weak, noKID}, 2},
		{"load of another key without a kid in its place", []json.RawMessage{signing, rotated, enc, weak, otherNoKID}, 3},
		{"load of the two skipped keys in swapped places", []json.RawMessage{signing, rotated, enc, otherNoKID, weak}, 3},
		{"load of the weak key alone", []json.RawMessage{signing, rotated, enc, weak}, 4},
		{"load without the skipped keys", []json.RawMessage{signing, rotated, enc}, 4},
		{"load of the weak key again", []json.RawMessage{signing, rotated, enc, weak}, 5},
	}
	for _, step := range steps {
		idp.publish(step.keys...)
		if err := set.Refresh(t.Context()); err != nil {
			t.Fatalf("Refresh() on the %s error = %v", step.name, err)
		}
		if got := log.count("skips"); got != step.want {
			t.Errorf("warnings about skipped keys after the %s = %d, want %d; warnings: %q", step.name, got, step.want, log.warnings)
		}
	}
}

// The error of the load that finds no usable key lists the weak key, and the
// next load, which skips the same key beside a signing key, warns about it
// once.
func TestRefresh_WarnsAboutTheSkippedKeysOfAJWKSWithoutAUsableKeyAtTheNextLoadThatFindsAKey(t *testing.T) {
	signing, weak := ecJWK(t, "k1", nil), rsaJWK(t, 1024, "weak", nil)
	idp := newIdP(t, weak)
	log := &warnRecorder{}
	opts := testOptions()
	opts.Log = log
	set := mustNew(t, Config{Providers: []Provider{issuer("realm", idp)}}, opts)
	if err := set.Refresh(t.Context()); !errors.Is(err, errNoUsableKey) {
		t.Fatalf("Refresh() of a JWKS whose only key is weak: error = %v, want %v", err, errNoUsableKey)
	}
	if got := log.count("skips"); got != 0 {
		t.Errorf("warnings about skipped keys after the load without a usable key = %d, want 0; warnings: %q", got, log.warnings)
	}
	idp.publish(signing, weak)
	for _, load := range []string{"first", "second"} {
		if err := set.Refresh(t.Context()); err != nil {
			t.Fatalf("Refresh() on the %s load of a signing key beside the weak key: error = %v", load, err)
		}
		if got := log.count(`skips 1 key of its JWKS: keys[1]: `); got != 1 {
			t.Errorf("warnings about the weak key after the %s load of a signing key beside it = %d, want 1; warnings: %q", load, got, log.warnings)
		}
	}
}

// Seven keys without a kid follow the signing key at keys[0].
func TestRefresh_WarnsWithTheFirstFiveSkippedKeysAndCountsTheRest(t *testing.T) {
	keys := append([]json.RawMessage{ecJWK(t, "k1", nil)}, slices.Repeat([]json.RawMessage{ecJWK(t, "", map[string]any{"kid": nil})}, 7)...)
	log := &warnRecorder{}
	opts := testOptions()
	opts.Log = log
	mustLoad(t, opts, issuer("realm", newIdP(t, keys...)))
	want := `trusted providers: provider "realm" skips 7 keys of its JWKS: ` +
		`keys[1]: has no kid; keys[2]: has no kid; keys[3]: has no kid; keys[4]: has no kid; keys[5]: has no kid; 2 more skipped keys`
	if !slices.Equal(log.warnings, []string{want}) {
		t.Errorf("warnings = %q, want %q", log.warnings, want)
	}
}

// The JWKS lists seven keys without a kid after the signing key, and the second
// load replaces the seventh, which no warning lists.
func TestRefresh_WarnsWhenASkippedKeyPastTheFifthChanges(t *testing.T) {
	keys := []json.RawMessage{ecJWK(t, "k1", nil)}
	for range 7 {
		keys = append(keys, ecJWK(t, "", map[string]any{"kid": nil}))
	}
	idp := newIdP(t, keys...)
	log := &warnRecorder{}
	opts := testOptions()
	opts.Log = log
	set := mustLoad(t, opts, issuer("realm", idp))
	keys[7] = ecJWK(t, "", map[string]any{"kid": nil})
	idp.publish(keys...)
	if err := set.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if got := log.count("skips 7 keys"); got != 2 {
		t.Errorf("warnings about the skipped keys after the second load = %d, want 2; warnings: %q", got, log.warnings)
	}
}

// The parser repeats the kty of the key in its error, line break included.
func TestRefresh_QuotesTheParserErrorOfASkippedKey(t *testing.T) {
	idp := newIdP(t, json.RawMessage(`{"kty":"RSA\nforged line","kid":"k1"}`))
	set := mustNew(t, Config{Providers: []Provider{issuer("realm", idp)}}, testOptions())
	err := set.Refresh(t.Context())
	if err == nil || strings.Contains(err.Error(), "\n") || !strings.Contains(err.Error(), `keys[0]: cannot be parsed: "`) {
		t.Errorf("Refresh() error = %q, want one line that quotes the parser error of keys[0]", err)
	}
}

// The sources come in an order that is neither by id nor by kind: realm d
// before realm b, and provider sso, whose id sorts after realm/cloud-common,
// before provider idp. Realm d keeps its keys, and realm a reloaded.
func TestJoinReloadErrors_OrdersItsLinesWhateverTheOrderOfTheSources(t *testing.T) {
	sourceOf := func(from Source, required bool) *source {
		return &source{fetcher: &fetcher{source: from}, required: required}
	}
	d := sourceOf(Source{Realm: "d"}, false)
	d.current.Store(&[]Key{{ID: "k1"}})
	sources := []*source{
		d,
		sourceOf(Source{Realm: "b"}, false),
		sourceOf(Source{Realm: "a"}, false),
		sourceOf(Source{Realm: "cloud-common"}, true),
		sourceOf(Source{Provider: &Provider{ID: "sso"}}, true),
		sourceOf(Source{Provider: &Provider{ID: "idp"}}, true),
	}
	errs := []error{errors.New("d failed"), errors.New("b failed"), nil, errors.New("cloud-common failed"), errors.New("sso failed"), errors.New("idp failed")}
	want := "idp failed\ncloud-common failed\nsso failed\n" +
		"2 of 3 realms that tokens named did not reload, 1 of them without keys; the first by name: b failed"
	if got := joinReloadErrors(sources, errs).Error(); got != want {
		t.Errorf("joinReloadErrors() = %q, want %q", got, want)
	}
}

// No warning lists the skipped keys of a JWKS without a usable key, so its error
// lists the reasons of the first five, counts the rest, and counts the
// encryption keys apart, at the end. The error contains each part of want and
// ends with the last one.
func TestRefresh_NamesTheReasonsOfAJWKSWithoutAUsableKey(t *testing.T) {
	enc := map[string]any{"use": "enc"}
	tests := []struct {
		name string
		keys []json.RawMessage
		want []string
	}{
		{
			"an encryption key and a weak key",
			[]json.RawMessage{ecJWK(t, "enc", enc), rsaJWK(t, 1024, "weak", nil)},
			[]string{"no usable signing key: keys[1]: cannot be parsed", "; 1 encryption key"},
		},
		{"two encryption keys", []json.RawMessage{ecJWK(t, "enc-1", enc), ecJWK(t, "enc-2", enc)}, []string{"no usable signing key: 2 encryption keys"}},
		{
			"six keys without a kid and an encryption key",
			append(slices.Repeat([]json.RawMessage{ecJWK(t, "", map[string]any{"kid": nil})}, 6), ecJWK(t, "enc", enc)),
			[]string{"no usable signing key: keys[0]: has no kid; keys[1]: has no kid; keys[2]: has no kid; keys[3]: has no kid; keys[4]: has no kid; 1 more skipped key; 1 encryption key"},
		},
		{"an empty keys array", []json.RawMessage{}, []string{"no usable signing key: the keys array is empty"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newIdP(t, tt.keys...)
			set := mustNew(t, Config{Providers: []Provider{issuer("realm", idp)}}, testOptions())
			err := set.Refresh(t.Context())
			if err == nil || !containsAll(err.Error(), tt.want...) || !strings.HasSuffix(err.Error(), tt.want[len(tt.want)-1]) {
				t.Errorf("Refresh() error = %v, want it to contain %q and end with the last", err, tt.want)
			}
		})
	}
}

func TestReady_StaysTrueWhenAReloadFails(t *testing.T) {
	idp := newIdP(t, ecJWK(t, "k1", nil))
	set := mustLoad(t, testOptions(), issuer("realm", idp))
	idp.setStatus(http.StatusServiceUnavailable)
	if err := set.Refresh(t.Context()); err == nil {
		t.Fatalf("Refresh() error = nil, want the HTTP 503")
	}
	if !set.Ready() {
		t.Errorf("Ready() after a failed reload = false, want true")
	}
}

func TestLookup_RefusesAnIssuerNoProviderHasByteForByte(t *testing.T) {
	provider := issuer("realm", newIdP(t, ecJWK(t, "k1", nil)))
	set := mustLoad(t, testOptions(), provider)
	for _, iss := range []string{"", provider.Issuer + "/", "https://other.example"} {
		if _, err := set.Lookup(Query{Issuer: iss, KID: "k1"}); !errors.Is(err, ErrIssuerUnknown) {
			t.Errorf("Lookup(issuer %q) error = %v, want %v", iss, err, ErrIssuerUnknown)
		}
	}
}
