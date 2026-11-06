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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
		if key.Provider.ID != p.ID {
			t.Errorf("Lookup(issuer of %q).Provider.ID = %q, want %q", p.ID, key.Provider.ID, p.ID)
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
	f := &fetcher{client: &http.Client{Transport: server}, log: &warnRecorder{},
		provider: &Provider{ID: "k8s", Issuer: issuer, TokenFile: writeFile(t, "token", "sa-token\n")}}
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
	f := &fetcher{client: client, log: &warnRecorder{},
		provider: &Provider{ID: "k8s", Issuer: issuer, TokenFile: writeFile(t, "token", "sa-token")}}
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
	f := &fetcher{client: &http.Client{Transport: server}, log: &warnRecorder{},
		provider: &Provider{ID: "k8s", Issuer: "https://kubernetes.default.svc", TokenFile: writeFile(t, "token", "sa-token")}}
	if _, err := f.fetch(t.Context()); err == nil || !strings.Contains(err.Error(), "has to be https") {
		t.Errorf("fetch() error = %v, want one that names https", err)
	}
	if slices.Contains(server.urls, jwksURI) {
		t.Errorf("requests = %q, want none to %q", server.urls, jwksURI)
	}

	control := &clusterAPIServer{jwksURI: jwksURI, jwks: jwks}
	withoutToken := &fetcher{client: &http.Client{Transport: control}, log: &warnRecorder{},
		provider: &Provider{ID: "idp", Issuer: "https://idp.example"}}
	if _, err := withoutToken.fetch(t.Context()); err != nil {
		t.Errorf("fetch() without a token error = %v, want none", err)
	}
	if got := strings.Join(control.headers, ""); got != "" {
		t.Errorf("Authorization headers without a token = %q, want none", got)
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
		{"JWKS whose only key is an encryption key", func(t *testing.T, idp *fakeIdP) {
			idp.publish(ecJWK(t, "enc", map[string]any{"use": "enc"}))
		}, false},
		{"JWKS without a keys array", func(t *testing.T, idp *fakeIdP) { idp.setJWKS(`{}`) }, true},
		{"JWKS whose keys is null", func(t *testing.T, idp *fakeIdP) { idp.setJWKS(`{"keys": null}`) }, true},
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

func TestRun_ReloadsOnTheInterval(t *testing.T) {
	idp := newIdP(t, ecJWK(t, "old", nil))
	opts := testOptions()
	opts.RefreshInterval = 20 * time.Millisecond
	provider := issuer("realm", idp)
	set := mustLoad(t, opts, provider)
	idp.publish(ecJWK(t, "new", nil))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		set.Run(ctx)
		close(done)
	}()
	waitFor(t, "Run to load the new key", func() bool { return loaded(set, provider, "new") })
	cancel()
	<-done
}

// A required source fails in each of the two ways a reload reports, and then
// recovers. Ready stays false until it does, and nothing ends Run.
func TestRun_RetriesARequiredSourceUntilItHasAKey(t *testing.T) {
	tests := []struct {
		name    string
		fail    func(t *testing.T, idp *fakeIdP)
		cause   string
		recover func(t *testing.T, idp *fakeIdP)
	}{
		{
			"provider that answers 503",
			func(t *testing.T, idp *fakeIdP) { idp.setStatus(http.StatusServiceUnavailable) },
			"HTTP 503",
			func(t *testing.T, idp *fakeIdP) { idp.setStatus(0) },
		},
		{
			"JWKS without a usable key",
			func(t *testing.T, idp *fakeIdP) { idp.publish(ecJWK(t, "enc", map[string]any{"use": "enc"})) },
			"no usable signing key",
			func(t *testing.T, idp *fakeIdP) { idp.publish(ecJWK(t, "k1", nil)) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newIdP(t, ecJWK(t, "k1", nil))
			tt.fail(t, idp)
			log := &warnRecorder{}
			opts := testOptions()
			opts.Log = log
			set := mustNew(t, Config{Providers: []Provider{issuer("realm", idp)}}, opts)
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			go func() {
				set.Run(ctx)
				close(done)
			}()
			waitFor(t, "a second failed attempt", func() bool { return log.count("retrying in") >= 2 })
			if got := log.count(tt.cause); got < 2 {
				t.Errorf("warnings that name %q = %d, want at least 2; warnings: %q", tt.cause, got, log.warnings)
			}
			if set.Ready() {
				t.Errorf("Ready() = true while the provider has no keys, want false")
			}
			tt.recover(t, idp)
			waitFor(t, "Ready() to return true", set.Ready)
			cancel()
			<-done
		})
	}
}

// The pause before the next attempt lasts an hour, so only the end of the
// context can end it.
func TestRun_ReturnsWhenItsContextEndsDuringARetryPause(t *testing.T) {
	idp := newIdP(t)
	idp.setStatus(http.StatusServiceUnavailable)
	log := &warnRecorder{}
	set := mustNew(t, Config{Providers: []Provider{issuer("realm", idp)}}, Options{firstRetryDelay: time.Hour, Log: log})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		set.Run(ctx)
		close(done)
	}()
	waitFor(t, "the retry pause", func() bool { return log.count("retrying in 1h0m0s") == 1 })
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("Run did not return within 5 s after its context ended")
	}
}

func TestRun_LogsAScheduledReloadThatFails(t *testing.T) {
	idp := newIdP(t, ecJWK(t, "k1", nil))
	log := &warnRecorder{}
	opts := testOptions()
	opts.Log = log
	opts.RefreshInterval = 20 * time.Millisecond
	set := mustLoad(t, opts, issuer("realm", idp))
	idp.setStatus(http.StatusServiceUnavailable)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		set.Run(ctx)
		close(done)
	}()
	waitFor(t, "the warning about the reload", func() bool { return log.count("trusted providers: reload: ") >= 1 })
	cancel()
	<-done
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

// The issuer of the provider also has the form of a realm of the Keycloak, and
// the Keycloak is not asked.
func TestLookupOrReload_PrefersAProviderToARealmOfTheSameIssuer(t *testing.T) {
	kc := newKeycloak(t)
	idp := newIdP(t, ecJWK(t, "k1", nil))
	provider := direct("external", idp)
	provider.Issuer = "https://idp.example/auth/realms/external"
	set := mustNew(t, Config{Keycloak: &Keycloak{URL: kc.srv.URL}, Providers: []Provider{provider}}, testOptions())
	key, err := set.LookupOrReload(t.Context(), Query{Issuer: provider.Issuer, KID: "k1"})
	if err != nil {
		t.Fatalf("LookupOrReload() error = %v", err)
	}
	if key.Provider.ID != "external" {
		t.Errorf("Provider.ID = %q, want %q", key.Provider.ID, "external")
	}
	if got := kc.loadCount(); got != 0 {
		t.Errorf("discovery requests to the Keycloak = %d, want 0", got)
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

// The provider publishes key-2 after the first load, as a rotation does;
// key-1 is the control that the first load already loaded.
func TestLookupOrReload_ReloadsForAKIDNoLoadedKeyHas(t *testing.T) {
	tests := []struct {
		name        string
		kid         string
		discoveries int
	}{
		{"kid of the first load", "key-1", 1},
		{"kid published after the first load", "key-2", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newIdP(t, ecJWK(t, "key-1", nil))
			provider := issuer("realm", idp)
			set := mustLoad(t, testOptions(), provider)
			idp.publish(ecJWK(t, "key-1", nil), ecJWK(t, "key-2", nil))
			if _, err := set.LookupOrReload(t.Context(), Query{Issuer: provider.Issuer, KID: tt.kid}); err != nil {
				t.Errorf("LookupOrReload(%q) error = %v, want none", tt.kid, err)
			}
			if got := idp.discoveries(); got != tt.discoveries {
				t.Errorf("discovery requests after LookupOrReload(%q) = %d, want %d", tt.kid, got, tt.discoveries)
			}
		})
	}
}

// The provider publishes key-2 after the first reload, within the minute in
// which no other reload starts. The discovery requests count the reloads
// after the first load.
func TestLookupOrReload_ReloadsAProviderAtMostOnceAMinute(t *testing.T) {
	idp := newIdP(t, ecJWK(t, "key-1", nil))
	first := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	now := first
	opts := testOptions()
	opts.now = func() time.Time { return now }
	provider := issuer("realm", idp)
	set := mustLoad(t, opts, provider)
	lookup := func(at time.Duration, kid string, wantFound bool, wantDiscoveries int) {
		t.Helper()
		now = first.Add(at)
		_, err := set.LookupOrReload(t.Context(), Query{Issuer: provider.Issuer, KID: kid})
		if got := idp.discoveries(); (err == nil) != wantFound || got != wantDiscoveries {
			t.Errorf("%s after the first reload, LookupOrReload(%q) error = %v with %d discovery requests, want found = %t with %d",
				at, kid, err, got, wantFound, wantDiscoveries)
		}
	}
	lookup(0, "unknown", false, 2)
	idp.publish(ecJWK(t, "key-1", nil), ecJWK(t, "key-2", nil))
	lookup(59*time.Second, "key-2", false, 2)
	lookup(60*time.Second, "key-2", true, 3)
}

// Every case has loaded keys before the reload, and each row shows what that
// reload gets. TestLookupOrReload_TakesA404AsAnAnswerOnlyForARealmWithNoKeys
// covers the 404 of a realm.
func TestLookupOrReload_ReportsKeysAsUnavailableOnlyWhenTheSourceGaveNoAnswer(t *testing.T) {
	tests := []struct {
		name   string
		reload func(idp *fakeIdP)
		want   error
	}{
		{"server error", func(idp *fakeIdP) { idp.setStatus(http.StatusServiceUnavailable) }, ErrKeysUnavailable},
		{"refused request", func(idp *fakeIdP) { idp.setStatus(http.StatusForbidden) }, ErrKeysUnavailable},
		{"no connection", func(idp *fakeIdP) { idp.srv.Close() }, ErrKeysUnavailable},
		{"JWKS that is not JSON", func(idp *fakeIdP) { idp.setJWKS("not json") }, ErrKeysUnavailable},
		{"JWKS whose keys is null", func(idp *fakeIdP) { idp.setJWKS(`{"keys": null}`) }, ErrKeysUnavailable},
		{"404 from a provider", func(idp *fakeIdP) { idp.setStatus(http.StatusNotFound) }, ErrKeysUnavailable},
		{"JWKS without a usable key", func(idp *fakeIdP) { idp.setJWKS(`{"keys": []}`) }, ErrKeyUnknown},
		{"JWKS without the key", func(*fakeIdP) {}, ErrKeyUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newIdP(t, ecJWK(t, "key-1", nil))
			provider := issuer("realm", idp)
			set := mustLoad(t, testOptions(), provider)
			tt.reload(idp)
			if _, err := set.LookupOrReload(t.Context(), Query{Issuer: provider.Issuer, KID: "rotated"}); !errors.Is(err, tt.want) {
				t.Errorf("LookupOrReload() error = %v, want %v", err, tt.want)
			}
		})
	}
}

// A provider that never loaded a key has no key to keep, so only the rule for a
// provider makes its 404 no answer.
func TestLookupOrReload_TakesA404OfAProviderWithNoKeysAsNoAnswer(t *testing.T) {
	idp := newIdP(t)
	idp.setStatus(http.StatusNotFound)
	provider := issuer("realm", idp)
	set := mustNew(t, Config{Providers: []Provider{provider}}, testOptions())
	if _, err := set.LookupOrReload(t.Context(), Query{Issuer: provider.Issuer, KID: "k1"}); !errors.Is(err, ErrKeysUnavailable) {
		t.Errorf("LookupOrReload() error = %v, want %v", err, ErrKeysUnavailable)
	}
}

// sequencedJWKS answers discovery at once and each JWKS request from bodies,
// by the order of arrival, and holds a request whose gate is set. A request
// reports its number on arrived before it is held.
type sequencedJWKS struct {
	srv     *httptest.Server
	bodies  map[int][]byte
	status  map[int]int
	gates   map[int]chan struct{}
	arrived chan int

	mu sync.Mutex
	n  int
}

func newSequencedJWKS(t *testing.T) *sequencedJWKS {
	t.Helper()
	s := &sequencedJWKS{bodies: map[int][]byte{}, status: map[int]int{}, gates: map[int]chan struct{}{}, arrived: make(chan int, 16)}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": s.srv.URL + "/jwks"})
			return
		}
		s.mu.Lock()
		s.n++
		i := s.n
		s.mu.Unlock()
		s.arrived <- i
		if gate := s.gates[i]; gate != nil {
			<-gate
		}
		if status := s.status[i]; status != 0 {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write(s.bodies[i])
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func jwksOf(t *testing.T, keys ...json.RawMessage) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// A scheduled Refresh holds the lock of the source while it stores two RSA keys,
// and the reload that their kid starts queues behind it. The wait can end before
// that reload does, or the reload can fail. Neither says that the keys cannot be
// loaded, because they have just arrived.
func TestLookupOrReload_FindsAKeyThatARefreshBroughtDuringTheWait(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		held       bool
		reloadWait time.Duration
	}{
		{"the wait runs out", 0, true, 300 * time.Millisecond},
		{"the reload fails", http.StatusServiceUnavailable, false, 5 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newSequencedJWKS(t)
			two := jwksOf(t, rsaJWK(t, 2048, "r1", nil), rsaJWK(t, 2048, "r2", nil))
			server.bodies[1], server.bodies[2], server.bodies[3] = jwksOf(t, ecJWK(t, "ec", nil)), two, two
			server.status[3] = tt.status
			refreshGate, reloadGate := make(chan struct{}), make(chan struct{})
			server.gates[2] = refreshGate
			if tt.held {
				server.gates[3] = reloadGate
			}
			t.Cleanup(sync.OnceFunc(func() { close(reloadGate) }))
			opts := testOptions()
			opts.ReloadWait = tt.reloadWait
			provider := Provider{ID: "p", Issuer: server.srv.URL}
			set := mustLoad(t, opts, provider)
			<-server.arrived

			refreshed := make(chan error, 1)
			go func() { refreshed <- set.Refresh(t.Context()) }()
			<-server.arrived
			looked := make(chan error, 1)
			go func() {
				_, err := set.LookupOrReload(t.Context(), Query{Issuer: provider.Issuer, KID: "r1"})
				looked <- err
			}()
			src := set.providers[provider.Issuer]
			waitFor(t, "the reload for the token to start", func() bool {
				src.onDemand.mu.Lock()
				defer src.onDemand.mu.Unlock()
				return src.onDemand.running != nil
			})
			close(refreshGate)
			if err := <-refreshed; err != nil {
				t.Fatalf("Refresh() error = %v", err)
			}
			if err := <-looked; err != nil {
				t.Errorf("LookupOrReload() error = %v, want none", err)
			}
		})
	}
}

// The lookup at 59 s falls in the minute in which no reload starts, so it has
// only the answer of the failed load. A key already loaded stays usable
// throughout, and the load at 60 s answers.
func TestLookupOrReload_ReportsKeysAsUnavailableUntilALoadAnswers(t *testing.T) {
	idp := newIdP(t, ecJWK(t, "key-1", nil))
	first := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	now := first
	opts := testOptions()
	opts.now = func() time.Time { return now }
	provider := issuer("realm", idp)
	set := mustLoad(t, opts, provider)
	idp.setStatus(http.StatusServiceUnavailable)
	lookup := func(at time.Duration, kid string, want error) {
		t.Helper()
		now = first.Add(at)
		if _, err := set.LookupOrReload(t.Context(), Query{Issuer: provider.Issuer, KID: kid}); !errors.Is(err, want) {
			t.Errorf("%s after the outage began, LookupOrReload(%q) error = %v, want %v", at, kid, err, want)
		}
	}
	lookup(0, "rotated", ErrKeysUnavailable)
	lookup(59*time.Second, "rotated", ErrKeysUnavailable)
	lookup(59*time.Second, "key-1", nil)
	idp.setStatus(0)
	lookup(60*time.Second, "rotated", ErrKeyUnknown)
}

// The JWKS response is held, so the reload the call starts is still running
// when the call returns.
func TestLookupOrReload_StopsWaitingWhenItsContextEnds(t *testing.T) {
	idp := newIdP(t, ecJWK(t, "key-1", nil))
	provider := issuer("realm", idp)
	set := mustLoad(t, testOptions(), provider)
	idp.publish(ecJWK(t, "key-1", nil), ecJWK(t, "key-2", nil))
	gate := make(chan struct{})
	idp.setGate(gate)
	release := sync.OnceFunc(func() { close(gate) })
	t.Cleanup(release)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	returned := make(chan error, 1)
	go func() {
		_, err := set.LookupOrReload(ctx, Query{Issuer: provider.Issuer, KID: "key-2"})
		returned <- err
	}()
	select {
	case err := <-returned:
		if !errors.Is(err, ErrKeysUnavailable) {
			t.Errorf("LookupOrReload(%q) with an ended context error = %v while the reload was held, want %v", "key-2", err, ErrKeysUnavailable)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("LookupOrReload(%q) with an ended context did not return within 5 s while the reload was held", "key-2")
	}
	release()
	waitFor(t, "the reload to load key-2", func() bool { return loaded(set, provider, "key-2") })
}

// The JWKS response is held past ReloadWait, and the context of the call lasts.
func TestLookupOrReload_StopsWaitingAfterTheReloadWait(t *testing.T) {
	idp := newIdP(t, ecJWK(t, "key-1", nil))
	provider := issuer("realm", idp)
	opts := testOptions()
	opts.ReloadWait = 20 * time.Millisecond
	set := mustLoad(t, opts, provider)
	idp.publish(ecJWK(t, "key-1", nil), ecJWK(t, "key-2", nil))
	gate := make(chan struct{})
	idp.setGate(gate)
	release := sync.OnceFunc(func() { close(gate) })
	t.Cleanup(release)
	if _, err := set.LookupOrReload(t.Context(), Query{Issuer: provider.Issuer, KID: "key-2"}); !errors.Is(err, ErrKeysUnavailable) {
		t.Errorf("LookupOrReload(%q) error = %v while the reload was held, want %v", "key-2", err, ErrKeysUnavailable)
	}
	release()
	waitFor(t, "the reload to load key-2", func() bool { return loaded(set, provider, "key-2") })
}

func TestLookupOrReload_WarnsWhenTheReloadFails(t *testing.T) {
	tests := []struct {
		name   string
		status int
		warned bool
	}{
		{"provider that answers 503", http.StatusServiceUnavailable, true},
		{"provider that answers", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newIdP(t, ecJWK(t, "key-1", nil))
			log := &warnRecorder{}
			opts := testOptions()
			opts.Log = log
			provider := issuer("realm", idp)
			set := mustLoad(t, opts, provider)
			idp.setStatus(tt.status)
			_, _ = set.LookupOrReload(t.Context(), Query{Issuer: provider.Issuer, KID: "unknown"})
			warned := slices.ContainsFunc(log.warnings, func(w string) bool {
				return containsAll(w, "reload for a token", `provider "realm"`)
			})
			if warned != tt.warned {
				t.Errorf("warned = %t, want %t; warnings: %q", warned, tt.warned, log.warnings)
			}
		})
	}
}
