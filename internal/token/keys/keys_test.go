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
	"context"
	"crypto/elliptic"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Both providers publish the kid "shared", so only the issuer tells the two
// keys apart.
func TestLookup_FindsTheKeyOfTheIssuerThatTheQueryNames(t *testing.T) {
	a := newIdP(t, ecJWK(t, "shared", nil))
	b := newIdP(t, ecJWK(t, "shared", nil))
	providerA, providerB := singleOf(IdentityProviderID, a), kubernetesOf(b)
	set := mustNew(t, Config{Providers: []Provider{providerA, providerB}}, testOptions())
	serveKubernetes(set, b.srv)
	if err := set.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
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
			provider := singleOf(IdentityProviderID, newIdP(t, tt.key, ecJWK(t, "control", nil)))
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
			provider := singleOf(IdentityProviderID, newIdP(t, tt.key))
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
			provider := singleOf(IdentityProviderID, newIdP(t, control, tt.key))
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
	provider := singleOf(IdentityProviderID, idp)
	set := mustLoad(t, testOptions(), provider)
	if !loaded(set, provider, "k1") {
		t.Errorf("Lookup(%q) found nothing, want the key of a JWKS of %d bytes", "k1", maxResponseBytes)
	}
}

func TestRefresh_ReportsAProviderWhoseKeysCannotBeRead(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, idp *fakeIdP)
		want  string
	}{
		{"JWKS answers 404", func(t *testing.T, idp *fakeIdP) { idp.status = http.StatusNotFound }, "/jwks: HTTP 404"},
		{"JWKS that is not JSON", func(t *testing.T, idp *fakeIdP) { idp.jwks = []byte(`<html></html>`) }, "invalid character '<'"},
		{"JWKS without a keys array", func(t *testing.T, idp *fakeIdP) { idp.jwks = []byte(`{}`) }, "no keys array"},
		{"JWKS whose keys array is empty", func(t *testing.T, idp *fakeIdP) { idp.jwks = []byte(`{"keys": []}`) }, "the keys array is empty"},
		{"JWKS whose keys is null", func(t *testing.T, idp *fakeIdP) { idp.jwks = []byte(`{"keys": null}`) }, "the keys array is empty"},
		{"JWKS whose keys is an object", func(t *testing.T, idp *fakeIdP) { idp.jwks = []byte(`{"keys": {}}`) }, "keys is not an array"},
		{"usable JWKS one byte over 1 MiB", func(t *testing.T, idp *fakeIdP) {
			idp.jwks = paddedJWKS(ecJWK(t, "k1", nil), maxResponseBytes+1)
		}, "/jwks: response is longer than 1048576 bytes"},
		{"JWKS whose only key has no kid", func(t *testing.T, idp *fakeIdP) {
			idp.keys = []json.RawMessage{ecJWK(t, "", map[string]any{"kid": nil})}
		}, "keys[0]: has no kid"},
		{"JWKS with two different keys under one kid", func(t *testing.T, idp *fakeIdP) {
			idp.keys = []json.RawMessage{ecJWK(t, "twin", nil), ecJWK(t, "twin", nil)}
		}, `kid "twin" names two different keys`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newIdP(t, ecJWK(t, "k1", nil))
			tt.setup(t, idp)
			set := mustNew(t, Config{Providers: []Provider{singleOf(IdentityProviderID, idp)}}, testOptions())
			err := set.Refresh(t.Context())
			if err == nil || !containsAll(err.Error(), `provider "identity-provider" has no keys`, tt.want) {
				t.Errorf("Refresh() error = %v, want an error saying provider %q has no keys: %s", err, IdentityProviderID, tt.want)
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
	provider := singleOf(IdentityProviderID, newIdP(t, key, key, ecJWK(t, "k2", nil)))
	set := mustLoad(t, testOptions(), provider)
	if !loaded(set, provider, "k1") {
		t.Errorf("Lookup(%q) found nothing, want the key listed twice", "k1")
	}
	if !loaded(set, provider, "k2") {
		t.Errorf("Lookup(%q) found nothing, want the key listed after the repeat", "k2")
	}
}

func TestRefresh_NamesEveryProviderThatStaysDown(t *testing.T) {
	down1 := newIdP(t)
	down1.setStatus(http.StatusServiceUnavailable)
	down2 := newIdP(t)
	down2.setStatus(http.StatusServiceUnavailable)
	set := mustNew(t, Config{Providers: []Provider{singleOf(IdentityProviderID, down1), kubernetesOf(down2)}}, testOptions())
	serveKubernetes(set, down2.srv)
	err := set.Refresh(t.Context())
	if err == nil || !containsAll(err.Error(), `provider "identity-provider"`, `provider "kubernetes"`, "HTTP 503") {
		t.Errorf("Refresh() error = %v, want an error naming providers %q and %q with HTTP 503", err, IdentityProviderID, KubernetesID)
	}
}

// The test server signs its certificate with a CA that only the test holds,
// so the roots of the system refuse it.
func TestRefresh_TrustsTheRootsOfTheSystemAlone(t *testing.T) {
	set := mustNew(t, Config{Providers: []Provider{singleOf(IdentityProviderID, newTLSIdP(t, ecJWK(t, "k1", nil)))}}, testOptions())
	var certErr *tls.CertificateVerificationError
	if err := set.Refresh(t.Context()); !errors.As(err, &certErr) {
		t.Errorf("Refresh() error = %v, want a *tls.CertificateVerificationError", err)
	}
}

// The token file holds a token when New reads it, and loses it before the
// request reads it again.
func TestRefresh_FailsWithoutAUsableTokenFile(t *testing.T) {
	tests := []struct {
		name string
		lose func(path string) error
	}{
		{"emptied file", func(path string) error { return os.WriteFile(path, []byte("\n"), 0o600) }},
		{"removed file", os.Remove},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newIdP(t, ecJWK(t, "k1", nil))
			provider := kubernetesOf(idp)
			provider.JWKSBearerTokenFile = writeFile(t, "token", "sa-token")
			set := mustNew(t, Config{Providers: []Provider{provider}}, testOptions())
			serveKubernetes(set, idp.srv)
			if err := tt.lose(provider.JWKSBearerTokenFile); err != nil {
				t.Fatal(err)
			}
			if err := set.Refresh(t.Context()); err == nil || !strings.Contains(err.Error(), "jwksBearerTokenFile") {
				t.Errorf("Refresh() error = %v, want an error naming jwksBearerTokenFile", err)
			}
			if got := idp.requestCount(); got != 0 {
				t.Errorf("Refresh() sent %d requests for the keys, want none", got)
			}
		})
	}
}

// The token changes between two reloads, as a projected service account token
// does when the kubelet rotates it.
func TestRefresh_TokenFileIsReadOnEveryRequest(t *testing.T) {
	idp := newIdP(t, ecJWK(t, "k1", nil))
	idp.token = "first"
	provider := kubernetesOf(idp)
	provider.JWKSBearerTokenFile = writeFile(t, "token", "first\n")
	set := mustNew(t, Config{Providers: []Provider{provider}}, testOptions())
	serveKubernetes(set, idp.srv)
	if err := set.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if got := idp.authorization(); got != "Bearer first" {
		t.Errorf("Authorization at the first reload = %q, want %q", got, "Bearer first")
	}
	if err := os.WriteFile(provider.JWKSBearerTokenFile, []byte("second"), 0o600); err != nil {
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

func TestRefresh_ReadsTheKeysOfTheProviderKubernetesWithoutATokenOutsideTheCluster(t *testing.T) {
	idp := newIdP(t, ecJWK(t, "k1", nil))
	provider := kubernetesOf(idp)
	provider.JWKSURI = "https://oidc.example/jwks"
	set := mustNew(t, Config{Providers: []Provider{provider}}, testOptions())
	serveKubernetes(set, idp.srv)
	if err := set.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if !loaded(set, provider, "k1") {
		t.Errorf("Lookup(%q) found nothing, want the key of %s", "k1", provider.JWKSURI)
	}
	if got := idp.authorization(); got != "" {
		t.Errorf("Authorization at %s = %q, want none", provider.JWKSURI, got)
	}
}

// The redirect target has the host of the jwksUri at another port, where an
// HTTP client still forwards an Authorization header. The transport of the
// test sends the requests to that port to the target server.
func TestRefresh_DoesNotFollowARedirect(t *testing.T) {
	target := newIdP(t, ecJWK(t, "k1", nil))
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://kubernetes.default.svc:8443/jwks", http.StatusFound)
	}))
	t.Cleanup(redirecting.Close)
	provider := Provider{
		ID:                  KubernetesID,
		Type:                Single,
		Issuer:              redirecting.URL,
		JWKSURI:             "https://kubernetes.default.svc/jwks",
		JWKSBearerTokenFile: writeFile(t, "token", "sa-token"),
	}
	set := mustNew(t, Config{Providers: []Provider{provider}}, testOptions())
	routeKubernetes(set, roundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Port() == "8443" {
			return toServer{target.srv}.RoundTrip(r)
		}
		return toServer{redirecting}.RoundTrip(r)
	}))
	if err := set.Refresh(t.Context()); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Errorf("Refresh() error = %v, want the HTTP 302 of the redirect", err)
	}
	if got := target.authorization(); got != "" {
		t.Errorf("Authorization at the redirect target = %q, want none", got)
	}
}

// errorBody is a response body that fails every read.
type errorBody struct{}

func (errorBody) Read([]byte) (int, error) { return 0, errors.New("connection reset by peer") }
func (errorBody) Close() error             { return nil }

func TestRefresh_ReportsABodyItCannotRead(t *testing.T) {
	provider := providerOf(IdentityProviderID)
	transport := roundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: errorBody{}}, nil
	})
	set := bubbleSetOf(t, Config{Providers: []Provider{provider}}, testOptions(), transport)
	if err := set.Refresh(t.Context()); err == nil || !strings.Contains(err.Error(), "GET https://idp.test/jwks: read body: connection reset by peer") {
		t.Errorf("Refresh() error = %v, want an error saying that the body of the JWKS could not be read", err)
	}
}

// roundTripper turns a function into an http.RoundTripper.
type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Replacing k1 with k3 keeps the count of keys, so only the change of a kid
// can make that load log.
func TestRefresh_LogsTheSigningKeysOfASourceWhenTheirKidsChange(t *testing.T) {
	k1, k2, k3 := ecJWK(t, "k1", nil), ecJWK(t, "k2", nil), ecJWK(t, "k3", nil)
	idp := newIdP(t, k1)
	log := &warnRecorder{}
	opts := testOptions()
	opts.Log = log
	set := mustNew(t, Config{Providers: []Provider{singleOf(IdentityProviderID, idp)}}, opts)
	steps := []struct {
		name string
		keys []json.RawMessage
		want []string
	}{
		{"first load", []json.RawMessage{k1}, []string{`trusted providers: provider "identity-provider" now publishes 1 signing key`}},
		{"load of the same key", []json.RawMessage{k1}, nil},
		{"load of a second key", []json.RawMessage{k1, k2}, []string{`trusted providers: provider "identity-provider" now publishes 2 signing keys`}},
		{"load of the two keys in the other order", []json.RawMessage{k2, k1}, nil},
		{"load that replaces a key", []json.RawMessage{k2, k3}, []string{`trusted providers: provider "identity-provider" now publishes 2 signing keys`}},
	}
	for _, step := range steps {
		idp.publish(step.keys...)
		log.infos = nil
		if err := set.Refresh(t.Context()); err != nil {
			t.Fatalf("Refresh() on the %s error = %v", step.name, err)
		}
		if !slices.Equal(log.infos, step.want) {
			t.Errorf("informational messages of the %s = %q, want %q", step.name, log.infos, step.want)
		}
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
	provider := singleOf(IdentityProviderID, idp)
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
	providerA, providerB := singleOf(IdentityProviderID, a), kubernetesOf(b)
	set := mustNew(t, Config{Providers: []Provider{providerA, providerB}}, testOptions())
	serveKubernetes(set, b.srv)
	if err := set.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	a.publish(ecJWK(t, "a-new", nil))
	b.setStatus(http.StatusServiceUnavailable)

	err := set.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), `provider "kubernetes"`) || strings.Contains(err.Error(), `provider "identity-provider"`) {
		t.Errorf("Refresh() error = %v, want an error naming provider %q and not provider %q", err, KubernetesID, IdentityProviderID)
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
			providerB := kubernetesOf(b)
			set := mustNew(t, Config{Providers: []Provider{singleOf(IdentityProviderID, a), providerB}}, testOptions())
			serveKubernetes(set, b.srv)
			if err := set.Refresh(t.Context()); err != nil {
				t.Fatalf("Refresh() error = %v", err)
			}
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
			provider := singleOf(IdentityProviderID, idp)
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
// skipped key is the same key wherever the JWKS lists it, two keys without a
// kid are two keys although their reason reads alike, and a key listed twice
// counts twice. A load that skips no key warns about nothing.
func TestRefresh_WarnsAboutSkippedKeysOnlyWhenTheyChange(t *testing.T) {
	signing, rotated, enc := ecJWK(t, "k1", nil), ecJWK(t, "k2", nil), ecJWK(t, "enc", map[string]any{"use": "enc"})
	weak := rsaJWK(t, 1024, "weak", nil)
	noKID, otherNoKID := ecJWK(t, "", map[string]any{"kid": nil}), ecJWK(t, "", map[string]any{"kid": nil})
	idp := newIdP(t, signing, enc)
	log := &warnRecorder{}
	opts := testOptions()
	opts.Log = log
	set := mustLoad(t, opts, singleOf(IdentityProviderID, idp))
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
		{"load that lists the weak key twice beside the first key without a kid", []json.RawMessage{signing, rotated, enc, weak, weak, noKID}, 6},
		{"load that lists the first key without a kid once and the other twice", []json.RawMessage{signing, rotated, enc, noKID, otherNoKID, otherNoKID}, 7},
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
	set := mustNew(t, Config{Providers: []Provider{singleOf(IdentityProviderID, idp)}}, opts)
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
	mustLoad(t, opts, singleOf(IdentityProviderID, newIdP(t, keys...)))
	want := `trusted providers: provider "identity-provider" skips 7 keys of its JWKS: ` +
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
	set := mustLoad(t, opts, singleOf(IdentityProviderID, idp))
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
	set := mustNew(t, Config{Providers: []Provider{singleOf(IdentityProviderID, idp)}}, testOptions())
	err := set.Refresh(t.Context())
	if err == nil || strings.Contains(err.Error(), "\n") || !strings.Contains(err.Error(), `keys[0]: cannot be parsed: "`) {
		t.Errorf("Refresh() error = %q, want one line that quotes the parser error of keys[0]", err)
	}
}

// The sources come in an order that is neither by id nor by kind: realm d
// before realm b, which fails before realm c, and provider kubernetes before
// provider identity-provider, whose ids both sort before realm/cloud-common.
// Realm d keeps its keys, and realm a reloaded.
func TestJoinReloadErrors_OrdersItsLinesWhateverTheOrderOfTheSources(t *testing.T) {
	sourceOf := func(from Source, required bool) *source {
		return &source{fetcher: &fetcher{source: from}, required: required}
	}
	idp := &Provider{ID: IdentityProviderID}
	realmOf := func(name string, required bool) *source {
		return sourceOf(Source{Provider: idp, Realm: name}, required)
	}
	d := realmOf("d", false)
	d.current.Store(&loadResult{keys: []Key{{ID: "k1"}}})
	sources := []*source{
		d,
		realmOf("b", false),
		realmOf("a", false),
		realmOf("c", false),
		realmOf("cloud-common", true),
		sourceOf(Source{Provider: &Provider{ID: KubernetesID}}, true),
		sourceOf(Source{Provider: idp}, true),
	}
	errs := []error{errors.New("d failed"), errors.New("b failed"), nil, errors.New("c failed"), errors.New("cloud-common failed"), errors.New("kubernetes failed"), errors.New("identity-provider failed")}
	want := "identity-provider failed\nkubernetes failed\ncloud-common failed\n" +
		"3 of 4 realms outside readinessRealms did not reload, 2 of them without keys; the first by name: b failed"
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
			set := mustNew(t, Config{Providers: []Provider{singleOf(IdentityProviderID, idp)}}, testOptions())
			err := set.Refresh(t.Context())
			if err == nil || !containsAll(err.Error(), tt.want...) || !strings.HasSuffix(err.Error(), tt.want[len(tt.want)-1]) {
				t.Errorf("Refresh() error = %v, want it to contain %q and end with the last", err, tt.want)
			}
		})
	}
}

func TestReady_StaysTrueWhenAReloadFails(t *testing.T) {
	idp := newIdP(t, ecJWK(t, "k1", nil))
	set := mustLoad(t, testOptions(), singleOf(IdentityProviderID, idp))
	idp.setStatus(http.StatusServiceUnavailable)
	if err := set.Refresh(t.Context()); err == nil {
		t.Fatalf("Refresh() error = nil, want the HTTP 503")
	}
	if !set.Ready() {
		t.Errorf("Ready() after a failed reload = false, want true")
	}
}

func TestLookup_RefusesAnIssuerNoProviderHasByteForByte(t *testing.T) {
	provider := singleOf(IdentityProviderID, newIdP(t, ecJWK(t, "k1", nil)))
	set := mustLoad(t, testOptions(), provider)
	for _, iss := range []string{"", provider.Issuer + "/", "https://other.example"} {
		if _, err := set.Lookup(Query{Issuer: iss, KID: "k1"}); !errors.Is(err, ErrIssuerUnknown) {
			t.Errorf("Lookup(issuer %q) error = %v, want %v", iss, err, ErrIssuerUnknown)
		}
	}
}
