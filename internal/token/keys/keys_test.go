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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

func TestLoad_IndexesEveryProvidersKeysByKID(t *testing.T) {
	a := newIdP(t, ecJWK(t, "a1", nil))
	b := newIdP(t, ecJWK(t, "b1", nil))
	set := mustLoad(t, testOptions(), issuer("a", a), issuer("b", b))
	for kid, provider := range map[string]string{"a1": "a", "b1": "b"} {
		key, ok := set.Lookup(kid)
		if !ok {
			t.Errorf("Lookup(%q) found nothing, want the key of provider %q", kid, provider)
			continue
		}
		if key.Provider.ID != provider {
			t.Errorf("Lookup(%q).Provider.ID = %q, want %q", kid, key.Provider.ID, provider)
		}
	}
}

func TestLoad_JWKSURISkipsDiscovery(t *testing.T) {
	idp := newIdP(t, ecJWK(t, "k1", nil))
	set := mustLoad(t, testOptions(), direct("k8s", idp))
	if _, ok := set.Lookup("k1"); !ok {
		t.Errorf("Lookup(%q) found nothing, want the key served at jwksUri", "k1")
	}
	if got := idp.discoveries(); got != 0 {
		t.Errorf("discovery requests = %d, want 0", got)
	}
}

// Each case comes first in a JWKS whose next key is usable, so a provider
// that loaded nothing, or stopped at the skipped key, fails the control
// instead of passing the case.
func TestLoad_SkipsAKeyThatCannotSignAnAcceptedToken(t *testing.T) {
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
			idp := newIdP(t, tt.key, ecJWK(t, "control", nil))
			set := mustLoad(t, testOptions(), issuer("realm", idp))
			if _, ok := set.Lookup("case"); ok {
				t.Errorf("Lookup(%q) found a key, want it skipped", "case")
			}
			if _, ok := set.Lookup("control"); !ok {
				t.Errorf("Lookup(%q) found nothing, want the usable key", "control")
			}
		})
	}
}

func TestLoad_AcceptsEverySigningKeyType(t *testing.T) {
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
			set := mustLoad(t, testOptions(), issuer("realm", newIdP(t, tt.key)))
			if _, ok := set.Lookup("k"); !ok {
				t.Errorf("Lookup(%q) found nothing, want the key", "k")
			}
		})
	}
}

// OPA lowers both jwx floors to zero in every binary it is linked into, the
// agent's among them, so the package has to refuse a weak key on its own.
// The control key is 2048 bits with the exponent 65537.
func TestLoad_SkipsAWeakRSAKeyWithTheJWXFloorsLowered(t *testing.T) {
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
			set := mustLoad(t, testOptions(), issuer("realm", newIdP(t, control, tt.key)))
			if _, ok := set.Lookup("case"); ok {
				t.Errorf("Lookup(%q) found a key, want it skipped", "case")
			}
			if _, ok := set.Lookup("control"); !ok {
				t.Errorf("Lookup(%q) found nothing, want the usable key", "control")
			}
		})
	}
}

func TestLoad_AcceptsAJWKSOfExactly1MiB(t *testing.T) {
	idp := newIdP(t)
	idp.jwks = paddedJWKS(ecJWK(t, "k1", nil), maxResponseBytes)
	set := mustLoad(t, testOptions(), issuer("realm", idp))
	if _, ok := set.Lookup("k1"); !ok {
		t.Errorf("Lookup(%q) found nothing, want the key of a JWKS of %d bytes", "k1", maxResponseBytes)
	}
}

func TestLoad_FailsForAProviderWhoseKeysCannotBeRead(t *testing.T) {
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
			opts := testOptions()
			opts.StartupTimeout = 200 * time.Millisecond
			_, err := Load(context.Background(), Config{Providers: []Provider{issuer("realm", idp)}}, opts)
			if err == nil || !strings.Contains(err.Error(), `provider "realm"`) {
				t.Errorf("Load() error = %v, want an error naming provider %q", err, "realm")
			}
		})
	}
}

// k2 is listed after the repeated key, so a load that stops at the repeat
// fails on k2.
func TestLoad_TheSameKeyListedTwiceLoadsOnce(t *testing.T) {
	key := ecJWK(t, "k1", nil)
	set := mustLoad(t, testOptions(), issuer("realm", newIdP(t, key, key, ecJWK(t, "k2", nil))))
	if _, ok := set.Lookup("k1"); !ok {
		t.Errorf("Lookup(%q) found nothing, want the key listed twice", "k1")
	}
	if _, ok := set.Lookup("k2"); !ok {
		t.Errorf("Lookup(%q) found nothing, want the key listed after the repeat", "k2")
	}
}

func TestLoad_AKIDTwoProvidersPublishIsRefused(t *testing.T) {
	a := newIdP(t, ecJWK(t, "shared", nil))
	b := newIdP(t, ecJWK(t, "shared", nil))
	_, err := Load(context.Background(), Config{Providers: []Provider{issuer("a", a), issuer("b", b)}}, testOptions())
	if err == nil || !strings.Contains(err.Error(), `kid "shared"`) {
		t.Errorf("Load() error = %v, want an error naming kid %q", err, "shared")
	}
}

func TestLoad_FailsWhileAnyProviderStaysDown(t *testing.T) {
	up := newIdP(t, ecJWK(t, "k1", nil))
	down1 := newIdP(t)
	down1.setStatus(http.StatusServiceUnavailable)
	down2 := newIdP(t)
	down2.setStatus(http.StatusServiceUnavailable)
	opts := testOptions()
	opts.StartupTimeout = 200 * time.Millisecond
	providers := []Provider{issuer("up", up), issuer("down-1", down1), issuer("down-2", down2)}
	_, err := Load(context.Background(), Config{Providers: providers}, opts)
	if err == nil || !containsAll(err.Error(), `provider "down-1"`, `provider "down-2"`, "HTTP 503") || strings.Contains(err.Error(), `provider "up"`) {
		t.Errorf("Load() error = %v, want an error naming providers %q and %q with HTTP 503, and not provider %q", err, "down-1", "down-2", "up")
	}
}

// The first attempt fails with 503, and the retry hangs on the JWKS until the
// startup timeout cancels it; the error carries the 503, the reason a reader
// can act on.
func TestLoad_ReportsTheLastFailureRatherThanTheTimeout(t *testing.T) {
	idp := newIdP(t, ecJWK(t, "k1", nil))
	idp.failures = 1
	gate := make(chan struct{})
	idp.setGate(gate)
	t.Cleanup(func() { close(gate) })
	opts := testOptions()
	opts.StartupTimeout = 200 * time.Millisecond
	_, err := Load(context.Background(), Config{Providers: []Provider{issuer("realm", idp)}}, opts)
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Errorf("Load() error = %v, want the HTTP 503 of the attempt before the timeout", err)
	}
}

func TestLoad_RetriesAProviderUntilItAnswers(t *testing.T) {
	idp := newIdP(t, ecJWK(t, "k1", nil))
	idp.failures = 2
	set := mustLoad(t, testOptions(), issuer("realm", idp))
	if _, ok := set.Lookup("k1"); !ok {
		t.Errorf("Lookup(%q) found nothing, want the key served after two failures", "k1")
	}
}

func TestLoad_CAFileTrustsAPrivateCertificate(t *testing.T) {
	idp := newTLSIdP(t, ecJWK(t, "k1", nil))
	provider := issuer("realm", idp)
	provider.CAFile = idp.caFile(t)
	set := mustLoad(t, testOptions(), provider)
	if _, ok := set.Lookup("k1"); !ok {
		t.Errorf("Lookup(%q) found nothing, want the key served over TLS", "k1")
	}
}

func TestLoad_TheSystemRootsRejectAPrivateCertificate(t *testing.T) {
	idp := newTLSIdP(t, ecJWK(t, "k1", nil))
	opts := testOptions()
	opts.StartupTimeout = 200 * time.Millisecond
	_, err := Load(context.Background(), Config{Providers: []Provider{issuer("realm", idp)}}, opts)
	var certErr *tls.CertificateVerificationError
	if !errors.As(err, &certErr) {
		t.Errorf("Load() error = %v, want a *tls.CertificateVerificationError without caFile", err)
	}
}

func TestLoad_RefusesAnUnusableCAFile(t *testing.T) {
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
			_, err := Load(context.Background(), Config{Providers: []Provider{provider}}, testOptions())
			if err == nil || !strings.Contains(err.Error(), "caFile") {
				t.Errorf("Load() with caFile %s error = %v, want an error naming caFile", tt.caFile, err)
			}
		})
	}
}

func TestLoad_FailsWithoutAUsableTokenFile(t *testing.T) {
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
			opts := testOptions()
			opts.StartupTimeout = 200 * time.Millisecond
			_, err := Load(context.Background(), Config{Providers: []Provider{provider}}, opts)
			if err == nil || !strings.Contains(err.Error(), "tokenFile") {
				t.Errorf("Load() with tokenFile %s error = %v, want an error naming tokenFile", tt.tokenFile, err)
			}
		})
	}
}

// The token changes between Load and Refresh, as a projected service account
// token does when the kubelet rotates it.
func TestLoad_TokenFileIsReadOnEveryRequest(t *testing.T) {
	idp := newIdP(t, ecJWK(t, "k1", nil))
	idp.token = "first"
	provider := direct("k8s", idp)
	provider.TokenFile = writeFile(t, "token", "first\n")
	set := mustLoad(t, testOptions(), provider)
	if got := idp.authorization(); got != "Bearer first" {
		t.Errorf("Authorization at Load = %q, want %q", got, "Bearer first")
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
		t.Errorf("Authorization at Refresh = %q, want %q", got, "Bearer second")
	}
}

// Each redirect target listens on the same host at another port, where an
// HTTP client still forwards an Authorization header. Only the JWKS request
// carries a token: a provider that names an issuer cannot have a tokenFile.
func TestLoad_DoesNotFollowARedirect(t *testing.T) {
	tests := []struct {
		name     string
		provider func(t *testing.T, redirecting string) Provider
	}{
		{"discovery request", func(_ *testing.T, redirecting string) Provider {
			return Provider{ID: "k8s", Issuer: redirecting}
		}},
		{"JWKS request with the token", func(t *testing.T, redirecting string) Provider {
			return Provider{ID: "k8s", JWKSURI: redirecting + "/jwks", TokenFile: writeFile(t, "token", "sa-token")}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := newIdP(t, ecJWK(t, "k1", nil))
			redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.srv.URL+r.URL.Path, http.StatusFound)
			}))
			t.Cleanup(redirecting.Close)
			provider := tt.provider(t, redirecting.URL)
			opts := testOptions()
			opts.StartupTimeout = 200 * time.Millisecond
			_, err := Load(context.Background(), Config{Providers: []Provider{provider}}, opts)
			if err == nil || !strings.Contains(err.Error(), "HTTP 302") {
				t.Errorf("Load() error = %v, want the HTTP 302 of the redirect", err)
			}
			if got := target.authorization(); got != "" {
				t.Errorf("Authorization at the redirect target = %q, want none", got)
			}
		})
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
	set := mustLoad(t, testOptions(), issuer("realm", idp))
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
		key, ok := set.Lookup(tt.kid)
		if !ok {
			t.Fatalf("Lookup(%q) found nothing", tt.kid)
		}
		if got := key.Allows(tt.alg); got != tt.want {
			t.Errorf("Lookup(%q).Allows(%q) = %t, want %t", tt.kid, tt.alg, got, tt.want)
		}
	}
}

func TestRefresh_AProviderThatFailsKeepsItsKeys(t *testing.T) {
	a := newIdP(t, ecJWK(t, "a-old", nil))
	b := newIdP(t, ecJWK(t, "b-old", nil))
	set := mustLoad(t, testOptions(), issuer("a", a), issuer("b", b))
	a.publish(ecJWK(t, "a-new", nil))
	b.setStatus(http.StatusServiceUnavailable)

	err := set.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), `provider "b"`) {
		t.Errorf("Refresh() error = %v, want an error naming provider %q", err, "b")
	}
	for kid, want := range map[string]bool{"a-new": true, "a-old": false, "b-old": true} {
		if _, ok := set.Lookup(kid); ok != want {
			t.Errorf("Lookup(%q) found = %t, want %t", kid, ok, want)
		}
	}
}

// Provider a fails in each of the two ways Refresh tells apart: a failed
// fetch and a JWKS without a usable key. Provider b is listed after a in the
// configuration.
func TestRefresh_AProviderListedAfterAFailingOneTakesItsNewKeys(t *testing.T) {
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
			set := mustLoad(t, testOptions(), issuer("a", a), issuer("b", b))
			tt.fail(t, a)
			b.publish(ecJWK(t, "b-new", nil))

			_ = set.Refresh(context.Background())
			for kid, want := range map[string]bool{"b-new": true, "b-old": false} {
				if _, ok := set.Lookup(kid); ok != want {
					t.Errorf("Lookup(%q) found = %t, want %t", kid, ok, want)
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
			set := mustLoad(t, testOptions(), issuer("realm", idp))
			tt.serve(t, idp)
			err := set.Refresh(context.Background())
			if (err != nil) != tt.wantKept {
				t.Errorf("Refresh() error = %v, want an error: %t", err, tt.wantKept)
			}
			if _, ok := set.Lookup("old"); ok != tt.wantKept {
				t.Errorf("Lookup(%q) found = %t, want %t", "old", ok, tt.wantKept)
			}
		})
	}
}

func TestRefresh_AKIDCollisionKeepsEveryPreviousKey(t *testing.T) {
	a := newIdP(t, ecJWK(t, "shared", nil))
	b := newIdP(t, ecJWK(t, "b-old", nil))
	set := mustLoad(t, testOptions(), issuer("a", a), issuer("b", b))
	a.publish(ecJWK(t, "shared", nil), ecJWK(t, "a-new", nil))
	b.publish(ecJWK(t, "shared", nil), ecJWK(t, "b-new", nil))

	err := set.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), `kid "shared"`) {
		t.Errorf("Refresh() error = %v, want an error naming kid %q", err, "shared")
	}
	for kid, want := range map[string]bool{"b-old": true, "b-new": false, "a-new": false} {
		if _, ok := set.Lookup(kid); ok != want {
			t.Errorf("Lookup(%q) found = %t, want %t", kid, ok, want)
		}
	}
	if key, ok := set.Lookup("shared"); !ok || key.Provider.ID != "a" {
		t.Errorf("Lookup(%q) = provider %v, found %t; want provider %q", "shared", key.Provider, ok, "a")
	}
}

func TestRun_ReloadsOnTheInterval(t *testing.T) {
	idp := newIdP(t, ecJWK(t, "old", nil))
	opts := testOptions()
	opts.RefreshInterval = 20 * time.Millisecond
	set := mustLoad(t, opts, issuer("realm", idp))
	idp.publish(ecJWK(t, "new", nil))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		set.Run(ctx)
		close(done)
	}()
	waitFor(t, "Run to load the new key", func() bool { _, ok := set.Lookup("new"); return ok })
	cancel()
	<-done
}
