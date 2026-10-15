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
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestLoad_IndexesEveryProvidersKeysByKID(t *testing.T) {
	a := newIdP(t, ecJWK(t, "a1", nil))
	b := newIdP(t, ecJWK(t, "b1", nil))
	set := mustLoad(t, testOptions(newClock()), issuer("a", a), issuer("b", b))
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
	set := mustLoad(t, testOptions(newClock()), Provider{ID: "k8s", JWKSURI: idp.srv.URL + "/jwks"})
	if _, ok := set.Lookup("k1"); !ok {
		t.Errorf("Lookup(%q) found nothing, want the key served at jwksUri", "k1")
	}
	if got := idp.discoveries(); got != 0 {
		t.Errorf("discovery requests = %d, want 0", got)
	}
}

// Each case shares its JWKS with a usable key, so a provider that loaded
// nothing at all fails the control instead of passing the case.
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
		{"RSA modulus of 1024 bits", rsaJWK(t, 1024, "case", nil)},
		{"RSA key without a modulus", json.RawMessage(`{"kty": "RSA", "kid": "case", "e": "AQAB"}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newIdP(t, ecJWK(t, "control", nil), tt.key)
			set := mustLoad(t, testOptions(newClock()), issuer("realm", idp))
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
		{"RSA key of 2048 bits with RS256", rsaJWK(t, 2048, "k", nil)},
		{"OKP key with EdDSA", edJWK(t, "k", nil)},
		{"key without use", ecJWK(t, "k", map[string]any{"use": nil})},
		{"key without alg", ecJWK(t, "k", map[string]any{"alg": nil})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := mustLoad(t, testOptions(newClock()), issuer("realm", newIdP(t, tt.key)))
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
			set := mustLoad(t, testOptions(newClock()), issuer("realm", newIdP(t, control, tt.key)))
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
	set := mustLoad(t, testOptions(newClock()), issuer("realm", idp))
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
			opts := testOptions(newClock())
			opts.StartupTimeout = 200 * time.Millisecond
			_, err := Load(context.Background(), Config{Providers: []Provider{issuer("realm", idp)}}, opts)
			if err == nil || !strings.Contains(err.Error(), `provider "realm"`) {
				t.Errorf("Load() error = %v, want an error naming provider %q", err, "realm")
			}
		})
	}
}

func TestLoad_TheSameKeyListedTwiceLoadsOnce(t *testing.T) {
	key := ecJWK(t, "k1", nil)
	set := mustLoad(t, testOptions(newClock()), issuer("realm", newIdP(t, key, key)))
	if _, ok := set.Lookup("k1"); !ok {
		t.Errorf("Lookup(%q) found nothing, want the key listed twice", "k1")
	}
}

func TestLoad_AKIDTwoProvidersPublishIsRefused(t *testing.T) {
	a := newIdP(t, ecJWK(t, "shared", nil))
	b := newIdP(t, ecJWK(t, "shared", nil))
	_, err := Load(context.Background(), Config{Providers: []Provider{issuer("a", a), issuer("b", b)}}, testOptions(newClock()))
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
	opts := testOptions(newClock())
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
	opts := testOptions(newClock())
	opts.StartupTimeout = 200 * time.Millisecond
	_, err := Load(context.Background(), Config{Providers: []Provider{issuer("realm", idp)}}, opts)
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Errorf("Load() error = %v, want the HTTP 503 of the attempt before the timeout", err)
	}
}

func TestLoad_RetriesAProviderUntilItAnswers(t *testing.T) {
	idp := newIdP(t, ecJWK(t, "k1", nil))
	idp.failures = 2
	set := mustLoad(t, testOptions(newClock()), issuer("realm", idp))
	if _, ok := set.Lookup("k1"); !ok {
		t.Errorf("Lookup(%q) found nothing, want the key served after two failures", "k1")
	}
}

func TestLoad_CAFileTrustsAPrivateCertificate(t *testing.T) {
	idp := newTLSIdP(t, ecJWK(t, "k1", nil))
	provider := issuer("realm", idp)
	provider.CAFile = idp.caFile(t)
	set := mustLoad(t, testOptions(newClock()), provider)
	if _, ok := set.Lookup("k1"); !ok {
		t.Errorf("Lookup(%q) found nothing, want the key served over TLS", "k1")
	}
}

func TestLoad_TheSystemRootsRejectAPrivateCertificate(t *testing.T) {
	idp := newTLSIdP(t, ecJWK(t, "k1", nil))
	opts := testOptions(newClock())
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
			_, err := Load(context.Background(), Config{Providers: []Provider{provider}}, testOptions(newClock()))
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
			provider := issuer("k8s", newIdP(t, ecJWK(t, "k1", nil)))
			provider.TokenFile = tt.tokenFile
			opts := testOptions(newClock())
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
	provider := issuer("k8s", idp)
	provider.TokenFile = writeFile(t, "token", "first\n")
	set := mustLoad(t, testOptions(newClock()), provider)
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
// HTTP client still forwards an Authorization header.
func TestLoad_DoesNotFollowARedirectWithTheToken(t *testing.T) {
	tests := []struct {
		name     string
		provider func(redirecting string) Provider
	}{
		{"discovery request", func(redirecting string) Provider { return Provider{ID: "k8s", Issuer: redirecting} }},
		{"JWKS request", func(redirecting string) Provider { return Provider{ID: "k8s", JWKSURI: redirecting + "/jwks"} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := newIdP(t, ecJWK(t, "k1", nil))
			redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.srv.URL+r.URL.Path, http.StatusFound)
			}))
			t.Cleanup(redirecting.Close)
			provider := tt.provider(redirecting.URL)
			provider.TokenFile = writeFile(t, "token", "sa-token")
			opts := testOptions(newClock())
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
	idp := newIdP(t, rsaJWK(t, 2048, "declared", nil), rsaJWK(t, 2048, "undeclared", map[string]any{"alg": nil}))
	set := mustLoad(t, testOptions(newClock()), issuer("realm", idp))
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

// Lookup before Resolve is the control: the rotated key is unknown until a
// reload fetches it.
func TestResolve_AnUnknownKIDReloadsTheKeys(t *testing.T) {
	c := newClock()
	idp := newIdP(t, ecJWK(t, "old", nil))
	set := mustLoad(t, testOptions(c), issuer("realm", idp))
	idp.publish(ecJWK(t, "old", nil), ecJWK(t, "rotated", nil))
	c.advance(DefaultUnknownKeyInterval)
	if _, ok := set.Lookup("rotated"); ok {
		t.Fatalf("Lookup(%q) found a key before any reload", "rotated")
	}
	if _, ok := set.Resolve(context.Background(), "rotated"); !ok {
		t.Errorf("Resolve(%q) found nothing, want the rotated key", "rotated")
	}
}

func TestResolve_DoesNotReloadWithinTheIntervalAfterLoad(t *testing.T) {
	c := newClock()
	idp := newIdP(t, ecJWK(t, "k1", nil))
	set := mustLoad(t, testOptions(c), issuer("realm", idp))
	c.advance(DefaultUnknownKeyInterval - time.Second)
	if _, ok := set.Resolve(context.Background(), "unknown"); ok {
		t.Errorf("Resolve(%q) found a key, want none", "unknown")
	}
	if got := idp.jwksFetches(); got != 1 {
		t.Errorf("JWKS fetches = %d, want 1: the one Load made", got)
	}
}

func TestResolve_DoesNotReloadWithinTheIntervalAfterAReloadItStarted(t *testing.T) {
	c := newClock()
	idp := newIdP(t, ecJWK(t, "k1", nil))
	set := mustLoad(t, testOptions(c), issuer("realm", idp))
	c.advance(DefaultUnknownKeyInterval)
	set.Resolve(context.Background(), "unknown-1")
	c.advance(DefaultUnknownKeyInterval - time.Second)
	set.Resolve(context.Background(), "unknown-2")
	if got := idp.jwksFetches(); got != 2 {
		t.Errorf("JWKS fetches = %d, want 2: one by Load and one by the first Resolve", got)
	}
}

func TestResolve_ReloadsOnceTheIntervalHasPassed(t *testing.T) {
	c := newClock()
	idp := newIdP(t, ecJWK(t, "k1", nil))
	set := mustLoad(t, testOptions(c), issuer("realm", idp))
	c.advance(DefaultUnknownKeyInterval)
	set.Resolve(context.Background(), "unknown")
	if got := idp.jwksFetches(); got != 2 {
		t.Errorf("JWKS fetches = %d, want 2: one by Load and one by Resolve", got)
	}
}

func TestResolve_ConcurrentUnknownKIDsShareOneReload(t *testing.T) {
	c := newClock()
	idp := newIdP(t, ecJWK(t, "k1", nil))
	set := mustLoad(t, testOptions(c), issuer("realm", idp))
	idp.publish(ecJWK(t, "k1", nil), ecJWK(t, "k2", nil))
	gate := make(chan struct{})
	idp.setGate(gate)
	c.advance(DefaultUnknownKeyInterval)

	const callers = 8
	found := make([]bool, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Go(func() { _, found[i] = set.Resolve(context.Background(), "k2") })
	}
	waitFor(t, "the reload to reach the provider", func() bool { return idp.jwksFetches() == 2 })
	close(gate)
	wg.Wait()

	if got := idp.jwksFetches(); got != 2 {
		t.Errorf("JWKS fetches = %d, want 2: one by Load and one shared by %d callers", got, callers)
	}
	for i, ok := range found {
		if !ok {
			t.Errorf("Resolve(%q) in caller %d found nothing, want the key the shared reload fetched", "k2", i)
		}
	}
}

func TestResolve_ACancelledCallerLeavesTheReloadRunning(t *testing.T) {
	c := newClock()
	idp := newIdP(t, ecJWK(t, "k1", nil))
	set := mustLoad(t, testOptions(c), issuer("realm", idp))
	idp.publish(ecJWK(t, "k1", nil), ecJWK(t, "k2", nil))
	gate := make(chan struct{})
	idp.setGate(gate)
	c.advance(DefaultUnknownKeyInterval)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan bool)
	go func() {
		_, ok := set.Resolve(ctx, "k2")
		result <- ok
	}()
	waitFor(t, "the reload to reach the provider", func() bool { return idp.jwksFetches() == 2 })
	cancel()
	if ok := <-result; ok {
		t.Errorf("Resolve(%q) with a cancelled context found a key, want none", "k2")
	}
	close(gate)
	waitFor(t, "the reload to load k2", func() bool { _, ok := set.Lookup("k2"); return ok })
}

func TestRefresh_AProviderThatFailsKeepsItsKeys(t *testing.T) {
	a := newIdP(t, ecJWK(t, "a-old", nil))
	b := newIdP(t, ecJWK(t, "b-old", nil))
	set := mustLoad(t, testOptions(newClock()), issuer("a", a), issuer("b", b))
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

func TestRefresh_AKIDCollisionKeepsEveryPreviousKey(t *testing.T) {
	a := newIdP(t, ecJWK(t, "shared", nil))
	b := newIdP(t, ecJWK(t, "b-old", nil))
	set := mustLoad(t, testOptions(newClock()), issuer("a", a), issuer("b", b))
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
	opts := testOptions(newClock())
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
