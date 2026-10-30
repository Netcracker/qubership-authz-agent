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

package verify

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"

	"authz-agent/internal/token/keys"
)

// start is the time every test begins at.
var start = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

// fakeKeys is a KeyFinder that holds its keys in memory.
type fakeKeys struct {
	mu    sync.Mutex
	byKID map[string]keys.Key
}

func newFakeKeys(signers ...*signer) *fakeKeys {
	f := &fakeKeys{byKID: map[string]keys.Key{}}
	for _, s := range signers {
		f.byKID[s.key.ID] = s.key
	}
	return f
}

func (f *fakeKeys) Lookup(kid string) (keys.Key, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.byKID[kid]
	return k, ok
}

func (f *fakeKeys) set(key keys.Key) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byKID[key.ID] = key
}

func (f *fakeKeys) remove(kid string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.byKID, kid)
}

// signer is a private key and the public keys.Key that verifies its
// signatures.
type signer struct {
	alg     jwa.SignatureAlgorithm
	private any
	key     keys.Key
}

// newSigner returns an ES256 signer whose key provider publishes under kid.
func newSigner(t *testing.T, kid string, provider *keys.Provider) *signer {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signerFor(t, jwa.ES256(), private, &private.PublicKey, kid, provider)
}

func newRSASigner(t *testing.T, alg jwa.SignatureAlgorithm, kid string, provider *keys.Provider) *signer {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return signerFor(t, alg, private, &private.PublicKey, kid, provider)
}

func newEdSigner(t *testing.T, kid string, provider *keys.Provider) *signer {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signerFor(t, jwa.EdDSA(), private, public, kid, provider)
}

func signerFor(t *testing.T, alg jwa.SignatureAlgorithm, private, public any, kid string, provider *keys.Provider) *signer {
	t.Helper()
	key, err := jwk.Import(public)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{alg: alg, private: private, key: keys.Key{Provider: provider, ID: kid, JWK: key}}
}

// republished returns the signer's key as a new jwk.Key value, as a reload
// that fetches the same JWKS again produces.
func (s *signer) republished(t *testing.T) keys.Key {
	t.Helper()
	raw, err := json.Marshal(s.key.JWK)
	if err != nil {
		t.Fatal(err)
	}
	again, err := jwk.ParseKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	key := s.key
	key.JWK = again
	return key
}

// sign returns a compact JWS of claims with the signer's kid.
func (s *signer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return s.signPayload(t, payload, nil)
}

// signWithHeaders returns a compact JWS of claims whose protected header
// holds the signer's kid and each entry of header.
func (s *signer) signWithHeaders(t *testing.T, claims, header map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return s.signPayload(t, payload, header)
}

// signPayload returns a compact JWS of payload, which need not be JSON,
// whose protected header holds the signer's kid and each entry of header.
func (s *signer) signPayload(t *testing.T, payload []byte, header map[string]any) string {
	t.Helper()
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, s.key.ID); err != nil {
		t.Fatal(err)
	}
	for name, value := range header {
		if err := headers.Set(name, value); err != nil {
			t.Fatal(err)
		}
	}
	token, err := jws.Sign(payload, jws.WithKey(s.alg, s.private, jws.WithProtectedHeaders(headers)))
	if err != nil {
		t.Fatal(err)
	}
	return string(token)
}

// unsigned returns header and claims in compact form with a signature of
// zeros, for a token Verify refuses before it checks any signature.
func unsigned(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	return segment(t, header) + "." + segment(t, claims) + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
}

func segment(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// claimsAt returns claims of a token issued at now that expires an hour
// later, with each entry of fields set, or removed when its value is nil.
func claimsAt(now time.Time, fields map[string]any) map[string]any {
	claims := map[string]any{
		"sub": "user-1",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	for name, value := range fields {
		if value == nil {
			delete(claims, name)
		} else {
			claims[name] = value
		}
	}
	return claims
}

// clock is a settable time source for Options.now.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newVerifier returns a Verifier on source whose clock reads start.
func newVerifier(source KeyFinder) (*Verifier, *clock) {
	c := &clock{now: start}
	return New(source, Options{now: c.Now}), c
}

// codeOf returns the Code of an *Error, and "" for nil or any other error.
func codeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
