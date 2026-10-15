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
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"

	"authz-agent/internal/token/keys"
)

func TestVerify_ReturnsTheClaimsOfAValidToken(t *testing.T) {
	realm := &keys.Provider{ID: "realm"}
	s := newSigner(t, "k1", realm)
	v, _ := newVerifier(newFakeKeys(s))
	exp := start.Add(time.Hour)
	raw := s.sign(t, map[string]any{
		"sub":          "user-1",
		"exp":          exp.Unix(),
		"realm_access": map[string]any{"roles": []string{"admin"}},
	})

	tok, err := v.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if tok.Provider != realm || tok.KeyID != "k1" || !tok.Expiry.Equal(exp) {
		t.Errorf("Verify() = provider %q, kid %q, expiry %s; want %q, %q, %s", tok.Provider.ID, tok.KeyID, tok.Expiry, "realm", "k1", exp)
	}
	want := map[string]any{
		"sub":          "user-1",
		"exp":          json.Number("1792069200"),
		"realm_access": map[string]any{"roles": []any{"admin"}},
	}
	if !reflect.DeepEqual(tok.Claims, want) {
		t.Errorf("Verify().Claims = %#v, want %#v", tok.Claims, want)
	}
}

func TestVerify_AcceptsEveryKeyType(t *testing.T) {
	realm := &keys.Provider{ID: "realm"}
	tests := []struct {
		name   string
		signer *signer
	}{
		{"EC key with ES256", newSigner(t, "k", realm)},
		{"RSA key with RS256", newRSASigner(t, jwa.RS256(), "k", realm)},
		{"RSA key with PS256", newRSASigner(t, jwa.PS256(), "k", realm)},
		{"OKP key with EdDSA", newEdSigner(t, "k", realm)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(tt.signer))
			if _, err := v.Verify(context.Background(), tt.signer.sign(t, claimsAt(start, nil))); err != nil {
				t.Errorf("Verify() error = %v, want none", err)
			}
		})
	}
}

func TestVerify_RefusesAMalformedToken(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	header := segment(t, map[string]any{"alg": "ES256", "kid": "k1"})
	tests := []struct {
		name string
		raw  string
	}{
		{"empty token", ""},
		{"two parts", header + "." + segment(t, claimsAt(start, nil))},
		{"five parts, as an encrypted token has", header + ".a.b.c.d"},
		{"header that is not base64url", "%%%." + segment(t, claimsAt(start, nil)) + ".c2ln"},
		{"header that is not JSON", "bm90IGpzb24." + segment(t, claimsAt(start, nil)) + ".c2ln"},
		{"header that is null", "bnVsbA." + segment(t, claimsAt(start, nil)) + ".c2ln"},
		{"kid that is not a string", unsigned(t, map[string]any{"alg": "ES256", "kid": 5}, claimsAt(start, nil))},
		{"payload that is not base64url", header + ".%%%.c2ln"},
		{"signature that is not base64url", header + "." + segment(t, claimsAt(start, nil)) + ".%%%"},
		{"alg that is not a string", unsigned(t, map[string]any{"alg": 256, "kid": "k1"}, claimsAt(start, nil))},
		{"payload that is a JSON array", s.signPayload(t, []byte(`[1, 2]`))},
		{"payload that is null", s.signPayload(t, []byte(`null`))},
		{"payload with data after the object", s.signPayload(t, []byte(`{"exp": 1792069200} {}`))},
		{"exp that is a string", s.sign(t, claimsAt(start, map[string]any{"exp": "tomorrow"}))},
		{"exp of 2^53 seconds", s.sign(t, claimsAt(start, map[string]any{"exp": int64(1) << 53}))},
		{"exp of 1e300 seconds", s.sign(t, claimsAt(start, map[string]any{"exp": 1e300}))},
		{"nbf that is a string", s.sign(t, claimsAt(start, map[string]any{"nbf": "now"}))},
		{"iat that is a string", s.sign(t, claimsAt(start, map[string]any{"iat": "now"}))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(s))
			_, err := v.Verify(context.Background(), tt.raw)
			if got := codeOf(err); got != CodeFormatInvalid {
				t.Errorf("Verify() error = %v, want code %s", err, CodeFormatInvalid)
			}
		})
	}
}

func TestVerify_RefusesAHeaderThatNamesNoUsableKey(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	claims := claimsAt(start, nil)
	tests := []struct {
		name string
		raw  string
		want Code
	}{
		{"alg none", unsigned(t, map[string]any{"alg": "none", "kid": "k1"}, claims), CodeAlgNotAllowed},
		{"alg HS256", unsigned(t, map[string]any{"alg": "HS256", "kid": "k1"}, claims), CodeAlgNotAllowed},
		{"alg the key type does not use", unsigned(t, map[string]any{"alg": "RS256", "kid": "k1"}, claims), CodeAlgNotAllowed},
		{"no kid", unsigned(t, map[string]any{"alg": "ES256"}, claims), CodeKIDMissing},
		{"unknown kid", unsigned(t, map[string]any{"alg": "ES256", "kid": "k2"}, claims), CodeKIDUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(s))
			_, err := v.Verify(context.Background(), tt.raw)
			if got := codeOf(err); got != tt.want {
				t.Errorf("Verify() error = %v, want code %s", err, tt.want)
			}
		})
	}
}

// Every value in a detail that comes from the sender is cut, because the
// detail goes into a log line.
func TestVerify_CutsSenderValuesInTheDetail(t *testing.T) {
	long := strings.Repeat("x", 1000)
	s := newSigner(t, "k1", &keys.Provider{ID: "realm", Audiences: []string{"account"}})
	tests := []struct {
		name string
		raw  string
		want Code
	}{
		{"kid", unsigned(t, map[string]any{"alg": "ES256", "kid": long}, claimsAt(start, nil)), CodeKIDUnknown},
		{"alg", unsigned(t, map[string]any{"alg": long, "kid": "k1"}, claimsAt(start, nil)), CodeAlgNotAllowed},
		{"exp", s.signPayload(t, []byte(`{"exp": 1`+strings.Repeat("0", 1000)+`}`)), CodeFormatInvalid},
		{"aud", s.sign(t, claimsAt(start, map[string]any{"aud": []any{long, long, long, long, long}})), CodeAudienceInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(s))
			_, err := v.Verify(context.Background(), tt.raw)
			if got := codeOf(err); got != tt.want {
				t.Fatalf("Verify() error = %v, want code %s", err, tt.want)
			}
			if size := len(err.Error()); size > 400 {
				t.Errorf("Verify() error is %d bytes, want at most 400: %.120s...", size, err)
			}
		})
	}
}

// A source asked for a key reloads it when the kid is unknown, so a token
// refused on its form or its algorithm must not cost that reload. Every kid
// here is unknown to the source.
func TestVerify_RefusesWithoutAskingForAKey(t *testing.T) {
	header := segment(t, map[string]any{"alg": "ES256", "kid": "random"})
	tests := []struct {
		name string
		raw  string
		want Code
	}{
		{"alg none", unsigned(t, map[string]any{"alg": "none", "kid": "random"}, claimsAt(start, nil)), CodeAlgNotAllowed},
		{"header that is null", "bnVsbA." + segment(t, claimsAt(start, nil)) + ".c2ln", CodeFormatInvalid},
		{"payload that is not base64url", header + ".%%%.c2ln", CodeFormatInvalid},
		{"signature that is not base64url", header + "." + segment(t, claimsAt(start, nil)) + ".%%%", CodeFormatInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := newFakeKeys()
			v, _ := newVerifier(source)
			_, err := v.Verify(context.Background(), tt.raw)
			if got := codeOf(err); got != tt.want {
				t.Errorf("Verify() error = %v, want code %s", err, tt.want)
			}
			if got := source.resolveCount(); got != 0 {
				t.Errorf("Resolve calls = %d, want 0", got)
			}
		})
	}
}

// The expired row is forged as well: the signature is checked before any
// claim, so the forgery is what Verify reports.
func TestVerify_RefusesATokenWhoseSignatureDoesNotVerify(t *testing.T) {
	realm := &keys.Provider{ID: "realm"}
	trusted := newSigner(t, "k1", realm)
	attacker := newSigner(t, "k1", realm)
	valid := trusted.sign(t, claimsAt(start, nil))
	parts := strings.Split(valid, ".")
	tests := []struct {
		name string
		raw  string
	}{
		{"signed by another key under the trusted kid", attacker.sign(t, claimsAt(start, nil))},
		{"payload replaced after signing", parts[0] + "." + segment(t, claimsAt(start, map[string]any{"sub": "admin"})) + "." + parts[2]},
		{"signature of another token", parts[0] + "." + parts[1] + "." + strings.Split(trusted.sign(t, claimsAt(start, map[string]any{"sub": "other"})), ".")[2]},
		{"forged and expired", attacker.sign(t, claimsAt(start, map[string]any{"exp": start.Add(-time.Hour).Unix()}))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(trusted))
			_, err := v.Verify(context.Background(), tt.raw)
			if got := codeOf(err); got != CodeSignatureInvalid {
				t.Errorf("Verify() error = %v, want code %s", err, CodeSignatureInvalid)
			}
			if err != nil && strings.Contains(err.Error(), tt.raw) {
				t.Errorf("Verify() error %q quotes the token", err)
			}
		})
	}
}

func TestVerify_RefusesATokenOutsideItsLifetime(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	beyond := DefaultLeeway + time.Second
	tests := []struct {
		name   string
		fields map[string]any
		want   Code
	}{
		{"no exp", map[string]any{"exp": nil}, CodeExpMissing},
		{"exp passed exactly the leeway ago", map[string]any{"exp": start.Add(-DefaultLeeway).Unix()}, CodeExpired},
		{"exp passed more than the leeway ago", map[string]any{"exp": start.Add(-beyond).Unix()}, CodeExpired},
		{"nbf more than the leeway ahead", map[string]any{"nbf": start.Add(beyond).Unix()}, CodeNotYetValid},
		{"iat more than the leeway ahead", map[string]any{"iat": start.Add(beyond).Unix()}, CodeIATInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(s))
			_, err := v.Verify(context.Background(), s.sign(t, claimsAt(start, tt.fields)))
			if got := codeOf(err); got != tt.want {
				t.Errorf("Verify() error = %v, want code %s", err, tt.want)
			}
		})
	}
}

// Finding the key can wait for a reload; the token expires during that
// wait, beyond the leeway, and the claims are checked after it.
func TestVerify_ChecksTheLifetimeAtTheTimeTheKeyIsFound(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	source := newFakeKeys(s)
	v, c := newVerifier(source)
	source.onResolve = func() { c.advance(time.Minute + DefaultLeeway + time.Second) }
	_, err := v.Verify(context.Background(), s.sign(t, claimsAt(start, map[string]any{"exp": start.Add(time.Minute).Unix()})))
	if got := codeOf(err); got != CodeExpired {
		t.Errorf("Verify() error = %v, want code %s", err, CodeExpired)
	}
}

func TestVerify_ToleratesTheLeewayAroundItsLifetime(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	within := DefaultLeeway - time.Second
	tests := []struct {
		name   string
		fields map[string]any
	}{
		{"exp passed less than the leeway ago", map[string]any{"exp": start.Add(-within).Unix()}},
		{"nbf exactly the leeway ahead", map[string]any{"nbf": start.Add(DefaultLeeway).Unix()}},
		{"iat exactly the leeway ahead", map[string]any{"iat": start.Add(DefaultLeeway).Unix()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(s))
			if _, err := v.Verify(context.Background(), s.sign(t, claimsAt(start, tt.fields))); err != nil {
				t.Errorf("Verify() error = %v, want none", err)
			}
		})
	}
}

func TestVerify_AcceptsAnExpAtTheLargestExactSecond(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	v, _ := newVerifier(newFakeKeys(s))
	if _, err := v.Verify(context.Background(), s.sign(t, claimsAt(start, map[string]any{"exp": int64(1)<<53 - 1}))); err != nil {
		t.Errorf("Verify() with exp 9007199254740991 error = %v, want none", err)
	}
}

func TestVerify_RefusesAnAudienceTheProviderDoesNotList(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm", Audiences: []string{"account"}})
	tests := []struct {
		name string
		aud  any
		want Code
	}{
		{"no aud", nil, CodeAudienceMissing},
		{"aud of another client", "other", CodeAudienceInvalid},
		{"aud that differs in case", "Account", CodeAudienceInvalid},
		{"array of other clients", []any{"x", "y"}, CodeAudienceInvalid},
		{"array with a number", []any{"account", 1}, CodeAudienceInvalid},
		{"aud that is a number", 42, CodeAudienceInvalid},
		{"aud that is an empty array", []any{}, CodeAudienceInvalid},
		{"aud that is null", json.RawMessage("null"), CodeAudienceInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(s))
			_, err := v.Verify(context.Background(), s.sign(t, claimsAt(start, map[string]any{"aud": tt.aud})))
			if got := codeOf(err); got != tt.want {
				t.Errorf("Verify() error = %v, want code %s", err, tt.want)
			}
		})
	}
}

func TestVerify_AcceptsAnAudienceTheProviderAllows(t *testing.T) {
	listed := &keys.Provider{ID: "realm", Audiences: []string{"account"}}
	tests := []struct {
		name     string
		provider *keys.Provider
		aud      any
	}{
		{"aud the provider lists", listed, "account"},
		{"array that holds it", listed, []any{"other", "account"}},
		{"no aud where the provider allows it", &keys.Provider{ID: "realm", Audiences: []string{"account"}, AllowMissingAud: true}, nil},
		{"any aud where the provider lists none", &keys.Provider{ID: "realm"}, "other"},
		{"no aud where the provider lists none", &keys.Provider{ID: "realm"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSigner(t, "k1", tt.provider)
			v, _ := newVerifier(newFakeKeys(s))
			if _, err := v.Verify(context.Background(), s.sign(t, claimsAt(start, map[string]any{"aud": tt.aud}))); err != nil {
				t.Errorf("Verify() error = %v, want none", err)
			}
		})
	}
}

func TestVerify_ServesARepeatedTokenFromTheCache(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	source := newFakeKeys(s)
	v, _ := newVerifier(source)
	raw := s.sign(t, claimsAt(start, nil))
	for range 2 {
		if _, err := v.Verify(context.Background(), raw); err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
	}
	if got := source.resolveCount(); got != 1 {
		t.Errorf("Resolve calls = %d, want 1: the second Verify is served from the cache", got)
	}
}

func TestVerify_WithTheCacheOffChecksEveryTime(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	source := newFakeKeys(s)
	v := New(source, Options{CacheSize: -1, now: func() time.Time { return start }})
	raw := s.sign(t, claimsAt(start, nil))
	for range 2 {
		if _, err := v.Verify(context.Background(), raw); err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
	}
	if got := source.resolveCount(); got != 2 {
		t.Errorf("Resolve calls = %d, want 2", got)
	}
}

func TestVerify_RefusesACachedTokenWhoseKeyIsGone(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	source := newFakeKeys(s)
	v, _ := newVerifier(source)
	raw := s.sign(t, claimsAt(start, nil))
	if _, err := v.Verify(context.Background(), raw); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	source.remove("k1")
	_, err := v.Verify(context.Background(), raw)
	if got := codeOf(err); got != CodeKIDUnknown {
		t.Errorf("Verify() after the key is gone error = %v, want code %s", err, CodeKIDUnknown)
	}
}

func TestVerify_ChecksACachedTokenAgainAfterItsKeyIsReloaded(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	source := newFakeKeys(s)
	v, _ := newVerifier(source)
	raw := s.sign(t, claimsAt(start, nil))
	if _, err := v.Verify(context.Background(), raw); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	source.set(s.republished(t))
	if _, err := v.Verify(context.Background(), raw); err != nil {
		t.Fatalf("Verify() after the reload error = %v", err)
	}
	if got := source.resolveCount(); got != 2 {
		t.Errorf("Resolve calls = %d, want 2: the reloaded key is a new value", got)
	}
}

func TestVerify_AFullCacheRefreshesATokenWhoseKeyWasReloaded(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	source := newFakeKeys(s)
	v := New(source, Options{CacheSize: 1, now: func() time.Time { return start }})
	raw := s.sign(t, claimsAt(start, nil))
	if _, err := v.Verify(context.Background(), raw); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	source.set(s.republished(t))
	for range 2 {
		if _, err := v.Verify(context.Background(), raw); err != nil {
			t.Fatalf("Verify() after the reload error = %v", err)
		}
	}
	if got := source.resolveCount(); got != 2 {
		t.Errorf("Resolve calls = %d, want 2: the check after the reload refreshes the full cache's entry", got)
	}
}

func TestVerify_ServesACachedTokenWithinTheLeewayAfterExp(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	source := newFakeKeys(s)
	v, c := newVerifier(source)
	raw := s.sign(t, claimsAt(start, nil))
	if _, err := v.Verify(context.Background(), raw); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	c.advance(time.Hour + DefaultLeeway - time.Second)
	if _, err := v.Verify(context.Background(), raw); err != nil {
		t.Fatalf("Verify() within the leeway error = %v", err)
	}
	if got := source.resolveCount(); got != 1 {
		t.Errorf("Resolve calls = %d, want 1: the second Verify is served from the cache", got)
	}
}

func TestVerify_RefusesACachedTokenOnceItExpires(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	v, c := newVerifier(newFakeKeys(s))
	raw := s.sign(t, claimsAt(start, nil))
	if _, err := v.Verify(context.Background(), raw); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	c.advance(time.Hour + DefaultLeeway)
	_, err := v.Verify(context.Background(), raw)
	if got := codeOf(err); got != CodeExpired {
		t.Errorf("Verify() after exp error = %v, want code %s", err, CodeExpired)
	}
}

func TestVerify_AFullCacheKeepsNoNewToken(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	source := newFakeKeys(s)
	c := &clock{now: start}
	v := New(source, Options{CacheSize: 1, now: c.Now})
	first := s.sign(t, claimsAt(start, map[string]any{"sub": "first"}))
	second := s.sign(t, claimsAt(start, map[string]any{"sub": "second"}))
	for _, raw := range []string{first, second, second, first} {
		if _, err := v.Verify(context.Background(), raw); err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
	}
	if got := source.resolveCount(); got != 3 {
		t.Errorf("Resolve calls = %d, want 3: the first token cached, the second checked twice", got)
	}
}

func TestVerify_AFullCacheReplacesAnExpiredToken(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	source := newFakeKeys(s)
	c := &clock{now: start}
	v := New(source, Options{CacheSize: 1, now: c.Now})
	short := s.sign(t, claimsAt(start, map[string]any{"exp": start.Add(time.Minute).Unix()}))
	long := s.sign(t, claimsAt(start, nil))
	if _, err := v.Verify(context.Background(), short); err != nil {
		t.Fatalf("Verify(short) error = %v", err)
	}
	c.advance(time.Minute + DefaultLeeway)
	for range 2 {
		if _, err := v.Verify(context.Background(), long); err != nil {
			t.Fatalf("Verify(long) error = %v", err)
		}
	}
	if got := source.resolveCount(); got != 2 {
		t.Errorf("Resolve calls = %d, want 2: the long token took the expired one's place", got)
	}
}

func TestVerify_IsSafeForConcurrentUse(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	v, _ := newVerifier(newFakeKeys(s))
	tokens := []string{
		s.sign(t, claimsAt(start, map[string]any{"sub": "a"})),
		s.sign(t, claimsAt(start, map[string]any{"sub": "b"})),
	}
	errs := make([]error, 16)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Go(func() { _, errs[i] = v.Verify(context.Background(), tokens[i%len(tokens)]) })
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("Verify() in goroutine %d error = %v", i, err)
		}
	}
}
