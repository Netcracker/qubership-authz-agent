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
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"

	"authz-agent/internal/token/keys"
)

// The payload keeps the text of every number, 5.0 among them, and the order
// of every key, as the provider signed it.
func TestVerify_ReturnsAValidTokenAsSigned(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	v, _ := newVerifier(newFakeKeys(s))
	payload := `{"sub":"user-1","level":5.0,"realm_access":{"roles":["admin"],"b":1,"a":2},` +
		`"iss":"https://idp.example/realms/r","iat":1792065600,"exp":1792069200}`
	raw := s.signPayload(t, []byte(payload), nil)

	tok := mustVerify(t, v, raw)
	if got := string(tok.Payload()); got != payload {
		t.Errorf("Payload() = %s, want %s", got, payload)
	}
	if got := tok.Raw(); got != raw {
		t.Errorf("Raw() = %q, want the token Verify received, %q", got, raw)
	}
	if got := tok.ProviderID(); got != "realm" {
		t.Errorf("ProviderID() = %q, want %q", got, "realm")
	}
	if got := tok.KeyID(); got != "k1" {
		t.Errorf("KeyID() = %q, want %q", got, "k1")
	}
	if got := tok.Issuer(); got != "https://idp.example/realms/r" {
		t.Errorf("Issuer() = %q, want %q", got, "https://idp.example/realms/r")
	}
	if got, want := tok.Expiry(), time.Unix(1792069200, 0); !got.Equal(want) {
		t.Errorf("Expiry() = %s, want %s", got, want)
	}
}

// verifyPayload verifies a token of payload, signed by a key of a provider
// that lists no audiences, at start.
func verifyPayload(t *testing.T, payload string) *Token {
	t.Helper()
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	v, _ := newVerifier(newFakeKeys(s))
	return mustVerify(t, v, s.signPayload(t, []byte(payload), nil))
}

// The claims are returned as the payload carries them, whatever their type:
// scope is a number here, level keeps the text 5.0, and tenant-id is null.
func TestToken_StandardHoldsEachClaimAsThePayloadCarriesIt(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    Standard
	}{
		{
			"every claim present",
			`{"sub":"user-1","preferred_username":"alice","realm_access":{"roles":["admin", "viewer"]},` +
				`"scope":5,"level":5.0,"tenant-id":null,"iat":1792065600,"exp":1792069200}`,
			Standard{
				Subject:           json.RawMessage(`"user-1"`),
				PreferredUsername: json.RawMessage(`"alice"`),
				Roles:             json.RawMessage(`["admin", "viewer"]`),
				Scope:             json.RawMessage(`5`),
				Level:             json.RawMessage(`5.0`),
				TenantID:          json.RawMessage(`null`),
			},
		},
		{
			"roles that is a string",
			`{"realm_access":{"roles":"admin"},"iat":1792065600,"exp":1792069200}`,
			Standard{Roles: json.RawMessage(`"admin"`)},
		},
		{"no claim present", `{"iat":1792065600,"exp":1792069200}`, Standard{}},
		{"realm_access that is an array", `{"realm_access":["admin"],"iat":1792065600,"exp":1792069200}`, Standard{}},
		{"realm_access without roles", `{"realm_access":{"role":"admin"},"iat":1792065600,"exp":1792069200}`, Standard{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := verifyPayload(t, tt.payload).Standard(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Standard() = %s, want %s", fields(got), fields(tt.want))
			}
		})
	}
}

// fields formats s with the name of every field, so that a nil field shows
// as a name with nothing after it.
func fields(s Standard) string {
	return fmt.Sprintf("{Subject: %s, PreferredUsername: %s, Roles: %s, Scope: %s, Level: %s, TenantID: %s}",
		s.Subject, s.PreferredUsername, s.Roles, s.Scope, s.Level, s.TenantID)
}

func TestToken_ClaimHoldsATopLevelClaimAsThePayloadCarriesIt(t *testing.T) {
	tok := verifyPayload(t, `{"kubernetes.io":{"namespace":"ns","b":1,"a":2},"iat":1792065600,"exp":1792069200}`)
	tests := []struct {
		name   string
		claim  string
		want   json.RawMessage
		wantOK bool
	}{
		{"claim that is an object", "kubernetes.io", json.RawMessage(`{"namespace":"ns","b":1,"a":2}`), true},
		{"member of a claim", "namespace", nil, false},
		{"claim the payload lacks", "sub", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tok.Claim(tt.claim)
			if !reflect.DeepEqual(got, tt.want) || ok != tt.wantOK {
				t.Errorf("Claim(%q) = %s, %t; want %s, %t", tt.claim, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestToken_IssuerIsTheIssClaimWhenItIsAString(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{"string", `{"iss":"https://idp.example/realms/r","iat":1792065600,"exp":1792069200}`, "https://idp.example/realms/r"},
		{"number", `{"iss":5,"iat":1792065600,"exp":1792069200}`, ""},
		{"null", `{"iss":null,"iat":1792065600,"exp":1792069200}`, ""},
		{"no iss", `{"iat":1792065600,"exp":1792069200}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := verifyPayload(t, tt.payload).Issuer(); got != tt.want {
				t.Errorf("Issuer() of %s = %q, want %q", tt.payload, got, tt.want)
			}
		})
	}
}

// Each row overwrites what one method returned and reads it again: the
// cache shares one Token between callers, so a change one caller makes must
// not reach the next.
func TestToken_ReturnsCopiesThatACallerCannotChange(t *testing.T) {
	tok := verifyPayload(t, `{"sub":"user-1","preferred_username":"alice","realm_access":{"roles":["admin"]},`+
		`"scope":"openid","level":"high","tenant-id":"t1","iat":1792065600,"exp":1792069200}`)
	tests := []struct {
		name string
		read func() []byte
	}{
		{"Payload", func() []byte { return tok.Payload() }},
		{"Claim", func() []byte { raw, _ := tok.Claim("sub"); return raw }},
		{"Standard().Subject", func() []byte { return tok.Standard().Subject }},
		{"Standard().PreferredUsername", func() []byte { return tok.Standard().PreferredUsername }},
		{"Standard().Roles", func() []byte { return tok.Standard().Roles }},
		{"Standard().Scope", func() []byte { return tok.Standard().Scope }},
		{"Standard().Level", func() []byte { return tok.Standard().Level }},
		{"Standard().TenantID", func() []byte { return tok.Standard().TenantID }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first := tt.read()
			want := string(first)
			for i := range first {
				first[i] = 'x'
			}
			if got := string(tt.read()); got != want {
				t.Errorf("%s after the caller overwrote the first result = %s, want %s", tt.name, got, want)
			}
		})
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
			if _, err := v.Verify(tt.signer.sign(t, claimsAt(start, nil))); err != nil {
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
		{"header that is a JSON array", "W10." + segment(t, claimsAt(start, nil)) + ".c2ln"},
		{"kid that is not a string", unsigned(t, map[string]any{"alg": "ES256", "kid": 5}, claimsAt(start, nil))},
		{"payload that is not base64url", header + ".%%%.c2ln"},
		{"signature that is not base64url", header + "." + segment(t, claimsAt(start, nil)) + ".%%%"},
		{"alg that is not a string", unsigned(t, map[string]any{"alg": 256, "kid": "k1"}, claimsAt(start, nil))},
		{"payload that is a JSON array", s.signPayload(t, []byte(`[1, 2]`), nil)},
		{"payload that is null", s.signPayload(t, []byte(`null`), nil)},
		{"payload with data after the object", s.signPayload(t, []byte(`{"exp": 1792069200} {}`), nil)},
		{"exp that is a string", s.sign(t, claimsAt(start, map[string]any{"exp": "tomorrow"}))},
		{"exp of 2^53 seconds", s.sign(t, claimsAt(start, map[string]any{"exp": int64(1) << 53}))},
		{"exp of 1e300 seconds", s.sign(t, claimsAt(start, map[string]any{"exp": 1e300}))},
		{"nbf that is a string", s.sign(t, claimsAt(start, map[string]any{"nbf": "now"}))},
		{"iat that is a string", s.sign(t, claimsAt(start, map[string]any{"iat": "now"}))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(s))
			_, err := v.Verify(tt.raw)
			if codeOf(err) != CodeFormatInvalid {
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
		{"alg the curve of the key does not use", unsigned(t, map[string]any{"alg": "ES512", "kid": "k1"}, claims), CodeAlgNotAllowed},
		{"no kid", unsigned(t, map[string]any{"alg": "ES256"}, claims), CodeKIDMissing},
		{"ALG in place of alg", unsigned(t, map[string]any{"ALG": "ES256", "kid": "k1"}, claims), CodeAlgNotAllowed},
		{"KID in place of kid", unsigned(t, map[string]any{"alg": "ES256", "KID": "k1"}, claims), CodeKIDMissing},
		{"alg that is null", unsigned(t, map[string]any{"alg": nil, "kid": "k1"}, claims), CodeAlgNotAllowed},
		{"kid that is null", unsigned(t, map[string]any{"alg": "ES256", "kid": nil}, claims), CodeKIDMissing},
		{"empty kid", unsigned(t, map[string]any{"alg": "ES256", "kid": ""}, claims), CodeKIDMissing},
		{"unknown kid", unsigned(t, map[string]any{"alg": "ES256", "kid": "k2"}, claims), CodeKIDUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(s))
			_, err := v.Verify(tt.raw)
			if codeOf(err) != tt.want {
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
		{"exp", s.signPayload(t, []byte(`{"aud": "account", "exp": 1`+strings.Repeat("0", 1000)+`}`), nil), CodeFormatInvalid},
		{"aud", s.sign(t, claimsAt(start, map[string]any{"aud": []any{long, long, long, long, long}})), CodeAudienceInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(s))
			_, err := v.Verify(tt.raw)
			if codeOf(err) != tt.want {
				t.Fatalf("Verify() error = %v, want code %s", err, tt.want)
			}
			if size := len(err.Error()); size > 400 {
				t.Errorf("Verify() error is %d bytes, want at most 400: %.120s...", size, err)
			}
		})
	}
}

// Every token here carries a valid signature. A header parameter that crit
// does not name is an extension the service may ignore, and so is one whose
// name differs from crit or b64 in case: those rows verify.
func TestVerify_RefusesATokenWhoseHeaderHasCritOrB64(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	tests := []struct {
		name   string
		header map[string]any
		want   Code
	}{
		{"crit naming an unknown extension", map[string]any{"crit": []string{"x-limit"}, "x-limit": "read-only"}, CodeFormatInvalid},
		{"crit naming b64", map[string]any{"crit": []string{"b64"}, "b64": true}, CodeFormatInvalid},
		{"crit that is an empty array", map[string]any{"crit": []string{}}, CodeFormatInvalid},
		{"extension that crit does not name", map[string]any{"x-limit": "read-only"}, ""},
		{"CRIT, which is not crit", map[string]any{"CRIT": []string{"x-limit"}, "x-limit": "read-only"}, ""},
		{"b64 that is true", map[string]any{"b64": true}, CodeFormatInvalid},
		{"B64, which is not b64", map[string]any{"B64": false}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(s))
			_, err := v.Verify(s.signWithHeaders(t, claimsAt(start, nil), tt.header))
			if codeOf(err) != tt.want {
				t.Errorf("Verify() error = %v, want code %q", err, tt.want)
			}
		})
	}
}

// The header and the form are checked before the key: every kid here is
// unknown to the source, and each token gets the code of its header or
// form, not TOKEN_KID_UNKNOWN.
func TestVerify_RefusesOnTheHeaderBeforeLookingUpTheKID(t *testing.T) {
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
		{"crit naming an unknown extension", unsigned(t, map[string]any{"alg": "ES256", "kid": "random", "crit": []string{"x-limit"}, "x-limit": "read-only"}, claimsAt(start, nil)), CodeFormatInvalid},
		{"crit that is null", unsigned(t, map[string]any{"alg": "ES256", "kid": "random", "crit": nil}, claimsAt(start, nil)), CodeFormatInvalid},
		{"crit that is a string", unsigned(t, map[string]any{"alg": "ES256", "kid": "random", "crit": "x-limit"}, claimsAt(start, nil)), CodeFormatInvalid},
		{"b64 that is false", unsigned(t, map[string]any{"alg": "ES256", "kid": "random", "b64": false}, claimsAt(start, nil)), CodeFormatInvalid},
		{"b64 that is null", unsigned(t, map[string]any{"alg": "ES256", "kid": "random", "b64": nil}, claimsAt(start, nil)), CodeFormatInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := newFakeKeys()
			v, _ := newVerifier(source)
			_, err := v.Verify(tt.raw)
			if codeOf(err) != tt.want {
				t.Errorf("Verify() error = %v, want code %s", err, tt.want)
			}
		})
	}
}

// Every token here also fails a claim check: none carries the aud the
// provider requires, and one has expired. The signature is checked before
// any claim, so the forgery is what Verify reports.
func TestVerify_RefusesATokenWhoseSignatureDoesNotVerify(t *testing.T) {
	realm := &keys.Provider{ID: "realm", Audiences: []string{"account"}}
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
			_, err := v.Verify(tt.raw)
			if codeOf(err) != CodeSignatureInvalid {
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
		{"no iat", map[string]any{"iat": nil}, CodeIATMissing},
		{"iat more than the leeway ahead", map[string]any{"iat": start.Add(beyond).Unix()}, CodeIATInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(s))
			_, err := v.Verify(s.sign(t, claimsAt(start, tt.fields)))
			if codeOf(err) != tt.want {
				t.Errorf("Verify() error = %v, want code %s", err, tt.want)
			}
		})
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
			if _, err := v.Verify(s.sign(t, claimsAt(start, tt.fields))); err != nil {
				t.Errorf("Verify() error = %v, want none", err)
			}
		})
	}
}

func TestVerify_AcceptsAnExpAtTheLargestExactSecond(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	v, _ := newVerifier(newFakeKeys(s))
	if _, err := v.Verify(s.sign(t, claimsAt(start, map[string]any{"exp": int64(1)<<53 - 1}))); err != nil {
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
			_, err := v.Verify(s.sign(t, claimsAt(start, map[string]any{"aud": tt.aud})))
			if codeOf(err) != tt.want {
				t.Errorf("Verify() error = %v, want code %s", err, tt.want)
			}
		})
	}
}

// Every token here is outside its lifetime as well, and the audience is
// what Verify reports.
func TestVerify_RefusesOnTheAudienceBeforeTheLifetime(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm", Audiences: []string{"account"}})
	beyond := DefaultLeeway + time.Second
	tests := []struct {
		name   string
		fields map[string]any
		want   Code
	}{
		{"no aud, expired", map[string]any{"exp": start.Add(-beyond).Unix()}, CodeAudienceMissing},
		{"aud of another client, expired", map[string]any{"aud": "other", "exp": start.Add(-beyond).Unix()}, CodeAudienceInvalid},
		{"aud of another client, no exp", map[string]any{"aud": "other", "exp": nil}, CodeAudienceInvalid},
		{"aud of another client, nbf ahead", map[string]any{"aud": "other", "nbf": start.Add(beyond).Unix()}, CodeAudienceInvalid},
		{"aud of another client, no iat", map[string]any{"aud": "other", "iat": nil}, CodeAudienceInvalid},
		{"aud of another client, iat ahead", map[string]any{"aud": "other", "iat": start.Add(beyond).Unix()}, CodeAudienceInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(s))
			_, err := v.Verify(s.sign(t, claimsAt(start, tt.fields)))
			if codeOf(err) != tt.want {
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
			if _, err := v.Verify(s.sign(t, claimsAt(start, map[string]any{"aud": tt.aud}))); err != nil {
				t.Errorf("Verify() error = %v, want none", err)
			}
		})
	}
}

// mustVerify verifies raw and stops the test when Verify fails.
func mustVerify(t *testing.T, v *Verifier, raw string) *Token {
	t.Helper()
	tok, err := v.Verify(raw)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	return tok
}

// A token served from the cache is the *Token an earlier Verify returned;
// a token checked again is a new one.
func TestVerify_ServesARepeatedTokenFromTheCache(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	v, _ := newVerifier(newFakeKeys(s))
	raw := s.sign(t, claimsAt(start, nil))
	first := mustVerify(t, v, raw)
	if mustVerify(t, v, raw) != first {
		t.Errorf("second Verify returned a new token, want the cached one")
	}
}

func TestVerify_WithTheCacheOffChecksEveryTime(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	v := New(newFakeKeys(s), Options{CacheSize: -1, now: func() time.Time { return start }})
	raw := s.sign(t, claimsAt(start, nil))
	first := mustVerify(t, v, raw)
	if mustVerify(t, v, raw) == first {
		t.Errorf("second Verify returned the first token, want a new check")
	}
}

func TestVerify_RefusesACachedTokenWhoseKeyIsGone(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	source := newFakeKeys(s)
	v, _ := newVerifier(source)
	raw := s.sign(t, claimsAt(start, nil))
	mustVerify(t, v, raw)
	source.remove("k1")
	_, err := v.Verify(raw)
	if codeOf(err) != CodeKIDUnknown {
		t.Errorf("Verify() after the key is gone error = %v, want code %s", err, CodeKIDUnknown)
	}
}

// A reload that fetches the same JWKS again yields a new key value.
func TestVerify_ChecksACachedTokenAgainAfterItsKeyIsReloaded(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	source := newFakeKeys(s)
	v, _ := newVerifier(source)
	raw := s.sign(t, claimsAt(start, nil))
	first := mustVerify(t, v, raw)
	source.set(s.republished(t))
	if mustVerify(t, v, raw) == first {
		t.Errorf("Verify after the reload returned the cached token, want a new check")
	}
}

func TestVerify_AFullCacheRefreshesATokenWhoseKeyWasReloaded(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	source := newFakeKeys(s)
	v := New(source, Options{CacheSize: 1, now: func() time.Time { return start }})
	raw := s.sign(t, claimsAt(start, nil))
	mustVerify(t, v, raw)
	source.set(s.republished(t))
	rechecked := mustVerify(t, v, raw)
	if mustVerify(t, v, raw) != rechecked {
		t.Errorf("Verify after the recheck returned a new token, want the refreshed cache entry")
	}
}

func TestVerify_ServesACachedTokenWithinTheLeewayAfterExp(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	v, c := newVerifier(newFakeKeys(s))
	raw := s.sign(t, claimsAt(start, nil))
	first := mustVerify(t, v, raw)
	c.advance(time.Hour + DefaultLeeway - time.Second)
	if mustVerify(t, v, raw) != first {
		t.Errorf("Verify within the leeway returned a new token, want the cached one")
	}
}

func TestVerify_RefusesACachedTokenOnceItExpires(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	v, c := newVerifier(newFakeKeys(s))
	raw := s.sign(t, claimsAt(start, nil))
	mustVerify(t, v, raw)
	c.advance(time.Hour + DefaultLeeway)
	_, err := v.Verify(raw)
	if codeOf(err) != CodeExpired {
		t.Errorf("Verify() after exp error = %v, want code %s", err, CodeExpired)
	}
}

// The cache holds two tokens. Reading a again makes b the token used least
// recently, so c takes the place of b, and a stays cached.
func TestVerify_AFullCacheReplacesTheTokenUsedLeastRecently(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	v := New(newFakeKeys(s), Options{CacheSize: 2, now: func() time.Time { return start }})
	a := s.sign(t, claimsAt(start, map[string]any{"sub": "a"}))
	b := s.sign(t, claimsAt(start, map[string]any{"sub": "b"}))
	c := s.sign(t, claimsAt(start, map[string]any{"sub": "c"}))
	cachedA := mustVerify(t, v, a)
	cachedB := mustVerify(t, v, b)
	mustVerify(t, v, a)
	mustVerify(t, v, c)
	if mustVerify(t, v, a) != cachedA {
		t.Errorf("Verify(a) returned a new token, want the cached one")
	}
	if mustVerify(t, v, b) == cachedB {
		t.Errorf("Verify(b) returned the cached token, want a new check")
	}
}

// The cache holds two tokens. Once short has expired, reading it again
// takes it out of the cache, so b takes its place and a stays cached.
func TestVerify_AnExpiredTokenLeavesTheCache(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	c := &clock{now: start}
	v := New(newFakeKeys(s), Options{CacheSize: 2, now: c.Now})
	short := s.sign(t, claimsAt(start, map[string]any{"exp": start.Add(time.Minute).Unix()}))
	a := s.sign(t, claimsAt(start, map[string]any{"sub": "a"}))
	b := s.sign(t, claimsAt(start, map[string]any{"sub": "b"}))
	mustVerify(t, v, short)
	cachedA := mustVerify(t, v, a)
	c.advance(time.Minute + DefaultLeeway)
	if _, err := v.Verify(short); codeOf(err) != CodeExpired {
		t.Fatalf("Verify(short) after exp error = %v, want code %s", err, CodeExpired)
	}
	mustVerify(t, v, b)
	if mustVerify(t, v, a) != cachedA {
		t.Errorf("Verify(a) returned a new token, want the cached one")
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
		wg.Go(func() {
			var tok *Token
			if tok, errs[i] = v.Verify(tokens[i%len(tokens)]); tok != nil {
				tok.Payload()
				tok.Claim("sub")
				tok.Standard()
				tok.Issuer()
			}
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("Verify() in goroutine %d error = %v", i, err)
		}
	}
}

func TestVerify_RunsAdmitOnAFreshlyVerifiedToken(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	v := New(newFakeKeys(s), Options{now: func() time.Time { return start }, Admit: func(*Token) *Error {
		return &Error{Code: CodeNamespaceNotAllowed}
	}})
	if _, err := v.Verify(s.sign(t, claimsAt(start, nil))); codeOf(err) != CodeNamespaceNotAllowed {
		t.Errorf("Verify() error = %v, want code %s", err, CodeNamespaceNotAllowed)
	}
}

// The answer of Admit can change while a token stays cached, as the allowed
// namespaces of a Kubernetes token do, so Admit runs on the cached token too.
func TestVerify_RunsAdmitOnACachedTokenToo(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	var refuse bool
	v := New(newFakeKeys(s), Options{now: func() time.Time { return start }, Admit: func(*Token) *Error {
		if refuse {
			return &Error{Code: CodeNamespaceNotAllowed}
		}
		return nil
	}})
	raw := s.sign(t, claimsAt(start, nil))
	mustVerify(t, v, raw)
	refuse = true
	if _, err := v.Verify(raw); codeOf(err) != CodeNamespaceNotAllowed {
		t.Errorf("Verify() of the cached token error = %v, want code %s", err, CodeNamespaceNotAllowed)
	}
}

func TestVerify_RunsNoAdmitForARefusedToken(t *testing.T) {
	realm := &keys.Provider{ID: "realm"}
	published := newSigner(t, "k1", realm)
	forger := newSigner(t, "k1", realm)
	var calls int
	v := New(newFakeKeys(published), Options{now: func() time.Time { return start }, Admit: func(*Token) *Error {
		calls++
		return nil
	}})
	if _, err := v.Verify(forger.sign(t, claimsAt(start, nil))); codeOf(err) != CodeSignatureInvalid {
		t.Fatalf("Verify() of a forged token error = %v, want code %s", err, CodeSignatureInvalid)
	}
	if calls != 0 {
		t.Errorf("Admit calls = %d, want 0", calls)
	}
}
