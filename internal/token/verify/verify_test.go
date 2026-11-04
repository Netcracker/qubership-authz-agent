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
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"

	"authz-agent/internal/token/keys"
)

// The payload keeps the text of every number, 5.0 among them, and the order
// of every key, as the provider signed it.
func TestVerify_ReturnsAValidTokenAsSigned(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	v, _ := newVerifier(newFakeKeys(s))
	payload := `{"sub":"user-1","level":5.0,"realm_access":{"roles":["admin"],"b":1,"a":2},` +
		`"iss":"` + testIssuer + `","iat":1792065600,"exp":1792069200}`
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
	if got := tok.Issuer(); got != testIssuer {
		t.Errorf("Issuer() = %q, want %q", got, testIssuer)
	}
	if got, want := tok.Expiry(), time.Unix(1792069200, 0); !got.Equal(want) {
		t.Errorf("Expiry() = %s, want %s", got, want)
	}
}

// The two providers share their id, so the mark alone decides the result.
// Admit passes every token, so Verify returns the marked one too.
func TestToken_KubernetesReportsTheMarkOfTheVerifyingProvider(t *testing.T) {
	tests := []struct {
		name     string
		provider keys.Provider
		want     bool
	}{
		{"marked provider", keys.Provider{ID: "kubernetes", Kubernetes: true}, true},
		{"unmarked provider", keys.Provider{ID: "kubernetes"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSigner(t, "k1", &tt.provider)
			v := newAdmittingVerifier(newFakeKeys(s))
			tok := mustVerify(t, v, s.sign(t, claimsAt(start, map[string]any{"sub": serviceAccountSub})))
			if got := tok.Kubernetes(); got != tt.want {
				t.Errorf("Kubernetes() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestToken_IsM2MFollowsTheLevelTheRolesAndTheProvider(t *testing.T) {
	roles := func(values ...any) map[string]any {
		return map[string]any{"realm_access": map[string]any{"roles": values}}
	}
	realm := keys.Provider{ID: "realm/r"}
	file := keys.Provider{ID: "idp"}
	tests := []struct {
		name     string
		provider keys.Provider
		fields   map[string]any
		want     bool
	}{
		{"neither a level nor roles", realm, nil, false},
		{"level m2m", realm, map[string]any{"level": "m2m"}, true},
		{"level m2m in upper case", realm, map[string]any{"level": "M2M"}, true},
		{"level key-manager", realm, map[string]any{"level": "key-manager"}, true},
		{"level key-manager in mixed case", realm, map[string]any{"level": "Key-Manager"}, true},
		{"level of a user", realm, map[string]any{"level": "user"}, false},
		{"level external", realm, map[string]any{"level": "external"}, false},
		{"level with a trailing space", realm, map[string]any{"level": "m2m "}, false},
		{"level that is a number", realm, map[string]any{"level": 2}, false},
		{"level that is an array", realm, map[string]any{"level": []string{"m2m"}}, false},
		{"the role among others", realm, roles("offline_access", "ROLE_M2M"), true},
		{"the role beside a value that is not a string", realm, roles(1, "ROLE_M2M"), true},
		{"the role in lower case", realm, roles("role_m2m"), false},
		{"a longer role that starts with it", realm, roles("ROLE_M2M_ADMIN"), false},
		{"no roles in the array", realm, roles(), false},
		{"roles that are a string", realm, map[string]any{"realm_access": map[string]any{"roles": "ROLE_M2M"}}, false},
		{"realm_access that is not an object", realm, map[string]any{"realm_access": "ROLE_M2M"}, false},
		{"the role at the top level", realm, map[string]any{"roles": []string{"ROLE_M2M"}}, false},
		{"service account sub on a realm token", realm, map[string]any{"sub": serviceAccountSub}, false},
		{"file token with level m2m", file, map[string]any{"level": "m2m"}, false},
		{"file token with the role", file, roles("ROLE_M2M"), false},
		{"file token with a service account sub", file, map[string]any{"sub": serviceAccountSub}, false},
		{"Kubernetes token", keys.Provider{ID: "k8s", Kubernetes: true}, map[string]any{"sub": serviceAccountSub}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSigner(t, "k1", &tt.provider)
			v := newAdmittingVerifier(newFakeKeys(s))
			tok := mustVerify(t, v, s.sign(t, claimsAt(start, tt.fields)))
			if got := tok.IsM2M(); got != tt.want {
				t.Errorf("IsM2M() = %t, want %t", got, tt.want)
			}
		})
	}
}

// The id of a provider of the file cannot start with realm/, so only a realm of
// the Keycloak has such a provider. The marked provider and the file provider
// share an id, so the id does not decide between them.
func TestToken_KindFollowsTheSourceOfTheKeyThatVerifiedIt(t *testing.T) {
	tests := []struct {
		name     string
		provider keys.Provider
		want     Kind
	}{
		{"key of a realm", keys.Provider{ID: "realm/r"}, KindRealm},
		{"key of a provider of the file", keys.Provider{ID: "idp"}, KindFile},
		{"key of a provider whose id mentions a realm", keys.Provider{ID: "realm-1"}, KindFile},
		{"key of a marked provider", keys.Provider{ID: "idp", Kubernetes: true}, KindKubernetes},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSigner(t, "k1", &tt.provider)
			v := newAdmittingVerifier(newFakeKeys(s))
			tok := mustVerify(t, v, s.sign(t, claimsAt(start, map[string]any{"sub": serviceAccountSub})))
			if got := tok.Kind(); got != tt.want {
				t.Errorf("Kind() = %q, want %q", got, tt.want)
			}
		})
	}
}

// verifyPayload verifies a token of testIssuer whose payload is the members of
// the JSON object members plus an iat and an exp, signed by a key of a
// provider that lists no audiences, at start.
func verifyPayload(t *testing.T, members string) *Token {
	t.Helper()
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	v, _ := newVerifier(newFakeKeys(s))
	payload := `{` + members + `"iss":"` + testIssuer + `","iat":1792065600,"exp":1792069200}`
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
			`"sub":"user-1","preferred_username":"alice","realm_access":{"roles":["admin", "viewer"]},` +
				`"scope":5,"level":5.0,"tenant-id":null,`,
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
			`"realm_access":{"roles":"admin"},`,
			Standard{Roles: json.RawMessage(`"admin"`)},
		},
		{"no claim present", ``, Standard{}},
		{"realm_access that is an array", `"realm_access":["admin"],`, Standard{}},
		{"realm_access without roles", `"realm_access":{"role":"admin"},`, Standard{}},
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
	tok := verifyPayload(t, `"kubernetes.io":{"namespace":"ns","b":1,"a":2},`)
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

// The iss selects the keys, so a token without a string iss has none to be
// checked against. The trusted iss is the control.
func TestVerify_RefusesATokenWhoseIssNamesNoTrustedIssuer(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	tests := []struct {
		name string
		iss  any
		want Code
	}{
		{"trusted iss", testIssuer, ""},
		{"iss of another issuer", "https://other.example/oidc", CodeIssuerUnknown},
		{"iss that is a number", 5, CodeIssuerUnknown},
		{"iss that is null", json.RawMessage("null"), CodeIssuerUnknown},
		{"no iss", nil, CodeIssuerUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(s))
			_, err := v.Verify(t.Context(), s.sign(t, claimsAt(start, map[string]any{"iss": tt.iss})))
			if codeOf(err) != tt.want {
				t.Errorf("Verify() error = %v, want code %q", err, tt.want)
			}
		})
	}
}

// Each row overwrites what one method returned and reads it again: the
// cache shares one Token between callers, so a change one caller makes must
// not reach the next.
func TestToken_ReturnsCopiesThatACallerCannotChange(t *testing.T) {
	tok := verifyPayload(t, `"sub":"user-1","preferred_username":"alice","realm_access":{"roles":["admin"]},`+
		`"scope":"openid","level":"high","tenant-id":"t1",`)
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
			if _, err := v.Verify(t.Context(), tt.signer.sign(t, claimsAt(start, nil))); err != nil {
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
			_, err := v.Verify(t.Context(), tt.raw)
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
			_, err := v.Verify(t.Context(), tt.raw)
			if codeOf(err) != tt.want {
				t.Errorf("Verify() error = %v, want code %s", err, tt.want)
			}
		})
	}
}

// The issuer of these tokens holds the key that signed them, and a reload would
// bring it again, so the missing kid is what refuses them.
func TestVerify_RefusesATokenWithoutAKIDAndStartsNoLoad(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	tests := []struct {
		name   string
		header map[string]any
	}{
		{"no kid", map[string]any{"kid": nil}},
		{"empty kid", map[string]any{"kid": ""}},
		{"x5t in place of the kid", map[string]any{"kid": nil, "x5t": "dGh1bWI"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := newFakeKeys(s)
			loads := 0
			source.reloading = func() { loads++ }
			v, _ := newVerifier(source)
			_, err := v.Verify(t.Context(), s.signWithHeaders(t, claimsAt(start, nil), tt.header))
			if codeOf(err) != CodeKIDMissing {
				t.Errorf("Verify() error = %v, want code %s", err, CodeKIDMissing)
			}
			if loads != 0 {
				t.Errorf("loads the token started = %d, want 0", loads)
			}
		})
	}
}

// The token's exp plus the 30 s leeway falls 1 s after start, and the reload
// that brings its key takes the time in the row.
func TestVerify_ChecksExpAtTheTimeTheReloadEnds(t *testing.T) {
	tests := []struct {
		name   string
		reload time.Duration
		want   Code
	}{
		{"reload that ends before exp", 0, ""},
		{"reload that ends after exp", 2 * time.Second, CodeExpired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSigner(t, "rotated", &keys.Provider{ID: "realm"})
			source := newFakeKeys()
			source.onReload = []keys.Key{s.key}
			v, c := newVerifier(source)
			source.reloading = func() { c.advance(tt.reload) }
			raw := s.sign(t, claimsAt(start.Add(-time.Hour), map[string]any{"exp": start.Add(-29 * time.Second).Unix()}))
			_, err := v.Verify(t.Context(), raw)
			if codeOf(err) != tt.want {
				t.Errorf("Verify() error = %v, want code %q", err, tt.want)
			}
		})
	}
}

// The source holds no key under the token's kid until the reload that the
// unknown kid starts, and the reload brings the key only to a caller whose
// context lasts until it ends.
func TestVerify_AcceptsATokenWhoseKeyAReloadBringsWhileItsContextLasts(t *testing.T) {
	ended, cancel := context.WithCancel(t.Context())
	cancel()
	tests := []struct {
		name string
		ctx  context.Context
		want Code
	}{
		{"context that lasts", t.Context(), ""},
		{"context that has ended", ended, CodeKIDUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSigner(t, "rotated", &keys.Provider{ID: "realm"})
			source := newFakeKeys()
			source.onReload = []keys.Key{s.key}
			v, _ := newVerifier(source)
			_, err := v.Verify(tt.ctx, s.sign(t, claimsAt(start, nil)))
			if codeOf(err) != tt.want {
				t.Errorf("Verify() error = %v, want code %q", err, tt.want)
			}
		})
	}
}

// Every value in a detail that comes from the sender is cut, because the
// detail goes into a log line.
func TestVerify_CutsSenderValuesInTheDetail(t *testing.T) {
	long := strings.Repeat("x", 1000)
	s := newSigner(t, "k1", &keys.Provider{ID: "realm", Audiences: []string{"account"}})
	marked := newSigner(t, "k2", &keys.Provider{ID: "k8s", Kubernetes: true})
	tests := []struct {
		name string
		raw  string
		want Code
	}{
		{"sub", marked.sign(t, claimsAt(start, map[string]any{"sub": long})), CodeSubjectInvalid},
		{"kid", unsigned(t, map[string]any{"alg": "ES256", "kid": long}, claimsAt(start, nil)), CodeKIDUnknown},
		{"iss", unsigned(t, map[string]any{"alg": "ES256", "kid": "k1"}, claimsAt(start, map[string]any{"iss": long})), CodeIssuerUnknown},
		{"alg", unsigned(t, map[string]any{"alg": long, "kid": "k1"}, claimsAt(start, nil)), CodeAlgNotAllowed},
		{"exp", s.signPayload(t, []byte(`{"iss": "`+testIssuer+`", "aud": "account", "exp": 1`+strings.Repeat("0", 1000)+`}`), nil), CodeFormatInvalid},
		{"aud", s.sign(t, claimsAt(start, map[string]any{"aud": []any{long, long, long, long, long}})), CodeAudienceInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(s, marked))
			_, err := v.Verify(t.Context(), tt.raw)
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
			_, err := v.Verify(t.Context(), s.signWithHeaders(t, claimsAt(start, nil), tt.header))
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
			_, err := v.Verify(t.Context(), tt.raw)
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
			_, err := v.Verify(t.Context(), tt.raw)
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(s))
			_, err := v.Verify(t.Context(), s.sign(t, claimsAt(start, tt.fields)))
			if codeOf(err) != tt.want {
				t.Errorf("Verify() error = %v, want code %s", err, tt.want)
			}
		})
	}
}

// Every iat here comes before the exp of the token, so only the rule for an
// iat in the future can refuse it.
func TestVerify_RefusesAnIATInTheFutureOnlyForAKubernetesProvider(t *testing.T) {
	unmarked := &keys.Provider{ID: "kubernetes"}
	marked := &keys.Provider{ID: "k8s", Kubernetes: true}
	tests := []struct {
		name     string
		provider *keys.Provider
		iat      time.Time
		want     Code
	}{
		{"unmarked provider, iat past the leeway", unmarked, start.Add(DefaultLeeway + time.Second), ""},
		{"marked provider, iat past the leeway", marked, start.Add(DefaultLeeway + time.Second), CodeIATInvalid},
		{"marked provider, iat exactly the leeway ahead", marked, start.Add(DefaultLeeway), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSigner(t, "k1", tt.provider)
			v := newAdmittingVerifier(newFakeKeys(s))
			_, err := v.Verify(t.Context(), s.sign(t, claimsAt(start, map[string]any{"iat": tt.iat.Unix(), "sub": serviceAccountSub})))
			if codeOf(err) != tt.want {
				t.Errorf("Verify() error = %v, want code %q", err, tt.want)
			}
		})
	}
}

// The rule compares exp with iat and leaves the clock out, so it holds on a
// marked and an unmarked provider, also for an exp that the leeway keeps from
// expiring. The iat of the marked row is not ahead of the clock.
func TestVerify_RefusesATokenThatExpiresBeforeItIsIssued(t *testing.T) {
	unmarked := &keys.Provider{ID: "realm"}
	marked := &keys.Provider{ID: "k8s", Kubernetes: true}
	later := start.Add(2 * time.Hour)
	tests := []struct {
		name     string
		provider *keys.Provider
		exp, iat time.Time
		want     Code
	}{
		{"exp a second before iat, both ahead of the clock", unmarked, later, later.Add(time.Second), CodeIATInvalid},
		{"exp a second before iat, within the leeway", unmarked, start.Add(-time.Second), start, CodeIATInvalid},
		{"exp a second before iat, marked provider", marked, start.Add(-time.Second), start, CodeIATInvalid},
		{"exp at iat", unmarked, later, later, ""},
		{"exp a second after iat", unmarked, later, later.Add(-time.Second), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSigner(t, "k1", tt.provider)
			v, _ := newVerifier(newFakeKeys(s))
			_, err := v.Verify(t.Context(), s.sign(t, claimsAt(start, map[string]any{"exp": tt.exp.Unix(), "iat": tt.iat.Unix(), "sub": serviceAccountSub})))
			if codeOf(err) != tt.want {
				t.Errorf("Verify() error = %v, want code %q", err, tt.want)
			}
		})
	}
}

// The unmarked provider is the control: the rule reads the mark, and a token of
// any other provider keeps a sub of its own.
func TestVerify_RefusesAKubernetesTokenWhoseSubNamesNoServiceAccount(t *testing.T) {
	unmarked := &keys.Provider{ID: "kubernetes"}
	marked := &keys.Provider{ID: "k8s", Kubernetes: true}
	tests := []struct {
		name     string
		provider *keys.Provider
		sub      any
		want     Code
	}{
		{"service account", marked, serviceAccountSub, ""},
		{"the prefix alone", marked, "system:serviceaccount", ""},
		{"another name", marked, "user-1", CodeSubjectInvalid},
		{"the prefix after other text", marked, "user:system:serviceaccount:ns:app", CodeSubjectInvalid},
		{"the prefix in another case", marked, "System:ServiceAccount:ns:app", CodeSubjectInvalid},
		{"the prefix cut short", marked, "system:serviceaccoun", CodeSubjectInvalid},
		{"sub that is a number", marked, 5, CodeSubjectInvalid},
		{"no sub", marked, nil, CodeSubjectInvalid},
		{"another name on an unmarked provider", unmarked, "user-1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSigner(t, "k1", tt.provider)
			v := newAdmittingVerifier(newFakeKeys(s))
			_, err := v.Verify(t.Context(), s.sign(t, claimsAt(start, map[string]any{"sub": tt.sub})))
			if codeOf(err) != tt.want {
				t.Errorf("Verify() error = %v, want code %q", err, tt.want)
			}
		})
	}
}

// The sub check comes last, so a token that also breaks an earlier rule gets
// the code of that rule.
func TestVerify_RefusesOnTheLifetimeBeforeTheSub(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "k8s", Kubernetes: true})
	v := newAdmittingVerifier(newFakeKeys(s))
	_, err := v.Verify(t.Context(), s.sign(t, claimsAt(start, map[string]any{"sub": "user-1", "exp": nil})))
	if codeOf(err) != CodeExpMissing {
		t.Errorf("Verify() error = %v, want code %s", err, CodeExpMissing)
	}
}

func TestVerify_ToleratesTheLeewayAroundItsLifetime(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	within := DefaultLeeway - time.Second
	tests := []struct {
		name   string
		fields map[string]any
	}{
		{"exp passed less than the leeway ago", map[string]any{"iat": start.Add(-time.Hour).Unix(), "exp": start.Add(-within).Unix()}},
		{"nbf exactly the leeway ahead", map[string]any{"nbf": start.Add(DefaultLeeway).Unix()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(s))
			if _, err := v.Verify(t.Context(), s.sign(t, claimsAt(start, tt.fields))); err != nil {
				t.Errorf("Verify() error = %v, want none", err)
			}
		})
	}
}

func TestVerify_AcceptsAnExpAtTheLargestExactSecond(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	v, _ := newVerifier(newFakeKeys(s))
	if _, err := v.Verify(t.Context(), s.sign(t, claimsAt(start, map[string]any{"exp": int64(1)<<53 - 1}))); err != nil {
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
			_, err := v.Verify(t.Context(), s.sign(t, claimsAt(start, map[string]any{"aud": tt.aud})))
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
		{"aud of another client, iat after exp", map[string]any{"aud": "other", "iat": start.Add(2 * time.Hour).Unix()}, CodeAudienceInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(s))
			_, err := v.Verify(t.Context(), s.sign(t, claimsAt(start, tt.fields)))
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
			if _, err := v.Verify(t.Context(), s.sign(t, claimsAt(start, map[string]any{"aud": tt.aud}))); err != nil {
				t.Errorf("Verify() error = %v, want none", err)
			}
		})
	}
}

// mustVerify verifies raw and stops the test when Verify fails.
func mustVerify(t *testing.T, v *Verifier, raw string) *Token {
	t.Helper()
	tok, err := v.Verify(t.Context(), raw)
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
	_, err := v.Verify(t.Context(), raw)
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
	_, err := v.Verify(t.Context(), raw)
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
	if _, err := v.Verify(t.Context(), short); codeOf(err) != CodeExpired {
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
			if tok, errs[i] = v.Verify(t.Context(), tokens[i%len(tokens)]); tok != nil {
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
	if _, err := v.Verify(t.Context(), s.sign(t, claimsAt(start, nil))); codeOf(err) != CodeNamespaceNotAllowed {
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
	if _, err := v.Verify(t.Context(), raw); codeOf(err) != CodeNamespaceNotAllowed {
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
	if _, err := v.Verify(t.Context(), forger.sign(t, claimsAt(start, nil))); codeOf(err) != CodeSignatureInvalid {
		t.Fatalf("Verify() of a forged token error = %v, want code %s", err, CodeSignatureInvalid)
	}
	if calls != 0 {
		t.Errorf("Admit calls = %d, want 0", calls)
	}
}

// A token whose signature has not verified only claims to come from a provider,
// so its refusal names none. The verifier has no Admit, so a token that passes
// every check reaches the refusal of a Kubernetes token.
func TestError_NamesTheProviderOnceTheSignatureVerifies(t *testing.T) {
	provider := &keys.Provider{ID: "k8s", Kubernetes: true, Audiences: []string{"netcracker"}}
	s := newSigner(t, "k1", provider)
	attacker := newSigner(t, "k1", provider)
	valid := func(fields map[string]any) map[string]any {
		claims := claimsAt(start, map[string]any{"sub": serviceAccountSub, "aud": "netcracker"})
		for name, value := range fields {
			claims[name] = value
		}
		return claims
	}
	tests := []struct {
		name         string
		raw          string
		wantCode     Code
		wantProvider string
	}{
		{"format of the token", "not-a-token", CodeFormatInvalid, ""},
		{"alg nothing accepts", unsigned(t, map[string]any{"alg": "HS256", "kid": "k1"}, valid(nil)), CodeAlgNotAllowed, ""},
		{"issuer", s.sign(t, valid(map[string]any{"iss": "https://other.example"})), CodeIssuerUnknown, ""},
		{"kid", unsigned(t, map[string]any{"alg": "ES256", "kid": "k2"}, valid(nil)), CodeKIDUnknown, ""},
		{"alg the found key does not accept", unsigned(t, map[string]any{"alg": "RS256", "kid": "k1"}, valid(nil)), CodeAlgNotAllowed, ""},
		{"signature", attacker.sign(t, valid(nil)), CodeSignatureInvalid, ""},
		{"aud", s.sign(t, valid(map[string]any{"aud": "other"})), CodeAudienceInvalid, "k8s"},
		{"exp that is not a number", s.sign(t, valid(map[string]any{"exp": "soon"})), CodeFormatInvalid, "k8s"},
		{"exp in the past", s.sign(t, valid(map[string]any{"iat": start.Add(-2 * time.Hour).Unix(), "exp": start.Add(-time.Hour).Unix()})), CodeExpired, "k8s"},
		{"nbf in the future", s.sign(t, valid(map[string]any{"nbf": start.Add(time.Minute).Unix()})), CodeNotYetValid, "k8s"},
		{"iat in the future", s.sign(t, valid(map[string]any{"iat": start.Add(time.Minute).Unix()})), CodeIATInvalid, "k8s"},
		{"sub", s.sign(t, valid(map[string]any{"sub": "user-1"})), CodeSubjectInvalid, "k8s"},
		{"no namespace check", s.sign(t, valid(nil)), CodeNamespaceNotAllowed, "k8s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(s))
			_, err := v.Verify(t.Context(), tt.raw)
			var refused *Error
			if !errors.As(err, &refused) {
				t.Fatalf("Verify() error = %v, want an *Error", err)
			}
			if refused.Code != tt.wantCode {
				t.Errorf("Verify() code = %s, want %s", refused.Code, tt.wantCode)
			}
			if refused.ProviderID != tt.wantProvider {
				t.Errorf("Verify() ProviderID = %q, want %q", refused.ProviderID, tt.wantProvider)
			}
		})
	}
}

// The detail reaches a log line, so it keeps the provider out as the field does.
func TestError_NamesNoProviderInTheDetailBeforeTheSignatureVerifies(t *testing.T) {
	provider := &keys.Provider{ID: "named-provider"}
	s := newSigner(t, "k1", provider)
	attacker := newSigner(t, "k1", provider)
	tests := []struct {
		name string
		raw  string
		want Code
	}{
		{"alg the found key does not accept", unsigned(t, map[string]any{"alg": "RS256", "kid": "k1"}, claimsAt(start, nil)), CodeAlgNotAllowed},
		{"signature", attacker.sign(t, claimsAt(start, nil)), CodeSignatureInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(newFakeKeys(s))
			_, err := v.Verify(t.Context(), tt.raw)
			if codeOf(err) != tt.want {
				t.Fatalf("Verify() error = %v, want code %s", err, tt.want)
			}
			if strings.Contains(err.Error(), provider.ID) {
				t.Errorf("Verify() error = %q, want it to name no provider", err)
			}
		})
	}
}

// Admit may return one *Error for many tokens, and the tokens may come from
// different providers, so Verify leaves that value as it is.
func TestVerify_NamesTheProviderOnACopyOfTheRefusalOfAdmit(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	refusal := &Error{Code: CodeNamespaceNotAllowed, Detail: "refused"}
	v := New(newFakeKeys(s), Options{now: func() time.Time { return start }, Admit: func(*Token) *Error { return refusal }})
	raw := s.sign(t, claimsAt(start, nil))
	for _, call := range []string{"first", "second, from the cache"} {
		_, err := v.Verify(t.Context(), raw)
		var refused *Error
		if !errors.As(err, &refused) {
			t.Fatalf("Verify(), %s call: error = %v, want an *Error", call, err)
		}
		if refused.ProviderID != "realm" {
			t.Errorf("Verify(), %s call: ProviderID = %q, want %q", call, refused.ProviderID, "realm")
		}
	}
	if refusal.ProviderID != "" {
		t.Errorf("the value Admit returned has ProviderID %q, want it unchanged", refusal.ProviderID)
	}
}

// Without Admit nothing checks the namespace of a Kubernetes token, so
// Verify refuses it. The unmarked provider shares its id and is the control.
func TestVerify_RefusesAKubernetesTokenWithoutAdmit(t *testing.T) {
	tests := []struct {
		name     string
		provider keys.Provider
		want     Code
	}{
		{"marked provider", keys.Provider{ID: "kubernetes", Kubernetes: true}, CodeNamespaceNotAllowed},
		{"unmarked provider", keys.Provider{ID: "kubernetes"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSigner(t, "k1", &tt.provider)
			v, _ := newVerifier(newFakeKeys(s))
			raw := s.sign(t, claimsAt(start, map[string]any{"sub": serviceAccountSub}))
			for _, call := range []string{"first", "second, from the cache"} {
				_, err := v.Verify(t.Context(), raw)
				if got := codeOf(err); got != tt.want || (tt.want == "" && err != nil) {
					t.Errorf("Verify(), %s call: error = %v, want code %q", call, err, tt.want)
				}
			}
		})
	}
}
