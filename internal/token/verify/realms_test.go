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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"authz-agent/internal/token/keys"
)

const realmsPath = "/auth/realms/"

// keycloakOf serves the JWKS of each realm of realms, whose keys are the
// public keys of the signers, each with its kid and the x5t that thumbprints
// holds for that kid. The JWKS of the realm r is at
// /auth/realms/r/protocol/openid-connect/certs. It returns the realms provider
// identity-provider of that server, whose tokens name the address
// https://public.example.
func keycloakOf(t *testing.T, realms map[string][]*signer, thumbprints map[string]string) keys.Provider {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realm, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, realmsPath), "/")
		signers, ok := realms[realm]
		if !ok || rest != "protocol/openid-connect/certs" {
			http.NotFound(w, r)
			return
		}
		published := make([]jwk.Key, 0, len(signers))
		for _, s := range signers {
			key, err := s.key.JWK.Clone()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = key.Set(jwk.KeyIDKey, s.key.ID)
			_ = key.Set(jwk.X509CertThumbprintKey, thumbprints[s.key.ID])
			published = append(published, key)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": published})
	}))
	t.Cleanup(srv.Close)
	return keys.Provider{
		ID:             keys.IdentityProviderID,
		Type:           keys.Realms,
		IssuerTemplate: "https://public.example" + realmsPath + "{realm}",
		JWKSURI:        srv.URL + realmsPath + "{realm}/protocol/openid-connect/certs",
		Audience:       keys.Audience{Mode: keys.Ignore},
	}
}

// The provider identity-provider is either a realms or a single provider,
// never both in one configuration, so each row builds a Set of its own on one
// server.
func TestVerify_AppliesTheM2MTestToEveryIdentityProviderToken(t *testing.T) {
	realmB := newSigner(t, "k1", providerOf("unused"))
	realms := keycloakOf(t, map[string][]*signer{"b": {realmB}}, map[string]string{"k1": "dGh1bWI"})
	const iss = "https://public.example" + realmsPath + "b"
	single := realms
	single.Type, single.Issuer, single.IssuerTemplate = keys.Single, iss, ""
	single.JWKSURI = strings.Replace(realms.JWKSURI, "{realm}", "b", 1)
	tests := []struct {
		name     string
		provider keys.Provider
	}{
		{"realm b of the realms provider", realms},
		{"single provider with the iss of realm b", single},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set, err := keys.New(keys.Config{Providers: []keys.Provider{tt.provider}}, keys.Options{})
			if err != nil {
				t.Fatal(err)
			}
			v, _ := newVerifier(set)
			tok, err := v.Verify(t.Context(), realmB.sign(t, claimsAt(start, map[string]any{"iss": iss, "level": "m2m"})))
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if got := tok.Kind(); got != KindIdentityProvider {
				t.Errorf("Kind() = %q, want %q", got, KindIdentityProvider)
			}
			if !tok.IsM2M() {
				t.Error("IsM2M() = false, want true")
			}
		})
	}
}

// These tokens go through a real [keys.Set], because the choice of the key is
// the behavior: which issuer a token names, and which key of that issuer its
// header selects. Realms a and b publish the same kid and have one key each, so
// a token signed in one realm that names the other selects a key that did not
// sign it.
func TestVerify_ChecksATokenAgainstTheKeyOfTheRealmItNames(t *testing.T) {
	realmA := newSigner(t, "k1", providerOf("unused"))
	realmB := newSigner(t, "k1", providerOf("unused"))
	first := newSigner(t, "first", providerOf("unused"))
	second := newSigner(t, "second", providerOf("unused"))
	provider := keycloakOf(t,
		map[string][]*signer{"a": {realmA}, "b": {realmB}, "two": {first, second}},
		map[string]string{"k1": "dGh1bWI", "first": "Zmlyc3Q", "second": "c2Vjb25k"},
	)
	set, err := keys.New(keys.Config{Providers: []keys.Provider{provider}}, keys.Options{})
	if err != nil {
		t.Fatal(err)
	}
	const public = "https://public.example" + realmsPath
	tests := []struct {
		name    string
		raw     string
		want    Code
		wantKID string
	}{
		{"token of the realm that signed it", realmA.sign(t, claimsAt(start, map[string]any{"iss": public + "a"})), "", "k1"},
		{
			"token signed in one realm that names another",
			realmA.sign(t, claimsAt(start, map[string]any{"iss": public + "b"})),
			CodeSignatureInvalid, "",
		},
		{
			"token signed in one realm under a kid that the realm it names lacks",
			first.sign(t, claimsAt(start, map[string]any{"iss": public + "b"})),
			CodeKIDUnknown, "",
		},
		{
			"no kid in a realm with one key",
			realmB.signWithHeaders(t, claimsAt(start, map[string]any{"iss": public + "b"}), map[string]any{"kid": nil}),
			CodeKIDMissing, "",
		},
		{
			"no kid, x5t of a key of the realm",
			second.signWithHeaders(t, claimsAt(start, map[string]any{"iss": public + "two"}), map[string]any{"kid": nil, "x5t": "c2Vjb25k"}),
			CodeKIDMissing, "",
		},
		{
			"no kid in a realm that does not exist",
			realmA.signWithHeaders(t, claimsAt(start, map[string]any{"iss": public + "ghost"}), map[string]any{"kid": nil}),
			CodeKIDMissing, "",
		},
		{"kid in a realm that does not exist", realmA.sign(t, claimsAt(start, map[string]any{"iss": public + "ghost"})), CodeKIDUnknown, ""},
		{"iss outside Keycloak", realmA.sign(t, claimsAt(start, map[string]any{"iss": "https://other.example/oidc"})), CodeIssuerUnknown, ""},
		{
			"iss of the realm that signed it under the address of the server",
			realmA.sign(t, claimsAt(start, map[string]any{"iss": provider.JWKSURI[:strings.Index(provider.JWKSURI, "{realm}")] + "a"})),
			CodeIssuerUnknown, "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(set)
			tok, err := v.Verify(t.Context(), tt.raw)
			if codeOf(err) != tt.want {
				t.Fatalf("Verify() error = %v, want code %q", err, tt.want)
			}
			if tok != nil && tok.KeyID() != tt.wantKID {
				t.Errorf("KeyID() = %q, want %q", tok.KeyID(), tt.wantKID)
			}
		})
	}
}

// statusVerifier returns a Verifier whose one provider is a realms provider
// whose server answers every request with status.
func statusVerifier(t *testing.T, status int) *Verifier {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	provider := keys.Provider{
		ID:             keys.IdentityProviderID,
		Type:           keys.Realms,
		IssuerTemplate: "https://public.example" + realmsPath + "{realm}",
		JWKSURI:        srv.URL + realmsPath + "{realm}/jwks",
		Audience:       keys.Audience{Mode: keys.Ignore},
	}
	set, err := keys.New(keys.Config{Providers: []keys.Provider{provider}}, keys.Options{})
	if err != nil {
		t.Fatal(err)
	}
	v, _ := newVerifier(set)
	return v
}

// The server of the provider answers 503 to every request, so the first load
// of the realm that the token names fails, and the token has no key.
func TestVerify_RefusesATokenWhoseKeysCannotBeLoadedWithTheReason(t *testing.T) {
	v := statusVerifier(t, http.StatusServiceUnavailable)
	s := newSigner(t, "k1", providerOf("unused"))
	_, err := v.Verify(t.Context(), s.sign(t, claimsAt(start, map[string]any{"iss": "https://public.example" + realmsPath + "a"})))
	verr, ok := errors.AsType[*Error](err)
	if !ok || verr.Code != CodeKeysUnavailable {
		t.Fatalf("Verify() error = %v, want code %q", err, CodeKeysUnavailable)
	}
	if want := `the token with kid "k1" cannot be checked: the last load of the source failed`; !strings.Contains(verr.Detail, want) {
		t.Errorf("Detail = %q, want it to contain %q", verr.Detail, want)
	}
	if verr.ProviderID != "" || verr.Realm != "" {
		t.Errorf("ProviderID, Realm = %q, %q, want both empty before the signature verifies", verr.ProviderID, verr.Realm)
	}
}

// The server of the provider answers 404 to every request, as for a realm that
// Keycloak does not hold, so the first load of the realm ends in a 404.
func TestVerify_RefusesATokenOfARealmThatAnswers404AsAnUnknownKID(t *testing.T) {
	v := statusVerifier(t, http.StatusNotFound)
	s := newSigner(t, "k1", providerOf("unused"))
	_, err := v.Verify(t.Context(), s.sign(t, claimsAt(start, map[string]any{"iss": "https://public.example" + realmsPath + "a"})))
	if codeOf(err) != CodeKIDUnknown {
		t.Errorf("Verify() error = %v, want code %q", err, CodeKIDUnknown)
	}
}

// jwksVerifier returns a Verifier whose one provider is a single provider
// identity-provider with the issuer testIssuer, whose server answers every
// request with a JWKS of entries.
func jwksVerifier(t *testing.T, entries ...jwk.Key) *Verifier {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": entries})
	}))
	t.Cleanup(srv.Close)
	provider := keys.Provider{
		ID:       keys.IdentityProviderID,
		Type:     keys.Single,
		Issuer:   testIssuer,
		JWKSURI:  srv.URL + "/jwks",
		Audience: keys.Audience{Mode: keys.Ignore},
	}
	set, err := keys.New(keys.Config{Providers: []keys.Provider{provider}}, keys.Options{})
	if err != nil {
		t.Fatal(err)
	}
	v, _ := newVerifier(set)
	return v
}

// entryOf returns the public JWK of s with its kid and alg, or with no alg
// member where alg is "".
func entryOf(t *testing.T, s *signer, alg string) jwk.Key {
	t.Helper()
	key, err := s.key.JWK.Clone()
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwk.KeyIDKey, s.key.ID); err != nil {
		t.Fatal(err)
	}
	if alg != "" {
		if err := key.Set(jwk.AlgorithmKey, alg); err != nil {
			t.Fatal(err)
		}
	}
	return key
}

// The JWKS lists four entries under the kid k1: an RSA key A with the alg
// RS256, A again with the alg PS256, another RSA key B with the alg RS384, and
// an EC key with no alg.
func TestVerify_ChecksATokenOnlyWithTheKeysOfItsKIDThatAcceptItsAlg(t *testing.T) {
	a := newRSASigner(t, jwa.RS256(), "k1", providerOf("unused"))
	b := newRSASigner(t, jwa.RS384(), "k1", providerOf("unused"))
	ec := newSigner(t, "k1", providerOf("unused"))
	v := jwksVerifier(t, entryOf(t, a, "RS256"), entryOf(t, a, "PS256"), entryOf(t, b, "RS384"), entryOf(t, ec, ""))
	signedByA := func(alg jwa.SignatureAlgorithm) *signer { return &signer{alg: alg, private: a.private, key: a.key} }
	tests := []struct {
		name string
		s    *signer
		want Code
	}{
		{"RS256 token of A", a, ""},
		{"PS256 token of A", signedByA(jwa.PS256()), ""},
		{"RS384 token of B", b, ""},
		{"ES256 token of the EC key", ec, ""},
		{"RS384 token of A, which only B accepts", signedByA(jwa.RS384()), CodeSignatureInvalid},
		{"RS512 token of A, which no entry accepts", signedByA(jwa.RS512()), CodeAlgNotAllowed},
		{"ES256 token of an EC key the JWKS does not list", newSigner(t, "k1", providerOf("unused")), CodeSignatureInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := v.Verify(t.Context(), tt.s.sign(t, claimsAt(start, nil)))
			if got := codeOf(err); got != tt.want || (tt.want == "" && err != nil) {
				t.Errorf("Verify() error = %v, want code %q", err, tt.want)
			}
		})
	}
}

// The issuerTemplate of the provider ends with {realm}, after 61 bytes of the
// address of a Keycloak inside the cluster, so the name of the realm ends the
// iss. The iss of a token that matches no provider is the sender's text
// throughout, and its detail keeps the first 200 bytes.
func TestVerify_CutsALongIssInTheDetail(t *testing.T) {
	realm := newSigner(t, "k1", providerOf("unused"))
	attacker := newSigner(t, "k1", providerOf("unused"))
	unknownKID := newSigner(t, "k9", providerOf("unused"))
	provider := keycloakOf(t, map[string][]*signer{
		"tenant-a":                             {realm},
		"tenant-0123456789abcdefghijklmnopqr":  {realm},
		"tenant-0123456789abcdefghijklmnopqrs": {realm},
	}, map[string]string{"k1": "dGh1bWI"})
	const keycloakInCluster = "https://keycloak.security.svc.cluster.local:8443" + realmsPath
	provider.IssuerTemplate = keycloakInCluster + "{realm}"
	set, err := keys.New(keys.Config{Providers: []keys.Provider{provider}}, keys.Options{})
	if err != nil {
		t.Fatal(err)
	}
	const long = keycloakInCluster + "tenant-0123456789abcdefghijklmnopqrs"
	const longQuoted = `"https://keycloak.security.svc.cl"..."ster.local:8443/auth/realms/tenant-0123456789abcdefghijklmnopqrs"`
	tests := []struct {
		name    string
		raw     string
		want    Code
		wantIss string
	}{
		{
			"signature, iss of a short realm name",
			attacker.sign(t, claimsAt(start, map[string]any{"iss": keycloakInCluster + "tenant-a"})),
			CodeSignatureInvalid, `"https://keycloak.security.svc.cluster.local:8443/auth/realms/tenant-a"`,
		},
		{
			"signature, iss of 96 bytes",
			attacker.sign(t, claimsAt(start, map[string]any{"iss": keycloakInCluster + "tenant-0123456789abcdefghijklmnopqr"})),
			CodeSignatureInvalid, `"https://keycloak.security.svc.cluster.local:8443/auth/realms/tenant-0123456789abcdefghijklmnopqr"`,
		},
		{"signature, iss of 97 bytes", attacker.sign(t, claimsAt(start, map[string]any{"iss": long})), CodeSignatureInvalid, longQuoted},
		{"alg, iss of 97 bytes", unsigned(t, map[string]any{"alg": "RS256", "kid": "k1"}, claimsAt(start, map[string]any{"iss": long})), CodeAlgNotAllowed, longQuoted},
		{"kid, iss of 97 bytes", unknownKID.sign(t, claimsAt(start, map[string]any{"iss": long})), CodeKIDUnknown, longQuoted},
		{
			"iss at a long forged host, cut to its first 200 bytes",
			realm.sign(t, claimsAt(start, map[string]any{"iss": "https://" + strings.Repeat("forged.", 40) + "example" + realmsPath + "tenant-a"})),
			CodeIssuerUnknown, `"https://` + strings.Repeat("forged.", 27) + `for"...`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(set)
			_, err := v.Verify(t.Context(), tt.raw)
			if codeOf(err) != tt.want {
				t.Fatalf("Verify() error = %v, want code %q", err, tt.want)
			}
			if !strings.Contains(err.Error(), "iss "+tt.wantIss) {
				t.Errorf("Verify() error = %q, want it to quote the iss as %s", err, tt.wantIss)
			}
		})
	}
}

// The first token of a realm loads the keys of the realm. A second token with
// another sub is a cache miss, so its key comes from the keys loaded then.
func TestVerify_AcceptsASecondTokenOfALoadedRealm(t *testing.T) {
	realmA := newSigner(t, "k1", providerOf("unused"))
	provider := keycloakOf(t, map[string][]*signer{"a": {realmA}}, map[string]string{"k1": "dGh1bWI"})
	set, err := keys.New(keys.Config{Providers: []keys.Provider{provider}}, keys.Options{})
	if err != nil {
		t.Fatal(err)
	}
	v, _ := newVerifier(set)
	const iss = "https://public.example" + realmsPath + "a"
	mustVerify(t, v, realmA.sign(t, claimsAt(start, map[string]any{"iss": iss, "sub": "user-1"})))
	tok, err := v.Verify(t.Context(), realmA.sign(t, claimsAt(start, map[string]any{"iss": iss, "sub": "user-2"})))
	if err != nil {
		t.Fatalf("Verify(second token of realm a) error = %v", err)
	}
	if got := tok.KeyID(); got != "k1" {
		t.Errorf("KeyID() = %q, want %q", got, "k1")
	}
}
