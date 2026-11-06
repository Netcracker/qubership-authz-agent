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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"authz-agent/internal/token/keys"
)

const realmsPath = "/auth/realms/"

// keycloakOf serves the OIDC discovery document and the JWKS of each realm of
// realms, whose keys are the public keys of the signers, each with its kid and
// the x5t that thumbprints holds for that kid, and returns the address of the
// server.
func keycloakOf(t *testing.T, realms map[string][]*signer, thumbprints map[string]string) string {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realm, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, realmsPath), "/")
		signers, ok := realms[realm]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if rest == ".well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": srv.URL + realmsPath + realm + "/jwks"})
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
	return srv.URL
}

// The claims make a realm token M2M, and the provider that the file names reads
// the same keys, so the source of the key alone decides each answer.
func TestVerify_ComputesTheM2MTestFromTheSourceOfARealKey(t *testing.T) {
	realm := newSigner(t, "k1", &keys.Provider{ID: "unused"})
	url := keycloakOf(t, map[string][]*signer{"a": {realm}, "b": {realm}}, nil)
	fileIssuer := url + realmsPath + "b"
	set, err := keys.New(keys.Config{
		Keycloak:  &keys.Keycloak{URL: url},
		Providers: []keys.Provider{{ID: "file", Issuer: fileIssuer}},
	}, keys.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := set.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		iss      string
		wantKind Kind
		wantM2M  bool
	}{
		{"token of a realm", "https://public.example" + realmsPath + "a", KindRealm, true},
		{"token of a provider whose issuer has the form of a realm", fileIssuer, KindFile, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newVerifier(set)
			tok, err := v.Verify(t.Context(), realm.sign(t, claimsAt(start, map[string]any{"iss": tt.iss, "level": "m2m"})))
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if got := tok.Kind(); got != tt.wantKind {
				t.Errorf("Kind() = %q, want %q", got, tt.wantKind)
			}
			if got := tok.IsM2M(); got != tt.wantM2M {
				t.Errorf("IsM2M() = %t, want %t", got, tt.wantM2M)
			}
		})
	}
}

// Keycloak is down and the realm has not loaded, so the code says that the
// token could not be checked. The same token names a realm that does not exist
// on a Keycloak that is up, and there the source has answered.
func TestVerify_TellsAnOutageOfKeycloakFromARealmThatDoesNotExist(t *testing.T) {
	s := newSigner(t, "k1", &keys.Provider{ID: "realm"})
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    Code
	}{
		{"Keycloak answers 503", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }, CodeKeysUnavailable},
		{"Keycloak answers 404", http.NotFound, CodeKIDUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			t.Cleanup(srv.Close)
			set, err := keys.New(keys.Config{Keycloak: &keys.Keycloak{URL: srv.URL}}, keys.Options{})
			if err != nil {
				t.Fatal(err)
			}
			v, _ := newVerifier(set)
			raw := s.sign(t, claimsAt(start, map[string]any{"iss": "https://public.example" + realmsPath + "tenant"}))
			if _, err := v.Verify(t.Context(), raw); codeOf(err) != tt.want {
				t.Errorf("Verify() error = %v, want code %q", err, tt.want)
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
	realmA := newSigner(t, "k1", &keys.Provider{ID: "unused"})
	realmB := newSigner(t, "k1", &keys.Provider{ID: "unused"})
	first := newSigner(t, "first", &keys.Provider{ID: "unused"})
	second := newSigner(t, "second", &keys.Provider{ID: "unused"})
	url := keycloakOf(t,
		map[string][]*signer{"a": {realmA}, "b": {realmB}, "two": {first, second}},
		map[string]string{"k1": "dGh1bWI", "first": "Zmlyc3Q", "second": "c2Vjb25k"},
	)
	set, err := keys.New(keys.Config{Keycloak: &keys.Keycloak{URL: url}}, keys.Options{})
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
