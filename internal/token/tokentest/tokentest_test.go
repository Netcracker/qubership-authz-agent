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

package tokentest_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jws"

	"authz-agent/internal/token/keys"
	"authz-agent/internal/token/tokentest"
	"authz-agent/internal/token/verify"
)

// verifierOn returns a Verifier that loaded the keys of cfg, a configuration
// of an issuer.
func verifierOn(t *testing.T, cfg keys.Config, opts verify.Options) *verify.Verifier {
	t.Helper()
	set, err := keys.New(cfg, keys.Options{})
	if err != nil {
		t.Fatalf("keys.New() error = %v", err)
	}
	if err := set.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	return verify.New(set, opts)
}

func newIssuer(t *testing.T) *tokentest.Issuer {
	t.Helper()
	issuer := tokentest.NewIssuer()
	t.Cleanup(issuer.Close)
	return issuer
}

// codeOf returns the Code of a *verify.Error, and "" for nil or any other
// error.
func codeOf(err error) verify.Code {
	var refused *verify.Error
	if errors.As(err, &refused) {
		return refused.Code
	}
	return ""
}

// get returns the body of a response with status 200 to a GET of url through a
// client that opens a connection of its own for each request, or the error of
// the request.
func get(t *testing.T, url string) ([]byte, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext(%q) error = %v", url, err)
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func TestIssuer_SignsATokenThatItsConfigVerifies(t *testing.T) {
	issuer := newIssuer(t)
	claims := issuer.Claims()
	claims["level"] = "m2m"
	tok, err := verifierOn(t, issuer.Config(), verify.Options{}).Verify(t.Context(), issuer.Sign(claims))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if got := tok.ProviderID(); got != keys.IdentityProviderID {
		t.Errorf("ProviderID() = %q, want %q", got, keys.IdentityProviderID)
	}
	if got := tok.Issuer(); got != issuer.URL() {
		t.Errorf("Issuer() = %q, want %q", got, issuer.URL())
	}
	if got := tok.Kind(); got != verify.KindIdentityProvider {
		t.Errorf("Kind() = %q, want %q", got, verify.KindIdentityProvider)
	}
	if !tok.IsM2M() {
		t.Error("IsM2M() = false for an identity-provider token whose claims set level m2m, want true")
	}
}

func TestIssuer_SignsARealmTokenThatItsRealmConfigVerifies(t *testing.T) {
	issuer := newIssuer(t)
	claims := issuer.Claims()
	claims["iss"] = issuer.RealmURL()
	claims["level"] = "m2m"
	tok, err := verifierOn(t, issuer.RealmConfig(), verify.Options{}).Verify(t.Context(), issuer.Sign(claims))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if got := tok.ProviderID(); got != keys.IdentityProviderID {
		t.Errorf("ProviderID() = %q, want %q", got, keys.IdentityProviderID)
	}
	if got := tok.Realm(); got != tokentest.Realm {
		t.Errorf("Realm() = %q, want %q", got, tokentest.Realm)
	}
	if got := tok.Kind(); got != verify.KindIdentityProvider {
		t.Errorf("Kind() = %q, want %q", got, verify.KindIdentityProvider)
	}
	if !tok.IsM2M() {
		t.Error("IsM2M() = false for a realm token whose claims set level m2m, want true")
	}
}

func TestIssuer_RealmConfigRefusesATokenOfAnotherRealm(t *testing.T) {
	issuer := newIssuer(t)
	claims := issuer.Claims()
	claims["iss"] = strings.TrimSuffix(issuer.RealmURL(), tokentest.Realm) + "other"
	_, err := verifierOn(t, issuer.RealmConfig(), verify.Options{}).Verify(t.Context(), issuer.Sign(claims))
	if got := codeOf(err); got != verify.CodeKIDUnknown {
		t.Errorf("Verify() error = %v, want code %s", err, verify.CodeKIDUnknown)
	}
}

// The claims have no exp and no iat, which a Sign that fills in the claims of a
// valid token would add.
func TestIssuer_SignsExactlyTheClaimsItIsGiven(t *testing.T) {
	issuer := newIssuer(t)
	msg, err := jws.Parse([]byte(issuer.Sign(map[string]any{"iss": issuer.URL(), "sub": "alice"})))
	if err != nil {
		t.Fatalf("jws.Parse() of the signed token error = %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(msg.Payload(), &got); err != nil {
		t.Fatalf("payload %s is not a JSON object: %v", msg.Payload(), err)
	}
	if want := map[string]any{"iss": issuer.URL(), "sub": "alice"}; !maps.Equal(got, want) {
		t.Errorf("payload of Sign(%v) = %s, want exactly those claims", want, msg.Payload())
	}
}

func TestIssuer_SignPanicsOnAClaimThatIsNotJSON(t *testing.T) {
	issuer := newIssuer(t)
	defer func() {
		r := recover()
		if msg, _ := r.(string); !strings.HasPrefix(msg, "tokentest: ") {
			t.Errorf("Sign() of a claim that holds a channel recovered %v, want a panic whose message starts with %q", r, "tokentest: ")
		}
	}()
	issuer.Sign(map[string]any{"sub": make(chan int)})
}

func TestIssuer_ClaimsAreThoseOfATokenIssuedNowThatExpiresInAnHour(t *testing.T) {
	issuer := newIssuer(t)
	before := time.Now().Unix()
	claims := issuer.Claims()
	after := time.Now().Unix()
	if got, want := slices.Sorted(maps.Keys(claims)), []string{"exp", "iat", "iss", "sub"}; !slices.Equal(got, want) {
		t.Errorf("names of Claims() = %q, want %q", got, want)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("json.Marshal(Claims()) error = %v", err)
	}
	var got struct {
		Iss string `json:"iss"`
		IAT int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("Claims() = %s, want iss a string and iat and exp integers: %v", payload, err)
	}
	if got.Iss != issuer.URL() {
		t.Errorf("iss of Claims() = %q, want %q", got.Iss, issuer.URL())
	}
	if got.IAT < before || got.IAT > after {
		t.Errorf("iat of Claims() = %d, want from %d to %d, the time of the call", got.IAT, before, after)
	}
	if got.Exp-got.IAT != 3600 {
		t.Errorf("exp - iat of Claims() = %d, want 3600", got.Exp-got.IAT)
	}
}

func TestIssuer_TokenSignedByAnotherIssuerFailsOnItsSignature(t *testing.T) {
	issuer := newIssuer(t)
	other := newIssuer(t)
	_, err := verifierOn(t, issuer.Config(), verify.Options{}).Verify(t.Context(), other.Sign(issuer.Claims()))
	if got := codeOf(err); got != verify.CodeSignatureInvalid {
		t.Errorf("Verify() error = %v, want code %s", err, verify.CodeSignatureInvalid)
	}
}

// kubernetesClaims returns the claims of a token of issuer that a verifier on
// its KubernetesKeys accepts with an Admit.
func kubernetesClaims(issuer *tokentest.Issuer) map[string]any {
	claims := issuer.Claims()
	claims["sub"] = "system:serviceaccount:ns:app"
	claims["aud"] = tokentest.Audience
	return claims
}

func TestIssuer_SignsAKubernetesTokenThatItsKubernetesKeysVerify(t *testing.T) {
	issuer := newIssuer(t)
	admit := func(*verify.Token) *verify.Error { return nil }
	tok, err := verify.New(issuer.KubernetesKeys(), verify.Options{Admit: admit}).Verify(t.Context(), issuer.Sign(kubernetesClaims(issuer)))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if got := tok.Kind(); got != verify.KindKubernetes {
		t.Errorf("Kind() = %q, want %q", got, verify.KindKubernetes)
	}
	if !tok.IsM2M() {
		t.Error("IsM2M() = false for a Kubernetes token, want true")
	}
}

func TestIssuer_KubernetesKeysRefuseATokenThatBreaksARuleOfAKubernetesToken(t *testing.T) {
	issuer := newIssuer(t)
	admit := func(*verify.Token) *verify.Error { return nil }
	tests := []struct {
		name   string
		fields map[string]any
		admit  func(*verify.Token) *verify.Error
		want   verify.Code
	}{
		{"no Admit", nil, nil, verify.CodeNamespaceNotAllowed},
		{"aud of another service", map[string]any{"aud": "other"}, admit, verify.CodeAudienceInvalid},
		{"sub of a user", map[string]any{"sub": "test-user"}, admit, verify.CodeSubjectInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := kubernetesClaims(issuer)
			maps.Copy(claims, tt.fields)
			_, err := verify.New(issuer.KubernetesKeys(), verify.Options{Admit: tt.admit}).Verify(t.Context(), issuer.Sign(claims))
			if got := codeOf(err); got != tt.want {
				t.Errorf("Verify() error = %v, want code %s", err, tt.want)
			}
		})
	}
}

// kidOf returns the kid in the header of raw, a token in compact form.
func kidOf(t *testing.T, raw string) string {
	t.Helper()
	msg, err := jws.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("jws.Parse() error = %v", err)
	}
	kid, ok := msg.Signatures()[0].ProtectedHeaders().KeyID()
	if !ok {
		t.Fatalf("token %s has no kid", raw)
	}
	return kid
}

func TestIssuer_KubernetesKeysHoldTheKeyOfTheIssuerAsAKeyOfKubernetes(t *testing.T) {
	issuer := newIssuer(t)
	query := keys.Query{Issuer: issuer.URL(), KID: kidOf(t, issuer.Sign(issuer.Claims()))}
	key, err := issuer.KubernetesKeys().Lookup(query)
	if err != nil {
		t.Fatalf("Lookup(%+v) error = %v", query, err)
	}
	if !key.Source.Kubernetes() {
		t.Errorf("Lookup(%+v) = a key of provider %q, want one of %q", query, key.Source.Provider.ID, keys.KubernetesID)
	}
}

func TestIssuer_KubernetesKeysHoldNoKeyForAnotherIssOrKid(t *testing.T) {
	issuer := newIssuer(t)
	kid := kidOf(t, issuer.Sign(issuer.Claims()))
	tests := []struct {
		name  string
		query keys.Query
		want  error
	}{
		{"iss of the realm", keys.Query{Issuer: issuer.RealmURL(), KID: kid}, keys.ErrIssuerUnknown},
		{"another kid", keys.Query{Issuer: issuer.URL(), KID: "other"}, keys.ErrKeyUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := issuer.KubernetesKeys().Lookup(tt.query); !errors.Is(err, tt.want) {
				t.Errorf("Lookup(%+v) error = %v, want %v", tt.query, err, tt.want)
			}
		})
	}
}

func TestIssuer_KubernetesProviderIsOneThatKeysAccepts(t *testing.T) {
	issuer := newIssuer(t)
	if err := (keys.Config{Providers: []keys.Provider{issuer.KubernetesProvider()}}).Validate(); err != nil {
		t.Errorf("Validate() of a configuration that holds KubernetesProvider() error = %v", err)
	}
}

func TestIssuer_ClaimsReturnsAMapOfItsOwnOnEachCall(t *testing.T) {
	issuer := newIssuer(t)
	delete(issuer.Claims(), "sub")
	if _, ok := issuer.Claims()["sub"]; !ok {
		t.Error("Claims() after a caller deleted sub from an earlier result has no sub, want one")
	}
}

func TestIssuer_CloseStopsTheServer(t *testing.T) {
	issuer := newIssuer(t)
	jwks := issuer.URL() + "/jwks"
	if _, err := get(t, jwks); err != nil {
		t.Fatalf("GET %s before Close() error = %v", jwks, err)
	}
	issuer.Close()
	if _, err := get(t, jwks); err == nil {
		t.Errorf("GET %s after Close() error = nil, want an error", jwks)
	}
}
