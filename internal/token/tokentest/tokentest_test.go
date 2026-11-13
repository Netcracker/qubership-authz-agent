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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jws"

	"authz-agent/internal/token/keys"
	"authz-agent/internal/token/tokentest"
	"authz-agent/internal/token/verify"
)

// verifierOn returns a Verifier that loaded the keys of cfg over HTTP.
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

// get returns the body of a response with status 200 to a GET of url, sent on
// a connection of its own, or the error of the request.
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

// The level would make a realm token M2M, so a kind taken from anything but the
// source of the key fails the test.
func TestIssuer_SignsATokenThatItsConfigVerifies(t *testing.T) {
	issuer := newIssuer(t)
	claims := issuer.Claims()
	claims["level"] = "m2m"
	tok, err := verifierOn(t, issuer.Config(), verify.Options{}).Verify(t.Context(), issuer.Sign(claims))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if got := tok.ProviderID(); got != tokentest.ProviderID {
		t.Errorf("ProviderID() = %q, want %q", got, tokentest.ProviderID)
	}
	if got := tok.Issuer(); got != issuer.URL() {
		t.Errorf("Issuer() = %q, want %q", got, issuer.URL())
	}
	if got := tok.Kind(); got != verify.KindFile {
		t.Errorf("Kind() = %q, want %q", got, verify.KindFile)
	}
	if tok.IsM2M() {
		t.Error("IsM2M() = true for a file token, want false")
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
	if got, want := tok.ProviderID(), "realm/"+tokentest.Realm; got != want {
		t.Errorf("ProviderID() = %q, want %q", got, want)
	}
	if got := tok.Kind(); got != verify.KindRealm {
		t.Errorf("Kind() = %q, want %q", got, verify.KindRealm)
	}
	if !tok.IsM2M() {
		t.Error("IsM2M() = false for a realm token whose claims set level m2m, want true")
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

func TestNewIssuer_PanicsWhenItCannotCreateItsDirectory(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	defer func() {
		r := recover()
		if msg, _ := r.(string); !strings.HasPrefix(msg, "tokentest: ") {
			t.Errorf("NewIssuer() with a TMPDIR that does not exist recovered %v, want a panic whose message starts with %q", r, "tokentest: ")
		}
	}()
	tokentest.NewIssuer().Close()
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
	var refused *verify.Error
	if !errors.As(err, &refused) || refused.Code != verify.CodeSignatureInvalid {
		t.Errorf("Verify() error = %v, want code %s", err, verify.CodeSignatureInvalid)
	}
}

func TestIssuer_SignsAKubernetesTokenThatItsKubernetesConfigVerifies(t *testing.T) {
	issuer := newIssuer(t)
	claims := issuer.Claims()
	claims["sub"] = "system:serviceaccount:ns:app"
	claims["aud"] = tokentest.Audience
	admit := func(*verify.Token) *verify.Error { return nil }
	tok, err := verifierOn(t, issuer.KubernetesConfig(), verify.Options{Admit: admit}).Verify(t.Context(), issuer.Sign(claims))
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

func TestIssuer_DiscoveryDocumentNamesTheIssuerItIsServedUnder(t *testing.T) {
	issuer := newIssuer(t)
	tests := []struct {
		name   string
		issuer string
	}{
		{"issuer of file tokens", issuer.URL()},
		{"realm", issuer.RealmURL()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := tt.issuer + "/.well-known/openid-configuration"
			body, err := get(t, url)
			if err != nil {
				t.Fatalf("GET %s error = %v", url, err)
			}
			var doc struct {
				Issuer string `json:"issuer"`
			}
			if err := json.Unmarshal(body, &doc); err != nil {
				t.Fatalf("GET %s = %s, want a JSON object: %v", url, body, err)
			}
			if doc.Issuer != tt.issuer {
				t.Errorf("issuer of the document at %s = %q, want %q", url, doc.Issuer, tt.issuer)
			}
		})
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

// A test may call keys.New on one configuration while another goroutine asks for
// the next, and keys.New reads the token file, so the file has to stay whole.
// Every signature of the key differs, so a file signed and written again
// differs in its content as well as in its time of modification.
func TestIssuer_KubernetesConfigLeavesTheTokenFileUnchanged(t *testing.T) {
	issuer := newIssuer(t)
	path := issuer.KubernetesConfig().Providers[0].TokenFile
	before, beforeInfo := readFile(t, path)
	issuer.KubernetesConfig()
	after, afterInfo := readFile(t, path)
	if string(after) != string(before) {
		t.Errorf("token file after a second KubernetesConfig() = %s, want it unchanged, %s", after, before)
	}
	if !afterInfo.ModTime().Equal(beforeInfo.ModTime()) {
		t.Errorf("token file modified at %s after a second KubernetesConfig(), want it unchanged, %s", afterInfo.ModTime(), beforeInfo.ModTime())
	}
}

// readFile returns the content of the file at path and its information.
func readFile(t *testing.T, path string) ([]byte, os.FileInfo) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	return content, info
}

func TestIssuer_CloseRemovesTheTokenFile(t *testing.T) {
	issuer := tokentest.NewIssuer()
	path := issuer.KubernetesConfig().Providers[0].TokenFile
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Stat() of the token file error = %v", err)
	}
	issuer.Close()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Stat() after Close() error = %v, want %v", err, os.ErrNotExist)
	}
}
