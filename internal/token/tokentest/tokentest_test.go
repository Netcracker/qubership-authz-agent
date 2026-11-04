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
	"errors"
	"os"
	"testing"

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

func TestIssuer_SignsExactlyTheClaimsItIsGiven(t *testing.T) {
	issuer := newIssuer(t)
	claims := issuer.Claims()
	delete(claims, "exp")
	_, err := verifierOn(t, issuer.Config(), verify.Options{}).Verify(t.Context(), issuer.Sign(claims))
	var refused *verify.Error
	if !errors.As(err, &refused) || refused.Code != verify.CodeExpMissing {
		t.Errorf("Verify() error = %v, want code %s", err, verify.CodeExpMissing)
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
