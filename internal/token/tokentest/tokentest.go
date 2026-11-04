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

// Package tokentest runs a fake identity provider for tests of the code that
// calls [verify]. An [Issuer] signs tokens and serves the key that verifies
// them. [Issuer.Config] and [Issuer.RealmConfig] return a [keys.Config] whose
// provider identity-provider trusts the Issuer, so a test of an
// identity-provider token goes through the real key loading and the real
// checks. [Issuer.KubernetesKeys] holds the key of the Issuer as a key of the
// provider kubernetes, for a test of a Kubernetes token.
//
// Production code must not import this package.
package tokentest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"authz-agent/internal/token/keys"
	"authz-agent/internal/token/verify"
)

const (
	// Realm is the one realm whose key an Issuer serves under
	// [Issuer.RealmConfig].
	Realm = "test"
	// Audience is the aud that a token of [Issuer.KubernetesProvider] needs,
	// as every Kubernetes token does.
	Audience = "netcracker"
)

// keyID is the kid of the key of every Issuer.
const keyID = "test-key"

// realmsPath starts the path of a realm under the address of an Issuer.
const realmsPath = "/realms/"

// Issuer is an identity provider that runs in the test process. It serves one
// ES256 key over http on an [httptest.Server], at [Issuer.URL] followed by
// /jwks and at [Issuer.RealmURL] followed by /jwks, and signs tokens with the
// private part of that key. Like that server, the Issuer panics on a failure no
// test can handle, and the test stops it with [Issuer.Close]. It is safe for
// concurrent use.
type Issuer struct {
	server  *httptest.Server
	private *ecdsa.PrivateKey
	public  jwk.Key
}

// NewIssuer starts an Issuer with a new key.
func NewIssuer() *Issuer {
	private := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	public := must(jwk.Import(&private.PublicKey))
	if err := public.Set(jwk.KeyIDKey, keyID); err != nil {
		panic(fmt.Sprintf("tokentest: set the kid: %v", err))
	}
	jwks := must(json.Marshal(map[string][]jwk.Key{"keys": {public}}))
	serve := func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(jwks)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /jwks", serve)
	mux.HandleFunc("GET "+realmsPath+Realm+"/jwks", serve)
	return &Issuer{server: httptest.NewServer(mux), private: private, public: public}
}

// Close stops the server.
func (i *Issuer) Close() { i.server.Close() }

// URL returns the address of the issuer, the iss of a token of [Issuer.Config]
// and of [Issuer.KubernetesKeys].
func (i *Issuer) URL() string { return i.server.URL }

// Config returns a configuration whose one provider is a single provider
// identity-provider: it takes a token whose iss is [Issuer.URL] and checks no
// aud.
func (i *Issuer) Config() keys.Config {
	return keys.Config{Providers: []keys.Provider{{
		ID:       keys.IdentityProviderID,
		Type:     keys.Single,
		Issuer:   i.URL(),
		JWKSURI:  i.URL() + "/jwks",
		Audience: keys.Audience{Mode: keys.Ignore},
	}}}
}

// RealmConfig returns a configuration whose one provider is a realms provider
// identity-provider at [Issuer.URL], which checks no aud. The issuer
// serves the key of [Realm] alone, so a token whose iss is [Issuer.RealmURL]
// passes, and a token of another realm is refused with
// [verify.CodeKIDUnknown].
func (i *Issuer) RealmConfig() keys.Config {
	return keys.Config{Providers: []keys.Provider{{
		ID:             keys.IdentityProviderID,
		Type:           keys.Realms,
		IssuerTemplate: i.URL() + realmsPath + "{realm}",
		JWKSURI:        i.URL() + realmsPath + "{realm}/jwks",
		Audience:       keys.Audience{Mode: keys.Ignore},
	}}}
}

// RealmURL returns the iss of a token of [Realm].
func (i *Issuer) RealmURL() string { return i.URL() + realmsPath + Realm }

// KubernetesProvider returns the provider kubernetes of this issuer: it takes a
// token whose iss is [Issuer.URL] and whose aud names [Audience]. Its jwksUri
// is the address of the keys of the API server in a cluster, which no test
// serves: the provider kubernetes reads its keys only over https, and a
// [keys.Set] trusts the certificate of no test server. [Issuer.KubernetesKeys]
// holds the key of this issuer as a key of this provider instead.
func (i *Issuer) KubernetesProvider() keys.Provider {
	return keys.Provider{
		ID:      keys.KubernetesID,
		Type:    keys.Single,
		Issuer:  i.URL(),
		JWKSURI: "https://kubernetes.default.svc/openid/v1/jwks",
	}
}

// KubernetesKeys returns a [verify.KeyFinder] whose one key is the key of this
// issuer, as a key of [Issuer.KubernetesProvider], so every token that a
// verifier on it accepts is a Kubernetes token. The verifier accepts a token
// of this issuer whose aud names [Audience] and whose sub starts with
// system:serviceaccount:, the prefix of the sub that the API server issues for
// a service account. It accepts such a token only when [verify.Options.Admit]
// admits it, and without Admit it refuses the token with
// [verify.CodeNamespaceNotAllowed].
// [authz-agent/internal/token/namespaces.Allowlist.Admit] admits only a token
// whose kubernetes.io claim names an allowed namespace, and [Issuer.Claims]
// holds no such claim.
func (i *Issuer) KubernetesKeys() verify.KeyFinder {
	provider := i.KubernetesProvider()
	return kubernetesKeys{key: keys.Key{Source: keys.Source{Provider: &provider}, ID: keyID, JWK: i.public}}
}

// kubernetesKeys is the [verify.KeyFinder] of [Issuer.KubernetesKeys].
type kubernetesKeys struct{ key keys.Key }

// Lookup implements [verify.KeyFinder].
func (k kubernetesKeys) Lookup(q keys.Query) (keys.Key, error) {
	if q.Issuer != k.key.Source.Provider.Issuer {
		return keys.Key{}, keys.ErrIssuerUnknown
	}
	if q.KID != k.key.ID {
		return keys.Key{}, keys.ErrKeyUnknown
	}
	return k.key, nil
}

// LookupOrReload implements [verify.KeyFinder]. It loads nothing, so it
// returns what [kubernetesKeys.Lookup] returns.
func (k kubernetesKeys) LookupOrReload(_ context.Context, q keys.Query) (keys.Key, error) {
	return k.Lookup(q)
}

// Claims returns the claims of a token issued now that expires in an hour: iss,
// sub, iat, and exp. A verifier on [Issuer.Config] accepts a token that holds
// them. The map belongs to the caller, which may change it before [Issuer.Sign].
func (i *Issuer) Claims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": i.URL(),
		"sub": "test-user",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
}

// Sign returns a token in compact form that holds exactly claims, signed with
// the key of the issuer and naming it in its kid. Every Issuer uses the same
// kid, so a token that one signs with the claims of another fails on its
// signature. Sign panics when claims cannot be marshaled to JSON.
func (i *Issuer) Sign(claims map[string]any) string {
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, keyID); err != nil {
		panic(fmt.Sprintf("tokentest: set the kid: %v", err))
	}
	return string(must(jws.Sign(must(json.Marshal(claims)), jws.WithKey(jwa.ES256(), i.private, jws.WithProtectedHeaders(headers)))))
}

// must returns value, and panics when err is set.
func must[T any](value T, err error) T {
	if err != nil {
		panic(fmt.Sprintf("tokentest: %v", err))
	}
	return value
}
