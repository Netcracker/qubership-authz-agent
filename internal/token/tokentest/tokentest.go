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
// calls [authz-agent/internal/token/verify]. An [Issuer] signs tokens and serves
// the keys that verify them, and [Issuer.Config], [Issuer.RealmConfig], and
// [Issuer.KubernetesConfig] return a [keys.Config] that trusts it, one for each
// kind of token, so a test goes through the real key loading and the real
// checks.
//
// Production code must not import this package.
package tokentest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"authz-agent/internal/token/keys"
)

const (
	// ProviderID is the id of the provider in [Issuer.Config] and
	// [Issuer.KubernetesConfig].
	ProviderID = "test"
	// Realm is the realm that [Issuer.RealmConfig] serves.
	Realm = "test"
	// Audience is the audience that [Issuer.KubernetesConfig] accepts.
	Audience = "netcracker"
)

// keyID is the kid of the key of every Issuer.
const keyID = "test-key"

// realmPath is the path of [Realm] under the address of an Issuer.
const realmPath = "/auth/realms/" + Realm

// Issuer is an identity provider that runs in the test process. It publishes
// one ES256 key through OIDC discovery on an [httptest.Server] and signs tokens
// with the private part of that key. Like that server, it panics on a failure
// no test can handle, and the test stops it with [Issuer.Close]. It is safe for
// concurrent use.
type Issuer struct {
	server  *httptest.Server
	private *ecdsa.PrivateKey
	// dir holds the token file of [Issuer.KubernetesConfig].
	dir string
}

// NewIssuer starts an Issuer with a new key.
func NewIssuer() *Issuer {
	private := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	public := must(jwk.Import(&private.PublicKey))
	if err := public.Set(jwk.KeyIDKey, keyID); err != nil {
		panic(fmt.Sprintf("tokentest: set the kid: %v", err))
	}
	jwks := must(json.Marshal(map[string][]jwk.Key{"keys": {public}}))

	mux := http.NewServeMux()
	server := httptest.NewUnstartedServer(mux)
	discovery := func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(must(json.Marshal(map[string]string{"issuer": server.URL, "jwks_uri": server.URL + "/jwks"})))
	}
	mux.HandleFunc("/.well-known/openid-configuration", discovery)
	mux.HandleFunc(realmPath+"/.well-known/openid-configuration", discovery)
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(jwks)
	})
	server.Start()
	return &Issuer{server: server, private: private, dir: must(os.MkdirTemp("", "tokentest"))}
}

// Close stops the server and removes the token file.
func (i *Issuer) Close() {
	i.server.Close()
	if err := os.RemoveAll(i.dir); err != nil {
		panic(fmt.Sprintf("tokentest: remove the token file: %v", err))
	}
}

// URL returns the address of the issuer, which is the iss of its tokens.
func (i *Issuer) URL() string { return i.server.URL }

// Config returns a configuration with one provider, [ProviderID], that trusts
// this issuer. Its tokens are file tokens, which no claim makes M2M.
func (i *Issuer) Config() keys.Config {
	return keys.Config{Providers: []keys.Provider{{ID: ProviderID, Issuer: i.URL()}}}
}

// RealmConfig returns a configuration whose Keycloak is this issuer. A token
// whose iss is [Issuer.RealmURL] is a realm token of [Realm].
func (i *Issuer) RealmConfig() keys.Config {
	return keys.Config{Keycloak: &keys.Keycloak{URL: i.URL()}}
}

// RealmURL returns the iss of a realm token of [Realm].
func (i *Issuer) RealmURL() string { return i.URL() + realmPath }

// KubernetesConfig returns a configuration with one provider, [ProviderID],
// marked [keys.Provider.Kubernetes]. Such a provider takes its issuer from a
// token file, so this method writes one that names [Issuer.URL]. A token is a
// Kubernetes token when it names [Audience] in aud and its sub starts with
// system:serviceaccount.
func (i *Issuer) KubernetesConfig() keys.Config {
	path := filepath.Join(i.dir, "token")
	if err := os.WriteFile(path, []byte(i.Sign(i.Claims())), 0o600); err != nil {
		panic(fmt.Sprintf("tokentest: write the token file: %v", err))
	}
	return keys.Config{Providers: []keys.Provider{{ID: ProviderID, TokenFile: path, Audiences: []string{Audience}, Kubernetes: true}}}
}

// Claims returns the claims of a token issued now that expires in an hour: iss,
// sub, iat, and exp. A verifier on [Issuer.Config] accepts a token that holds
// them. The map belongs to the caller, which changes it before [Issuer.Sign].
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
