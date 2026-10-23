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

package keys

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// fakeIdP serves an OIDC discovery document at /.well-known/openid-configuration
// that points at /jwks, and the JWKS there. Every field set through its
// methods takes effect on the next request.
type fakeIdP struct {
	srv *httptest.Server

	mu sync.Mutex
	// keys is the JWKS the provider publishes.
	keys []json.RawMessage
	// discovery and jwks replace the documents served, when non-nil.
	discovery []byte
	jwks      []byte
	// status, when non-zero, answers every request.
	status int
	// failures is how many of the next requests get 503.
	failures int
	// token, when set, is the bearer token a request has to carry.
	token     string
	lastAuth  string
	discovers int
	// gate, when non-nil, holds every JWKS response until it is closed.
	gate chan struct{}
}

func newIdP(t *testing.T, keys ...json.RawMessage) *fakeIdP {
	t.Helper()
	idp := &fakeIdP{keys: keys}
	idp.srv = httptest.NewServer(idp)
	t.Cleanup(idp.srv.Close)
	return idp
}

func newTLSIdP(t *testing.T, keys ...json.RawMessage) *fakeIdP {
	t.Helper()
	idp := &fakeIdP{keys: keys}
	idp.srv = httptest.NewTLSServer(idp)
	t.Cleanup(idp.srv.Close)
	return idp
}

func (idp *fakeIdP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	idp.mu.Lock()
	idp.lastAuth = r.Header.Get("Authorization")
	switch {
	case idp.status != 0:
		idp.mu.Unlock()
		w.WriteHeader(idp.status)
		return
	case idp.failures > 0:
		idp.failures--
		idp.mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	case idp.token != "" && idp.lastAuth != "Bearer "+idp.token:
		idp.mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var body []byte
	var gate chan struct{}
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		idp.discovers++
		body = idp.discovery
		if body == nil {
			body, _ = json.Marshal(map[string]string{"jwks_uri": idp.srv.URL + "/jwks"})
		}
	case "/jwks":
		gate = idp.gate
		body = idp.jwks
		if body == nil {
			body, _ = json.Marshal(map[string]any{"keys": idp.keys})
		}
	default:
		idp.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	idp.mu.Unlock()
	if gate != nil {
		<-gate
	}
	_, _ = w.Write(body)
}

func (idp *fakeIdP) publish(keys ...json.RawMessage) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.keys = keys
}

// setJWKS serves body in place of the JWKS built from the published keys.
func (idp *fakeIdP) setJWKS(body string) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.jwks = []byte(body)
}

func (idp *fakeIdP) setStatus(status int) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.status = status
}

func (idp *fakeIdP) setGate(gate chan struct{}) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.gate = gate
}

func (idp *fakeIdP) discoveries() int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.discovers
}

func (idp *fakeIdP) authorization() string {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.lastAuth
}

// caFile writes the server certificate of a TLS fakeIdP as a PEM file.
func (idp *fakeIdP) caFile(t *testing.T) string {
	t.Helper()
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idp.srv.Certificate().Raw})
	return writeFile(t, "ca.pem", string(block))
}

// issuer is a provider found through the discovery document of idp.
func issuer(id string, idp *fakeIdP) Provider {
	return Provider{ID: id, Issuer: idp.srv.URL}
}

// direct is a provider whose JWKS is fetched from idp without discovery.
func direct(id string, idp *fakeIdP) Provider {
	return Provider{ID: id, JWKSURI: idp.srv.URL + "/jwks"}
}

// ecJWK returns the public JWK of a new P-256 key with kid, alg ES256, and
// use sig. Each entry of fields sets that member of the JWK, and a nil value
// removes it.
func ecJWK(t *testing.T, kid string, fields map[string]any) json.RawMessage {
	t.Helper()
	return curveJWK(t, elliptic.P256(), "ES256", kid, fields)
}

// curveJWK returns the public JWK of a new EC key on curve with kid, alg,
// and use sig, with fields applied as in ecJWK.
func curveJWK(t *testing.T, curve elliptic.Curve, alg, kid string, fields map[string]any) json.RawMessage {
	t.Helper()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicJWK(t, &private.PublicKey, map[string]any{"kid": kid, "alg": alg, "use": "sig"}, fields)
}

// x25519JWK returns the public JWK of a new X25519 key, an OKP key that
// agrees on secrets and signs nothing, with kid and use sig.
func x25519JWK(t *testing.T, kid string) json.RawMessage {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicJWK(t, private.PublicKey(), map[string]any{"kid": kid, "use": "sig"}, nil)
}

// edJWK returns the public JWK of a new Ed25519 key with kid, alg EdDSA, and
// use sig, with fields applied as in ecJWK.
func edJWK(t *testing.T, kid string, fields map[string]any) json.RawMessage {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicJWK(t, public, map[string]any{"kid": kid, "alg": "EdDSA", "use": "sig"}, fields)
}

// paddedJWKS returns a JWKS that lists key and is padded with spaces to size
// bytes.
func paddedJWKS(key json.RawMessage, size int) []byte {
	body := `{"keys": [` + string(key) + `]}`
	return []byte(body + strings.Repeat(" ", size-len(body)))
}

// rsaJWK returns the public JWK of a new RSA key of bits with kid, alg
// RS256, and use sig, with fields applied as in ecJWK. It writes the members
// itself, because jwk.Import refuses a modulus shorter than 2048 bits.
func rsaJWK(t *testing.T, bits int, kid string, fields map[string]any) json.RawMessage {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	members := map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(private.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(private.E)).Bytes()),
	}
	return withMembers(t, members, map[string]any{"kid": kid, "alg": "RS256", "use": "sig"}, fields)
}

func publicJWK(t *testing.T, public any, defaults, fields map[string]any) json.RawMessage {
	t.Helper()
	key, err := jwk.Import(public)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]any
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}
	return withMembers(t, members, defaults, fields)
}

// withMembers applies defaults and then fields to members, removing a member
// whose value is nil, and returns the JSON.
func withMembers(t *testing.T, members, defaults, fields map[string]any) json.RawMessage {
	t.Helper()
	for _, set := range []map[string]any{defaults, fields} {
		for name, value := range set {
			if value == nil {
				delete(members, name)
			} else {
				members[name] = value
			}
		}
	}
	out, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// testOptions has Load retry a failed fetch after 10 ms, doubling the pause
// each time, for up to two seconds.
func testOptions() Options {
	return Options{StartupTimeout: 2 * time.Second, firstRetryDelay: 10 * time.Millisecond}
}

// mustLoad loads providers with opts and stops the test when Load fails.
func mustLoad(t *testing.T, opts Options, providers ...Provider) *Set {
	t.Helper()
	set, err := Load(context.Background(), Config{Providers: providers}, opts)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return set
}

// waitFor polls cond every 5 ms for up to five seconds and fails the test
// with what when it never holds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after 5s waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// containsAll reports whether s contains every one of parts.
func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}
