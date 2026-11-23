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
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// fakeIdP serves a JWKS at /jwks. Every field set through its methods takes
// effect on the next request.
type fakeIdP struct {
	srv *httptest.Server

	mu sync.Mutex
	// keys is the JWKS the provider publishes.
	keys []json.RawMessage
	// jwks replaces the document served, when non-nil.
	jwks []byte
	// status, when non-zero, answers every request.
	status int
	// failures is how many of the next requests get 503.
	failures int
	// token, when set, is the bearer token a request has to carry.
	token    string
	lastAuth string
	// requests counts the requests served.
	requests int
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
	idp.requests++
	idp.lastAuth = r.Header.Get("Authorization")
	switch {
	case idp.status != 0:
		status := idp.status
		idp.mu.Unlock()
		w.WriteHeader(status)
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
	if r.URL.Path != "/jwks" {
		idp.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	body := idp.jwks
	if body == nil {
		body, _ = json.Marshal(map[string]any{"keys": idp.keys})
	}
	idp.mu.Unlock()
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

func (idp *fakeIdP) authorization() string {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.lastAuth
}

// requestCount returns how many requests idp has served.
func (idp *fakeIdP) requestCount() int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.requests
}

// ignoreAudience is the audience of a provider whose aud is not checked.
var ignoreAudience = Audience{Mode: Ignore}

// kubernetesOf is the provider kubernetes whose issuer is the address of idp
// and whose jwksUri is an https address in the cluster, which
// [serveKubernetes] directs to idp.
func kubernetesOf(idp *fakeIdP) Provider {
	return Provider{ID: KubernetesID, Type: Single, Issuer: idp.srv.URL, JWKSURI: "https://kubernetes.default.svc/jwks"}
}

// serveKubernetes has set send each request of its provider kubernetes to srv,
// with its path, query, and headers, so the jwksUri of that provider may be an
// https address that srv does not serve.
func serveKubernetes(set *Set, srv *httptest.Server) {
	routeKubernetes(set, toServer{srv})
}

// routeKubernetes has set send each request of its provider kubernetes through
// transport.
func routeKubernetes(set *Set, transport http.RoundTripper) {
	for _, src := range set.single {
		if src.fetcher.source.Provider.ID == KubernetesID {
			src.fetcher.client.Transport = transport
		}
	}
}

// toServer is an http.RoundTripper that sends every request to srv over plain
// http.
type toServer struct{ srv *httptest.Server }

func (s toServer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.URL.Scheme, r.URL.Host = "http", s.srv.Listener.Addr().String()
	return s.srv.Client().Transport.RoundTrip(r)
}

// singleOf is a single provider with key id whose issuer is the address of
// idp and whose JWKS idp serves.
func singleOf(id string, idp *fakeIdP) Provider {
	return Provider{ID: id, Type: Single, Issuer: idp.srv.URL, JWKSURI: idp.srv.URL + "/jwks", Audience: ignoreAudience}
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

// twinJWKs returns a JWK of one new RSA key under the kid twin, with alg RS256
// and use sig, for each of fields, applied as in ecJWK.
func twinJWKs(t *testing.T, fields ...map[string]any) []json.RawMessage {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]json.RawMessage, len(fields))
	for i, f := range fields {
		members := map[string]any{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(private.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(private.E)).Bytes()),
		}
		out[i] = withMembers(t, members, map[string]any{"kid": "twin", "alg": "RS256", "use": "sig"}, f)
	}
	return out
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

// testOptions has Run retry a failed fetch after 10 ms, doubling the pause
// each time.
func testOptions() Options {
	return Options{firstRetryDelay: 10 * time.Millisecond}
}

// mustLoad returns a Set of providers with opts, after one Refresh, and stops
// the test when Refresh fails.
func mustLoad(t *testing.T, opts Options, providers ...Provider) *Set {
	t.Helper()
	set := mustNew(t, Config{Providers: providers}, opts)
	if err := set.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	return set
}

// mustNew returns a Set of cfg with opts and stops the test when New fails.
func mustNew(t *testing.T, cfg Config, opts Options) *Set {
	t.Helper()
	set, err := New(cfg, opts)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return set
}

// loaded reports whether set holds a key under kid for the issuer of p, a
// single provider.
func loaded(set *Set, p Provider, kid string) bool {
	_, err := set.Lookup(Query{Issuer: p.Issuer, KID: kid})
	return err == nil
}

// warnRecorder is a Logger that keeps the warnings and the informational
// messages.
type warnRecorder struct {
	mu       sync.Mutex
	warnings []string
	infos    []string
}

func (r *warnRecorder) Infof(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.infos = append(r.infos, fmt.Sprintf(format, args...))
}

func (r *warnRecorder) Warnf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.warnings = append(r.warnings, fmt.Sprintf(format, args...))
}

// matches reports whether one warning contains every one of parts.
func (r *warnRecorder) matches(parts ...string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.ContainsFunc(r.warnings, func(w string) bool { return containsAll(w, parts...) })
}

// count returns how many warnings contain part.
func (r *warnRecorder) count(part string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	matched := 0
	for _, w := range r.warnings {
		if strings.Contains(w, part) {
			matched++
		}
	}
	return matched
}

// The reasons of an UnavailableError that need no value of a Set.
const (
	reasonOfTheLoadLimit  = "the agent started 10 on-demand loads of the provider in the last minute, the most it allows for one provider"
	reasonOfAFailedLoad   = "the last load of the source failed"
	reasonOfAnEndedCaller = "the caller stopped waiting before the load ended"
)

// unavailable reports whether err is an *UnavailableError with reason.
func unavailable(err error, reason string) bool {
	u, ok := errors.AsType[*UnavailableError](err)
	return ok && u.Reason == reason
}

// errorText returns the text of err, and "" for nil.
func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
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
