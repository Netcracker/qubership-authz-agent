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
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// maxResponseBytes bounds the body of every response that a load reads,
// whatever its status, 1 MiB (1048576 bytes). It bounds the body after the
// transport removes the gzip coding that the transport requests.
const maxResponseBytes = 1 << 20

// maxListedSkippedKeys bounds the skipped keys whose reasons a warning or an
// error lists; the skipped keys after them are only counted. A JWKS may list
// any number of entries, and a required source logs the error of every retry.
const maxListedSkippedKeys = 5

// The weakest RSA public key a provider may sign with: a modulus of
// minRSAModulusBits and a public exponent of minRSAPublicExponent.
// [jwk.ParseKey] applies the same floors by default, but they are
// process-wide settings any package can lower, and OPA sets both to zero
// when it is linked in.
const (
	minRSAModulusBits    = 2048
	minRSAPublicExponent = 3
)

// algorithmKeyType maps every JWS algorithm a token may be signed with to
// the JWK key type that verifies it. Only asymmetric algorithms are listed:
// the keys come from a JWKS anyone can read, and an HMAC key anyone can read
// lets anyone sign.
var algorithmKeyType = map[string]string{
	"RS256": "RSA", "RS384": "RSA", "RS512": "RSA",
	"PS256": "RSA", "PS384": "RSA", "PS512": "RSA",
	"ES256": "EC", "ES384": "EC", "ES512": "EC",
	"EdDSA": "OKP",
}

// algorithmCurve maps every accepted algorithm that signs with a single
// curve to that curve: each ES algorithm to its NIST curve (RFC 7518,
// section 3.4), and EdDSA to Ed25519, the one curve the service verifies.
var algorithmCurve = map[string]string{
	"ES256": "P-256", "ES384": "P-384", "ES512": "P-521",
	"EdDSA": "Ed25519",
}

// acceptedCurve reports whether an accepted algorithm signs with curve.
func acceptedCurve(curve string) bool {
	for _, c := range algorithmCurve {
		if c == curve {
			return true
		}
	}
	return false
}

// curveOf returns the crv of an EC or OKP key, and "" for any other key.
func curveOf(key jwk.Key) string {
	var crv jwa.EllipticCurveAlgorithm
	switch k := key.(type) {
	case jwk.ECDSAPublicKey:
		crv, _ = k.Crv()
	case jwk.OKPPublicKey:
		crv, _ = k.Crv()
	default:
		return ""
	}
	return crv.String()
}

// fetcher downloads the signing keys of one source.
type fetcher struct {
	source Source
	// address is the address discovery runs under: the Issuer of a provider,
	// or the address of a realm under [Keycloak.URL].
	address string
	client  *http.Client
	log     Logger
	// skipped identifies the keys that the last parse to load a key skipped,
	// other than encryption keys, so a parse warns only when those keys
	// change. A provider can therefore change its skipped keys without a
	// warning, but only keys it publishes itself. The fetches of a source are
	// serialized, so it needs no lock.
	skipped entrySum
	// otherIssuer is the iss, other than the issuer of the provider, that the
	// token named at the last warning of [fetcher.logIssuerChange], and "" while
	// the token names the issuer of the provider. The fetches of a source are
	// serialized, so it needs no lock.
	otherIssuer string
}

// jwksURI returns the [Provider.JWKSURI] of a provider, and "" for a realm.
func (f *fetcher) jwksURI() string {
	if f.source.Provider == nil {
		return ""
	}
	return f.source.Provider.JWKSURI
}

// tokenFile returns the [Provider.TokenFile] that a provider sends with its
// requests: "" for a realm, and for a provider that discovers its keys without
// its token, as [Provider.discoversWithoutToken] decides.
func (f *fetcher) tokenFile() string {
	p := f.source.Provider
	if p == nil || p.discoversWithoutToken() {
		return ""
	}
	return p.TokenFile
}

// emptyCertPool is the base pool of a caFile that replaces the system roots.
func emptyCertPool() (*x509.CertPool, error) { return x509.NewCertPool(), nil }

// newClient builds the HTTP client for one server: the proxy settings of the
// environment, timeout per request, and no redirect followed. When caFile is
// set, the client trusts the pool that base returns with caFile added. Without
// it the client trusts the system roots. [http.Client] forwards the bearer
// token of [Provider.TokenFile] to a redirect target on the same host or a
// subdomain of it, whatever its port or scheme, so a redirect ends the
// request as a failure instead. label names caFile in an error.
func newClient(label string, base func() (*x509.CertPool, error), caFile string, timeout time.Duration) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		roots, err := base()
		if err != nil {
			return nil, fmt.Errorf("%s: system roots: %w", label, err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s %s holds no PEM certificate", label, caFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// errNoUsableKey reports a JWKS that parses and holds no usable signing key.
// A reload that gets it removes the keys of the source.
var errNoUsableKey = errors.New("no usable signing key")

// errRealmMissing reports the 404 that Keycloak returns for the discovery
// document of a realm it does not hold: a JSON object whose member named
// exactly error is [realmDoesNotExist]. A 404 with another body, such as one
// from a proxy with no route for the path, is not one, and neither is a 404 of
// the JWKS: a realm whose discovery document returns 200 exists.
var errRealmMissing = errors.New("the Keycloak reports that the realm does not exist")

// realmDoesNotExist is the error member of the body of the 404 that Keycloak
// returns for a realm it does not hold.
const realmDoesNotExist = "Realm does not exist"

// statusError reports a response to a GET whose status is not 2xx.
type statusError struct {
	url    string
	status int
	// missingRealm reports whether the response is the 404 that Keycloak
	// returns for a realm it does not hold.
	missingRealm bool
}

// reportsMissingRealm reports whether a response with status and body is the
// 404 that Keycloak returns for a realm it does not hold: a JSON object whose
// member named exactly error, read through [member], is the string
// [realmDoesNotExist].
func reportsMissingRealm(status int, body []byte) bool {
	if status != http.StatusNotFound {
		return false
	}
	var message string
	return member(body, "error", &message) == nil && message == realmDoesNotExist
}

// member decodes into v the member of doc named exactly name, and leaves v as
// it is when doc has no such member. It fails when doc is neither a JSON object
// nor null, and when the member does not decode into v. It decodes doc into a
// map, because [json.Unmarshal] matches the name of a struct field without
// regard to case, so a struct would take KEYS or Keys for keys.
func member(doc []byte, name string, v any) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(doc, &members); err != nil {
		return err
	}
	raw, ok := members[name]
	if !ok {
		return nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func (e *statusError) Error() string { return fmt.Sprintf("GET %s: HTTP %d", e.url, e.status) }

// fetch downloads the JWKS of the source, through discovery unless a provider
// names a JWKSURI, and returns its signing keys. It fails when a request fails
// or returns a status other than 2xx, when it gets a response whose body is
// longer than 1 MiB, when a document is not the JSON it should be, when
// discovery names an address that is not https for a provider that sets
// Kubernetes, and when the JWKS lists two usable keys with different key
// material under one kid. Keycloak's 404 for a realm it does not hold, on the
// discovery document, fails with errRealmMissing, and a JWKS without a usable
// signing key with errNoUsableKey. It matches each member it reads by its exact
// name, through [member]: the jwks_uri of the discovery document, the keys of
// the JWKS, and the error of Keycloak's 404.
func (f *fetcher) fetch(ctx context.Context) ([]Key, error) {
	f.logIssuerChange()
	uri := f.jwksURI()
	if uri == "" {
		discovery := strings.TrimRight(f.address, "/") + "/.well-known/openid-configuration"
		body, err := f.get(ctx, discovery)
		if failed, ok := errors.AsType[*statusError](err); ok && failed.missingRealm {
			return nil, fmt.Errorf("%w: %w", err, errRealmMissing)
		}
		if err != nil {
			return nil, err
		}
		var jwksURI string
		if err := member(body, "jwks_uri", &jwksURI); err != nil {
			return nil, fmt.Errorf("discovery document %s: %w", discovery, err)
		}
		if jwksURI == "" {
			return nil, fmt.Errorf("discovery document %s has no jwks_uri", discovery)
		}
		if p := f.source.Provider; p != nil && p.Kubernetes && !isHTTPSURL(jwksURI) {
			return nil, fmt.Errorf("discovery document %s names the jwks_uri %.200q; %s sets kubernetes, so it reads its keys only over https; to read the keys without discovery, set jwksUri to %s%s", discovery, jwksURI, f.source.label(), apiServerJWKSURI, p.caFileRemedy())
		}
		uri = jwksURI
	}
	body, err := f.get(ctx, uri)
	if err != nil {
		return nil, err
	}
	keys, err := f.parseJWKS(body)
	if err != nil {
		return nil, fmt.Errorf("JWKS %s: %w", uri, err)
	}
	return keys, nil
}

// get returns the body of a 2xx response to a GET of url, with the bearer token
// in the file that [fetcher.tokenFile] returns, where it returns one. A
// response whose body is longer than maxResponseBytes fails whatever its
// status, and its error is not a *statusError. Any other status, a redirect
// included, is a *statusError.
func (f *fetcher) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if path := f.tokenFile(); path != "" {
		token, err := readToken(path)
		if err != nil {
			return nil, fmt.Errorf("%s tokenFile: %w", f.source.label(), err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: read body: %w", url, err)
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("GET %s: HTTP %d: response body is longer than %d bytes", url, resp.StatusCode, maxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &statusError{url: url, status: resp.StatusCode, missingRealm: reportsMissingRealm(resp.StatusCode, body)}
	}
	return body, nil
}

// logIssuerChange reads the iss of the token that [New] took the issuer of a
// provider from, whether or not the provider sends that token. It logs a
// warning each time the iss changes to one other than the issuer of the
// provider, and an informational record when the token names that issuer
// again after a warning. A token file it cannot read or parse is skipped with
// no record, and the next fetch reads it again.
func (f *fetcher) logIssuerChange() {
	p := f.source.Provider
	if p == nil || !p.Kubernetes {
		return
	}
	issuer, err := issuerOfTokenFile(p.TokenFile)
	switch {
	case err != nil, issuer == f.otherIssuer, issuer == p.Issuer && f.otherIssuer == "":
		return
	case issuer == p.Issuer:
		f.log.Infof("trusted providers: the token in %s names the issuer %q of %s again, so the warning about the issuer %q no longer holds", p.TokenFile, issuer, f.source.label(), f.otherIssuer)
		f.otherIssuer = ""
		return
	}
	f.otherIssuer = issuer
	f.log.Warnf("trusted providers: the token in %s names the issuer %q, and %s accepts only the issuer %q that it took at start; tokens of the new issuer are refused until the agent restarts", p.TokenFile, issuer, f.source.label(), p.Issuer)
}

func readToken(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return token, nil
}

// parseJWKS returns the signing keys of a JWKS document. A key that cannot sign
// a token the service accepts is skipped, and when the parse loads a key,
// [fetcher.reportSkipped] reports the skipped keys. A key listed again under
// the same kid with the same key material is loaded once, from the first of
// its usable entries, and two usable keys with different key material under
// one kid are an error. A keys member that is missing or is not an array, null
// included, is an error too; [member] reads it by that exact name. So is a JWKS
// left with no usable signing key, which fails with errNoUsableKey and the
// [skippedKeys.describe] text: the reasons of the first maxListedSkippedKeys
// skipped keys, the count of the rest, and the count of encryption keys.
func (f *fetcher) parseJWKS(body []byte) ([]Key, error) {
	var entries []json.RawMessage
	if err := member(body, "keys", &entries); err != nil {
		return nil, err
	}
	if entries == nil {
		return nil, errors.New("no keys array")
	}
	var out []Key
	var skipped skippedKeys
	thumbprints := make(map[string][]byte, len(entries))
	for i, raw := range entries {
		key, reason := signingKey(raw)
		if reason == encryptionKey {
			skipped.encryption++
			continue
		}
		if reason != "" {
			skipped.add(i, raw, reason)
			continue
		}
		thumbprint, err := key.JWK.Thumbprint(crypto.SHA256)
		if err != nil {
			skipped.add(i, raw, fmt.Sprintf("thumbprint: %q", err.Error()))
			continue
		}
		if earlier, seen := thumbprints[key.ID]; seen {
			if bytes.Equal(earlier, thumbprint) {
				continue
			}
			return nil, fmt.Errorf("kid %q names two different keys", key.ID)
		}
		thumbprints[key.ID] = thumbprint
		key.Source = f.source
		out = append(out, key)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %s", errNoUsableKey, skipped.describe())
	}
	f.reportSkipped(skipped)
	return out, nil
}

// skippedKeys describes the keys of one JWKS that a parse skipped.
type skippedKeys struct {
	// reasons names each of the first maxListedSkippedKeys skipped keys other
	// than encryption keys by its position and the reason.
	reasons []string
	// entries identifies the skipped keys other than encryption keys.
	entries entrySum
	// encryption counts the encryption keys, which are skipped silently.
	encryption int
}

func (k *skippedKeys) add(i int, raw json.RawMessage, reason string) {
	k.entries.add(raw)
	if len(k.reasons) < maxListedSkippedKeys {
		k.reasons = append(k.reasons, fmt.Sprintf("keys[%d]: %s", i, reason))
	}
}

// entrySum identifies a collection of JWKS entries by their count and by the
// sum of the SHA-256 digests of their JSON text, modulo 2^256. Its size does
// not depend on the count, and the sum does not change when an entry moves
// within the JWKS. The zero value counts no entry. Whoever chooses the entries
// can build two different collections with the same count and sum.
type entrySum struct {
	count int
	// sum holds the sum as four 64-bit words, the most significant first.
	sum [4]uint64
}

// add counts raw, the JSON text of one entry.
func (s *entrySum) add(raw json.RawMessage) {
	digest := sha256.Sum256(raw)
	var carry uint64
	for i := len(s.sum) - 1; i >= 0; i-- {
		s.sum[i], carry = bits.Add64(s.sum[i], binary.BigEndian.Uint64(digest[8*i:]), carry)
	}
	s.count++
}

// listed returns the reasons of the first maxListedSkippedKeys skipped keys
// other than encryption keys, and the count of the rest.
func (k *skippedKeys) listed() []string {
	parts := slices.Clone(k.reasons)
	if rest := k.entries.count - len(k.reasons); rest > 0 {
		parts = append(parts, countOf(rest, "more skipped key"))
	}
	return parts
}

// describe describes the skipped keys: the ones [skippedKeys.listed] lists, and
// the encryption keys by their count.
func (k *skippedKeys) describe() string {
	parts := k.listed()
	if k.encryption > 0 {
		parts = append(parts, countOf(k.encryption, "encryption key"))
	}
	if len(parts) == 0 {
		return "the keys array is empty"
	}
	return strings.Join(parts, "; ")
}

// countOf returns n and noun, with an s for any n but 1.
func countOf(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// reportSkipped warns about the keys that a parse which loaded a key skipped,
// other than encryption keys, when they differ from the keys that the last such
// parse skipped. A source is parsed on every load, and an unchanged JWKS says
// nothing new. A parse that loads no key does not call it: its errNoUsableKey
// error lists the keys, and the hourly reload may log that error for only one
// realm of many, so the next parse that loads a key reports them.
func (f *fetcher) reportSkipped(keys skippedKeys) {
	if keys.entries == f.skipped {
		return
	}
	f.skipped = keys.entries
	if keys.entries.count > 0 {
		f.log.Warnf("trusted providers: %s skips %s of its JWKS: %s", f.source.label(), countOf(keys.entries.count, "key"), strings.Join(keys.listed(), "; "))
	}
}

// encryptionKey is the reason [signingKey] gives for a key whose use is enc.
// Keycloak publishes such a key in the JWKS of every realm beside the signing
// keys, so skipping it is expected and is not reported.
const encryptionKey = "an encryption key"

// signingKey returns the public signing key raw describes, or the reason it
// is not one: [jwk.ParseKey] refuses it; it has no kid; its use is other
// than sig; no accepted algorithm uses its key type or, for an EC or OKP
// key, its curve; it declares an alg that [algorithmKeyType] does not map
// to its key type or [algorithmCurve] does not map to its curve; or it is
// an RSA key below the floors of minRSAModulusBits and minRSAPublicExponent.
func signingKey(raw json.RawMessage) (Key, string) {
	key, err := jwk.ParseKey(raw)
	if err != nil {
		return Key{}, fmt.Sprintf("cannot be parsed: %q", err.Error())
	}
	kid, _ := key.KeyID()
	if kid == "" {
		return Key{}, "has no kid"
	}
	if use, ok := key.KeyUsage(); ok && use == "enc" {
		return Key{}, encryptionKey
	}
	if use, ok := key.KeyUsage(); ok && use != "sig" {
		return Key{}, fmt.Sprintf("kid %q has use %q, not sig", kid, use)
	}
	kty := key.KeyType().String()
	if kty != "RSA" && kty != "EC" && kty != "OKP" {
		return Key{}, fmt.Sprintf("kid %q has key type %q, which no accepted algorithm uses", kid, kty)
	}
	alg := ""
	if declared, ok := key.Algorithm(); ok {
		alg = declared.String()
		if algorithmKeyType[alg] != kty {
			return Key{}, fmt.Sprintf("kid %q declares alg %q, which is not an accepted algorithm for key type %q", kid, alg, kty)
		}
	}
	public, err := jwk.PublicKeyOf(key)
	if err != nil {
		return Key{}, fmt.Sprintf("kid %q: public key: %q", kid, err.Error())
	}
	if reason := unusableKey(public, alg); reason != "" {
		return Key{}, fmt.Sprintf("kid %q %s", kid, reason)
	}
	return Key{ID: kid, JWK: public, alg: alg}, ""
}

// unusableKey returns why public cannot verify an accepted token, or "": an
// RSA key falls below minRSAModulusBits or minRSAPublicExponent; an EC or
// OKP key is on a curve no accepted algorithm signs with, or declares an alg
// of another curve. public is an RSA, EC, or OKP key, and alg is the
// algorithm it declares, "" when it declares none.
func unusableKey(public jwk.Key, alg string) string {
	if rsaKey, ok := public.(jwk.RSAPublicKey); ok {
		return weakRSA(rsaKey)
	}
	curve := curveOf(public)
	if !acceptedCurve(curve) {
		return fmt.Sprintf("has curve %q, which no accepted algorithm uses", curve)
	}
	if want, ok := algorithmCurve[alg]; ok && want != curve {
		return fmt.Sprintf("declares alg %q, which signs with %s, not with its curve %s", alg, want, curve)
	}
	return ""
}

// weakRSA returns why key falls below the RSA floors, or "".
func weakRSA(key jwk.RSAPublicKey) string {
	n, _ := key.N()
	if bits := new(big.Int).SetBytes(n).BitLen(); bits < minRSAModulusBits {
		return fmt.Sprintf("has an RSA modulus of %d bits, shorter than %d", bits, minRSAModulusBits)
	}
	e, _ := key.E()
	if exponent := new(big.Int).SetBytes(e); exponent.Cmp(big.NewInt(minRSAPublicExponent)) < 0 {
		return fmt.Sprintf("has an RSA public exponent of %s, less than %d", exponent, minRSAPublicExponent)
	}
	return ""
}
