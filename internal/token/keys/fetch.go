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
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// maxResponseBytes bounds the body of a JWKS, 1 MiB (1048576 bytes).
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
	// address is the address of the JWKS: the jwksUri of a single provider,
	// or the jwksUri of a realms provider with the realm name in place of
	// {realm}.
	address string
	client  *http.Client
	log     Logger
	// skipped identifies the keys that the last parse to load a key skipped,
	// other than encryption keys, so a parse warns only when those keys
	// change. A provider can therefore change its skipped keys without a
	// warning, but only keys it publishes itself. The fetches of a source are
	// serialized, so it needs no lock.
	skipped entrySum
}

// newClient builds the HTTP client of one provider: the proxy settings and
// the trusted roots of the environment, timeout per request, and no redirect
// followed. [http.Client] forwards the bearer token of
// [Provider.JWKSBearerTokenFile] to a redirect target on the same host or a
// subdomain of it, whatever its port or scheme, so a redirect ends the request
// as a failure instead.
func newClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: http.DefaultTransport.(*http.Transport).Clone(),
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// errNoUsableKey reports a JWKS that parses and holds no usable signing key.
// A reload that gets it removes the keys of the source.
var errNoUsableKey = errors.New("no usable signing key")

// statusError reports a response whose status is not 2xx.
type statusError struct {
	url    string
	status int
}

func (e *statusError) Error() string { return fmt.Sprintf("GET %s: HTTP %d", e.url, e.status) }

// isNotFound reports whether err holds a [statusError] for HTTP 404.
func isNotFound(err error) bool {
	status, ok := errors.AsType[*statusError](err)
	return ok && status.status == http.StatusNotFound
}

// fetch downloads the JWKS of the source and returns its signing keys. It
// fails with a *statusError when the response is not 2xx, and with a
// *requestError when [http.Client.Do] fails, as it does for a redirect whose
// Location header does not parse. It also fails when the body is longer than
// maxResponseBytes or is not the JSON of a JWKS; a JWKS without a usable
// signing key fails with errNoUsableKey.
func (f *fetcher) fetch(ctx context.Context) ([]Key, error) {
	body, err := f.get(ctx)
	if err != nil {
		return nil, err
	}
	keys, err := f.parseJWKS(body)
	if err != nil {
		return nil, fmt.Errorf("JWKS %s: %w", f.address, err)
	}
	return keys, nil
}

// get returns the body of a 2xx response to a GET of the address, with the
// bearer token of the [Provider.JWKSBearerTokenFile] of a provider that sets
// one. Any other status, a redirect included, is a *statusError, and its body
// is not read. A request that [http.Client.Do] fails, a redirect whose Location
// header does not parse included, is a *requestError.
func (f *fetcher) get(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if path := f.source.Provider.JWKSBearerTokenFile; path != "" {
		token, err := readToken(path)
		if err != nil {
			return nil, fmt.Errorf("%s jwksBearerTokenFile: %w", f.source.label(), err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, &requestError{err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &statusError{url: f.address, status: resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: read body: %w", f.address, err)
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("GET %s: response is longer than %d bytes", f.address, maxResponseBytes)
	}
	return body, nil
}

// requestError is err from [http.Client.Do] with the text of its cause cut:
// the method and the URL as [url.Error] prints them, then the text of the
// cause quoted and cut to its first 200 runes. The provider decides how long
// that text is: net/http parses the Location header of a 3xx before
// CheckRedirect stops the redirect, quotes an unparsable header twice, and
// by default accepts response headers up to 10 MiB. Unwrap returns err, so
// errors.Is and errors.As reach the *url.Error and its cause.
type requestError struct {
	err error
}

func (e *requestError) Error() string {
	var unsent *url.Error
	if !errors.As(e.err, &unsent) {
		// Do documents a *url.Error for every error it returns; an error of
		// any other type is cut whole.
		return quoted(e.err.Error(), 200)
	}
	return fmt.Sprintf("%s %q: %s", unsent.Op, unsent.URL, quoted(unsent.Err.Error(), 200))
}

func (e *requestError) Unwrap() error { return e.err }

// quoted quotes s, cut to its first limit runes with "..." after the cut.
func quoted(s string, limit int) string {
	// s can run to tens of megabytes, and []rune(s) would take four bytes
	// for each of them.
	n := 0
	for i := range s {
		if n == limit {
			return strconv.Quote(s[:i]) + "..."
		}
		n++
	}
	return strconv.Quote(s)
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

// parseJWKS returns the signing keys of a JWKS document in the order of the
// entries of its keys array. The member of the document named exactly keys
// holds that array; a document without that member, or with null or another
// value in it, is an error. Each usable
// entry is a key of its own, also where several entries share a kid. A key
// that cannot sign a token the service accepts is skipped, and when the parse
// loads a key, [fetcher.reportSkipped] reports the skipped keys. A JWKS left
// with no usable signing key fails with errNoUsableKey and the
// [skippedKeys.describe] text: the reasons of the first maxListedSkippedKeys
// skipped keys, the count of the rest, and the count of encryption keys.
func (f *fetcher) parseJWKS(body []byte) ([]Key, error) {
	// A map, unlike a struct, matches a member by its exact name.
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	keys, ok := doc["keys"]
	if !ok || isNull(keys) {
		return nil, errors.New("no keys array")
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(keys, &entries); err != nil {
		return nil, fmt.Errorf("keys is not an array: %w", err)
	}
	var out []Key
	var skipped skippedKeys
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
// nothing new. A parse that loads no key does not call it, because its
// errNoUsableKey error already lists the skipped keys. The record of skipped
// keys then stays as the last parse that loaded a key left it, and the next
// such parse compares against that record.
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
