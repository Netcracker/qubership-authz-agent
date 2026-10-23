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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

// maxResponseBytes bounds the body of a discovery document and of a JWKS,
// 1 MiB (1048576 bytes).
const maxResponseBytes = 1 << 20

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

// fetcher downloads the signing keys of one provider.
type fetcher struct {
	provider *Provider
	client   *http.Client
	log      Logger
}

// newFetcher builds the HTTP client for p: the proxy settings of the
// environment, timeout per request, p.CAFile as the only trusted roots when
// it is set, and no redirect followed. [http.Client] forwards the bearer
// token of p.TokenFile to a redirect target on the same host or a subdomain
// of it, whatever its port or scheme, so a redirect ends the request as a
// failure instead.
func newFetcher(p *Provider, timeout time.Duration, log Logger) (*fetcher, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if p.CAFile != "" {
		pem, err := os.ReadFile(p.CAFile)
		if err != nil {
			return nil, fmt.Errorf("provider %q caFile: %w", p.ID, err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("provider %q caFile %s holds no PEM certificate", p.ID, p.CAFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &fetcher{provider: p, client: client, log: log}, nil
}

// errNoUsableKey reports a JWKS that parses and holds no usable signing key.
// [Load] retries such a provider and fails when it stays so; [Set.Refresh]
// removes the provider's keys.
var errNoUsableKey = errors.New("no usable signing key")

// fetch downloads the provider's JWKS, through discovery when the provider
// names an issuer, and returns its signing keys. It fails when a request
// fails or answers a status other than 2xx, when a document is not the JSON
// it should be, and when the JWKS lists two different keys under one kid;
// a JWKS without a usable signing key fails with errNoUsableKey.
func (f *fetcher) fetch(ctx context.Context) ([]Key, error) {
	uri := f.provider.JWKSURI
	if uri == "" {
		discovery := strings.TrimRight(f.provider.Issuer, "/") + "/.well-known/openid-configuration"
		body, err := f.get(ctx, discovery)
		if err != nil {
			return nil, err
		}
		var doc struct {
			JWKSURI string `json:"jwks_uri"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, fmt.Errorf("discovery document %s: %w", discovery, err)
		}
		if doc.JWKSURI == "" {
			return nil, fmt.Errorf("discovery document %s has no jwks_uri", discovery)
		}
		uri = doc.JWKSURI
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

// get returns the body of a 2xx response to a GET of url, with the bearer
// token of the provider's TokenFile when it has one. Any other status,
// a redirect included, is an error.
func (f *fetcher) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if f.provider.TokenFile != "" {
		token, err := readToken(f.provider.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("provider %q tokenFile: %w", f.provider.ID, err)
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
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("GET %s: response is longer than %d bytes", url, maxResponseBytes)
	}
	return body, nil
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

// parseJWKS returns the signing keys of a JWKS document. A key that cannot
// sign a token the service accepts is skipped with a warning, and the same
// key listed twice under one kid is kept once. A keys member that is null
// counts as an empty array, the way a Go server writes an empty key set;
// one that is missing or holds another value is an error, and so is a JWKS
// left with no usable signing key, which fails with errNoUsableKey.
func (f *fetcher) parseJWKS(body []byte) ([]Key, error) {
	var doc struct {
		Keys json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if doc.Keys == nil {
		return nil, errors.New("no keys array")
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(doc.Keys, &entries); err != nil {
		return nil, fmt.Errorf("keys is not an array: %w", err)
	}
	var out []Key
	thumbprints := make(map[string][]byte, len(entries))
	skipped := 0
	for i, raw := range entries {
		key, reason := signingKey(raw)
		if reason != "" {
			skipped++
			f.log.Warnf("trusted providers: provider %q skips keys[%d]: %s", f.provider.ID, i, reason)
			continue
		}
		thumbprint, err := key.JWK.Thumbprint(crypto.SHA256)
		if err != nil {
			skipped++
			f.log.Warnf("trusted providers: provider %q skips keys[%d]: thumbprint: %v", f.provider.ID, i, err)
			continue
		}
		if earlier, seen := thumbprints[key.ID]; seen {
			if bytes.Equal(earlier, thumbprint) {
				continue
			}
			return nil, fmt.Errorf("kid %q names two different keys", key.ID)
		}
		thumbprints[key.ID] = thumbprint
		key.Provider = f.provider
		out = append(out, key)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w (%d skipped)", errNoUsableKey, skipped)
	}
	return out, nil
}

// signingKey returns the public signing key raw describes, or the reason it
// is not one: [jwk.ParseKey] refuses it; it has no kid; its use is other
// than sig; no accepted algorithm uses its key type or, for an EC or OKP
// key, its curve; it declares an alg that [algorithmKeyType] does not map
// to its key type or [algorithmCurve] does not map to its curve; or it is
// an RSA key below the floors of minRSAModulusBits and minRSAPublicExponent.
func signingKey(raw json.RawMessage) (Key, string) {
	key, err := jwk.ParseKey(raw)
	if err != nil {
		return Key{}, fmt.Sprintf("cannot be parsed: %v", err)
	}
	kid, _ := key.KeyID()
	if kid == "" {
		return Key{}, "has no kid"
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
		return Key{}, fmt.Sprintf("kid %q: public key: %v", kid, err)
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
