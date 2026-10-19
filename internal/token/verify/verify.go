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

// Package verify checks a JWT against the signing keys of the trusted
// providers and returns its claims. [Verifier.Verify] reads nothing from the
// payload until the signature verifies: the header names the algorithm and
// the kid, a [KeySource] finds the key, and only a token whose signature
// that key accepts has its exp, nbf, iat, and aud checked. A refused token
// yields an [*Error] whose [Code] names the reason.
//
// A verified token is cached by the SHA-256 digest of its compact form
// until it expires, so a token presented again costs a map lookup.
package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"authz-agent/internal/token/keys"
)

// Code names the reason a token was refused. The values are the reason
// codes the service reports to its callers.
type Code string

// Reasons a token is refused.
const (
	// CodeFormatInvalid marks a token that is not three base64url parts
	// separated by dots, whose header or payload is not a JSON object, or
	// whose exp, nbf, or iat is not a number within ±(2^53 - 1) seconds.
	CodeFormatInvalid Code = "TOKEN_FORMAT_INVALID"
	// CodeAlgNotAllowed marks a token whose header names an algorithm that no
	// key accepts, or one that the key its kid names does not accept.
	CodeAlgNotAllowed Code = "TOKEN_ALG_NOT_ALLOWED"
	// CodeKIDMissing marks a token whose header has no kid.
	CodeKIDMissing Code = "TOKEN_KID_MISSING"
	// CodeKIDUnknown marks a token whose kid no trusted provider publishes.
	CodeKIDUnknown Code = "TOKEN_KID_UNKNOWN"
	// CodeSignatureInvalid marks a token whose signature does not verify
	// with the key its kid names.
	CodeSignatureInvalid Code = "TOKEN_SIGNATURE_INVALID"
	// CodeExpMissing marks a token without an exp claim.
	CodeExpMissing Code = "TOKEN_EXP_MISSING"
	// CodeExpired marks a token whose exp has passed.
	CodeExpired Code = "TOKEN_EXPIRED"
	// CodeNotYetValid marks a token whose nbf has not come yet.
	CodeNotYetValid Code = "TOKEN_NOT_YET_VALID"
	// CodeIATMissing marks a token without an iat claim.
	CodeIATMissing Code = "TOKEN_IAT_MISSING"
	// CodeIATInvalid marks a token whose iat is in the future.
	CodeIATInvalid Code = "TOKEN_IAT_INVALID"
	// CodeAudienceMissing marks a token without an aud claim from a provider
	// that requires one.
	CodeAudienceMissing Code = "TOKEN_AUDIENCE_MISSING"
	// CodeAudienceInvalid marks a token whose aud names none of the
	// provider's audiences, or is neither a string nor an array of strings.
	CodeAudienceInvalid Code = "TOKEN_AUDIENCE_INVALID"
)

// Error is the reason a token was refused.
type Error struct {
	Code Code
	// Detail describes the fault for a log line. It never contains the
	// token itself.
	Detail string
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Detail }

func fail(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// Token is a verified token.
type Token struct {
	// Provider is the provider whose key signed the token.
	Provider *keys.Provider
	// KeyID is the kid of that key.
	KeyID string
	// Expiry is the time exp names.
	Expiry time.Time
	// Claims holds every claim of the payload, with numbers as [json.Number].
	// Every caller that verifies the same token gets the same map, so no
	// caller may modify it.
	Claims map[string]any

	// key is the key that verified the token. A cached Token is returned
	// only while the [KeySource] returns this key for KeyID.
	key jwk.Key
}

// KeySource finds a signing key by kid; [*keys.Set] implements it.
type KeySource interface {
	// Resolve returns the key published under kid, and may reload the keys
	// first when kid is unknown.
	Resolve(ctx context.Context, kid string) (keys.Key, bool)
	// Lookup returns the key published under kid from the keys already
	// loaded.
	Lookup(kid string) (keys.Key, bool)
}

// Defaults of [Options].
const (
	DefaultLeeway    = 30 * time.Second
	DefaultCacheSize = 10000
)

// Options tunes a [Verifier]. A zero field takes its default.
type Options struct {
	// Leeway is the difference between the clocks of the provider and of the
	// service that exp, nbf, and iat tolerate.
	Leeway time.Duration
	// CacheSize is the largest number of verified tokens the cache keeps; a
	// negative value turns the cache off.
	CacheSize int

	// now is the clock the claims are checked against.
	now func() time.Time
}

func (o Options) withDefaults() Options {
	if o.Leeway <= 0 {
		o.Leeway = DefaultLeeway
	}
	if o.CacheSize == 0 {
		o.CacheSize = DefaultCacheSize
	}
	if o.now == nil {
		o.now = time.Now
	}
	return o
}

// Verifier checks tokens against the keys of a [KeySource]. It is safe for
// concurrent use.
type Verifier struct {
	keys KeySource
	opts Options
	// cache is nil when Options.CacheSize turns it off.
	cache *cache
}

// New returns a [Verifier] that finds keys in source.
func New(source KeySource, opts Options) *Verifier {
	opts = opts.withDefaults()
	v := &Verifier{keys: source, opts: opts}
	if opts.CacheSize > 0 {
		v.cache = newCache(opts.CacheSize)
	}
	return v
}

// Verify checks raw, a JWT in compact serialization without a "Bearer"
// prefix, and returns the verified token. The checks run in this order, and
// the first that fails is returned as an [*Error]: the format, the alg and
// the kid of the header, the key the kid names, the signature, exp, nbf,
// iat, and aud. Nothing from the payload is read before the signature
// verifies, so a forged token is refused with [CodeSignatureInvalid]
// whatever its claims say.
//
// A token verified earlier that has not expired is returned from the cache
// while the [KeySource] returns the same key for its kid. Verify may wait
// for the source to reload the keys when the kid is unknown; ctx bounds that
// wait, and exp, nbf, and iat are checked against the time after that wait.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Token, error) {
	now := v.opts.now()
	digest := sha256.Sum256([]byte(raw))
	if tok := v.cached(digest, now); tok != nil {
		return tok, nil
	}
	alg, kid, err := readHeader(raw)
	if err != nil {
		return nil, err
	}
	key, ok := v.keys.Resolve(ctx, kid)
	if !ok {
		return nil, fail(CodeKIDUnknown, "kid %s is published by no trusted provider", short(kid))
	}
	if !key.Allows(alg) {
		return nil, fail(CodeAlgNotAllowed, "key %s of provider %q does not accept %s", short(kid), key.Provider.ID, alg)
	}
	algorithm, _ := jwa.LookupSignatureAlgorithm(alg)
	payload, err := jws.Verify([]byte(raw), jws.WithKey(algorithm, key.JWK), jws.WithCompact())
	if err != nil {
		return nil, fail(CodeSignatureInvalid, "signature does not verify with key %s of provider %q", short(kid), key.Provider.ID)
	}
	claims, err := decodeClaims(payload)
	if err != nil {
		return nil, err
	}
	// Resolve may have waited for a reload, long enough for the token to
	// expire, so the clock is read again.
	now = v.opts.now()
	expiry, err := checkTimes(claims, now, v.opts.Leeway)
	if err != nil {
		return nil, err
	}
	if err := checkAudience(claims, key.Provider); err != nil {
		return nil, err
	}
	tok := &Token{Provider: key.Provider, KeyID: kid, Expiry: expiry, Claims: claims, key: key.JWK}
	if v.cache != nil {
		v.cache.put(digest, tok, now, v.opts.Leeway)
	}
	return tok, nil
}

// cached returns the cached token for digest when it has not expired and its
// key is still the one the source publishes under its kid.
func (v *Verifier) cached(digest [sha256.Size]byte, now time.Time) *Token {
	if v.cache == nil {
		return nil
	}
	tok := v.cache.get(digest, now, v.opts.Leeway)
	if tok == nil {
		return nil
	}
	if key, ok := v.keys.Lookup(tok.KeyID); !ok || key.JWK != tok.key {
		return nil
	}
	return tok
}

// readHeader checks that raw is three base64url parts and returns the alg
// and the kid of its header. Every check here runs before any key is asked
// for, so a token that fails one never makes the source reload.
func readHeader(raw string) (alg, kid string, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", "", fail(CodeFormatInvalid, "a compact JWS has 3 parts separated by dots, the token has %d", len(parts))
	}
	var decoded [3][]byte
	for i, name := range []string{"header", "payload", "signature"} {
		if decoded[i], err = base64.RawURLEncoding.DecodeString(parts[i]); err != nil {
			return "", "", fail(CodeFormatInvalid, "%s is not base64url: %v", name, err)
		}
	}
	var header *struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(decoded[0], &header); err != nil || header == nil {
		return "", "", fail(CodeFormatInvalid, "header is not a JSON object with string alg and kid")
	}
	if !keys.AcceptsAlgorithm(header.Alg) {
		return "", "", fail(CodeAlgNotAllowed, "alg %s is not an accepted signature algorithm", short(header.Alg))
	}
	if header.Kid == "" {
		return "", "", fail(CodeKIDMissing, "header has no kid")
	}
	return header.Alg, header.Kid, nil
}

// decodeClaims parses the payload as one JSON object, keeping numbers as
// [json.Number].
func decodeClaims(payload []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil || claims == nil {
		return nil, fail(CodeFormatInvalid, "payload is not a JSON object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fail(CodeFormatInvalid, "payload has data after the JSON object")
	}
	return claims, nil
}

// short quotes s for a detail, cut to 64 bytes: s is the sender's text,
// and a detail goes into a log line.
func short(s string) string {
	const limit = 64
	if len(s) > limit {
		return fmt.Sprintf("%q...", s[:limit])
	}
	return fmt.Sprintf("%q", s)
}

// shortList quotes the first three of values as [short] does and counts the
// rest.
func shortList(values []string) string {
	const limit = 3
	quoted := make([]string, 0, limit)
	for _, v := range values[:min(len(values), limit)] {
		quoted = append(quoted, short(v))
	}
	list := "[" + strings.Join(quoted, " ") + "]"
	if len(values) > limit {
		list += fmt.Sprintf(" and %d more", len(values)-limit)
	}
	return list
}
