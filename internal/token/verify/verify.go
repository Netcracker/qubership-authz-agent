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
// the kid, a [KeyFinder] finds the key, and only a token whose signature
// that key accepts has its aud, exp, nbf, and iat checked. A refused token
// yields an [*Error] whose [Code] names the reason; a verified one is a
// [*Token], which keeps the payload as the provider signed it.
//
// A verified token is cached by the SHA-256 digest of its compact form
// until it expires, so a token presented again costs a map lookup.
package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"

	"authz-agent/internal/token/keys"
)

// Code names the reason a token was refused. The values are the reason
// codes the service reports to its callers.
type Code string

// Reasons a token is refused.
const (
	// CodeFormatInvalid marks a token that is not three base64url parts
	// separated by dots, or whose header or payload is not a JSON object. It
	// also marks a header whose alg or kid is not a string or that has a crit
	// or a b64 parameter, and an exp, nbf, or iat that is not a number within
	// ±(2^53 - 1) seconds.
	CodeFormatInvalid Code = "TOKEN_FORMAT_INVALID"
	// CodeAlgNotAllowed marks a token whose header names no algorithm, one
	// that no key accepts, or one that the key its kid names does not accept.
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
	// CodeNamespaceNotAllowed marks a Kubernetes token from a namespace the
	// service does not accept, or one that names no namespace.
	CodeNamespaceNotAllowed Code = "TOKEN_NAMESPACE_NOT_ALLOWED"
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

// Token is a verified token. Nothing changes a Token after Verify returns
// it, and every method that returns JSON text returns a copy, so one Token is
// safe to read from many goroutines, and the cache shares it between the
// callers that present the same token.
type Token struct {
	raw        string
	payload    []byte
	claims     map[string]json.RawMessage
	standard   Standard
	providerID string
	keyID      string
	issuer     string
	expiry     time.Time

	// key is the key that verified the token. A cached Token is returned
	// only while the [KeyFinder] returns this key for keyID.
	key jwk.Key
}

// Standard holds the claims a policy input is usually built from. Each field
// is the JSON text of its claim exactly as the payload carries it, or nil
// when the payload has no such claim. Verify checks neither the presence
// nor the type of any of them.
type Standard struct {
	// Subject is the sub claim.
	Subject json.RawMessage
	// PreferredUsername is the preferred_username claim.
	PreferredUsername json.RawMessage
	// Roles is the roles member of the realm_access claim. It is nil when
	// realm_access is not a JSON object or has no roles member.
	Roles json.RawMessage
	// Scope is the scope claim.
	Scope json.RawMessage
	// Level is the level claim.
	Level json.RawMessage
	// TenantID is the tenant-id claim.
	TenantID json.RawMessage
}

// Raw returns the token in the compact form Verify received it in.
func (t *Token) Raw() string { return t.raw }

// Payload returns the JSON text of the payload exactly as the provider
// signed it, with the text of every number and the order of every key.
func (t *Token) Payload() json.RawMessage { return bytes.Clone(t.payload) }

// Claim returns the JSON text of the top-level claim name, and false when
// the payload has no such claim.
func (t *Token) Claim(name string) (json.RawMessage, bool) {
	raw, ok := t.claims[name]
	return bytes.Clone(raw), ok
}

// Standard returns the claims a policy input is usually built from.
func (t *Token) Standard() Standard {
	return Standard{
		Subject:           bytes.Clone(t.standard.Subject),
		PreferredUsername: bytes.Clone(t.standard.PreferredUsername),
		Roles:             bytes.Clone(t.standard.Roles),
		Scope:             bytes.Clone(t.standard.Scope),
		Level:             bytes.Clone(t.standard.Level),
		TenantID:          bytes.Clone(t.standard.TenantID),
	}
}

// ProviderID returns the id of the provider whose key verified the token.
func (t *Token) ProviderID() string { return t.providerID }

// KeyID returns the kid of the key that verified the token.
func (t *Token) KeyID() string { return t.keyID }

// Issuer returns the iss claim, or "" when the payload has no iss or iss is
// not a JSON string. Verify accepts a token whatever its iss.
func (t *Token) Issuer() string { return t.issuer }

// Expiry returns the time exp names.
func (t *Token) Expiry() time.Time { return t.expiry }

// KeyFinder finds a signing key by kid; [*keys.Set] implements it.
type KeyFinder interface {
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
	// Admit, when set, runs on every token Verify is about to return,
	// verified now or taken from the cache, and the *Error it returns
	// refuses the token. It holds the checks whose answer can change while
	// a token stays cached, such as the namespaces a Kubernetes token may
	// come from.
	Admit func(*Token) *Error

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

// Verifier checks tokens against the keys of a [KeyFinder]. It is safe for
// concurrent use.
type Verifier struct {
	keys KeyFinder
	opts Options
	// cache is nil when Options.CacheSize turns it off.
	cache *cache
}

// New returns a [Verifier] that finds keys in source.
func New(source KeyFinder, opts Options) *Verifier {
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
// the kid of the header, the key the kid names, the signature, aud, exp,
// nbf, and iat. Nothing from the payload is read before the signature
// verifies, so a forged token is refused with [CodeSignatureInvalid]
// whatever its claims say.
//
// A token verified earlier that has not expired is served from the cache,
// as the *Token the earlier call returned, while the [KeyFinder] returns the
// same key for its kid. [Options.Admit] then runs on the token either way.
func (v *Verifier) Verify(raw string) (*Token, error) {
	now := v.opts.now()
	digest := sha256.Sum256([]byte(raw))
	tok := v.cached(digest, now)
	if tok == nil {
		var err error
		if tok, err = v.check(raw, digest, now); err != nil {
			return nil, err
		}
	}
	if v.opts.Admit != nil {
		if err := v.opts.Admit(tok); err != nil {
			return nil, err
		}
	}
	return tok, nil
}

// check verifies raw, whose SHA-256 digest is digest, at now and caches the
// token it returns.
func (v *Verifier) check(raw string, digest [sha256.Size]byte, now time.Time) (*Token, error) {
	alg, kid, err := readHeader(raw)
	if err != nil {
		return nil, err
	}
	key, ok := v.keys.Lookup(kid)
	if !ok {
		return nil, fail(CodeKIDUnknown, "kid %s is published by no trusted provider", short(kid))
	}
	if !key.Allows(alg) {
		return nil, fail(CodeAlgNotAllowed, "key %s of provider %q does not accept %s", short(kid), key.Provider.ID, alg)
	}
	algorithm, _ := jwa.LookupSignatureAlgorithm(alg)
	payload, err := jws.Verify([]byte(raw), jws.WithKey(algorithm, key.JWK), jws.WithCompact(), jws.WithCritValidation(true))
	if err != nil {
		return nil, fail(CodeSignatureInvalid, "signature does not verify with key %s of provider %q", short(kid), key.Provider.ID)
	}
	claims, err := decodeClaims(payload)
	if err != nil {
		return nil, err
	}
	if err := checkAudience(claims, key.Provider); err != nil {
		return nil, err
	}
	expiry, err := checkTimes(claims, now, v.opts.Leeway)
	if err != nil {
		return nil, err
	}
	tok := &Token{
		raw:        raw,
		payload:    payload,
		claims:     claims,
		standard:   standardOf(claims),
		providerID: key.Provider.ID,
		keyID:      kid,
		issuer:     stringClaim(claims, "iss"),
		expiry:     expiry,
		key:        key.JWK,
	}
	if v.cache != nil {
		v.cache.put(digest, tok)
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
	if key, ok := v.keys.Lookup(tok.keyID); !ok || key.JWK != tok.key {
		return nil
	}
	return tok
}

// readHeader checks that raw is three base64url parts whose header is a JSON
// object without a crit or a b64 parameter, names an accepted alg, and has a
// kid, and returns the alg and the kid. Parameter names match exactly, case
// included, so a KID parameter is not read as the kid. Every check here runs
// before any key is looked up.
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
	// encoding/json matches struct fields without regard to case, so the
	// header is read into a map, whose keys match only the same string, as
	// RFC 7515, section 10.13, requires.
	var header map[string]json.RawMessage
	if err := json.Unmarshal(decoded[0], &header); err != nil || header == nil {
		return "", "", fail(CodeFormatInvalid, "header is not a JSON object")
	}
	if alg, err = headerString(header, "alg"); err != nil {
		return "", "", fail(CodeFormatInvalid, "header alg is not a string")
	}
	if kid, err = headerString(header, "kid"); err != nil {
		return "", "", fail(CodeFormatInvalid, "header kid is not a string")
	}
	// A recipient has to refuse a token whose crit lists an extension it
	// does not understand (RFC 7515, section 4.1.11), and the service
	// understands none.
	if _, ok := header["crit"]; ok {
		return "", "", fail(CodeFormatInvalid, "header has a crit parameter, and no extension is supported")
	}
	// b64 (RFC 7797) changes what the signature covers, and the service
	// supports only the default base64url payload.
	if _, ok := header["b64"]; ok {
		return "", "", fail(CodeFormatInvalid, "header has a b64 parameter, and only the default payload encoding is supported")
	}
	if !keys.AcceptsAlgorithm(alg) {
		return "", "", fail(CodeAlgNotAllowed, "alg %s is not an accepted signature algorithm", short(alg))
	}
	if kid == "" {
		return "", "", fail(CodeKIDMissing, "header has no kid")
	}
	return alg, kid, nil
}

// headerString returns the parameter name of header as a string, "" when it
// is absent or null, and an error when it is any other JSON value.
func headerString(header map[string]json.RawMessage, name string) (string, error) {
	raw, ok := header[name]
	if !ok {
		return "", nil
	}
	var s string
	err := json.Unmarshal(raw, &s)
	return s, err
}

// decodeClaims parses the payload as one JSON object and keeps the JSON
// text of every claim.
func decodeClaims(payload []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	var claims map[string]json.RawMessage
	if err := dec.Decode(&claims); err != nil || claims == nil {
		return nil, fail(CodeFormatInvalid, "payload is not a JSON object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fail(CodeFormatInvalid, "payload has data after the JSON object")
	}
	return claims, nil
}

// standardOf picks the claims of a [Standard] out of claims.
func standardOf(claims map[string]json.RawMessage) Standard {
	s := Standard{
		Subject:           claims["sub"],
		PreferredUsername: claims["preferred_username"],
		Scope:             claims["scope"],
		Level:             claims["level"],
		TenantID:          claims["tenant-id"],
	}
	var realmAccess map[string]json.RawMessage
	if json.Unmarshal(claims["realm_access"], &realmAccess) == nil {
		s.Roles = realmAccess["roles"]
	}
	return s
}

// stringClaim returns the claim name when it is a JSON string, and ""
// otherwise.
func stringClaim(claims map[string]json.RawMessage, name string) string {
	var s string
	if json.Unmarshal(claims[name], &s) != nil {
		return ""
	}
	return s
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
