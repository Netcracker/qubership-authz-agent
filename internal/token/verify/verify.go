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

// Package verify checks a JWT against the signing keys of the trusted sources
// and returns its claims. [Verifier.Verify] reads one claim before the
// signature verifies: iss selects the source whose keys are searched. It grants
// nothing, because a [KeyFinder] takes keys only from configured addresses, and
// a token that names another source than the one that signed it finds no key
// there or fails on its signature. The header names the algorithm and the key,
// and only a token whose signature that key accepts has its aud, exp, nbf, and
// iat checked, and, for a Kubernetes token, its sub. A refused token yields an
// [*Error] whose [Code] names the reason; a verified one is a [*Token], which
// keeps the payload as its issuer signed it.
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
	// separated by dots, or whose header or payload is not a JSON object. It
	// also marks a header whose alg or kid is not a string or that has a crit
	// or a b64 parameter, and an exp, nbf, or iat that is not a number within
	// ±(2^53 - 1) seconds.
	CodeFormatInvalid Code = "TOKEN_FORMAT_INVALID"
	// CodeAlgNotAllowed marks a token whose header names no algorithm, one
	// that no key accepts, or one that the key its iss and kid select does not
	// accept.
	CodeAlgNotAllowed Code = "TOKEN_ALG_NOT_ALLOWED"
	// CodeIssuerUnknown marks a token whose iss is missing, is not a string,
	// or matches no provider: it equals the issuer of no single provider byte
	// for byte, and no realms provider matches it with a valid realm name in
	// place of {realm}, as [keys.Provider] states. A realms provider matches an
	// iss whether or not the realm exists.
	CodeIssuerUnknown Code = "TOKEN_ISSUER_UNKNOWN"
	// CodeKIDMissing marks a token whose header has no kid, or an empty one.
	CodeKIDMissing Code = "TOKEN_KID_MISSING"
	// CodeKIDUnknown marks a token whose kid no loaded key of its source has.
	CodeKIDUnknown Code = "TOKEN_KID_UNKNOWN"
	// CodeSignatureInvalid marks a token whose signature does not verify
	// with the key its iss and kid select.
	CodeSignatureInvalid Code = "TOKEN_SIGNATURE_INVALID"
	// CodeExpMissing marks a token without an exp claim.
	CodeExpMissing Code = "TOKEN_EXP_MISSING"
	// CodeExpired marks a token whose exp has passed.
	CodeExpired Code = "TOKEN_EXPIRED"
	// CodeNotYetValid marks a token whose nbf has not come yet.
	CodeNotYetValid Code = "TOKEN_NOT_YET_VALID"
	// CodeIATMissing marks a token without an iat claim.
	CodeIATMissing Code = "TOKEN_IAT_MISSING"
	// CodeIATInvalid marks a token whose exp comes before its iat, and a
	// Kubernetes token whose iat is in the future.
	CodeIATInvalid Code = "TOKEN_IAT_INVALID"
	// CodeAudienceMissing marks a token without an aud claim from a provider
	// whose audience mode is [keys.MatchAny], or from the provider
	// [keys.KubernetesID].
	CodeAudienceMissing Code = "TOKEN_AUDIENCE_MISSING"
	// CodeAudienceInvalid marks a token from a provider whose audience mode is
	// [keys.MatchAny] and whose aud names none of the audience values, or is
	// neither a string nor an array of strings. The provider
	// [keys.KubernetesID] counts as a provider with that mode and the one
	// value netcracker.
	CodeAudienceInvalid Code = "TOKEN_AUDIENCE_INVALID"
	// CodeSubjectInvalid marks a Kubernetes token without a sub, with a sub
	// that is not a string, or with a sub that does not start with
	// system:serviceaccount:.
	CodeSubjectInvalid Code = "TOKEN_SUBJECT_INVALID"
	// CodeNamespaceNotAllowed marks a Kubernetes token from a namespace the
	// service does not accept, one that names no namespace, and every
	// Kubernetes token of a [Verifier] without [Options.Admit].
	CodeNamespaceNotAllowed Code = "TOKEN_NAMESPACE_NOT_ALLOWED"
)

// Error is the reason a token was refused.
type Error struct {
	Code Code
	// Detail describes the fault for a log line. It never contains the
	// token itself.
	Detail string
	// ProviderID is the [keys.Provider.ID] of the provider whose key verified
	// the signature of the token, as [Token.ProviderID] returns it. It is ""
	// when Verify refused the token before the signature verified.
	// [CodeFormatInvalid] is the one code that Verify returns both before and
	// after the signature verifies: for an exp, nbf, or iat that is not a
	// number in range it comes after the signature and carries the id, and
	// for every other fault it comes before. Verify sets the id on a copy of
	// an error of [Options.Admit], replacing any value Admit set, so Admit
	// need not set it.
	ProviderID string
	// Realm is the name of the realm whose key verified the signature of the
	// token, as [Token.Realm] returns it. Verify sets it wherever it sets
	// ProviderID, and it is "" for a token of a single provider.
	Realm string
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Detail }

func fail(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// withSource returns a copy of e whose ProviderID is providerID and whose Realm
// is realm. It copies because [Options.Admit] may return one *Error for many
// tokens.
func (e *Error) withSource(providerID, realm string) *Error {
	named := *e
	named.ProviderID, named.Realm = providerID, realm
	return &named
}

// Kind is the kind of a verified token. The name of a provider is its key in
// the providers object of a provider file, and the name of the provider whose
// signing key verified the token decides the kind: no member of the provider,
// its type included, and no claim of the token changes it.
type Kind string

// Kinds of a verified token.
const (
	// KindIdentityProvider marks a token that a key of the provider
	// [keys.IdentityProviderID] verified, whether the provider is single or the
	// key belongs to one of its realms.
	KindIdentityProvider Kind = "identity-provider"
	// KindKubernetes marks a token that a key of the provider
	// [keys.KubernetesID] verified.
	KindKubernetes Kind = "kubernetes"
)

// Token is a verified token. Nothing changes a Token after Verify returns
// it, and every method that returns JSON text returns a copy, so one Token is
// safe to read from many goroutines, and the cache shares it between the
// callers that present the same token.
type Token struct {
	payload    []byte
	claims     map[string]json.RawMessage
	standard   Standard
	providerID string
	realm      string
	kind       Kind
	m2m        bool
	keyID      string
	issuer     string
	expiry     time.Time

	// key is the key that verified the token. A cached Token is returned
	// only while [KeyFinder.Lookup] returns this key for issuer and keyID.
	key jwk.Key
}

// Standard holds the claims a policy input is usually built from. Each field
// is the JSON text of its claim exactly as the payload carries it, or nil
// when the payload has no such claim. Verify checks neither the presence
// nor the type of any of them, except the sub of a Kubernetes token.
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

// ProviderID returns the [keys.Provider.ID] of the provider whose key verified
// the token, for a token of a realm too.
func (t *Token) ProviderID() string { return t.providerID }

// Realm returns the name of the realm whose key verified the token, the part of
// its iss in place of {realm}, percent-decoded, and "" for a token of a single
// provider. A realm name is the token's text, so a caller that logs it quotes
// it.
func (t *Token) Realm() string { return t.realm }

// Kind returns the kind of the token.
func (t *Token) Kind() Kind { return t.kind }

// Kubernetes reports whether the token is a Kubernetes token: whether the key
// that verified it is a key of the provider [keys.KubernetesID].
func (t *Token) Kubernetes() bool { return t.kind == KindKubernetes }

// IsM2M reports whether the token is a machine-to-machine token. Every token of
// [KindKubernetes] is one, because [Verifier.Verify] refuses such a token unless
// its sub starts with system:serviceaccount:, the prefix of the sub that the API
// server issues for a service account. A token of [KindIdentityProvider] is one
// when its level claim is m2m or key-manager, compared without regard to case,
// or when its realm_access.roles array holds the string ROLE_M2M, compared
// exactly. A level or a role that is not a string does not make a token M2M.
func (t *Token) IsM2M() bool { return t.m2m }

// KeyID returns the kid of the key that verified the token.
func (t *Token) KeyID() string { return t.keyID }

// Issuer returns the iss claim.
func (t *Token) Issuer() string { return t.issuer }

// Expiry returns the time exp names.
func (t *Token) Expiry() time.Time { return t.expiry }

// KeyFinder finds the signing key a token asks for; [*keys.Set] implements it.
// Every key that its methods return has a [keys.Source.Provider]. Both methods
// report a key they cannot return with [keys.ErrIssuerUnknown] or
// [keys.ErrKeyUnknown].
type KeyFinder interface {
	// Lookup returns the key q names from the keys already loaded, without
	// waiting.
	Lookup(q keys.Query) (keys.Key, error)
	// LookupOrReload returns the key q names. When no loaded key matches, it
	// may reload the keys first; it returns once the reload ends or ctx ends,
	// from the keys loaded by then.
	LookupOrReload(ctx context.Context, q keys.Query) (keys.Key, error)
}

// Defaults of [Options].
const (
	DefaultLeeway    = 30 * time.Second
	DefaultCacheSize = 10000
)

// Options tunes a [Verifier]. A zero field takes its default.
type Options struct {
	// Leeway is how far the clocks of the provider and of the service may
	// differ. It applies when exp and nbf are compared with the clock, and
	// when the iat of a Kubernetes token is; exp is compared with iat
	// without it.
	Leeway time.Duration
	// CacheSize is the largest number of verified tokens the cache keeps; a
	// negative value turns the cache off.
	CacheSize int
	// Admit, when set, runs on every token Verify is about to return,
	// verified now or taken from the cache, and the *Error it returns
	// refuses the token: Verify returns a copy of that *Error with
	// [Error.ProviderID] and [Error.Realm] set. It holds the checks whose
	// answer can change while a token stays cached, such as the namespaces a
	// Kubernetes token may come from. Without Admit, Verify refuses every
	// token for which [Token.Kubernetes] reports true, since nothing then
	// checks its namespace.
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
// the first that fails is returned as an [*Error]: the format of the token and
// of its header, the alg, the kid, the format of the payload, the key that the
// iss and the kid select, the signature, aud, exp, nbf, iat, and, for a
// Kubernetes token, sub. A token without a kid is refused before any key is
// looked up, so it starts no load. The payload is parsed before the signature
// verifies, but of its claims only iss is used, so a forged token whose key is
// found is refused with [CodeSignatureInvalid] whatever its other claims say.
//
// When no loaded key matches, Verify waits for the reload that
// [KeyFinder.LookupOrReload] may start, until the reload ends or ctx ends.
// When ctx ends first, the key is looked up among the keys loaded by then, and
// a token still without a key is refused with [CodeKIDUnknown], not with
// ctx.Err().
//
// A token verified earlier that has not expired is served from the cache,
// as the *Token the earlier call returned, while [KeyFinder.Lookup] returns
// the same key for its issuer and kid. [Options.Admit] then runs on the token
// either way; without Admit, a Kubernetes token is refused with
// [CodeNamespaceNotAllowed].
func (v *Verifier) Verify(ctx context.Context, raw string) (*Token, error) {
	now := v.opts.now()
	digest := sha256.Sum256([]byte(raw))
	tok := v.cached(digest, now)
	if tok == nil {
		var err error
		if tok, err = v.check(ctx, raw, digest); err != nil {
			return nil, err
		}
	}
	if v.opts.Admit == nil {
		if tok.Kubernetes() {
			return nil, fail(CodeNamespaceNotAllowed, "a Kubernetes token of provider %q needs a namespace check, and the verifier has none", tok.ProviderID()).withSource(tok.providerID, tok.realm)
		}
		return tok, nil
	}
	if err := v.opts.Admit(tok); err != nil {
		return nil, err.withSource(tok.providerID, tok.realm)
	}
	return tok, nil
}

// check verifies raw, whose SHA-256 digest is digest, and caches the token
// it returns.
func (v *Verifier) check(ctx context.Context, raw string, digest [sha256.Size]byte) (*Token, error) {
	alg, query, claims, err := parse(raw)
	if err != nil {
		return nil, err
	}
	key, err := v.keys.LookupOrReload(ctx, query)
	if err != nil {
		return nil, lookupFailure(query, claims, err)
	}
	payload, refused := checkSignature(raw, alg, query.Issuer, key)
	if refused != nil {
		return nil, refused
	}
	tok, refused := v.checkClaims(payload, query, claims, key)
	if refused != nil {
		return nil, refused.withSource(key.Source.Provider.ID, key.Source.Realm)
	}
	if v.cache != nil {
		v.cache.put(digest, tok)
	}
	return tok, nil
}

// checkSignature returns the signed payload of raw when key, the one that the
// iss and the kid of raw selected, accepts alg and verifies its signature. A
// refusal quotes iss, the issuer that raw claims, and names no source, because
// such a token only claims to come from the source of key.
func checkSignature(raw, alg, iss string, key keys.Key) ([]byte, *Error) {
	if !key.Allows(alg) {
		return nil, fail(CodeAlgNotAllowed, "key %s of iss %s does not accept %s", short(key.ID), shortIssuer(iss), alg)
	}
	algorithm, _ := jwa.LookupSignatureAlgorithm(alg)
	payload, err := jws.Verify([]byte(raw), jws.WithKey(algorithm, key.JWK), jws.WithCompact(), jws.WithCritValidation(true))
	if err != nil {
		return nil, fail(CodeSignatureInvalid, "signature does not verify with key %s of iss %s", short(key.ID), shortIssuer(iss))
	}
	return payload, nil
}

// checkClaims runs the checks that follow the signature and returns the verified
// token, or the refusal of the first check that fails; [Verifier.check] sets
// [Error.ProviderID] and [Error.Realm] on that refusal. It reads the clock for
// exp, nbf, and iat after the key is found, because finding the key can wait
// for a reload.
func (v *Verifier) checkClaims(payload []byte, query keys.Query, claims map[string]json.RawMessage, key keys.Key) (*Token, *Error) {
	if err := checkAudience(claims, key.Source); err != nil {
		return nil, err
	}
	expiry, refused := checkTimes(claims, key.Source, v.opts.now(), v.opts.Leeway)
	if refused != nil {
		return nil, refused
	}
	if err := checkSubject(claims, key.Source); err != nil {
		return nil, err
	}
	standard := standardOf(claims)
	kind := kindOf(key.Source)
	return &Token{
		payload:    payload,
		claims:     claims,
		standard:   standard,
		providerID: key.Source.Provider.ID,
		realm:      key.Source.Realm,
		kind:       kind,
		m2m:        isM2M(kind, standard),
		keyID:      key.ID,
		issuer:     query.Issuer,
		expiry:     expiry,
		key:        key.JWK,
	}, nil
}

// lookupFailure returns the [*Error] for err, the error a [KeyFinder] returned
// for q, the query of a token with claims. Each [Error.Detail] quotes the
// sender's text through [cut], [short], or [shortIssuer]. The detail of
// [CodeIssuerUnknown] quotes the first maxIssuerBytes bytes of iss, so a
// reader can find the byte where the iss departs from a configured issuer.
// For a token without an iss that is a string, the detail says so.
func lookupFailure(q keys.Query, claims map[string]json.RawMessage, err error) *Error {
	if errors.Is(err, keys.ErrIssuerUnknown) {
		if !isString(claims["iss"]) {
			return fail(CodeIssuerUnknown, "token has no iss that is a string, so it matches no trusted provider")
		}
		return fail(CodeIssuerUnknown, "iss %s matches no trusted provider", cut(q.Issuer, maxIssuerBytes))
	}
	return fail(CodeKIDUnknown, "no key of iss %s has kid %s", shortIssuer(q.Issuer), short(q.KID))
}

// cached returns the cached token for digest when it has not expired and its
// key is still the one the source publishes for its issuer and kid.
func (v *Verifier) cached(digest [sha256.Size]byte, now time.Time) *Token {
	if v.cache == nil {
		return nil
	}
	tok := v.cache.get(digest, now, v.opts.Leeway)
	if tok == nil {
		return nil
	}
	key, err := v.keys.Lookup(keys.Query{Issuer: tok.issuer, KID: tok.keyID})
	if err != nil || key.JWK != tok.key {
		return nil
	}
	return tok
}

// parse checks that raw is three base64url parts. Its header has to be a JSON
// object that names an accepted alg and a kid and has no crit or b64 parameter,
// and its payload a JSON object. It returns the alg, the query for the key, and
// the claims. The caller reads iss from the query before the signature
// verifies, and every other claim only after it.
// Parameter names match exactly, case included, so a KID parameter is not read
// as the kid. Every check here runs before any key is looked up.
func parse(raw string) (alg string, query keys.Query, claims map[string]json.RawMessage, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", keys.Query{}, nil, fail(CodeFormatInvalid, "a compact JWS has 3 parts separated by dots, the token has %d", len(parts))
	}
	var decoded [3][]byte
	for i, name := range []string{"header", "payload", "signature"} {
		if decoded[i], err = base64.RawURLEncoding.DecodeString(parts[i]); err != nil {
			return "", keys.Query{}, nil, fail(CodeFormatInvalid, "%s is not base64url: %v", name, err)
		}
	}
	alg, kid, err := parseHeader(decoded[0])
	if err != nil {
		return "", keys.Query{}, nil, err
	}
	if claims, err = decodeClaims(decoded[1]); err != nil {
		return "", keys.Query{}, nil, err
	}
	return alg, keys.Query{Issuer: stringClaim(claims, "iss"), KID: kid}, claims, nil
}

// parseHeader returns the alg and the kid of the protected header, and refuses
// a header that breaks a rule of [parse].
func parseHeader(raw []byte) (alg, kid string, err error) {
	// encoding/json matches struct fields without regard to case, so the
	// header is read into a map, whose keys match only the same string, as
	// RFC 7515, section 10.13, requires.
	var header map[string]json.RawMessage
	if err := json.Unmarshal(raw, &header); err != nil || header == nil {
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
	return cut(s, 64)
}

// maxIssuerBytes bounds the iss that the detail of [CodeIssuerUnknown] quotes,
// in bytes.
const maxIssuerBytes = 200

// cut quotes s, cut to its first limit bytes with "..." after the cut.
func cut(s string, limit int) string {
	if len(s) > limit {
		return fmt.Sprintf("%q...", s[:limit])
	}
	return fmt.Sprintf("%q", s)
}

// isString reports whether raw is the JSON text of a string, which null is
// not.
func isString(raw json.RawMessage) bool {
	_, ok := decode(raw).(string)
	return ok
}

// shortIssuer quotes iss for a detail, because iss is the sender's text. An iss
// of at most 96 bytes is quoted whole, and a longer one keeps its first 32
// bytes and its last 64, each quoted, with ... between them. Where {realm} is
// the last segment of the issuerTemplate of a provider, as for a Keycloak, the
// last 64 bytes hold the whole name of a realm that the iss spells in at most
// 64 bytes.
func shortIssuer(iss string) string {
	const head, tail = 32, 64
	if len(iss) <= head+tail {
		return fmt.Sprintf("%q", iss)
	}
	return fmt.Sprintf("%q...%q", iss[:head], iss[len(iss)-tail:])
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
