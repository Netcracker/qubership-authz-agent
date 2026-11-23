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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Dir is the provider directory, the one place the agent reads its providers
// from, at start.
const Dir = "/etc/authz/providers"

// The ids a provider may have. The id alone decides how the tokens of a
// provider are checked.
const (
	// IdentityProviderID is the id of the provider of the platform's identity
	// provider, which signs the tokens of users and services.
	IdentityProviderID = "identity-provider"
	// KubernetesID is the id of the provider of Kubernetes service account
	// tokens.
	KubernetesID = "kubernetes"
)

// IssuerType says how the iss of a token is compared with [Issuer.Value].
type IssuerType string

// The values of [IssuerType].
const (
	// Exact matches an iss equal to [Issuer.Value] byte for byte.
	Exact IssuerType = "exact"
	// RealmTemplate matches an iss equal to [Issuer.Value] with a realm name
	// in place of its one {realm} segment, as [Provider] states.
	RealmTemplate IssuerType = "realm-template"
)

// AudienceMode says how the aud of a token is checked.
type AudienceMode string

// The values of [AudienceMode].
const (
	// MatchAny accepts a token whose aud names one of [Audience.Values].
	MatchAny AudienceMode = "matchAny"
	// SkipValidation leaves the aud of a token unchecked.
	SkipValidation AudienceMode = "skipValidation"
)

// realmPlaceholder stands for the realm name in the issuer.value and the
// jwksUri of a realm-template provider.
const realmPlaceholder = "{realm}"

// Config is the list of providers that the provider files hold together.
type Config struct {
	Providers []Provider
}

// Provider is one trusted provider of a provider file. Its tokens carry an iss
// that matches Issuer, and its keys are read from JWKSURI and nowhere else.
//
// An exact provider is one source of keys. A realm-template provider is a
// source of keys for every realm name that a token's iss puts in place of
// {realm}: the part of the iss between the bytes of Issuer.Value before
// {realm} and the bytes after it, percent-decoded. A realm name is valid UTF-8
// of 1 to 255 bytes, is neither "." nor "..", and holds no '/', '?', '#', or
// control character. The keys of a realm are read from JWKSURI with the name,
// escaped as one path segment, in place of {realm}, so a token picks a realm
// but never the server that is asked.
type Provider struct {
	// ID is [IdentityProviderID] or [KubernetesID].
	ID string
	// Issuer says which iss values select the provider.
	Issuer Issuer
	// JWKSURI is the absolute URL of the JWKS. Its scheme is http or https,
	// matched case-insensitively. It is written in the printable ASCII
	// characters other than the space, and has no fragment. In a
	// realm-template provider it holds {realm} once, as a whole segment of its
	// path, and no other '{' or '}'; in an exact provider it holds no '{' or
	// '}'. No request follows a redirect.
	JWKSURI string
	// JWKSBearerTokenFile is the absolute path of a file whose content, with
	// the surrounding white space removed, goes as a bearer token with every
	// JWKS request of this provider, and with no other request. The file is
	// read on every request, so a rotated token takes effect without a
	// restart. Only the provider [KubernetesID] may set it.
	JWKSBearerTokenFile string
	// ReadinessRealms lists the realms whose keys [Set.Ready] requires, by the
	// realm names that tokens carry, percent-decoded as [Source.Realm] holds
	// them. Only a realm-template provider [IdentityProviderID] may set it,
	// and no realm is required without it.
	ReadinessRealms []string
	// Audience says how the aud of the provider's tokens is checked.
	Audience Audience

	// file is the provider file that holds the provider, and "" for a
	// provider that no provider file holds.
	file string
}

// Issuer says which iss values select a provider.
type Issuer struct {
	// Type is [Exact] or [RealmTemplate].
	Type IssuerType
	// Value is compared with the iss as Type says, byte for byte, with nothing
	// normalized: not the case of the scheme or the host, a default port, a
	// trailing slash, or the percent-encoding outside the realm name. It is
	// not empty. In a realm-template provider it is an absolute URL with a
	// host that holds {realm} once, as a whole segment of its path, and no
	// other '{' or '}'. That URL is written in the printable ASCII characters
	// other than the space and has no fragment. In an exact provider it holds
	// no {realm}.
	Value string
}

// Audience says how the aud of a token is checked.
type Audience struct {
	// Mode is [MatchAny] or [SkipValidation].
	Mode AudienceMode
	// Values lists the aud values that MatchAny accepts, compared byte for
	// byte. It holds at least one value and no empty one with MatchAny, and is
	// nil with SkipValidation.
	Values []string
}

// members lists, for each provider id, whether a provider with that id
// requires a member of a provider file or allows it. A member that the map of
// an id does not hold is not allowed there.
var members = map[string]map[string]bool{
	IdentityProviderID: {"id": true, "issuer": true, "jwksUri": true, "audience": true, "readinessRealms": false},
	KubernetesID:       {"id": true, "issuer": true, "jwksUri": true, "audience": true, "jwksBearerTokenFile": false},
}

// memberOrder lists the members of a provider in the order an error names
// them.
var memberOrder = []string{"id", "issuer", "jwksUri", "jwksBearerTokenFile", "readinessRealms", "audience"}

// ReadDir reads the provider files in dir and returns the providers they
// hold together, in the order of the file names and then of each providers
// array. A provider file is an entry directly in dir whose name ends in .json
// and does not start with '.', unless it is a directory or a symbolic link to
// one; the file is read through a symbolic link, and every other entry is
// skipped.
//
// ReadDir fails when dir or a provider file cannot be read, when no file holds
// a provider, when a file is not UTF-8, and when the JSON of a file breaks the
// format: a file holds one object whose only member is providers, an array of
// providers, and each provider, issuer, and audience holds the members its id
// allows and requires, each once, by its exact name, with a value of its JSON
// type and not null.
// It also fails on every condition [Config.Validate] refuses. The error names
// dir or the file at fault, and the provider by its id when the provider holds
// one member id that is a string, and by its position in providers otherwise.
func ReadDir(dir string) (Config, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Config{}, fmt.Errorf("provider directory %s: %w", dir, err)
	}
	var cfg Config
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		path := filepath.Join(dir, name)
		providers, err := readFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("provider file %s: %w", path, err)
		}
		cfg.Providers = append(cfg.Providers, providers...)
	}
	if len(cfg.Providers) == 0 {
		return Config{}, fmt.Errorf(`provider directory %s holds no provider; add a provider file, a file named *.json that holds {"providers": [...]}`, dir)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// readFile returns the providers of the provider file at path, each with its
// file set, and nil for a directory, which is no provider file.
func readFile(path string) ([]Provider, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, nil
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("is not a regular file but %s", info.Mode().Type())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	providers, err := parseFile(data)
	if err != nil {
		return nil, err
	}
	for i := range providers {
		providers[i].file = path
	}
	return providers, nil
}

// parseFile returns the providers of the content of a provider file.
func parseFile(data []byte) ([]Provider, error) {
	// encoding/json reads a byte that is not UTF-8 in a string as U+FFFD and
	// reports no error, so a value would silently differ from the file.
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size == 1 {
			return nil, fmt.Errorf("holds 0x%02X at byte %d, which is not UTF-8; save the file in UTF-8, the encoding RFC 8259 requires of a JSON text", data[i], i)
		}
		i += size
	}
	fileMembers, err := object(data)
	if err != nil {
		return nil, fmt.Errorf(`%w; a provider file holds {"providers": [...]}`, err)
	}
	var raw json.RawMessage
	var others []string
	for _, m := range fileMembers {
		if m.name == "providers" {
			raw = m.value
		} else {
			others = append(others, fmt.Sprintf("%q", m.name))
		}
	}
	if len(others) > 0 {
		return nil, fmt.Errorf(`holds %s beside "providers"; a provider file holds no member but "providers"`, strings.Join(others, ", "))
	}
	var entries []json.RawMessage
	if raw == nil || isNull(raw) || json.Unmarshal(raw, &entries) != nil {
		return nil, errors.New(`holds no array "providers"; a provider file holds {"providers": [...]}`)
	}
	providers := make([]Provider, 0, len(entries))
	for i, entry := range entries {
		p, err := parseProvider(entry)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entryName(i, entry), err)
		}
		providers = append(providers, p)
	}
	return providers, nil
}

// entryName names the provider at index i of a providers array whose JSON is
// raw: by its id when the provider holds one member id that is a string, even
// when it repeats another member, and by its position otherwise.
func entryName(i int, raw json.RawMessage) string {
	fields, _ := object(raw)
	var ids []json.RawMessage
	for _, m := range fields {
		if m.name == "id" {
			ids = append(ids, m.value)
		}
	}
	var id string
	if len(ids) == 1 && !isNull(ids[0]) && json.Unmarshal(ids[0], &id) == nil {
		return fmt.Sprintf("provider %q", id)
	}
	return fmt.Sprintf("providers[%d]", i)
}

// parseProvider returns the provider that raw, one entry of a providers
// array, describes. It checks the JSON shape, which members are present, and
// that a jwksBearerTokenFile that is present is an absolute path, since an
// empty one would read as absent; [Provider.validate] checks the other values.
func parseProvider(raw json.RawMessage) (Provider, error) {
	fields, err := object(raw)
	if err != nil {
		return Provider{}, err
	}
	var p Provider
	values := make(map[string]json.RawMessage, len(fields))
	for _, m := range fields {
		values[m.name] = m.value
	}
	id, ok := values["id"]
	if !ok || isNull(id) || json.Unmarshal(id, &p.ID) != nil {
		return Provider{}, fmt.Errorf(`has no member "id" that is a string; the id of a provider is %q or %q`, IdentityProviderID, KubernetesID)
	}
	allowed, ok := members[p.ID]
	if !ok {
		return Provider{}, errUnknownID(p.ID)
	}
	for _, m := range fields {
		if _, ok := allowed[m.name]; !ok {
			return Provider{}, errNotAllowed(p.ID, m.name)
		}
		if isNull(m.value) {
			return Provider{}, fmt.Errorf("member %q is null", m.name)
		}
	}
	for _, name := range memberOrder {
		if _, present := values[name]; allowed[name] && !present {
			return Provider{}, fmt.Errorf("has no member %q; %s", name, holds(p.ID))
		}
	}
	if err := decodeMember(values, "jwksUri", &p.JWKSURI); err != nil {
		return Provider{}, err
	}
	if err := decodeMember(values, "readinessRealms", &p.ReadinessRealms); err != nil {
		return Provider{}, err
	}
	if file, ok := values["jwksBearerTokenFile"]; ok {
		if err := json.Unmarshal(file, &p.JWKSBearerTokenFile); err != nil {
			return Provider{}, fmt.Errorf("member %q is not a string", "jwksBearerTokenFile")
		}
		if err := checkTokenFile(p.JWKSBearerTokenFile); err != nil {
			return Provider{}, err
		}
	}
	if p.Issuer, err = parseIssuer(values["issuer"]); err != nil {
		return Provider{}, err
	}
	if p.Audience, err = parseAudience(values["audience"]); err != nil {
		return Provider{}, err
	}
	return p, nil
}

// parseIssuer returns the issuer that raw, the JSON of the member issuer,
// describes.
func parseIssuer(raw json.RawMessage) (Issuer, error) {
	const shape = `an issuer is {"type": "exact" or "realm-template", "value": "<iss>"}`
	fields, err := object(raw)
	if err != nil {
		return Issuer{}, fmt.Errorf("member %q: %w; %s", "issuer", err, shape)
	}
	values := make(map[string]json.RawMessage, len(fields))
	for _, m := range fields {
		if m.name != "type" && m.name != "value" {
			return Issuer{}, fmt.Errorf("member %q holds %q; %s", "issuer", m.name, shape)
		}
		values[m.name] = m.value
	}
	var issuer Issuer
	if err := decodeRequired(values, "issuer", "type", (*string)(&issuer.Type), shape); err != nil {
		return Issuer{}, err
	}
	if err := decodeRequired(values, "issuer", "value", &issuer.Value, shape); err != nil {
		return Issuer{}, err
	}
	return issuer, nil
}

// parseAudience returns the audience that raw, the JSON of the member
// audience, describes.
func parseAudience(raw json.RawMessage) (Audience, error) {
	const shape = `an audience is {"mode": "matchAny", "values": ["<aud>", ...]} or {"mode": "skipValidation"}`
	fields, err := object(raw)
	if err != nil {
		return Audience{}, fmt.Errorf("member %q: %w; %s", "audience", err, shape)
	}
	values := make(map[string]json.RawMessage, len(fields))
	for _, m := range fields {
		if m.name != "mode" && m.name != "values" {
			return Audience{}, fmt.Errorf("member %q holds %q; %s", "audience", m.name, shape)
		}
		values[m.name] = m.value
	}
	var audience Audience
	if err := decodeRequired(values, "audience", "mode", (*string)(&audience.Mode), shape); err != nil {
		return Audience{}, err
	}
	if raw, ok := values["values"]; ok {
		if isNull(raw) || json.Unmarshal(raw, &audience.Values) != nil {
			return Audience{}, fmt.Errorf("member %q of %q is not an array of strings; %s", "values", "audience", shape)
		}
	}
	return audience, nil
}

// decodeMember decodes the member name of values into v when values holds
// it, and fails when it does not decode.
func decodeMember(values map[string]json.RawMessage, name string, v any) error {
	raw, ok := values[name]
	if !ok {
		return nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("member %q has the wrong type: %w", name, err)
	}
	return nil
}

// decodeRequired decodes into s the member name of values, the members of the
// object parent, which has to hold it as a string. shape describes parent for
// the error.
func decodeRequired(values map[string]json.RawMessage, parent, name string, s *string, shape string) error {
	raw, ok := values[name]
	if !ok || isNull(raw) || json.Unmarshal(raw, s) != nil {
		return fmt.Errorf("member %q of %q is not a string; %s", name, parent, shape)
	}
	return nil
}

// member is one member of a JSON object.
type member struct {
	name  string
	value json.RawMessage
}

// object returns the members of raw, one JSON object, in their order, by
// their names as written, so a caller compares a name exactly, case included,
// which a Go struct does not do. It fails when
// raw is not one JSON object or holds data after it, and then returns no
// member. It also fails when raw names a member twice, and then returns every
// member, the repeated ones each time.
func object(raw []byte) ([]member, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	var out []member
	var repeated error
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("not a JSON object: %w", err)
		}
		name, _ := token.(string)
		if repeated == nil && slices.ContainsFunc(out, func(m member) bool { return m.name == name }) {
			repeated = fmt.Errorf("member %q appears twice", name)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, fmt.Errorf("not a JSON object: %w", err)
		}
		out = append(out, member{name, value})
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("data after the JSON object")
	}
	return out, repeated
}

func isNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func errUnknownID(id string) error {
	return fmt.Errorf("the id %q is neither %q nor %q", id, IdentityProviderID, KubernetesID)
}

// errNotAllowed reports the member name in a provider with id, which does not
// allow it.
func errNotAllowed(id, name string) error {
	err := fmt.Errorf("member %q is not allowed; %s", name, holds(id))
	if name == "jwksBearerTokenFile" {
		err = fmt.Errorf("%w; the provider of Kubernetes tokens has the id %q", err, KubernetesID)
	}
	return err
}

// holds lists the members of a provider with id, which [members] knows.
func holds(id string) string {
	var required, optional []string
	for _, name := range memberOrder {
		isRequired, ok := members[id][name]
		switch {
		case isRequired:
			required = append(required, name)
		case ok:
			optional = append(optional, name)
		}
	}
	return fmt.Sprintf("a provider %q holds %s, and may hold %s", id, strings.Join(required, ", "), strings.Join(optional, ", "))
}

// Validate returns an error for a Config without a provider, for the first
// provider whose values break a rule of [Provider], [Issuer], or [Audience],
// for two providers with one id, and for two providers whose issuers overlap:
// two exact issuers that are equal, an exact issuer that the other provider's
// realm-template matches, or two realm-templates with the same scheme, host,
// and port, compared as written, and the same number of path segments that
// are equal in every segment where neither holds {realm}. The error names each provider by its
// id, with the provider file that holds it.
func (c Config) Validate() error {
	if len(c.Providers) == 0 {
		return errors.New("no provider is configured")
	}
	for _, p := range c.Providers {
		if err := p.validate(); err != nil {
			return fmt.Errorf("%s: %w", p.name(), err)
		}
	}
	for i, a := range c.Providers {
		for _, b := range c.Providers[:i] {
			if a.ID == b.ID {
				return fmt.Errorf("%s and %s have one id; each id names one provider", b.name(), a.name())
			}
			if overlap(a.Issuer, b.Issuer) {
				return fmt.Errorf("the issuer.value %q of %s and the issuer.value %q of %s can match one iss; no iss may select two providers", b.Issuer.Value, b.name(), a.Issuer.Value, a.name())
			}
		}
	}
	return nil
}

// name names p in an error: by its id, and by its provider file where one
// holds it.
func (p Provider) name() string {
	if p.file == "" {
		return fmt.Sprintf("provider %q", p.ID)
	}
	return fmt.Sprintf("provider %q in %s", p.ID, p.file)
}

// validate returns an error for the first value of p that breaks a rule of
// [Provider], [Issuer], or [Audience].
func (p Provider) validate() error {
	if _, ok := members[p.ID]; !ok {
		return errUnknownID(p.ID)
	}
	if err := p.validateIssuer(); err != nil {
		return err
	}
	if err := checkJWKSURI(p.JWKSURI, p.Issuer.Type == RealmTemplate); err != nil {
		return fmt.Errorf("jwksUri %q %w", p.JWKSURI, err)
	}
	if p.JWKSBearerTokenFile != "" {
		if p.ID != KubernetesID {
			return errNotAllowed(p.ID, "jwksBearerTokenFile")
		}
		if err := checkTokenFile(p.JWKSBearerTokenFile); err != nil {
			return err
		}
	}
	if err := p.validateReadinessRealms(); err != nil {
		return err
	}
	return p.Audience.validate()
}

// validateIssuer checks Issuer, and that the JWKSURI of an exact provider holds
// no {realm}.
func (p Provider) validateIssuer() error {
	switch p.Issuer.Type {
	case Exact:
		if p.Issuer.Value == "" {
			return errors.New("issuer.value is empty")
		}
		for _, field := range []struct{ name, value string }{{"issuer.value", p.Issuer.Value}, {"jwksUri", p.JWKSURI}} {
			if strings.Contains(field.value, realmPlaceholder) {
				return fmt.Errorf("%s %q holds {realm}, which an exact provider does not; set issuer.type to %q, or remove {realm}", field.name, field.value, RealmTemplate)
			}
		}
	case RealmTemplate:
		if err := checkURL(p.Issuer.Value, true); err != nil {
			return fmt.Errorf("issuer.value %q %w", p.Issuer.Value, err)
		}
	default:
		return fmt.Errorf("issuer.type is %q; it is %q or %q", p.Issuer.Type, Exact, RealmTemplate)
	}
	return nil
}

// validateReadinessRealms checks ReadinessRealms, which only a realm-template
// provider [IdentityProviderID] may set.
func (p Provider) validateReadinessRealms() error {
	if p.ReadinessRealms == nil {
		return nil
	}
	if p.ID != IdentityProviderID {
		return errNotAllowed(p.ID, "readinessRealms")
	}
	if p.Issuer.Type != RealmTemplate {
		return fmt.Errorf("member %q is not allowed in an exact provider, which loads its keys at start in any case", "readinessRealms")
	}
	for _, name := range p.ReadinessRealms {
		if err := checkRealmName(name); err != nil {
			return fmt.Errorf("readinessRealms: %q %w", name, err)
		}
	}
	return nil
}

func (a Audience) validate() error {
	switch a.Mode {
	case MatchAny:
		if len(a.Values) == 0 {
			return fmt.Errorf("audience.values is empty; the mode %q needs at least one value", MatchAny)
		}
		if slices.Contains(a.Values, "") {
			return errors.New("audience.values holds an empty string")
		}
	case SkipValidation:
		if a.Values != nil {
			return fmt.Errorf("audience.values is set with the mode %q, which checks no value; remove it, or set the mode to %q", SkipValidation, MatchAny)
		}
	default:
		return fmt.Errorf("audience.mode is %q; it is %q or %q", a.Mode, MatchAny, SkipValidation)
	}
	return nil
}

// checkJWKSURI accepts a URL that [checkURL] accepts with template and whose
// scheme is http or https, matched case-insensitively.
func checkJWKSURI(s string, template bool) error {
	if err := checkPrintableASCII(s); err != nil {
		return err
	}
	scheme, _, found := strings.Cut(s, "://")
	if !found || !strings.EqualFold(scheme, "http") && !strings.EqualFold(scheme, "https") {
		return errors.New("is not an http or https URL")
	}
	return checkURL(s, template)
}

// checkTokenFile accepts an absolute path.
func checkTokenFile(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("jwksBearerTokenFile %q is not an absolute path", path)
	}
	return nil
}

// template is the issuer.value or the jwksUri of a realm-template provider,
// split at its one {realm}.
type template struct {
	prefix, suffix string
}

// splitTemplate splits s at its one {realm}; s has passed [checkURL] as a
// template.
func splitTemplate(s string) template {
	prefix, suffix, _ := strings.Cut(s, realmPlaceholder)
	return template{prefix, suffix}
}

// realm returns the realm name that iss puts in place of {realm}, and false
// when iss does not match t or the name is not one that [checkRealmName]
// accepts. iss comes from a token whose signature is not checked yet, so the
// name is the sender's text.
func (t template) realm(iss string) (string, bool) {
	if len(iss) <= len(t.prefix)+len(t.suffix) || !strings.HasPrefix(iss, t.prefix) || !strings.HasSuffix(iss, t.suffix) {
		return "", false
	}
	name, err := url.PathUnescape(iss[len(t.prefix) : len(iss)-len(t.suffix)])
	if err != nil || checkRealmName(name) != nil {
		return "", false
	}
	return name, true
}

// with returns t with name, escaped as one path segment, in place of {realm}.
func (t template) with(name string) string {
	return t.prefix + url.PathEscape(name) + t.suffix
}

// checkURL accepts an absolute URL with a host, written in the printable ASCII
// characters other than the space, with no fragment and no '{' or '}'. With
// template, the URL holds {realm} once, as a whole segment of its path, and
// '{' and '}' only there.
func checkURL(s string, template bool) error {
	if err := checkPrintableASCII(s); err != nil {
		return err
	}
	outsideRealm := s
	if template {
		start, end, ok := pathBounds(s)
		if !ok {
			return errors.New("is not an absolute URL")
		}
		if n := strings.Count(s, realmPlaceholder); n != 1 {
			return fmt.Errorf("holds {realm} %d times; a realm-template provider holds it once, as a whole segment of the path", n)
		}
		i := strings.Index(s, realmPlaceholder)
		after := i + len(realmPlaceholder)
		if i < start || after > end || s[i-1] != '/' || (after < end && s[after] != '/') {
			return errors.New("holds {realm} outside a whole segment of its path; write it as /{realm}/ or as the last segment, as in https://keycloak:8080/auth/realms/{realm}")
		}
		outsideRealm = s[:i] + s[after:]
	}
	if strings.Contains(s, "#") {
		return errors.New("holds a fragment; remove the '#' and the text after it, or percent-encode a '#' of the path or the query as %23")
	}
	if strings.ContainsAny(outsideRealm, "{}") {
		if template {
			return errors.New("holds '{' or '}' outside its {realm}; percent-encode them as %7B and %7D")
		}
		return errors.New("holds '{' or '}'; percent-encode them as %7B and %7D")
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("is not a URL: %w", err)
	}
	if u.Scheme == "" {
		return errors.New("is not an absolute URL")
	}
	if u.Host == "" {
		return errors.New("has no host")
	}
	return nil
}

// checkPrintableASCII accepts a URL written in the printable ASCII characters
// other than the space.
func checkPrintableASCII(s string) error {
	if i := strings.IndexFunc(s, func(r rune) bool { return r < '!' || r > '~' }); i >= 0 {
		_, size := utf8.DecodeRuneInString(s[i:])
		return fmt.Errorf("holds %+q at byte %d; a URL here holds only printable ASCII characters other than the space, so remove the character or percent-encode it as %s", s[i:i+size], i, url.PathEscape(s[i:i+size]))
	}
	return nil
}

// pathBounds returns where the path of the absolute URL s starts and ends:
// after the authority, and before a query or a fragment. It takes the text
// before the first "://" as the scheme, and reports false when s holds no
// "://" or nothing before it.
func pathBounds(s string) (start, end int, ok bool) {
	scheme, rest, found := strings.Cut(s, "://")
	if !found || scheme == "" {
		return 0, 0, false
	}
	start = len(scheme) + len("://")
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		start += i
	} else {
		start = len(s)
	}
	end = len(s)
	if i := strings.IndexAny(s[start:], "?#"); i >= 0 {
		end = start + i
	}
	return start, end, true
}

// maxRealmNameBytes bounds a realm name, in bytes.
const maxRealmNameBytes = 255

// checkRealmName accepts a realm name: valid UTF-8 of 1 to 255 bytes, neither
// "." nor "..", which a server resolves to another path, and without '/', '?',
// '#', or a character of the Unicode class Cc. Every other character is
// escaped in the address of the realm.
func checkRealmName(name string) error {
	switch {
	case name == "":
		return errors.New("is empty")
	case len(name) > maxRealmNameBytes:
		return fmt.Errorf("is %d bytes long, longer than %d", len(name), maxRealmNameBytes)
	case name == "." || name == "..":
		return errors.New("is a dot segment")
	case !utf8.ValidString(name):
		return errors.New("is not valid UTF-8")
	case strings.ContainsAny(name, "/?#"):
		return errors.New("holds '/', '?', or '#'")
	case strings.ContainsFunc(name, func(r rune) bool { return unicode.Is(unicode.Cc, r) }):
		return errors.New("holds a control character")
	}
	return nil
}

// overlap reports whether one iss can match both a and b, as [Config.Validate]
// defines it.
func overlap(a, b Issuer) bool {
	switch {
	case a.Type == Exact && b.Type == Exact:
		return a.Value == b.Value
	case a.Type == Exact:
		_, ok := splitTemplate(b.Value).realm(a.Value)
		return ok
	case b.Type == Exact:
		_, ok := splitTemplate(a.Value).realm(b.Value)
		return ok
	}
	return templatesOverlap(a.Value, b.Value)
}

// templatesOverlap reports whether the realm-templates a and b have the same
// scheme, host, and port, compared as written, and the same number of path
// segments, equal in every segment where neither holds {realm}.
func templatesOverlap(a, b string) bool {
	aStart, aEnd, _ := pathBounds(a)
	bStart, bEnd, _ := pathBounds(b)
	if a[:aStart] != b[:bStart] {
		return false
	}
	aSegments := strings.Split(a[aStart:aEnd], "/")
	bSegments := strings.Split(b[bStart:bEnd], "/")
	if len(aSegments) != len(bSegments) {
		return false
	}
	for i := range aSegments {
		if aSegments[i] != realmPlaceholder && bSegments[i] != realmPlaceholder && aSegments[i] != bSegments[i] {
			return false
		}
	}
	return true
}
