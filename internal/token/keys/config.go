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
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Dir is the provider directory, the one place the agent reads its providers
// from, at start.
const Dir = "/etc/authz/providers"

// The keys a provider may have in the providers object of a provider file.
// The key alone decides how the tokens of a provider are checked.
const (
	// IdentityProviderID is the key of the provider of the platform's identity
	// provider, which signs the tokens of users and services.
	IdentityProviderID = "identity-provider"
	// KubernetesID is the key of the provider of Kubernetes service account
	// tokens.
	KubernetesID = "kubernetes"
)

// ProviderType says which member of a provider names the issuers of its
// tokens.
type ProviderType string

// The values of [ProviderType].
const (
	// Realms names an issuer for every realm with [Provider.IssuerTemplate].
	Realms ProviderType = "realms"
	// Single names one issuer with [Provider.Issuer].
	Single ProviderType = "single"
)

// AudienceMode says how the aud of a token is checked.
type AudienceMode string

// The values of [AudienceMode].
const (
	// MatchAny accepts a token whose aud names one of [Audience.Values].
	MatchAny AudienceMode = "matchAny"
	// Ignore leaves the aud of a token unchecked, whether the token has one or
	// not.
	Ignore AudienceMode = "ignore"
)

// realmPlaceholder stands for the realm name in the issuerTemplate and the
// jwksUri of a realms provider.
const realmPlaceholder = "{realm}"

// fileShape describes a provider file for an error about its shape.
const fileShape = `a provider file holds {"providers": {"<key>": {...}}}`

// Config is the list of providers that the provider files hold together.
type Config struct {
	Providers []Provider
}

// Provider is one trusted provider of a provider file. Its tokens carry an iss
// that matches Issuer or IssuerTemplate, and its keys are read from JWKSURI
// and nowhere else.
//
// A single provider is one source of keys. A realms provider is a source of
// keys for every realm name that a token's iss puts in place of {realm}: the
// part of the iss between the bytes of IssuerTemplate before {realm} and the
// bytes after it, percent-decoded. A realm name is valid UTF-8 of 1 to 255
// bytes, is neither "." nor "..", and holds no '/', '?', '#', or control
// character. The keys of a realm are read from JWKSURI with the name, escaped
// as one path segment, in place of {realm}, so a token picks a realm but never
// the server that is asked.
type Provider struct {
	// ID is the key of the provider in the providers object of its file,
	// [IdentityProviderID] or [KubernetesID].
	ID string
	// Type is [Realms] or [Single]. The provider [KubernetesID] is [Single].
	Type ProviderType
	// Issuer is the iss of the tokens of a single provider, and "" in a realms
	// provider. It is an absolute URL with a host, written in the printable
	// ASCII characters other than the space, with no fragment and no '{' or
	// '}'. It is compared with the iss byte for byte, with nothing normalized:
	// not the case of the scheme or the host, a default port, a trailing
	// slash, or the percent-encoding.
	Issuer string
	// IssuerTemplate is the iss of the tokens of a realms provider with {realm}
	// in place of the realm name, and "" in a single provider. It is an
	// absolute URL with a host that holds {realm} once, as a whole segment of
	// its path, and no other '{' or '}'. That URL is written in the printable
	// ASCII characters other than the space and has no fragment. Outside the
	// realm name, an iss has to hold the bytes of IssuerTemplate, with nothing
	// normalized.
	IssuerTemplate string
	// JWKSURI is the absolute URL of the JWKS. Its scheme is http or https,
	// matched case-insensitively. It is written in the printable ASCII
	// characters other than the space, and has no fragment. In a realms
	// provider it holds {realm} once, as a whole segment of its path, and no
	// other '{' or '}'; in a single provider it holds no '{' or '}'. No request
	// follows a redirect.
	JWKSURI string
	// JWKSBearerTokenFile is the absolute path of a file whose content, with
	// the surrounding white space removed, goes as a bearer token with every
	// JWKS request of this provider, and with no other request. The file is
	// read on every request, so a rotated token takes effect without a
	// restart. Only the provider [KubernetesID] may set it.
	JWKSBearerTokenFile string
	// ReadinessRealms lists the realms whose keys [Set.Ready] requires, by the
	// realm names that tokens carry, percent-decoded as [Source.Realm] holds
	// them. Only a realms provider may set it, and no realm is required
	// without it.
	ReadinessRealms []string
	// Audience says how the aud of the provider's tokens is checked.
	Audience Audience

	// file is the provider file that holds the provider, and "" for a
	// provider that no provider file holds.
	file string
}

// Audience says how the aud of a token is checked.
type Audience struct {
	// Mode is [MatchAny] or [Ignore].
	Mode AudienceMode
	// Values lists the aud values that MatchAny accepts, compared byte for
	// byte. It holds at least one value and no empty one with MatchAny, and is
	// nil with Ignore.
	Values []string
}

// members lists the members that a provider allows by its key and its type,
// and whether it requires each. A key, a type, or a member that the map does
// not hold is not allowed there.
var members = map[string]map[ProviderType]map[string]bool{
	IdentityProviderID: {
		Realms: {"type": true, "issuerTemplate": true, "jwksUri": true, "audience": true, "readinessRealms": false},
		Single: {"type": true, "issuer": true, "jwksUri": true, "audience": true},
	},
	KubernetesID: {
		Single: {"type": true, "issuer": true, "jwksUri": true, "audience": true, "jwksBearerTokenFile": false},
	},
}

// memberOrder lists the members of a provider in the order an error names
// them.
var memberOrder = []string{"type", "issuer", "issuerTemplate", "jwksUri", "jwksBearerTokenFile", "readinessRealms", "audience"}

// typeOrder lists the types of a provider in the order an error names them.
var typeOrder = []ProviderType{Realms, Single}

// ReadDir reads the provider files in dir and returns the providers they
// hold together, in the order of the file names and then of the keys in each
// providers object. A provider file is an entry directly in dir whose name
// ends in .json and does not start with '.', unless it is a directory or a
// symbolic link to one; the file is read through a symbolic link, and every
// other entry is skipped.
//
// ReadDir fails when dir or a provider file cannot be read, when no file holds
// a provider, when a file is not UTF-8, and when the JSON of a file breaks the
// format: a file holds one object with the member providers and may hold the
// member $schema, a string. providers is an object of providers keyed by
// [IdentityProviderID] or [KubernetesID], and each provider and its audience
// hold the members that its key and its type allow and require, each once,
// by its exact name, with a value of its JSON type and not null.
// It also fails on every condition [Config.Validate] refuses. The error names
// dir or the file at fault, and the provider by its key.
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
		return Config{}, fmt.Errorf(`provider directory %s holds no provider; add a provider file, a file named *.json that holds {"providers": {"<key>": {...}}}`, dir)
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
		return nil, fmt.Errorf("%w; %s", err, fileShape)
	}
	var raw json.RawMessage
	var others []string
	for _, m := range fileMembers {
		switch m.name {
		case "providers":
			raw = m.value
		case "$schema":
			var schema string
			if isNull(m.value) || json.Unmarshal(m.value, &schema) != nil {
				return nil, errors.New(`member "$schema" is not a string; it names the JSON Schema of the file`)
			}
		default:
			others = append(others, strconv.Quote(m.name))
		}
	}
	if len(others) > 0 {
		return nil, fmt.Errorf(`holds %s beside "providers"; a provider file holds no member but "providers" and "$schema"`, strings.Join(others, ", "))
	}
	if raw == nil {
		return nil, fmt.Errorf(`has no member "providers"; %s`, fileShape)
	}
	entries, err := object(raw)
	if err != nil {
		return nil, fmt.Errorf(`member "providers": %w; %s`, err, fileShape)
	}
	providers := make([]Provider, 0, len(entries))
	for _, entry := range entries {
		p, err := parseProvider(entry.name, entry.value)
		if err != nil {
			return nil, fmt.Errorf("provider %q: %w", entry.name, err)
		}
		providers = append(providers, p)
	}
	return providers, nil
}

// parseProvider returns the provider that raw describes. raw is the value
// under key in a providers object, and key is the name of the provider. It
// checks the key, the JSON shape, which members are present, and that a
// jwksBearerTokenFile that is present is an absolute path, since an empty one
// would read as absent; [Provider.validate] checks the other values.
func parseProvider(key string, raw json.RawMessage) (Provider, error) {
	types, ok := members[key]
	if !ok {
		return Provider{}, errUnknownKey(key)
	}
	fields, err := object(raw)
	if err != nil {
		return Provider{}, err
	}
	values := make(map[string]json.RawMessage, len(fields))
	for _, m := range fields {
		values[m.name] = m.value
	}
	p := Provider{ID: key}
	if _, ok := values["type"]; !ok || decodeString(values, "type", (*string)(&p.Type)) != nil {
		return Provider{}, fmt.Errorf(`has no member "type" that is a string; %s`, typesOf(key))
	}
	allowed, ok := types[p.Type]
	if !ok {
		return Provider{}, errUnknownType(key, p.Type)
	}
	if err := checkMembers(key, p.Type, allowed, fields, values); err != nil {
		return Provider{}, err
	}
	if err := p.decodeMembers(values); err != nil {
		return Provider{}, err
	}
	return p, nil
}

// checkMembers checks the members of a provider with key and typ, which fields
// lists in their order and values holds by name: each member is one that
// allowed holds and is not null, and each member that allowed requires is
// present.
func checkMembers(key string, typ ProviderType, allowed map[string]bool, fields []member, values map[string]json.RawMessage) error {
	for _, m := range fields {
		if _, ok := allowed[m.name]; !ok {
			return errNotAllowed(key, typ, m.name)
		}
		if isNull(m.value) {
			return fmt.Errorf("member %q is null", m.name)
		}
	}
	for _, name := range memberOrder {
		if _, present := values[name]; allowed[name] && !present {
			return fmt.Errorf("has no member %q; %s", name, holds(key, typ))
		}
	}
	return nil
}

// decodeMembers decodes into p the members of values other than type, which
// [checkMembers] has checked.
func (p *Provider) decodeMembers(values map[string]json.RawMessage) error {
	for _, s := range []struct {
		name  string
		value *string
	}{{"issuer", &p.Issuer}, {"issuerTemplate", &p.IssuerTemplate}, {"jwksUri", &p.JWKSURI}, {"jwksBearerTokenFile", &p.JWKSBearerTokenFile}} {
		if err := decodeString(values, s.name, s.value); err != nil {
			return err
		}
	}
	if _, ok := values["jwksBearerTokenFile"]; ok {
		if err := checkTokenFile(p.JWKSBearerTokenFile); err != nil {
			return err
		}
	}
	if raw, ok := values["readinessRealms"]; ok {
		if p.ReadinessRealms, ok = stringArray(raw); !ok {
			return fmt.Errorf("member %q is not an array of strings", "readinessRealms")
		}
	}
	var err error
	p.Audience, err = parseAudience(values["audience"])
	return err
}

// parseAudience returns the audience that raw, the JSON of the member
// audience, describes.
func parseAudience(raw json.RawMessage) (Audience, error) {
	const shape = `an audience is {"mode": "matchAny", "values": ["<aud>", ...]} or {"mode": "ignore"}`
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
	if _, ok := values["mode"]; !ok || decodeString(values, "mode", (*string)(&audience.Mode)) != nil {
		return Audience{}, fmt.Errorf("member %q of %q is not a string; %s", "mode", "audience", shape)
	}
	if raw, ok := values["values"]; ok {
		if audience.Values, ok = stringArray(raw); !ok {
			return Audience{}, fmt.Errorf("member %q of %q is not an array of strings; %s", "values", "audience", shape)
		}
	}
	return audience, nil
}

// decodeString decodes into s the member name of values when values holds it,
// and fails when that member is not a string.
func decodeString(values map[string]json.RawMessage, name string, s *string) error {
	raw, ok := values[name]
	if !ok {
		return nil
	}
	if isNull(raw) || json.Unmarshal(raw, s) != nil {
		return fmt.Errorf("member %q is not a string", name)
	}
	return nil
}

// stringArray returns the strings of raw, a JSON array of strings, and false
// when raw is something else, an array that holds null included.
func stringArray(raw json.RawMessage) ([]string, bool) {
	var items []json.RawMessage
	if isNull(raw) || json.Unmarshal(raw, &items) != nil {
		return nil, false
	}
	out := make([]string, len(items))
	for i, item := range items {
		if isNull(item) || json.Unmarshal(item, &out[i]) != nil {
			return nil, false
		}
	}
	return out, true
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
// member, the repeated ones each time. Its time is linear in the number of
// members, which the providers object of a file does not bound.
func object(raw []byte) ([]member, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	var out []member
	seen := make(map[string]struct{})
	var repeated error
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("not a JSON object: %w", err)
		}
		name, _ := token.(string)
		if _, twice := seen[name]; twice && repeated == nil {
			repeated = fmt.Errorf("member %q appears twice", name)
		}
		seen[name] = struct{}{}
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

func errUnknownKey(key string) error {
	return fmt.Errorf("the key %q is neither %q nor %q", key, IdentityProviderID, KubernetesID)
}

// errUnknownType reports the type typ in a provider with key, which [members]
// knows and which does not allow typ.
func errUnknownType(key string, typ ProviderType) error {
	return fmt.Errorf("the type %q is not allowed; %s", typ, typesOf(key))
}

// errNotAllowed reports the member name in a provider with key and typ, which
// do not allow it.
func errNotAllowed(key string, typ ProviderType, name string) error {
	err := fmt.Errorf("member %q is not allowed; %s", name, holds(key, typ))
	// Only identity-provider refuses jwksBearerTokenFile, and only a single
	// provider refuses readinessRealms.
	switch name {
	case "jwksBearerTokenFile":
		err = fmt.Errorf("%w; the provider of Kubernetes tokens has the key %q", err, KubernetesID)
	case "readinessRealms":
		err = fmt.Errorf("%w; the agent waits for the keys of a provider of the type %q at start in any case", err, Single)
	}
	return err
}

// typesOf lists the types of a provider with key, which [members] knows.
func typesOf(key string) string {
	var names []string
	for _, typ := range typeOrder {
		if _, ok := members[key][typ]; ok {
			names = append(names, strconv.Quote(string(typ)))
		}
	}
	return fmt.Sprintf("a provider %q has the type %s", key, strings.Join(names, " or "))
}

// holds lists the members of a provider with key and typ, which [members]
// knows.
func holds(key string, typ ProviderType) string {
	var required, optional []string
	for _, name := range memberOrder {
		isRequired, ok := members[key][typ][name]
		switch {
		case isRequired:
			required = append(required, name)
		case ok:
			optional = append(optional, name)
		}
	}
	s := fmt.Sprintf("a provider %q of the type %q holds %s", key, typ, strings.Join(required, ", "))
	if len(optional) > 0 {
		s += ", and may hold " + strings.Join(optional, ", ")
	}
	return s
}

// Validate returns an error for a Config without a provider, for the first
// provider whose values break a rule of [Provider] or [Audience], for two
// providers with one key, and for two providers whose issuers overlap: two
// single providers whose issuers are equal, a single provider whose issuer the
// issuerTemplate of a realms provider matches, or two realms providers whose
// issuerTemplates have the same scheme, host, and port, compared as written,
// and the same number of path segments that are equal in every segment where
// neither holds {realm}. The error names each provider by its key, with the
// provider file that holds it.
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
				return fmt.Errorf("%s and %s have the same key; each key names one provider", b.name(), a.name())
			}
			if overlap(a, b) {
				bMember, bValue := b.issuerMember()
				aMember, aValue := a.issuerMember()
				return fmt.Errorf("the %s %q of %s and the %s %q of %s can match one iss; no iss may select two providers", bMember, bValue, b.name(), aMember, aValue, a.name())
			}
		}
	}
	return nil
}

// name names p in an error: by its key, and by its provider file where one
// holds it.
func (p Provider) name() string {
	if p.file == "" {
		return fmt.Sprintf("provider %q", p.ID)
	}
	return fmt.Sprintf("provider %q in %s", p.ID, p.file)
}

// issuerMember returns the name and the value of the member that names the
// issuers of p: issuerTemplate in a realms provider, issuer otherwise.
func (p Provider) issuerMember() (string, string) {
	if p.Type == Realms {
		return "issuerTemplate", p.IssuerTemplate
	}
	return "issuer", p.Issuer
}

// validate returns an error for the first value of p that breaks a rule of
// [Provider] or [Audience].
func (p Provider) validate() error {
	types, ok := members[p.ID]
	if !ok {
		return errUnknownKey(p.ID)
	}
	allowed, ok := types[p.Type]
	if !ok {
		return errUnknownType(p.ID, p.Type)
	}
	for _, field := range []struct {
		name string
		set  bool
	}{
		{"issuer", p.Issuer != ""},
		{"issuerTemplate", p.IssuerTemplate != ""},
		{"jwksBearerTokenFile", p.JWKSBearerTokenFile != ""},
		{"readinessRealms", p.ReadinessRealms != nil},
	} {
		if _, ok := allowed[field.name]; field.set && !ok {
			return errNotAllowed(p.ID, p.Type, field.name)
		}
	}
	if err := p.validateAddresses(); err != nil {
		return err
	}
	if p.JWKSBearerTokenFile != "" {
		if err := checkTokenFile(p.JWKSBearerTokenFile); err != nil {
			return err
		}
	}
	for _, name := range p.ReadinessRealms {
		if err := checkRealmName(name); err != nil {
			return fmt.Errorf("readinessRealms: %q %w", name, err)
		}
	}
	return p.Audience.validate()
}

// validateAddresses checks the URL that names the issuers of p and its
// JWKSURI.
func (p Provider) validateAddresses() error {
	if p.Type == Single {
		for _, field := range []struct{ name, value string }{{"issuer", p.Issuer}, {"jwksUri", p.JWKSURI}} {
			if strings.Contains(field.value, realmPlaceholder) {
				return fmt.Errorf("%s %q holds {realm}, which a provider of the type %q does not; %s", field.name, field.value, Single, realmRemedy(p.ID))
			}
		}
	}
	name, value := p.issuerMember()
	if err := checkURL(value, p.Type == Realms); err != nil {
		return fmt.Errorf("%s %q %w", name, value, err)
	}
	if err := checkJWKSURI(p.JWKSURI, p.Type == Realms); err != nil {
		return fmt.Errorf("jwksUri %q %w", p.JWKSURI, err)
	}
	return nil
}

// realmRemedy says how to repair a {realm} in a single provider with key.
func realmRemedy(key string) string {
	if _, ok := members[key][Realms]; ok {
		return fmt.Sprintf("set type to %q and name the iss in issuerTemplate, or remove {realm}", Realms)
	}
	return "remove {realm}"
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
	case Ignore:
		if a.Values != nil {
			return fmt.Errorf("audience.values is set with the mode %q, which checks no value; remove it, or set the mode to %q", Ignore, MatchAny)
		}
	default:
		return fmt.Errorf("audience.mode is %q; it is %q or %q", a.Mode, MatchAny, Ignore)
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

// template is the issuerTemplate or the jwksUri of a realms provider, split at
// its one {realm}.
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
			return fmt.Errorf("holds {realm} %d times; a realms provider holds it once, as a whole segment of the path", n)
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
	if u.Hostname() == "" {
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
func overlap(a, b Provider) bool {
	switch {
	case a.Type == Single && b.Type == Single:
		return a.Issuer == b.Issuer
	case a.Type == Single:
		_, ok := splitTemplate(b.IssuerTemplate).realm(a.Issuer)
		return ok
	case b.Type == Single:
		_, ok := splitTemplate(a.IssuerTemplate).realm(b.Issuer)
		return ok
	}
	return templatesOverlap(a.IssuerTemplate, b.IssuerTemplate)
}

// templatesOverlap reports whether the issuerTemplates a and b have the same
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
