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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
)

// Config is the trusted providers file: a JSON object that names the sources
// of the keys that sign a token the service accepts. At least one of Keycloak
// and Providers is set.
type Config struct {
	// Keycloak trusts every realm of one Keycloak.
	Keycloak *Keycloak `json:"keycloak,omitempty"`
	// Providers lists the identity providers with one fixed issuer each.
	Providers []Provider `json:"providers,omitempty"`
}

// Keycloak is a Keycloak whose realms are all trusted. The realm of a token
// is the part of its iss after the last slash, for an iss that contains
// /auth/realms/. The keys of the realm are read through OIDC discovery under
// URL, whatever host the iss names, so a token cannot choose the server that
// is asked for keys. The aud of a realm token is not checked.
type Keycloak struct {
	// URL is the address of the Keycloak, an absolute http or https URL.
	URL string `json:"url"`
	// RequiredRealms lists the realms whose keys [Set.Ready] waits for. Any
	// other realm is loaded when the first token names it.
	RequiredRealms []string `json:"requiredRealms,omitempty"`
	// CAFile is a PEM bundle that replaces the system roots for HTTPS
	// requests to this Keycloak.
	CAFile string `json:"caFile,omitempty"`
}

// Provider is one trusted identity provider with a fixed issuer. Its keys are
// found through OIDC discovery under Issuer unless JWKSURI names them
// directly. Neither the discovery request nor the JWKS request follows a
// redirect: a 3xx answer fails the fetch.
type Provider struct {
	// ID names the provider in logs and in the keys it publishes. It is
	// unique within a Config and uses only letters, digits, '.', '_', and '-'.
	ID string `json:"id"`
	// Issuer is the iss of the provider's tokens, compared byte for byte, and
	// an absolute http or https URL. It is unique within a Config. The OIDC
	// discovery document lies under it, at
	// /.well-known/openid-configuration. A provider that sets Kubernetes
	// leaves it empty: [New] takes it from the token in TokenFile.
	Issuer string `json:"issuer,omitempty"`
	// JWKSURI is the address of the provider's JWKS, an absolute http or
	// https URL. With it, the keys are fetched without discovery.
	JWKSURI string `json:"jwksUri,omitempty"`
	// Audiences lists the aud values accepted in a token signed by one of the
	// provider's keys; no entry is empty. An empty list accepts any aud.
	Audiences []string `json:"audiences,omitempty"`
	// AllowMissingAud admits a token that carries no aud claim at all. It
	// requires Audiences.
	AllowMissingAud bool `json:"allowMissingAud,omitempty"`
	// CAFile is a PEM bundle that replaces the system roots for HTTPS
	// requests to this provider. [New] does not use it for a provider that
	// takes an issuer outside its cluster from its token and has no JWKSURI:
	// such a provider trusts the system roots and [Options.InternalCAFile].
	CAFile string `json:"caFile,omitempty"`
	// TokenFile holds a bearer token sent with every request for the keys of
	// this provider. A provider that does not set Kubernetes needs JWKSURI
	// with it. A provider that sets Kubernetes has to set it, because [New]
	// takes the Issuer from this token. That token grants access to the API
	// server, so such a provider sends it to a JWKSURI only on an https
	// in-cluster name of the API server. Without a JWKSURI it sends the token
	// through discovery when the Issuer is an https in-cluster name and
	// CAFile is set: that server names the jwks_uri the token goes to, and a
	// fetch fails when that address is not https. Under any other issuer it
	// sends no token. No request follows a redirect, so the token goes to no
	// other address. It is read on every request, so a rotated token takes
	// effect without a restart.
	TokenFile string `json:"tokenFile,omitempty"`
	// Kubernetes marks the provider as the service account token issuer of
	// a Kubernetes API server, and
	// [authz-agent/internal/token/verify.Token.Kubernetes] reports the mark
	// on every token its keys verify. Such a token is refused when its sub
	// does not start with system:serviceaccount, when its iat is ahead of
	// the verifier's clock by more than the verifier's leeway, and when its
	// namespace is not an allowed one. The mark requires Audiences, because
	// every Pod's default token is issued for the API server itself, and
	// refuses AllowMissingAud, so a Kubernetes token is accepted only when it
	// names an audience the service accepts. A provider with the id
	// kubernetes, or with an address on an in-cluster name of the API server,
	// has to set the mark.
	Kubernetes bool `json:"kubernetes,omitempty"`
}

// validProviderID is the accepted shape of [Provider.ID].
var validProviderID = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// ReadConfig reads and validates the trusted providers file at path.
func ReadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read trusted providers file: %w", err)
	}
	cfg, err := ParseConfig(data)
	if err != nil {
		return Config{}, fmt.Errorf("trusted providers file %s: %w", path, err)
	}
	return cfg, nil
}

// ParseConfig parses and validates a trusted providers document. An unknown
// field, a second JSON value after the first, and every condition
// [Config.Validate] rejects are errors.
func ParseConfig(data []byte) (Config, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("parse: unexpected data after the JSON object")
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate returns an error for a Config that names no source of keys, for a
// [Keycloak] that breaks a rule, and for the first entry that breaks a rule
// of [Provider]; the error names the entry by its index in Providers.
func (c Config) Validate() error {
	if c.Keycloak == nil && len(c.Providers) == 0 {
		return errors.New("neither keycloak nor providers is configured")
	}
	if c.Keycloak != nil {
		if err := c.Keycloak.validate(); err != nil {
			return fmt.Errorf("keycloak: %w", err)
		}
	}
	ids := make(map[string]bool, len(c.Providers))
	for i, p := range c.Providers {
		if err := p.validate(); err != nil {
			return fmt.Errorf("providers[%d]: %w", i, err)
		}
		if ids[p.ID] {
			return fmt.Errorf("providers[%d]: id %q is used by an earlier provider", i, p.ID)
		}
		ids[p.ID] = true
	}
	return c.checkIssuers()
}

// checkIssuers returns an error for two providers with one issuer. A provider
// without an issuer yet is left out, so [New] calls it again once it has read
// the tokens.
func (c Config) checkIssuers() error {
	issuers := make(map[string]bool, len(c.Providers))
	for i, p := range c.Providers {
		if p.Issuer == "" {
			continue
		}
		if issuers[p.Issuer] {
			return fmt.Errorf("providers[%d]: issuer %q is used by an earlier provider", i, p.Issuer)
		}
		issuers[p.Issuer] = true
	}
	return nil
}

func (k Keycloak) validate() error {
	if err := checkHTTPURL(k.URL); err != nil {
		return fmt.Errorf("url: %w", err)
	}
	for _, realm := range k.RequiredRealms {
		if !validRealm(realm) {
			return fmt.Errorf("requiredRealms: %q is not a realm name", realm)
		}
	}
	return nil
}

func (p Provider) validate() error {
	switch {
	case p.ID == "":
		return errors.New("id is empty")
	case !validProviderID.MatchString(p.ID):
		return fmt.Errorf("id %q has a character other than a letter, a digit, '.', '_', or '-'", p.ID)
	case p.Kubernetes && p.Issuer != "":
		return fmt.Errorf("provider %q sets both kubernetes and issuer; a provider that sets kubernetes takes its issuer from the token in tokenFile, so remove issuer", p.ID)
	case p.Issuer == "" && !p.takesIssuerFromToken():
		return fmt.Errorf("provider %q has no issuer; only a provider that sets kubernetes and tokenFile takes it from its token", p.ID)
	case !p.Kubernetes && p.TokenFile != "" && p.JWKSURI == "":
		return fmt.Errorf("provider %q sets tokenFile without jwksUri; only a provider that sets kubernetes sends a token through discovery, so set jwksUri or remove tokenFile", p.ID)
	case p.AllowMissingAud && len(p.Audiences) == 0:
		return fmt.Errorf("provider %q sets allowMissingAud without audiences", p.ID)
	case p.Kubernetes && len(p.Audiences) == 0:
		return fmt.Errorf("provider %q sets kubernetes without audiences; every Pod's default token is issued for the API server, so list the audience this service accepts", p.ID)
	case p.Kubernetes && p.AllowMissingAud:
		return fmt.Errorf("provider %q sets both kubernetes and allowMissingAud; a Kubernetes token has to name an audience this service accepts", p.ID)
	case !p.Kubernetes && p.looksLikeKubernetes():
		return fmt.Errorf("provider %q looks like a Kubernetes API server by its id or an address but does not set \"kubernetes\": true, so the token of any Pod of the cluster would pass with no namespace check; set it on this provider, or give the provider another id if it is not the API server", p.ID)
	}
	for _, aud := range p.Audiences {
		if aud == "" {
			return fmt.Errorf("provider %q lists an empty audience", p.ID)
		}
	}
	if p.Issuer != "" {
		if err := checkHTTPURL(p.Issuer); err != nil {
			return fmt.Errorf("provider %q issuer: %w", p.ID, err)
		}
	}
	if p.JWKSURI == "" {
		return nil
	}
	if err := checkHTTPURL(p.JWKSURI); err != nil {
		return fmt.Errorf("provider %q jwksUri: %w", p.ID, err)
	}
	if p.Kubernetes {
		return p.checkTokenAddress()
	}
	return nil
}

// checkTokenAddress refuses a JWKSURI that p, which sets Kubernetes, must not
// send its token to.
func (p Provider) checkTokenAddress() error {
	u, err := url.Parse(p.JWKSURI)
	switch {
	case err != nil || !kubernetesHosts[strings.ToLower(u.Hostname())]:
		return fmt.Errorf("provider %q sends the token in tokenFile to jwksUri %q, which is outside the cluster, and that token grants access to the API server; set jwksUri to an https address on kubernetes.default.svc or kubernetes.default.svc.cluster.local, or remove jwksUri to find the keys through discovery", p.ID, p.JWKSURI)
	case u.Scheme != "https":
		return fmt.Errorf("provider %q sends the token in tokenFile to jwksUri %q over http, and that token grants access to the API server; use https", p.ID, p.JWKSURI)
	}
	return nil
}

// checkHTTPURL accepts an absolute http or https URL with a host.
func checkHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%q is not an http or https URL", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("%q has no host", raw)
	}
	return nil
}

// IssuerOfTokenFile returns the iss of the JWT in the file at path, without
// checking its signature. A Pod holds such a file, written by the kubelet, so
// a [Provider] of the API server can take the issuer of the cluster from it
// rather than from a setting. It returns an error when the file cannot be read
// or does not hold three parts whose second is a payload with a non-empty
// string iss.
func IssuerOfTokenFile(path string) (string, error) {
	token, err := readToken(path)
	if err != nil {
		return "", fmt.Errorf("issuer of a token file: %w", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("issuer of a token file: %s holds %d parts separated by dots, and a JWT has 3", path, len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("issuer of a token file: payload of %s: %w", path, err)
	}
	// A map matches only the exact key, where a struct field would also take
	// ISS.
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("issuer of a token file: payload of %s: %w", path, err)
	}
	var issuer string
	if err := json.Unmarshal(claims["iss"], &issuer); err != nil || issuer == "" {
		return "", fmt.Errorf("issuer of a token file: the token in %s has no non-empty string iss", path)
	}
	return issuer, nil
}

// kubernetesHosts are the in-cluster names of the Kubernetes API server.
var kubernetesHosts = map[string]bool{
	"kubernetes.default.svc":               true,
	"kubernetes.default.svc.cluster.local": true,
}

// looksLikeKubernetes reports whether p is named kubernetes or names an
// in-cluster address of the Kubernetes API server, whether or not it sets
// [Provider.Kubernetes].
func (p Provider) looksLikeKubernetes() bool {
	if p.ID == "kubernetes" {
		return true
	}
	for _, raw := range []string{p.JWKSURI, p.Issuer} {
		if u, err := url.Parse(raw); err == nil && kubernetesHosts[strings.ToLower(u.Hostname())] {
			return true
		}
	}
	return false
}

// hasInClusterIssuer reports whether the issuer of p is an https address on an
// in-cluster name of the Kubernetes API server.
func (p Provider) hasInClusterIssuer() bool {
	u, err := url.Parse(p.Issuer)
	return err == nil && u.Scheme == "https" && kubernetesHosts[strings.ToLower(u.Hostname())]
}

// takesIssuerFromToken reports whether [New] fills in the issuer of p.
func (p Provider) takesIssuerFromToken() bool {
	return p.Issuer == "" && p.Kubernetes && p.TokenFile != ""
}

// discoversOutsideTheCluster reports whether p, whose issuer is filled in,
// finds its keys through discovery under an address outside its cluster.
func (p Provider) discoversOutsideTheCluster() bool {
	return p.Kubernetes && p.JWKSURI == "" && !p.hasInClusterIssuer()
}

// withIssuers returns a copy of c with the issuer of each provider that takes
// it from its token. The token and the CA of such a provider belong to its
// cluster, so discovery outside the cluster uses neither: it sends no token, and
// [New] gives it a client on the system roots and [Options.InternalCAFile]. It
// fails when a token file holds no token with an iss, when that iss is not an
// http or https URL, when an in-cluster issuer has neither a caFile nor a
// jwksUri, and when two providers end up with one issuer.
func (c Config) withIssuers(log Logger) (Config, error) {
	c.Providers = slices.Clone(c.Providers)
	for i := range c.Providers {
		p := &c.Providers[i]
		if !p.takesIssuerFromToken() {
			continue
		}
		issuer, err := IssuerOfTokenFile(p.TokenFile)
		if err != nil {
			return Config{}, fmt.Errorf("provider %q takes its issuer from tokenFile, so mount the token there or fix tokenFile: %w", p.ID, err)
		}
		if err := checkHTTPURL(issuer); err != nil {
			return Config{}, fmt.Errorf("provider %q issuer: %w", p.ID, err)
		}
		p.Issuer = issuer
		switch {
		case p.discoversOutsideTheCluster():
			log.Infof("trusted providers: provider %q takes the issuer %q from %s; discovery under an issuer outside the cluster sends no token and ignores caFile, so set jwksUri if it needs them", p.ID, issuer, p.TokenFile)
			p.TokenFile, p.CAFile = "", ""
		case p.JWKSURI == "" && p.CAFile == "":
			return Config{}, fmt.Errorf("provider %q takes the in-cluster issuer %q from tokenFile, and discovery there needs the cluster CA, so set caFile", p.ID, issuer)
		default:
			log.Infof("trusted providers: provider %q takes the issuer %q from %s", p.ID, issuer, p.TokenFile)
		}
	}
	return c, c.checkIssuers()
}
