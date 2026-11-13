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
	"path/filepath"
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
	// this provider. It is read on every request, so a rotated token takes
	// effect without a restart. A provider that does not set Kubernetes needs
	// JWKSURI with it, and its TokenFile, made absolute and cleaned, may not
	// lie under /var/run/secrets/tokens/kubernetes/, where the Pod holds the
	// token for the API server.
	//
	// A provider that sets Kubernetes has to set it, because [New] takes the
	// Issuer from this token. That token grants access to the API server, so
	// such a provider sends it only to that server and only over https. It
	// goes to a JWKSURI on an in-cluster name, or through discovery under an
	// https in-cluster Issuer, where that server names the jwks_uri and a
	// fetch fails when that address is not https. Both need CAFile,
	// the cluster CA: [Config.Validate] refuses a JWKSURI without it, and
	// [New] refuses discovery under an in-cluster Issuer without it. Without a
	// JWKSURI and under any other issuer, the provider sends no token. No
	// request follows a redirect, so the token goes to no other address.
	TokenFile string `json:"tokenFile,omitempty"`
	// Kubernetes marks the provider as the service account token issuer of
	// a Kubernetes API server, and
	// [authz-agent/internal/token/verify.Token.Kubernetes] reports the mark
	// on every token its keys verify. Such a token is refused when its sub
	// does not start with system:serviceaccount:, when its iat is ahead of
	// the verifier's clock by more than the verifier's leeway, and when its
	// namespace is not an allowed one. The mark requires Audiences to be
	// exactly netcracker, the audience that the services of an installation
	// request, and refuses AllowMissingAud, so a token that a Pod got for the
	// API server or for another service is refused. A provider whose id is
	// kubernetes in any case, or whose issuer or jwksUri is on an in-cluster
	// name of the API server, has to set the mark.
	//
	// [New] takes the issuer from TokenFile once. When the token there later
	// names another iss, as after the cluster changes its issuer, the
	// provider still accepts only the first one, so the tokens of the new
	// issuer are refused until a restart. A fetch of the keys that sends the
	// token logs a warning each time the iss of the token changes to one the
	// provider does not accept.
	Kubernetes bool `json:"kubernetes,omitempty"`
}

// validProviderID is the accepted shape of [Provider.ID].
var validProviderID = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// kubernetesAudience is the one audience a provider that sets
// [Provider.Kubernetes] accepts.
const kubernetesAudience = "netcracker"

// apiServerTokenDir is the directory of the Pod that holds the token for the
// API server, which only a provider that sets [Provider.Kubernetes] sends.
const apiServerTokenDir = "/var/run/secrets/tokens/kubernetes"

// apiServerJWKSURI is the address of the keys on the API server, which a
// provider that sets [Provider.Kubernetes] reads with its token and caFile.
const apiServerJWKSURI = "https://kubernetes.default.svc/openid/v1/jwks"

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
	case !p.Kubernetes && isAPIServerToken(p.TokenFile):
		return fmt.Errorf("provider %q sends the token for the API server in tokenFile %q but does not set \"kubernetes\": true, and that token grants access to the API server; set it on this provider if it is the API server, or point tokenFile at the token this provider needs", p.ID, p.TokenFile)
	case !p.Kubernetes && p.TokenFile != "" && p.JWKSURI == "":
		return fmt.Errorf("provider %q sets tokenFile without jwksUri; only a provider that sets kubernetes sends a token through discovery, so set jwksUri or remove tokenFile", p.ID)
	case p.AllowMissingAud && len(p.Audiences) == 0:
		return fmt.Errorf("provider %q sets allowMissingAud without audiences", p.ID)
	case p.Kubernetes && !slices.Equal(p.Audiences, []string{kubernetesAudience}):
		return fmt.Errorf("provider %q sets kubernetes with the audiences %q; a Kubernetes token is accepted only for %s, the audience that the services of an installation request, so set audiences to [%q]", p.ID, p.Audiences, kubernetesAudience, kubernetesAudience)
	case p.Kubernetes && p.AllowMissingAud:
		return fmt.Errorf("provider %q sets both kubernetes and allowMissingAud; a Kubernetes token has to name an audience this service accepts", p.ID)
	case !p.Kubernetes && strings.EqualFold(p.ID, "kubernetes"):
		return fmt.Errorf("provider %q has the id of a Kubernetes API server but does not set \"kubernetes\": true, so the token of any Pod of the cluster would pass with no namespace check; set it on this provider, or give the provider another id if it is not the API server", p.ID)
	case !p.Kubernetes && p.inClusterAddress() != "":
		return fmt.Errorf("provider %q sets %s on an in-cluster name of the Kubernetes API server but does not set \"kubernetes\": true, so the token of any Pod of the cluster would pass with no namespace check; set it on this provider", p.ID, p.inClusterAddress())
	}
	if slices.Contains(p.Audiences, "") {
		return fmt.Errorf("provider %q lists an empty audience", p.ID)
	}
	return p.checkAddresses()
}

// checkAddresses refuses a set Issuer or JWKSURI of p that is not an absolute
// http or https URL with a host. For a provider that sets Kubernetes, it also
// refuses a JWKSURI that [Provider.checkTokenAddress] refuses.
func (p Provider) checkAddresses() error {
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
// send its token to. It also refuses one when p has no CAFile, because the
// cluster CA signs the certificate of the API server.
func (p Provider) checkTokenAddress() error {
	u, err := url.Parse(p.JWKSURI)
	switch {
	case err != nil || !kubernetesHosts[strings.ToLower(u.Hostname())]:
		return fmt.Errorf("provider %q sends the token in tokenFile to jwksUri %q, which is outside the cluster, and that token grants access to the API server; set jwksUri to an https address on kubernetes.default.svc or kubernetes.default.svc.cluster.local, or remove jwksUri to find the keys through discovery", p.ID, p.JWKSURI)
	case u.Scheme != "https":
		return fmt.Errorf("provider %q sends the token in tokenFile to jwksUri %q over http, and that token grants access to the API server; use https", p.ID, p.JWKSURI)
	case p.CAFile == "":
		return fmt.Errorf("provider %q sets jwksUri %q on the API server without caFile, and the cluster CA signs the certificate of that server; set caFile to the cluster CA", p.ID, p.JWKSURI)
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

// issuerOfTokenFile returns the iss of the JWT in the file at path, without
// checking its signature. A Pod holds such a file, written by the kubelet, so
// a [Provider] of the API server can take the issuer of the cluster from it
// rather than from a setting. It returns an error when the file cannot be read
// or when [issuerOf] fails on its token.
func issuerOfTokenFile(path string) (string, error) {
	token, err := readToken(path)
	if err != nil {
		return "", fmt.Errorf("issuer of a token file: %w", err)
	}
	issuer, err := issuerOf(token)
	if err != nil {
		return "", fmt.Errorf("issuer of a token file: %s: %w", path, err)
	}
	return issuer, nil
}

// issuerOf returns the iss of the compact JWT token, without checking its
// signature. It returns an error when token does not hold three parts whose
// second is a base64url payload with a non-empty string iss.
func issuerOf(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("the token holds %d parts separated by dots, and a JWT has 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("payload of the token: %w", err)
	}
	// A map matches only the exact key, where a struct field would also take
	// ISS.
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("payload of the token: %w", err)
	}
	var issuer string
	if err := json.Unmarshal(claims["iss"], &issuer); err != nil || issuer == "" {
		return "", errors.New("the token has no non-empty string iss")
	}
	return issuer, nil
}

// kubernetesHosts are the in-cluster names of the Kubernetes API server.
var kubernetesHosts = map[string]bool{
	"kubernetes.default.svc":               true,
	"kubernetes.default.svc.cluster.local": true,
}

// inClusterAddress returns the field of p, jwksUri or issuer, whose host is an
// in-cluster name of the Kubernetes API server, as its name and its quoted
// value, and "" when neither is. The host is compared without regard to case
// and to one trailing dot, which names the same host.
func (p Provider) inClusterAddress() string {
	for _, field := range []struct{ name, value string }{{"jwksUri", p.JWKSURI}, {"issuer", p.Issuer}} {
		u, err := url.Parse(field.value)
		if err == nil && kubernetesHosts[strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")] {
			return fmt.Sprintf("%s %q", field.name, field.value)
		}
	}
	return ""
}

// isAPIServerToken reports whether path, made absolute and cleaned, lies in
// apiServerTokenDir. A relative path is resolved against the working directory,
// as a read of the file would resolve it.
func isAPIServerToken(path string) bool {
	if path == "" {
		return false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = filepath.Clean(path)
	}
	return strings.HasPrefix(abs, apiServerTokenDir+"/")
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
// jwksUri, and when two providers end up with one issuer. It logs the issuer it
// takes to opts.Log.
func (c Config) withIssuers(opts Options) (Config, error) {
	c.Providers = slices.Clone(c.Providers)
	for i := range c.Providers {
		p := &c.Providers[i]
		if !p.takesIssuerFromToken() {
			continue
		}
		issuer, err := issuerOfTokenFile(p.TokenFile)
		if err != nil {
			return Config{}, fmt.Errorf("provider %q takes its issuer from tokenFile, so mount the token there or fix tokenFile: %w", p.ID, err)
		}
		if err := checkHTTPURL(issuer); err != nil {
			return Config{}, fmt.Errorf("provider %q takes its issuer from the iss of the token in %s, and that iss is not usable: %w; mount the token for the API server there or fix tokenFile", p.ID, p.TokenFile, err)
		}
		p.Issuer = issuer
		switch {
		case p.discoversOutsideTheCluster():
			roots := "the system roots"
			if opts.InternalCAFile != "" {
				roots += " and the internal CA file " + opts.InternalCAFile
			}
			opts.Log.Infof("trusted providers: provider %q takes the issuer %q from %s; discovery under that issuer, outside the cluster, sends no token and trusts %s instead of caFile; to send the token and use caFile, set jwksUri to %s", p.ID, issuer, p.TokenFile, roots, apiServerJWKSURI)
			p.TokenFile, p.CAFile = "", ""
		case p.JWKSURI == "" && p.CAFile == "":
			return Config{}, fmt.Errorf("provider %q takes the in-cluster issuer %q from tokenFile, and discovery there needs the cluster CA, so set caFile", p.ID, issuer)
		default:
			opts.Log.Infof("trusted providers: provider %q takes the issuer %q from %s", p.ID, issuer, p.TokenFile)
		}
	}
	return c, c.checkIssuers()
}
