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
	// Issuer is the iss of the provider's tokens, compared byte for byte. It
	// is unique within a Config. An Issuer that the file sets is an absolute
	// http or https URL, and the OIDC discovery document lies under it, at
	// /.well-known/openid-configuration. A provider that sets Kubernetes may
	// not set it: [New] takes it from the token in TokenFile, under the rules
	// of [Provider.Kubernetes].
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
	// requests to this provider. [New] does not use it for a provider that sets
	// Kubernetes, has no JWKSURI, and takes from its token an issuer that is
	// not an https in-cluster address: such a provider trusts the system roots
	// and [Options.InternalCAFile].
	CAFile string `json:"caFile,omitempty"`
	// TokenFile holds a bearer token for the requests for the keys of this
	// provider. It is read on every request that sends it, so a rotated token
	// takes effect without a restart. A provider that does not set Kubernetes
	// sends it with every request and needs JWKSURI with it. Its TokenFile may
	// name neither a file in /var/run/secrets/tokens/kubernetes/, where the Pod
	// holds the token for the API server, nor the TokenFile of a provider that
	// sets Kubernetes, whether the path leads there as written or through a
	// symbolic link. [Config.Validate] follows the links on the filesystem
	// where it runs, so a path through a link is refused only where the link
	// and the file exist then.
	//
	// A provider that sets Kubernetes has to set it, because [New] takes the
	// Issuer from this token. That token grants access to the API server, so
	// such a provider sends it only to that server and only over https: to a
	// JWKSURI on an in-cluster name, or through discovery under an https
	// in-cluster Issuer, together with the request to the jwks_uri that this
	// server names. Both need CAFile, the cluster CA: [Config.Validate] refuses
	// a JWKSURI without it, and [New] refuses discovery under an https
	// in-cluster Issuer without it. Without a JWKSURI and under any other
	// issuer, the provider sends no token. No request follows a redirect, so
	// the token goes to no other address.
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
	// API server or for another service is refused. [Config.Validate] refuses
	// a provider without the mark whose id matches kubernetes
	// case-insensitively, or whose issuer or jwksUri is on an in-cluster name
	// of the API server.
	//
	// Such a provider reads its keys only over https. [New] takes the issuer
	// from TokenFile once. With JWKSURI, that issuer may be any non-empty
	// string, because it is only compared with the iss of a token. Without
	// JWKSURI, the keys are found through discovery under that issuer, so it
	// has to be an https URL with a host, and so does the jwks_uri that
	// discovery names.
	//
	// When the token in TokenFile later names another iss, as after the
	// cluster changes its issuer, the provider still accepts only the first
	// one, so the tokens of the new issuer are refused until a restart. Each
	// fetch of the keys reads the iss of that token, whether or not the
	// provider sends the token. It logs a warning each time the iss changes to
	// one the provider does not accept, and an informational record when the
	// token names the issuer of the provider again after a warning.
	Kubernetes bool `json:"kubernetes,omitempty"`
}

// validProviderID is the accepted shape of [Provider.ID].
var validProviderID = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// netcrackerAudience is the one audience a provider that sets
// [Provider.Kubernetes] accepts.
const netcrackerAudience = "netcracker"

// apiServerTokenDir is the directory of the Pod that holds the token for the
// API server, which only a provider that sets [Provider.Kubernetes] sends.
const apiServerTokenDir = "/var/run/secrets/tokens/kubernetes"

// apiServerTokenFile is the file of the Pod that holds the token for the API
// server.
const apiServerTokenFile = apiServerTokenDir + "/token"

// clusterCAFile is the file of the Pod that holds the cluster CA, which signs
// the certificate of the API server.
const clusterCAFile = apiServerTokenDir + "/ca.crt"

// apiServerJWKSURI is the address of the keys on the API server. The refusals
// and the start-up record offer it as the jwksUri of a provider that sets
// [Provider.Kubernetes].
const apiServerJWKSURI = "https://kubernetes.default.svc/openid/v1/jwks"

// markedEntry returns the entry of the providers file that marks p as the API
// server of the Pod's cluster: the mark, the audience netcracker, and no
// issuer, with the settings of p that such an entry may hold. Its tokenFile
// is the TokenFile of p where that lies in apiServerTokenDir, and the token
// for the API server otherwise. Its caFile is the CAFile of p where p sets
// one, and the cluster CA otherwise. Where the JWKSURI of p is on an
// in-cluster name, its jwksUri is that JWKSURI where
// [Provider.checkTokenAddress] accepts it, and apiServerJWKSURI where it does
// not. A JWKSURI outside the cluster is left out.
func markedEntry(p Provider) string {
	entry := struct {
		ID         string   `json:"id"`
		JWKSURI    string   `json:"jwksUri,omitempty"`
		CAFile     string   `json:"caFile"`
		TokenFile  string   `json:"tokenFile"`
		Audiences  []string `json:"audiences"`
		Kubernetes bool     `json:"kubernetes"`
	}{ID: p.ID, CAFile: clusterCAFile, TokenFile: apiServerTokenFile, Audiences: []string{netcrackerAudience}, Kubernetes: true}
	if isAPIServerToken(p.TokenFile) {
		entry.TokenFile = p.TokenFile
	}
	if p.CAFile != "" {
		entry.CAFile = p.CAFile
	}
	if onInClusterName(p.JWKSURI) {
		entry.JWKSURI = apiServerJWKSURI
		if (Provider{ID: p.ID, JWKSURI: p.JWKSURI, CAFile: entry.CAFile}).checkTokenAddress() == nil {
			entry.JWKSURI = p.JWKSURI
		}
	}
	// Marshal cannot fail on strings, a slice of strings, and a bool.
	out, _ := json.Marshal(entry)
	return string(out)
}

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
// [Keycloak] that breaks a rule, and for the first entry of Providers that
// breaks a rule of [Provider]; the error names the entry by its index in
// Providers. It resolves the symbolic links of every [Provider.TokenFile] on
// the local filesystem, so its result for a TokenFile depends on the host it
// runs on.
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
	firsts := make(map[string]int, len(c.Providers))
	for i, p := range c.Providers {
		if err := p.validate(); err != nil {
			return fmt.Errorf("providers[%d]: %w", i, err)
		}
		if ids[p.ID] {
			return fmt.Errorf("providers[%d]: id %q is used by an earlier provider", i, p.ID)
		}
		ids[p.ID] = true
		if err := c.checkIssuer(i, firsts); err != nil {
			return err
		}
		if err := c.checkTokenFileOf(i); err != nil {
			return err
		}
	}
	return nil
}

// checkTokenFileOf returns an error when the provider at index i of c does not
// set Kubernetes and its TokenFile is the TokenFile of a provider that does,
// as written or after symbolic links are followed.
func (c Config) checkTokenFileOf(i int) error {
	p := c.Providers[i]
	if p.Kubernetes || p.TokenFile == "" {
		return nil
	}
	for _, marked := range c.Providers {
		if marked.Kubernetes && sameFile(p.TokenFile, marked.TokenFile) {
			return fmt.Errorf("providers[%d]: provider %q sends in tokenFile %q the token of provider %q, which sets kubernetes, and that token grants access to the API server; point tokenFile at the token this provider needs", i, p.ID, p.TokenFile, marked.ID)
		}
	}
	return nil
}

// checkIssuers returns an error for the first provider of c that has the same
// issuer as an earlier provider, and leaves out a provider without an issuer.
// [New] calls it once it has taken the issuers from the tokens;
// [Config.Validate] makes the same check entry by entry with
// [Config.checkIssuer].
func (c Config) checkIssuers() error {
	firsts := make(map[string]int, len(c.Providers))
	for i := range c.Providers {
		if err := c.checkIssuer(i, firsts); err != nil {
			return err
		}
	}
	return nil
}

// checkIssuer returns an error when the issuer of the provider at index i of c
// is in firsts, which maps the issuer of each earlier provider to the index of
// the first one, and adds that issuer to firsts otherwise. An empty issuer
// passes.
func (c Config) checkIssuer(i int, firsts map[string]int) error {
	p := c.Providers[i]
	if p.Issuer == "" {
		return nil
	}
	first, seen := firsts[p.Issuer]
	if !seen {
		firsts[p.Issuer] = i
		return nil
	}
	return fmt.Errorf("providers[%d]: %w", i, sharedIssuer(c.Providers[first], p))
}

// sharedIssuer returns the refusal of the provider later, which has the same
// issuer as the provider earlier. For a provider that sets Kubernetes it names
// the TokenFile the issuer came from. Where only one of the two sets
// Kubernetes, it names the other one as the provider to remove, because that
// one accepts the tokens of the cluster with no namespace check.
func sharedIssuer(earlier, later Provider) error {
	switch {
	case earlier.Kubernetes && later.Kubernetes:
		return fmt.Errorf("provider %q takes the issuer %q from the token in %s, as provider %q does from %s; keep one of the two", later.ID, later.Issuer, later.TokenFile, earlier.ID, earlier.TokenFile)
	case later.Kubernetes:
		return fmt.Errorf("provider %q takes the issuer %q from the token in %s, and provider %q sets the same issuer; remove provider %q, because a provider that does not set kubernetes accepts a token of that issuer with no namespace check", later.ID, later.Issuer, later.TokenFile, earlier.ID, earlier.ID)
	case earlier.Kubernetes:
		return fmt.Errorf("provider %q sets the issuer %q, which provider %q takes from the token in %s; remove provider %q, because a provider that does not set kubernetes accepts a token of that issuer with no namespace check", later.ID, later.Issuer, earlier.ID, earlier.TokenFile, later.ID)
	}
	return fmt.Errorf("issuer %q is used by the earlier provider %q", later.Issuer, earlier.ID)
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
	case p.Kubernetes && p.TokenFile == "":
		return fmt.Errorf("provider %q sets kubernetes without tokenFile; a provider that sets kubernetes takes its issuer from the token in tokenFile, so set tokenFile to the token for the API server, %s", p.ID, apiServerTokenFile)
	case !p.Kubernetes && isAPIServerToken(p.TokenFile):
		return fmt.Errorf("provider %q sends the token for the API server in tokenFile %q but does not set \"kubernetes\": true, and that token grants access to the API server; point tokenFile at the token this provider needs, or, if it is the API server, replace the entry with %s", p.ID, p.TokenFile, markedEntry(p))
	case !p.Kubernetes && strings.EqualFold(p.ID, "kubernetes"):
		return fmt.Errorf("provider %q has the id of a Kubernetes API server but does not set \"kubernetes\": true, so the token of any Pod of the cluster would pass with no namespace check; if it is the API server, replace the entry with %s, and otherwise give the provider another id", p.ID, markedEntry(p))
	case !p.Kubernetes && p.inClusterField() != "":
		return fmt.Errorf("provider %q sets %s on an in-cluster name of the Kubernetes API server but does not set \"kubernetes\": true, so the token of any Pod of the cluster would pass with no namespace check; replace the entry with %s", p.ID, p.inClusterField(), markedEntry(p))
	case !p.Kubernetes && p.Issuer == "":
		return fmt.Errorf("provider %q has no issuer; set issuer to the iss of its tokens", p.ID)
	case !p.Kubernetes && p.TokenFile != "" && p.JWKSURI == "":
		return fmt.Errorf("provider %q sets tokenFile without jwksUri; only a provider that sets kubernetes sends a token through discovery, so set jwksUri or remove tokenFile", p.ID)
	case p.AllowMissingAud && len(p.Audiences) == 0:
		return fmt.Errorf("provider %q sets allowMissingAud without audiences", p.ID)
	case p.Kubernetes && !slices.Equal(p.Audiences, []string{netcrackerAudience}):
		return fmt.Errorf("provider %q sets kubernetes with the audiences %q; a Kubernetes token is accepted only for %s, the audience that the services of an installation request, so set audiences to [%q]", p.ID, p.Audiences, netcrackerAudience, netcrackerAudience)
	case p.Kubernetes && p.AllowMissingAud:
		return fmt.Errorf("provider %q sets both kubernetes and allowMissingAud; a Kubernetes token has to name an audience this service accepts", p.ID)
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
// cluster CA signs the certificate of the API server. Where p has no CAFile,
// the other refusals name caFile in their remedy as well.
func (p Provider) checkTokenAddress() error {
	u, err := url.Parse(p.JWKSURI)
	outside := err != nil || !kubernetesHosts[strings.ToLower(u.Hostname())]
	switch {
	case outside && p.CAFile == "":
		return fmt.Errorf("provider %q sends the token in tokenFile to jwksUri %q, which is outside the cluster, and that token grants access to the API server; set jwksUri to %s and caFile to the cluster CA, %s", p.ID, p.JWKSURI, apiServerJWKSURI, clusterCAFile)
	case outside:
		return fmt.Errorf("provider %q sends the token in tokenFile to jwksUri %q, which is outside the cluster, and that token grants access to the API server; set jwksUri to an https address on kubernetes.default.svc or kubernetes.default.svc.cluster.local, or, where the iss of the token in tokenFile is an https URL with a host, remove jwksUri to find the keys through discovery", p.ID, p.JWKSURI)
	case u.Scheme != "https" && p.CAFile == "":
		return fmt.Errorf("provider %q sends the token in tokenFile to jwksUri %q over http, and that token grants access to the API server; use https, and set caFile to the cluster CA, %s", p.ID, p.JWKSURI, clusterCAFile)
	case u.Scheme != "https":
		return fmt.Errorf("provider %q sends the token in tokenFile to jwksUri %q over http, and that token grants access to the API server; use https", p.ID, p.JWKSURI)
	case p.CAFile == "":
		return fmt.Errorf("provider %q sets jwksUri %q on the API server without caFile, and the cluster CA signs the certificate of that server; set caFile to the cluster CA, %s", p.ID, p.JWKSURI, clusterCAFile)
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
	// encoding/json matches a struct field to a key case-insensitively, so a
	// field would also take ISS; claims["iss"] takes only iss.
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

// kubernetesHosts are the in-cluster names of the Kubernetes API server. A
// check that decides where the token for the API server goes compares a host
// with them exactly, apart from case, so it errs toward sending no token: a
// host with a trailing dot gets none. A check that refuses an unmarked
// provider drops one trailing dot first, so it errs toward refusing.
var kubernetesHosts = map[string]bool{
	"kubernetes.default.svc":               true,
	"kubernetes.default.svc.cluster.local": true,
}

// inClusterField returns the field of p, jwksUri or issuer, whose host is an
// in-cluster name of the Kubernetes API server, as its name and its quoted
// value, and "" when neither is. The host is compared without regard to case
// and to one trailing dot.
func (p Provider) inClusterField() string {
	for _, field := range []struct{ name, value string }{{"jwksUri", p.JWKSURI}, {"issuer", p.Issuer}} {
		if onInClusterName(field.value) {
			return fmt.Sprintf("%s %q", field.name, field.value)
		}
	}
	return ""
}

// onInClusterName reports whether raw is a URL whose host is an in-cluster
// name of the Kubernetes API server, compared without regard to case and to
// one trailing dot.
func onInClusterName(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && kubernetesHosts[strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")]
}

// isAPIServerToken reports whether path names a file in apiServerTokenDir, as
// [liesUnder] compares them.
func isAPIServerToken(path string) bool { return liesUnder(path, apiServerTokenDir) }

// liesUnder reports whether path names a file under dir in either of two
// comparisons, and false for an empty path. The first compares path, made
// absolute and cleaned, with dir as written. The second follows the symbolic
// links of path the way a read opens the file, so a link is resolved before a
// ".." that comes after it, and compares the result with dir with its links
// followed. The second comparison needs both path and dir to exist, so for a
// missing file only the first one decides.
func liesUnder(path, dir string) bool {
	if path == "" {
		return false
	}
	if abs, err := filepath.Abs(path); err == nil && strings.HasPrefix(abs, dir+string(filepath.Separator)) {
		return true
	}
	resolvedPath, err := resolvedAbs(path)
	if err != nil {
		return false
	}
	resolvedDir, err := filepath.EvalSymlinks(dir)
	return err == nil && strings.HasPrefix(resolvedPath, resolvedDir+string(filepath.Separator))
}

// resolvedAbs returns path with its symbolic links resolved as a read
// resolves them, made absolute against the working directory with its own
// links resolved, so a ".." that leads out of a linked working directory
// leads where a read goes.
func resolvedAbs(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.IsAbs(resolved) {
		return resolved, err
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if wd, err = filepath.EvalSymlinks(wd); err != nil {
		return "", err
	}
	return filepath.Join(wd, resolved), nil
}

// sameFile reports whether a read of the path a and a read of the path b open
// one file. Where both files exist, it compares them after their symbolic
// links are followed the way a read opens them, and where only one exists,
// they are not one file. Where neither exists, it compares the two paths made
// absolute and cleaned. An empty path names no file.
func sameFile(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	infoA, errA := os.Stat(a)
	infoB, errB := os.Stat(b)
	switch {
	case errA == nil && errB == nil:
		return os.SameFile(infoA, infoB)
	case errA == nil || errB == nil:
		return false
	}
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	return errA == nil && errB == nil && absA == absB
}

// hasInClusterIssuer reports whether the issuer of p is an https address on an
// in-cluster name of the Kubernetes API server.
func (p Provider) hasInClusterIssuer() bool {
	u, err := url.Parse(p.Issuer)
	return err == nil && u.Scheme == "https" && kubernetesHosts[strings.ToLower(u.Hostname())]
}

// isHTTPSURL reports whether raw is an absolute https URL with a host.
func isHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// hasHTTPSScheme reports whether raw parses as a URL with the https scheme,
// with or without a host. A Kubernetes API server serves its discovery document
// and its keys only under an issuer that has that scheme
// (NewOpenIDMetadataProvider in Kubernetes), and it needs no host, so it serves
// them under https:cluster-1 too. The API server also serves neither under an
// issuer with a query or a fragment, which OIDC Discovery forbids;
// hasHTTPSScheme checks for neither.
func hasHTTPSScheme(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https"
}

// discoversWithoutToken reports whether p, whose issuer is filled in, sets
// Kubernetes and finds its keys through discovery under an issuer that is not
// an https in-cluster address. The token for the API server goes only to that
// server, and the cluster CA signs only its certificate, so [fetcher.tokenFile]
// returns no file for such a provider, and [clientOf] gives it a client on the
// system roots and [Options.InternalCAFile].
func (p Provider) discoversWithoutToken() bool {
	return p.Kubernetes && p.JWKSURI == "" && !p.hasInClusterIssuer()
}

// caFileRemedy returns the end of a remedy that sets jwksUri for p, a provider
// that sets Kubernetes. A jwksUri on the API server needs caFile, so where p
// has no CAFile, the end tells the operator to set caFile to the cluster CA;
// where p has one, the end is "".
func (p Provider) caFileRemedy() string {
	if p.CAFile != "" {
		return ""
	}
	return " and caFile to the cluster CA, " + clusterCAFile
}

// withoutTokenNote returns the end of the start-up record of p, a provider
// that discovers its keys without its token: what discovery sends and trusts,
// and the settings that would send the token. internalCA is
// [Options.InternalCAFile].
func (p Provider) withoutTokenNote(internalCA string) string {
	roots := "the system roots"
	if internalCA != "" {
		roots += " and the internal CA file " + internalCA
	}
	const head = "that issuer is not an https address on an in-cluster name, so discovery under it sends no token and trusts "
	if p.CAFile == "" {
		return head + roots + "; to send the token, set jwksUri to " + apiServerJWKSURI + " and caFile to the cluster CA, " + clusterCAFile
	}
	return head + roots + " instead of caFile; to send the token and use caFile, set jwksUri to " + apiServerJWKSURI
}

// withIssuers returns a copy of c in which each provider that sets Kubernetes
// has the issuer of the token in its TokenFile, and logs the issuer it takes to
// opts.Log. It fails when a token file holds no token with a non-empty string
// iss, when a provider without a jwksUri takes an iss that is not an https URL
// with a host, when an https in-cluster issuer has neither a caFile nor a
// jwksUri, and when two providers end up with one issuer. c has passed
// [Config.Validate], so every such provider has a TokenFile and no issuer of
// its own.
func (c Config) withIssuers(opts Options) (Config, error) {
	c.Providers = slices.Clone(c.Providers)
	for i := range c.Providers {
		p := &c.Providers[i]
		if !p.Kubernetes {
			continue
		}
		issuer, err := issuerOfTokenFile(p.TokenFile)
		if err != nil {
			return Config{}, fmt.Errorf("provider %q takes its issuer from tokenFile, so mount the token there or fix tokenFile: %w", p.ID, err)
		}
		p.Issuer = issuer
		switch {
		case p.JWKSURI == "" && !hasHTTPSScheme(issuer):
			return Config{}, fmt.Errorf("provider %q takes the issuer %q from the token in %s, and an API server whose issuer does not use the https scheme serves no keys, so jwksUri cannot help; set --service-account-issuer of the API server to an https URL, or remove this provider, and the agent then refuses Kubernetes tokens", p.ID, issuer, p.TokenFile)
		case p.JWKSURI == "" && !isHTTPSURL(issuer):
			return Config{}, fmt.Errorf("provider %q takes the issuer %q from the token in %s, and discovery under that issuer needs an https URL with a host; to read the keys without discovery, set jwksUri to %s%s", p.ID, issuer, p.TokenFile, apiServerJWKSURI, p.caFileRemedy())
		case p.discoversWithoutToken():
			opts.Log.Infof("trusted providers: provider %q takes the issuer %q from %s; %s", p.ID, issuer, p.TokenFile, p.withoutTokenNote(opts.InternalCAFile))
		case p.JWKSURI == "" && p.CAFile == "":
			return Config{}, fmt.Errorf("provider %q takes the in-cluster issuer %q from tokenFile, and discovery there needs the cluster CA, so set caFile to the cluster CA, %s", p.ID, issuer, clusterCAFile)
		default:
			opts.Log.Infof("trusted providers: provider %q takes the issuer %q from %s", p.ID, issuer, p.TokenFile)
		}
	}
	return c, c.checkIssuers()
}
