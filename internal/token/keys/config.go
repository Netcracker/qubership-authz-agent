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
	"regexp"
)

// Config is the trusted providers file: a JSON object whose providers array
// lists every identity provider whose keys sign a token the service accepts.
type Config struct {
	Providers []Provider `json:"providers"`
}

// Provider is one trusted identity provider. It names the address of its
// keys in one of two forms and never both: Issuer, resolved through OIDC
// discovery to a jwks_uri, or JWKSURI, fetched as it is.
type Provider struct {
	// ID names the provider in logs and in the keys it publishes. It is
	// unique within a Config and uses only letters, digits, '.', '_', and '-'.
	ID string `json:"id"`
	// Issuer is the base address of the provider, an absolute http or https
	// URL. The keys are found through the OIDC discovery document under it,
	// at /.well-known/openid-configuration.
	Issuer string `json:"issuer,omitempty"`
	// JWKSURI is the address of the provider's JWKS, an absolute http or
	// https URL.
	JWKSURI string `json:"jwksUri,omitempty"`
	// Audiences lists the aud values accepted in a token signed by one of the
	// provider's keys; no entry is empty. An empty list accepts any aud.
	Audiences []string `json:"audiences,omitempty"`
	// AllowMissingAud admits a token that carries no aud claim at all. It
	// requires Audiences.
	AllowMissingAud bool `json:"allowMissingAud,omitempty"`
	// CAFile is a PEM bundle that replaces the system roots for HTTPS
	// requests to this provider.
	CAFile string `json:"caFile,omitempty"`
	// TokenFile holds a bearer token sent with every discovery and JWKS
	// request to this provider. It is read on every request, so a rotated
	// token takes effect without a restart.
	TokenFile string `json:"tokenFile,omitempty"`
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

// Validate returns an error for an empty provider list and for the first
// entry that breaks a rule of [Provider]; the error names the entry by its
// index in Providers.
func (c Config) Validate() error {
	if len(c.Providers) == 0 {
		return errors.New("no providers configured")
	}
	seen := make(map[string]bool, len(c.Providers))
	for i, p := range c.Providers {
		if err := p.validate(); err != nil {
			return fmt.Errorf("providers[%d]: %w", i, err)
		}
		if seen[p.ID] {
			return fmt.Errorf("providers[%d]: id %q is used by an earlier provider", i, p.ID)
		}
		seen[p.ID] = true
	}
	return nil
}

func (p Provider) validate() error {
	switch {
	case p.ID == "":
		return errors.New("id is empty")
	case !validProviderID.MatchString(p.ID):
		return fmt.Errorf("id %q has a character other than a letter, a digit, '.', '_', or '-'", p.ID)
	case p.Issuer == "" && p.JWKSURI == "":
		return fmt.Errorf("provider %q sets neither issuer nor jwksUri", p.ID)
	case p.Issuer != "" && p.JWKSURI != "":
		return fmt.Errorf("provider %q sets both issuer and jwksUri; keep one", p.ID)
	case p.AllowMissingAud && len(p.Audiences) == 0:
		return fmt.Errorf("provider %q sets allowMissingAud without audiences", p.ID)
	}
	for _, aud := range p.Audiences {
		if aud == "" {
			return fmt.Errorf("provider %q lists an empty audience", p.ID)
		}
	}
	address, field := p.Issuer, "issuer"
	if p.JWKSURI != "" {
		address, field = p.JWKSURI, "jwksUri"
	}
	if err := checkHTTPURL(address); err != nil {
		return fmt.Errorf("provider %q %s: %w", p.ID, field, err)
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
