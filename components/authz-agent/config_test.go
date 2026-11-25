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

package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"authz-agent/components/authz-agent/internal/authn"
	"authz-agent/components/authz-agent/internal/m2m"
	"authz-agent/components/authz-agent/internal/pull"
	"authz-agent/internal/pips"
)

func fromMap(values map[string]string) lookup {
	return func(key, fallback string) string {
		if v, ok := values[key]; ok {
			return v
		}
		return fallback
	}
}

// fileHolding writes content to a new file of mode perm in a new temporary
// directory and returns its path.
func fileHolding(t *testing.T, content string, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatal(err)
	}
	return path
}

// missingEndpoint is the refusal of an unset or empty AUTHZ_OUTGOING_TOKEN_URL
// with AUTHZ_OUTGOING_TOKEN_SOURCE client-credentials, its default.
const missingEndpoint = `AUTHZ_OUTGOING_TOKEN_URL="": expected the http or https URL of the token endpoint, ` +
	`required while AUTHZ_OUTGOING_TOKEN_SOURCE is client-credentials, which is its default; ` +
	`AUTHZ_OUTGOING_TOKEN_SOURCE=token-file sends a token from a file instead`

// tokenFile writes a token to a new file and returns its path, which differs
// from call to call.
func tokenFile(t *testing.T) string {
	t.Helper()
	return fileHolding(t, "token", 0o600)
}

// load is loadConfig over values with a token endpoint and an existing token
// file added, so that either value of AUTHZ_OUTGOING_TOKEN_SOURCE loads; a key
// of values replaces the added one.
func load(t *testing.T, values map[string]string) (config, error) {
	t.Helper()
	merged := map[string]string{"authz.outgoing.token.url": "http://idp/token", "authz.pap.client.token.file": tokenFile(t)}
	for key, value := range values {
		merged[key] = value
	}
	return loadConfig(fromMap(merged))
}

// mustLoad is load over values; a refused value fails the test.
func mustLoad(t *testing.T, values map[string]string) config {
	t.Helper()
	cfg, err := load(t, values)
	if err != nil {
		t.Fatalf("load(%v) error = %v, want none", values, err)
	}
	return cfg
}

// refusal is the error of load over values; a configuration that loadConfig
// accepts fails the test.
func refusal(t *testing.T, values map[string]string) string {
	t.Helper()
	_, err := load(t, values)
	if err == nil {
		t.Fatalf("load(%v) error = nil, want a refusal", values)
	}
	return err.Error()
}

// TestLoadConfig_EnvironmentOnly: the settings come from the environment
// keys, with the service defaults behind them.
func TestLoadConfig_EnvironmentOnly(t *testing.T) {
	cfg := mustLoad(t, map[string]string{})
	if cfg.Addr != "0.0.0.0:8181" || cfg.PublicAddr != "0.0.0.0:8080" {
		t.Fatalf("default addresses: %+v", cfg)
	}
	cfg = mustLoad(t, map[string]string{
		"authz.http.addr":   ":9090",
		"authz.public.addr": ":9091",
	})
	if cfg.Addr != ":9090" || cfg.PublicAddr != ":9091" {
		t.Fatalf("addresses from env: %+v", cfg)
	}
}

// TestLoadConfig_LoopsOnTheServicesOwn: with a token endpoint, the one value
// it needs, the service takes its files from their default paths and leaves
// the address of every other service it calls empty, which keeps the policy
// pull and the realm lookup off; each key of the loops is read from its
// variable.
func TestLoadConfig_LoopsOnTheServicesOwn(t *testing.T) {
	cfg, err := loadConfig(fromMap(map[string]string{"authz.outgoing.token.url": "http://idp/token"}))
	if err != nil {
		t.Fatalf("loadConfig() with a token endpoint alone error = %v, want none", err)
	}
	wantAuthn := authn.Config{File: "/etc/authz/trusted-providers.json", Required: true, HTTPTimeout: 5 * time.Second, HTTPRetries: 3,
		TenantManagerURL: "", ReloadInterval: 30 * time.Second}
	if cfg.Authn != wantAuthn {
		t.Errorf("default trusted providers = %+v, want %+v", cfg.Authn, wantAuthn)
	}
	wantPull := pull.Config{Interval: 30 * time.Second, HTTPTimeout: 30 * time.Second}
	if cfg.Pull != wantPull {
		t.Errorf("default pull = %+v, want %+v", cfg.Pull, wantPull)
	}
	wantM2M := m2m.Config{TokenURL: "http://idp/token", ClientIDFile: "/etc/secret/username", ClientSecretFile: "/etc/secret/password",
		RenewBefore: 60 * time.Second, TokenFile: "/var/run/secrets/tokens/netcracker/token", WatchInterval: 15 * time.Second}
	if cfg.M2M != wantM2M {
		t.Errorf("default m2m = %+v, want %+v", cfg.M2M, wantM2M)
	}
	cfg = mustLoad(t, map[string]string{
		"authz.trusted.providers.file":            "/p.json",
		"authz.jwks.bootstrap.required":           "false",
		"authz.jwks.http.timeout":                 "2",
		"authz.jwks.http.retries":                 "20",
		"authz.trusted.providers.reload.interval": "0",
		"authz.tenant.manager.url":                "http://tm:8080",
		"authz.pap.client.source.url":             "http://policy-admin:18090/",
		"authz.pap.client.pull.interval":          "2",
		"authz.pap.client.token.file":             "/t",
		"authz.outgoing.token.url":                "http://idp/token",
		"authz.outgoing.client.id.file":           "/id",
		"authz.outgoing.client.secret.file":       "/secret",
		"authz.outgoing.renew.before.seconds":     "30",
	})
	if cfg.Authn.File != "/p.json" || cfg.Authn.Required || cfg.Authn.HTTPTimeout != 2*time.Second || cfg.Authn.HTTPRetries != 20 ||
		cfg.Authn.ReloadInterval != 0 || cfg.Authn.TenantManagerURL != "http://tm:8080" {
		t.Errorf("trusted providers from env = %+v", cfg.Authn)
	}
	if cfg.Pull.SourceURL != "http://policy-admin:18090" || cfg.Pull.Interval != 2*time.Second {
		t.Errorf("pull from env = %+v", cfg.Pull)
	}
	if cfg.M2M.TokenURL != "http://idp/token" || cfg.M2M.ClientIDFile != "/id" || cfg.M2M.ClientSecretFile != "/secret" ||
		cfg.M2M.RenewBefore != 30*time.Second || cfg.M2M.TokenFile != "/t" {
		t.Errorf("m2m from env = %+v", cfg.M2M)
	}
}

// TestLoadConfig_EmptyProvidersFileStaysEmpty: an empty
// AUTHZ_TRUSTED_PROVIDERS_FILE runs the service without trusted providers,
// so loadConfig keeps it empty rather than taking the default path.
func TestLoadConfig_EmptyProvidersFileStaysEmpty(t *testing.T) {
	cfg := mustLoad(t, map[string]string{"authz.trusted.providers.file": ""})
	if cfg.Authn.File != "" {
		t.Errorf("loadConfig() with authz.trusted.providers.file empty: Authn.File = %q, want empty", cfg.Authn.File)
	}
}

func TestLoadConfig_RefusesAnInvalidValue(t *testing.T) {
	for _, tt := range []struct {
		name, key, value, want string
	}{
		{"a unit after the seconds", "authz.pap.client.pull.interval", "2s",
			`AUTHZ_PAP_CLIENT_PULL_INTERVAL="2s": expected an integer number of seconds from 0 to 9223372036`},
		{"a fraction of a second", "authz.trusted.providers.reload.interval", "1.5",
			`AUTHZ_TRUSTED_PROVIDERS_RELOAD_INTERVAL="1.5": expected an integer number of seconds from 0 to 9223372036`},
		{"a space before the seconds", "authz.jwks.http.timeout", " 5",
			`AUTHZ_JWKS_HTTP_TIMEOUT=" 5": expected an integer number of seconds from 1 to 9223372036`},
		{"seconds below the minimum", "authz.jwks.http.timeout", "0",
			`AUTHZ_JWKS_HTTP_TIMEOUT="0": expected an integer number of seconds from 1 to 9223372036`},
		{"negative seconds", "authz.outgoing.renew.before.seconds", "-1",
			`AUTHZ_OUTGOING_RENEW_BEFORE_SECONDS="-1": expected an integer number of seconds from 0 to 9223372036`},
		{"more seconds than a duration holds", "authz.pap.client.pull.interval", "9223372037",
			`AUTHZ_PAP_CLIENT_PULL_INTERVAL="9223372037": expected an integer number of seconds from 0 to 9223372036`},
		{"an entitlements timeout without an entitlements URL", "authz.entitlements.http.timeout", "0",
			`AUTHZ_ENTITLEMENTS_HTTP_TIMEOUT="0": expected an integer number of seconds from 1 to 9223372036`},
		{"a count below the minimum", "authz.jwks.http.retries", "0",
			`AUTHZ_JWKS_HTTP_RETRIES="0": expected an integer from 1 to 100`},
		{"a count above the maximum", "authz.entitlements.http.retries", "101",
			`AUTHZ_ENTITLEMENTS_HTTP_RETRIES="101": expected an integer from 1 to 100`},
		{"a count in words", "authz.entitlements.http.retries", "three",
			`AUTHZ_ENTITLEMENTS_HTTP_RETRIES="three": expected an integer from 1 to 100`},
		{"a count above the range of int", "authz.jwks.http.retries", "9223372036854775808",
			`AUTHZ_JWKS_HTTP_RETRIES="9223372036854775808": expected an integer from 1 to 100`},
		{"yes for a boolean", "authz.jwks.bootstrap.required", "yes",
			`AUTHZ_JWKS_BOOTSTRAP_REQUIRED="yes": expected true or false`},
		{"1 for a boolean", "authz.jwks.bootstrap.required", "1",
			`AUTHZ_JWKS_BOOTSTRAP_REQUIRED="1": expected true or false`},
		{"on for a boolean", "authz.jwks.bootstrap.required", "on",
			`AUTHZ_JWKS_BOOTSTRAP_REQUIRED="on": expected true or false`},
		{"0 for a boolean", "authz.jwks.bootstrap.required", "0",
			`AUTHZ_JWKS_BOOTSTRAP_REQUIRED="0": expected true or false`},
		{"no for a boolean", "authz.jwks.bootstrap.required", "no",
			`AUTHZ_JWKS_BOOTSTRAP_REQUIRED="no": expected true or false`},
		{"off for a boolean", "authz.jwks.bootstrap.required", "off",
			`AUTHZ_JWKS_BOOTSTRAP_REQUIRED="off": expected true or false`},
		{"a misspelled boolean", "authz.jwks.bootstrap.required", "ture",
			`AUTHZ_JWKS_BOOTSTRAP_REQUIRED="ture": expected true or false`},
		{"an unknown log level", "logging.level.root", "verbose",
			`LOGGING_LEVEL_ROOT="verbose": expected one of debug, info, warn, error, fatal`},
		{"a space before the log level", "logging.level.root", " info",
			`LOGGING_LEVEL_ROOT=" info": expected one of debug, info, warn, error, fatal`},
		{"a root log level under LOG_LEVEL", "log.level", "debug",
			`LOG_LEVEL="debug": expected no value, since the agent reads the root log level from LOGGING_LEVEL_ROOT alone`},
		{"a listen address without a port", "authz.public.addr", "bogus",
			`AUTHZ_PUBLIC_ADDR="bogus": expected <host>:<port>, with the host empty, an IP address, or a host name and the port from 0 to 65535, such as 0.0.0.0:8080`},
		{"a negative port", "authz.http.addr", "0.0.0.0:-1",
			`AUTHZ_HTTP_ADDR="0.0.0.0:-1": expected <host>:<port>, with the host empty, an IP address, or a host name and the port from 0 to 65535, such as 0.0.0.0:8181`},
		{"a port above 65535", "authz.http.addr", ":65536",
			`AUTHZ_HTTP_ADDR=":65536": expected <host>:<port>, with the host empty, an IP address, or a host name and the port from 0 to 65535, such as 0.0.0.0:8181`},
		{"a port by its service name", "authz.public.addr", ":http",
			`AUTHZ_PUBLIC_ADDR=":http": expected <host>:<port>, with the host empty, an IP address, or a host name and the port from 0 to 65535, such as 0.0.0.0:8080`},
		{"a port with a plus sign", "authz.public.addr", ":+80",
			`AUTHZ_PUBLIC_ADDR=":+80": expected <host>:<port>, with the host empty, an IP address, or a host name and the port from 0 to 65535, such as 0.0.0.0:8080`},
		{"a space before the listen address", "authz.public.addr", " 0.0.0.0:8080",
			`AUTHZ_PUBLIC_ADDR=" 0.0.0.0:8080": expected <host>:<port>, with the host empty, an IP address, or a host name and the port from 0 to 65535, such as 0.0.0.0:8080`},
		{"an empty port", "authz.public.addr", "0.0.0.0:",
			`AUTHZ_PUBLIC_ADDR="0.0.0.0:": expected <host>:<port>, with the host empty, an IP address, or a host name and the port from 0 to 65535, such as 0.0.0.0:8080`},
		{"four numbers that are no IP address", "authz.public.addr", "999.1.1.1:8080",
			`AUTHZ_PUBLIC_ADDR="999.1.1.1:8080": expected <host>:<port>, with the host empty, an IP address, or a host name and the port from 0 to 65535, such as 0.0.0.0:8080`},
		{"a host name label that ends in a hyphen", "authz.http.addr", "agent-.local:8181",
			`AUTHZ_HTTP_ADDR="agent-.local:8181": expected <host>:<port>, with the host empty, an IP address, or a host name and the port from 0 to 65535, such as 0.0.0.0:8181`},
		{"a host name label that starts with a hyphen", "authz.http.addr", "-agent.local:8181",
			`AUTHZ_HTTP_ADDR="-agent.local:8181": expected <host>:<port>, with the host empty, an IP address, or a host name and the port from 0 to 65535, such as 0.0.0.0:8181`},
		{"a host name with an empty label", "authz.http.addr", "agent..local:8181",
			`AUTHZ_HTTP_ADDR="agent..local:8181": expected <host>:<port>, with the host empty, an IP address, or a host name and the port from 0 to 65535, such as 0.0.0.0:8181`},
		{"a URL without a scheme", "authz.tenant.manager.url", "tenant-manager:8080",
			`AUTHZ_TENANT_MANAGER_URL has no http or https scheme: expected an http or https URL with a host, a port from 1 to 65535 if it has one, and no user, query, or fragment, in the characters RFC 3986 allows`},
		{"a path with no scheme", "authz.outgoing.token.url", "/auth/realms/cloud-common/protocol/openid-connect/token",
			`AUTHZ_OUTGOING_TOKEN_URL has no http or https scheme: expected an http or https URL with a host, a port from 1 to 65535 if it has one, and no user, query, or fragment, in the characters RFC 3986 allows`},
		{"a URL with an empty host", "authz.outgoing.token.url", "http://:8080/token",
			`AUTHZ_OUTGOING_TOKEN_URL has no host: expected an http or https URL with a host, a port from 1 to 65535 if it has one, and no user, query, or fragment, in the characters RFC 3986 allows`},
		{"a URL of another scheme", "authz.pap.client.source.url", "ftp://authz-policy-admin",
			`AUTHZ_PAP_CLIENT_SOURCE_URL has no http or https scheme: expected an http or https URL with a host, a port from 1 to 65535 if it has one, and no user, query, or fragment, in the characters RFC 3986 allows`},
		{"a URL with a query", "authz.entitlements.url", "http://entitlements:8080?x=1",
			`AUTHZ_ENTITLEMENTS_URL has a query: expected an http or https URL with a host, a port from 1 to 65535 if it has one, and no user, query, or fragment, in the characters RFC 3986 allows`},
		{"a URL that ends in a fragment mark", "authz.tenant.manager.url", "http://tenant-manager:8080#",
			`AUTHZ_TENANT_MANAGER_URL has a fragment: expected an http or https URL with a host, a port from 1 to 65535 if it has one, and no user, query, or fragment, in the characters RFC 3986 allows`},
		{"a URL with a user and a password", "authz.tenant.manager.url", "http://user:s3cret@tenant-manager:8080",
			`AUTHZ_TENANT_MANAGER_URL has a user: expected an http or https URL with a host, a port from 1 to 65535 if it has one, and no user, query, or fragment, in the characters RFC 3986 allows`},
		{"a password before the host with no scheme", "authz.tenant.manager.url", "svc:s3cret@tenant-manager:8080",
			`AUTHZ_TENANT_MANAGER_URL has no http or https scheme: expected an http or https URL with a host, a port from 1 to 65535 if it has one, and no user, query, or fragment, in the characters RFC 3986 allows`},
		{"a URL port that is not a number", "authz.tenant.manager.url", "http://tenant-manager:abc",
			`AUTHZ_TENANT_MANAGER_URL does not parse as a URL: expected an http or https URL with a host, a port from 1 to 65535 if it has one, and no user, query, or fragment, in the characters RFC 3986 allows`},
		{"a URL port above 65535", "authz.tenant.manager.url", "http://tenant-manager:65536",
			`AUTHZ_TENANT_MANAGER_URL has a port outside 1 to 65535: expected an http or https URL with a host, a port from 1 to 65535 if it has one, and no user, query, or fragment, in the characters RFC 3986 allows`},
		{"URL port 0", "authz.outgoing.token.url", "https://idp:0/token",
			`AUTHZ_OUTGOING_TOKEN_URL has a port outside 1 to 65535: expected an http or https URL with a host, a port from 1 to 65535 if it has one, and no user, query, or fragment, in the characters RFC 3986 allows`},
		{"a space before a URL", "authz.entitlements.url", " http://entitlements:8080",
			`AUTHZ_ENTITLEMENTS_URL holds a space or another character outside RFC 3986: expected an http or https URL with a host, a port from 1 to 65535 if it has one, and no user, query, or fragment, in the characters RFC 3986 allows`},
		{"a space after a URL path", "authz.entitlements.url", "http://entitlements:8080/ ",
			`AUTHZ_ENTITLEMENTS_URL holds a space or another character outside RFC 3986: expected an http or https URL with a host, a port from 1 to 65535 if it has one, and no user, query, or fragment, in the characters RFC 3986 allows`},
		{"a space inside a URL path", "authz.pap.client.source.url", "http://authz-policy-admin:18090/a b",
			`AUTHZ_PAP_CLIENT_SOURCE_URL holds a space or another character outside RFC 3986: expected an http or https URL with a host, a port from 1 to 65535 if it has one, and no user, query, or fragment, in the characters RFC 3986 allows`},
		{"a letter outside ASCII in a URL path", "authz.entitlements.url", "http://entitlements:8080/caf\u00e9",
			`AUTHZ_ENTITLEMENTS_URL holds a space or another character outside RFC 3986: expected an http or https URL with a host, a port from 1 to 65535 if it has one, and no user, query, or fragment, in the characters RFC 3986 allows`},
		{"a URL of spaces", "authz.entitlements.url", "   ",
			`AUTHZ_ENTITLEMENTS_URL holds a space or another character outside RFC 3986: expected an http or https URL with a host, a port from 1 to 65535 if it has one, and no user, query, or fragment, in the characters RFC 3986 allows`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := refusal(t, map[string]string{tt.key: tt.value}); got != tt.want {
				t.Errorf("loadConfig() with %s=%q refused with %q, want %q", tt.key, tt.value, got, tt.want)
			}
		})
	}
}

func TestLoadConfig_ReadsAnAcceptedValue(t *testing.T) {
	for _, tt := range []struct {
		name, key, value string
		read             func(config) any
		want             any
	}{
		{"the minimum of a timeout", "authz.jwks.http.timeout", "1",
			func(c config) any { return c.Authn.HTTPTimeout }, time.Second},
		{"zero seconds where zero is allowed", "authz.pap.client.pull.interval", "0",
			func(c config) any { return c.Pull.Interval }, time.Duration(0)},
		{"the most seconds a duration holds", "authz.trusted.providers.reload.interval", "9223372036",
			func(c config) any { return c.Authn.ReloadInterval }, 9223372036 * time.Second},
		{"seconds with a plus sign", "authz.outgoing.renew.before.seconds", "+30",
			func(c config) any { return c.M2M.RenewBefore }, 30 * time.Second},
		{"the minimum of a count", "authz.jwks.http.retries", "1",
			func(c config) any { return c.Authn.HTTPRetries }, 1},
		{"the maximum of a count", "authz.jwks.http.retries", "100",
			func(c config) any { return c.Authn.HTTPRetries }, 100},
		{"false in capitals", "authz.jwks.bootstrap.required", "FALSE",
			func(c config) any { return c.Authn.Required }, false},
		{"true in mixed case", "authz.jwks.bootstrap.required", "True",
			func(c config) any { return c.Authn.Required }, true},
		{"port 0, which picks a free port", "authz.http.addr", "127.0.0.1:0",
			func(c config) any { return c.Addr }, "127.0.0.1:0"},
		{"the highest port with no host", "authz.public.addr", ":65535",
			func(c config) any { return c.PublicAddr }, ":65535"},
		{"an IPv6 listen address", "authz.public.addr", "[::1]:8080",
			func(c config) any { return c.PublicAddr }, "[::1]:8080"},
		{"a host name", "authz.http.addr", "localhost:8181",
			func(c config) any { return c.Addr }, "localhost:8181"},
		{"a host name of several labels", "authz.http.addr", "authz-agent.default.svc:8181",
			func(c config) any { return c.Addr }, "authz-agent.default.svc:8181"},
		{"an https URL with its scheme in capitals", "authz.tenant.manager.url", "HTTPS://tenant-manager.example.com",
			func(c config) any { return c.Authn.TenantManagerURL }, "HTTPS://tenant-manager.example.com"},
		{"a URL with the highest port", "authz.tenant.manager.url", "http://tenant-manager:65535",
			func(c config) any { return c.Authn.TenantManagerURL }, "http://tenant-manager:65535"},
		{"a URL with port 1", "authz.tenant.manager.url", "http://tenant-manager:1",
			func(c config) any { return c.Authn.TenantManagerURL }, "http://tenant-manager:1"},
		{"a URL with an IPv6 host", "authz.outgoing.token.url", "http://[::1]:8080/token",
			func(c config) any { return c.M2M.TokenURL }, "http://[::1]:8080/token"},
		{"a URL with a percent-encoded space in its path", "authz.pap.client.source.url", "http://authz-policy-admin:18090/a%20b",
			func(c config) any { return c.Pull.SourceURL }, "http://authz-policy-admin:18090/a%20b"},
		{"a host name that ends in a dot", "authz.public.addr", "localhost.:0",
			func(c config) any { return c.PublicAddr }, "localhost.:0"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.read(mustLoad(t, map[string]string{tt.key: tt.value})); got != tt.want {
				t.Errorf("loadConfig() with %s=%q read %v, want %v", tt.key, tt.value, got, tt.want)
			}
		})
	}
}

func TestLoadConfig_TakesALogLevelInCapitals(t *testing.T) {
	mustLoad(t, map[string]string{"logging.level.root": "INFO"})
}

func TestLoadConfig_RefusesLOG_LEVELBesideAValidRootLevel(t *testing.T) {
	got := refusal(t, map[string]string{"logging.level.root": "info", "log.level": "debug"})
	want := `LOG_LEVEL="debug": expected no value, since the agent reads the root log level from LOGGING_LEVEL_ROOT alone`
	if got != want {
		t.Errorf("loadConfig() with LOGGING_LEVEL_ROOT=info and LOG_LEVEL=debug refused with %q, want %q", got, want)
	}
}

func TestOtherRootLevelNames(t *testing.T) {
	for _, tt := range []struct {
		name    string
		environ []string
		want    []string
	}{
		{"log_level in lower case", []string{"log_level=debug"},
			[]string{`log_level="debug": expected no variable of this name, since the agent reads the root log level from LOGGING_LEVEL_ROOT alone`}},
		{"LOG_LEVEL spelled with dots and mixed case", []string{"Log.Level=debug"},
			[]string{`Log.Level="debug": expected no variable of this name, since the agent reads the root log level from LOGGING_LEVEL_ROOT alone`}},
		{"logging_level_root in lower case beside LOGGING_LEVEL_ROOT", []string{"LOGGING_LEVEL_ROOT=info", "logging_level_root=verbose"},
			[]string{`logging_level_root="verbose": expected no variable of this name, since the agent reads the root log level from LOGGING_LEVEL_ROOT alone`}},
		{"LOG_LEVEL and LOGGING_LEVEL_ROOT themselves", []string{"LOG_LEVEL=debug", "LOGGING_LEVEL_ROOT=info"}, nil},
		{"an empty log_level", []string{"log_level="},
			[]string{`log_level="": expected no variable of this name, since the agent reads the root log level from LOGGING_LEVEL_ROOT alone`}},
		{"a variable below LOGGING_LEVEL_ROOT", []string{"LOGGING_LEVEL_ROOT=info", "LOGGING_LEVEL_ROOT_X=1"},
			[]string{`LOGGING_LEVEL_ROOT_X="1": expected no variable of this name, since the agent reads the root log level from LOGGING_LEVEL_ROOT alone`}},
		{"package levels of the agent's logger", []string{"LOG_LEVEL_PACKAGE_AUTHZ-AGENT=info", "LOGGING_LEVEL_AUTHZ-AGENT=debug"}, nil},
		{"a variable below LOG_LEVEL", []string{"LOG_LEVEL_X=1"}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := otherRootLevelNames(tt.environ); !slices.Equal(got, tt.want) {
				t.Errorf("otherRootLevelNames(%q) = %q, want %q", tt.environ, got, tt.want)
			}
		})
	}
}

func TestLoadConfig_EmptyValuesTakeTheDefaults(t *testing.T) {
	empty := map[string]string{
		"authz.pap.client.token.file":             "",
		"authz.jwks.bootstrap.required":           "",
		"authz.jwks.http.timeout":                 "",
		"authz.jwks.http.retries":                 "",
		"authz.trusted.providers.reload.interval": "",
		"authz.pap.client.pull.interval":          "",
		"authz.outgoing.renew.before.seconds":     "",
		"authz.entitlements.http.timeout":         "",
		"authz.entitlements.http.retries":         "",
		"logging.level.root":                      "",
		"log.level":                               "",
		"authz.http.addr":                         "",
		"authz.public.addr":                       "",
		"authz.tenant.manager.url":                "",
		"authz.pap.client.source.url":             "",
		"authz.entitlements.url":                  "",
		"authz.outgoing.token.source":             "",
	}
	want, err := loadConfig(fromMap(map[string]string{"authz.outgoing.token.url": "http://idp/token"}))
	if err != nil {
		t.Fatalf("loadConfig() with a token endpoint alone error = %v, want none", err)
	}
	if got := mustLoad(t, empty); got != want {
		t.Errorf("loadConfig() with the variables empty = %+v, want the defaults %+v", got, want)
	}
}

func TestLoadConfig_RefusesEveryInvalidValueInOneError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	for _, tt := range []struct {
		name   string
		values map[string]string
		want   string
	}{
		{"a timeout and a log level", map[string]string{"authz.jwks.http.timeout": "0", "logging.level.root": "verbose"},
			`AUTHZ_JWKS_HTTP_TIMEOUT="0": expected an integer number of seconds from 1 to 9223372036; ` +
				`LOGGING_LEVEL_ROOT="verbose": expected one of debug, info, warn, error, fatal`},
		{"a timeout and no token endpoint", map[string]string{"authz.jwks.http.timeout": "0", "authz.outgoing.token.url": ""},
			`AUTHZ_JWKS_HTTP_TIMEOUT="0": expected an integer number of seconds from 1 to 9223372036; ` +
				missingEndpoint},
		{"a timeout and no token file with token-file",
			map[string]string{"authz.jwks.http.timeout": "0", "authz.outgoing.token.source": "token-file", "authz.pap.client.token.file": missing},
			`AUTHZ_JWKS_HTTP_TIMEOUT="0": expected an integer number of seconds from 1 to 9223372036; ` +
				`AUTHZ_PAP_CLIENT_TOKEN_FILE="` + missing + `": no such file or directory, and AUTHZ_OUTGOING_TOKEN_SOURCE=token-file sends the token in this file`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := refusal(t, tt.values); got != tt.want {
				t.Errorf("loadConfig(%v) refused with %q, want %q", tt.values, got, tt.want)
			}
		})
	}
}

func TestLoadConfig_PinsTheEntitlementsPIPOnlyWithAURL(t *testing.T) {
	for _, tt := range []struct {
		name   string
		values map[string]string
		want   *pips.EntitlementsConfig
	}{
		{"no URL", map[string]string{"authz.entitlements.http.timeout": "2"}, nil},
		{"an empty URL", map[string]string{"authz.entitlements.url": ""}, nil},
		{"a URL with a trailing slash", map[string]string{"authz.entitlements.url": "http://entitlements-mock:8080/"},
			&pips.EntitlementsConfig{URL: "http://entitlements-mock:8080", HTTPTimeoutSeconds: 5, HTTPRetries: 3}},
		{"a URL with its timeout and retries", map[string]string{
			"authz.entitlements.url":          "http://entitlements-mock:8080",
			"authz.entitlements.http.timeout": "2",
			"authz.entitlements.http.retries": "10",
		}, &pips.EntitlementsConfig{URL: "http://entitlements-mock:8080", HTTPTimeoutSeconds: 2, HTTPRetries: 10}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := mustLoad(t, tt.values).Pull.Entitlements; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("loadConfig(%v) entitlements = %+v, want %+v", tt.values, got, tt.want)
			}
		})
	}
}

func TestLoadConfig_TokenFileReadsTheTokenFileAlone(t *testing.T) {
	file := tokenFile(t)
	cfg := mustLoad(t, map[string]string{
		"authz.outgoing.token.source": "TOKEN-FILE",
		"authz.outgoing.token.url":    "http://idp/token",
		"authz.pap.client.token.file": file,
	})
	if cfg.M2M.TokenURL != "" || cfg.M2M.TokenFile != file {
		t.Errorf("loadConfig() with AUTHZ_OUTGOING_TOKEN_SOURCE=TOKEN-FILE took the token from %q and %q, want the file %q alone",
			cfg.M2M.TokenURL, cfg.M2M.TokenFile, file)
	}
}

func TestLoadConfig_ByDefaultAnUnsetTokenEndpointIsRefused(t *testing.T) {
	want := missingEndpoint
	if _, err := loadConfig(fromMap(map[string]string{})); err == nil || err.Error() != want {
		t.Errorf("loadConfig() with no variable set returned %v, want %q", err, want)
	}
}

func TestLoadConfig_TokenFileNeedsNoTokenEndpoint(t *testing.T) {
	file := tokenFile(t)
	cfg := mustLoad(t, map[string]string{
		"authz.outgoing.token.source": "token-file",
		"authz.outgoing.token.url":    "",
		"authz.pap.client.token.file": file,
	})
	if cfg.M2M.TokenURL != "" || cfg.M2M.TokenFile != file {
		t.Errorf("loadConfig() with AUTHZ_OUTGOING_TOKEN_SOURCE=token-file and no token endpoint took the token from %q and %q, want the file %q alone",
			cfg.M2M.TokenURL, cfg.M2M.TokenFile, file)
	}
}

func TestLoadConfig_ClientCredentialsReadsTheTokenEndpointAlone(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	for _, tt := range []struct {
		name   string
		values map[string]string
	}{
		{"unset", map[string]string{"authz.pap.client.token.file": missing}},
		{"client-credentials", map[string]string{"authz.outgoing.token.source": "client-credentials", "authz.pap.client.token.file": missing}},
		{"client-credentials in capitals", map[string]string{"authz.outgoing.token.source": "CLIENT-CREDENTIALS", "authz.pap.client.token.file": missing}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := mustLoad(t, tt.values).M2M.TokenURL; got != "http://idp/token" {
				t.Errorf("loadConfig(%v) took the token endpoint %q, want http://idp/token", tt.values, got)
			}
		})
	}
}

func TestLoadConfig_RefusesATokenSourceItCannotUse(t *testing.T) {
	directory := t.TempDir()
	missing := filepath.Join(directory, "missing")
	empty := fileHolding(t, "", 0o600)
	blank := fileHolding(t, " \n", 0o600)
	for _, tt := range []struct {
		name   string
		values map[string]string
		want   string
	}{
		{"no token endpoint with client-credentials, the default", map[string]string{"authz.outgoing.token.url": ""},
			missingEndpoint},
		{"a misspelled AUTHZ_OUTGOING_TOKEN_SOURCE and no token endpoint", map[string]string{"authz.outgoing.token.source": "tokenfile", "authz.outgoing.token.url": ""},
			`AUTHZ_OUTGOING_TOKEN_SOURCE="tokenfile": expected one of client-credentials, token-file`},
		{"a token endpoint without a scheme with client-credentials", map[string]string{"authz.outgoing.token.url": "idp/token"},
			`AUTHZ_OUTGOING_TOKEN_URL has no http or https scheme: expected an http or https URL with a host, a port from 1 to 65535 if it has one, and no user, query, or fragment, in the characters RFC 3986 allows`},
		{"a token endpoint without a scheme with token-file", map[string]string{"authz.outgoing.token.source": "token-file", "authz.outgoing.token.url": "idp/token"},
			`AUTHZ_OUTGOING_TOKEN_URL has no http or https scheme: expected an http or https URL with a host, a port from 1 to 65535 if it has one, and no user, query, or fragment, in the characters RFC 3986 allows`},
		{"no token file with token-file", map[string]string{"authz.outgoing.token.source": "token-file", "authz.pap.client.token.file": missing},
			`AUTHZ_PAP_CLIENT_TOKEN_FILE="` + missing + `": no such file or directory, and AUTHZ_OUTGOING_TOKEN_SOURCE=token-file sends the token in this file`},
		{"an empty token file with token-file", map[string]string{"authz.outgoing.token.source": "token-file", "authz.pap.client.token.file": empty},
			`AUTHZ_PAP_CLIENT_TOKEN_FILE="` + empty + `": holds no token, and AUTHZ_OUTGOING_TOKEN_SOURCE=token-file sends the token in this file`},
		{"a token file of white space alone with token-file", map[string]string{"authz.outgoing.token.source": "token-file", "authz.pap.client.token.file": blank},
			`AUTHZ_PAP_CLIENT_TOKEN_FILE="` + blank + `": holds no token, and AUTHZ_OUTGOING_TOKEN_SOURCE=token-file sends the token in this file`},
		{"a directory for the token file with token-file", map[string]string{"authz.outgoing.token.source": "token-file", "authz.pap.client.token.file": directory},
			`AUTHZ_PAP_CLIENT_TOKEN_FILE="` + directory + `": is not a regular file, and AUTHZ_OUTGOING_TOKEN_SOURCE=token-file sends the token in this file`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := refusal(t, tt.values); got != tt.want {
				t.Errorf("loadConfig(%v) refused with %q, want %q", tt.values, got, tt.want)
			}
		})
	}
}

func TestLoadConfig_TokenFileRefusesAFileItCannotRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file of mode 0000")
	}
	file := fileHolding(t, "token", 0o000)
	values := map[string]string{"authz.outgoing.token.source": "token-file", "authz.pap.client.token.file": file}
	want := `AUTHZ_PAP_CLIENT_TOKEN_FILE="` + file + `": permission denied, and AUTHZ_OUTGOING_TOKEN_SOURCE=token-file sends the token in this file`
	if got := refusal(t, values); got != want {
		t.Errorf("loadConfig(%v) refused with %q, want %q", values, got, want)
	}
}

func TestLoadConfig_TokenFileChecksTheDefaultPathForAnUnsetOrEmptyOne(t *testing.T) {
	if _, err := os.Stat(m2m.DefaultTokenFile); !errors.Is(err, fs.ErrNotExist) {
		t.Skipf("os.Stat(%s) = %v, and the refusal below expects no such file", m2m.DefaultTokenFile, err)
	}
	want := `AUTHZ_PAP_CLIENT_TOKEN_FILE="/var/run/secrets/tokens/netcracker/token": no such file or directory, and AUTHZ_OUTGOING_TOKEN_SOURCE=token-file sends the token in this file`
	for _, tt := range []struct {
		name   string
		values map[string]string
	}{
		{"unset", map[string]string{"authz.outgoing.token.source": "token-file"}},
		{"empty", map[string]string{"authz.outgoing.token.source": "token-file", "authz.pap.client.token.file": ""}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := loadConfig(fromMap(tt.values)); err == nil || err.Error() != want {
				t.Errorf("loadConfig(%v) returned %v, want %q", tt.values, err, want)
			}
		})
	}
}

// The chart passes its LOG_LEVEL value as LOGGING_LEVEL_ROOT and every other
// value under its own name. The test compares each value whose name loadConfig
// reads, and fails on a keyword or a type of its schema that it does not
// compare with the agent.
func TestLoadConfig_AgreesWithTheChartSchemaAtEachBound(t *testing.T) {
	checks := chartChecks(t)
	if len(checks) == 0 {
		t.Fatal("the chart schema checks no value that it passes to an agent variable")
	}
	for _, check := range checks {
		key := strings.ToLower(strings.ReplaceAll(check.variable, "_", "."))
		for _, value := range check.accepted {
			if _, err := load(t, map[string]string{key: value}); err != nil {
				t.Errorf("loadConfig() with %s=%q, which the chart schema accepts, refused it: %v", check.variable, value, err)
			}
		}
		for _, value := range check.refused {
			if _, err := load(t, map[string]string{key: value}); err == nil || !strings.Contains(err.Error(), check.variable+"=") {
				t.Errorf("loadConfig() with %s=%q, which the chart schema refuses, returned %v, want an error that names %s", check.variable, value, err, check.variable)
			}
		}
	}
}

// chartCheck is one variable whose value the chart's values schema checks,
// with values on both sides of each bound of the check.
type chartCheck struct {
	variable          string
	accepted, refused []string
}

// comparedKeywords are the keywords of a schema property that
// [TestLoadConfig_AgreesWithTheChartSchemaAtEachBound] compares with the
// agent, or that check nothing.
var comparedKeywords = map[string]bool{
	"$id": true, "title": true, "description": true, "default": true, "examples": true, "envSpecific": true, "internal": true,
	"type": true, "minimum": true, "maximum": true, "enum": true,
}

func chartChecks(t *testing.T) []chartCheck {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "helm-templates", "authz-agent", "values.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	read := agentVariables()
	var checks []chartCheck
	for name, property := range schema.Properties {
		variable, passed := chartVariable(name, read)
		if !passed {
			continue
		}
		if check, checked := boundValues(t, name, property); checked {
			check.variable = variable
			checks = append(checks, check)
		}
	}
	return checks
}

// agentVariables are the environment variables that loadConfig reads.
func agentVariables() map[string]bool {
	read := map[string]bool{}
	_, _ = loadConfig(func(key, fallback string) string {
		read[variable(key)] = true
		return fallback
	})
	return read
}

// chartVariable is the agent variable to which the chart passes the value
// name: LOGGING_LEVEL_ROOT for LOG_LEVEL, and name itself where read holds
// it. passed is false for any other value.
func chartVariable(name string, read map[string]bool) (variable string, passed bool) {
	switch {
	case name == "LOG_LEVEL":
		return "LOGGING_LEVEL_ROOT", true
	case read[name]:
		return name, true
	}
	return "", false
}

// boundValues are the values on both sides of each bound of property;
// checked is false for a property that a string type alone describes. A
// keyword or a type that the test does not compare fails it.
func boundValues(t *testing.T, name string, property map[string]json.RawMessage) (check chartCheck, checked bool) {
	t.Helper()
	for keyword := range property {
		if !comparedKeywords[keyword] {
			t.Errorf("%s: the chart schema checks it with %q, which this test does not compare with the agent", name, keyword)
		}
	}
	var kind string
	var minimum, maximum *int64
	var enum []string
	for keyword, into := range map[string]any{"type": &kind, "minimum": &minimum, "maximum": &maximum, "enum": &enum} {
		if value, ok := property[keyword]; ok {
			if err := json.Unmarshal(value, into); err != nil {
				t.Fatalf("%s: %s: %v", name, keyword, err)
			}
		}
	}
	switch {
	case kind == "integer":
		return integerBounds(minimum, maximum), true
	case kind == "boolean":
		return chartCheck{accepted: []string{"true", "false"}, refused: []string{"yes"}}, true
	case kind == "string" && len(enum) > 0:
		return chartCheck{accepted: enum, refused: []string{enum[0] + "x"}}, true
	case kind == "string":
		return chartCheck{}, false
	}
	t.Errorf("%s: the chart schema gives it the type %q, which this test does not compare with the agent", name, kind)
	return chartCheck{}, false
}

// integerBounds are the values on both sides of minimum and maximum, and a
// fraction, which no integer check accepts. Where the schema states no
// minimum, the agent has to accept -1, and where it states no maximum, the
// largest int64: the schema accepts both then.
func integerBounds(minimum, maximum *int64) chartCheck {
	check := chartCheck{refused: []string{"1.5"}}
	if minimum != nil {
		check.accepted = append(check.accepted, strconv.FormatInt(*minimum, 10))
		check.refused = append(check.refused, strconv.FormatInt(*minimum-1, 10))
	} else {
		check.accepted = append(check.accepted, "-1")
	}
	if maximum != nil {
		check.accepted = append(check.accepted, strconv.FormatInt(*maximum, 10))
		check.refused = append(check.refused, strconv.FormatInt(*maximum+1, 10))
	} else {
		check.accepted = append(check.accepted, "9223372036854775807")
	}
	return check
}
