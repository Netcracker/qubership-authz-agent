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
	"os"
	"path/filepath"
	"reflect"
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

// tokenFile is the path of a token file that exists.
func tokenFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("token"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// load is loadConfig over values with a token endpoint and an existing token
// file added, so that either value of KUBERNETES_M2M_ENABLED loads; a key of
// values replaces the added one.
func load(t *testing.T, values map[string]string) (config, error) {
	t.Helper()
	merged := map[string]string{"authz.m2m.token.url": "http://idp/token", "authz.pap.client.token.file": tokenFile(t)}
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
// it needs, the service runs every loop from its default place, and each key
// of the loops is read from its variable.
func TestLoadConfig_LoopsOnTheServicesOwn(t *testing.T) {
	cfg, err := loadConfig(fromMap(map[string]string{"authz.m2m.token.url": "http://idp/token"}))
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
		"authz.m2m.token.url":                     "http://idp/token",
		"authz.m2m.client.id.file":                "/id",
		"authz.m2m.client.secret.file":            "/secret",
		"authz.m2m.renew.before.seconds":          "30",
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
		{"negative seconds", "authz.m2m.renew.before.seconds", "-1",
			`AUTHZ_M2M_RENEW_BEFORE_SECONDS="-1": expected an integer number of seconds from 0 to 9223372036`},
		{"more seconds than a duration holds", "authz.pap.client.pull.interval", "9223372037",
			`AUTHZ_PAP_CLIENT_PULL_INTERVAL="9223372037": expected an integer number of seconds from 0 to 9223372036`},
		{"an entitlements timeout without an entitlements URL", "authz.entitlements.http.timeout", "0",
			`AUTHZ_ENTITLEMENTS_HTTP_TIMEOUT="0": expected an integer number of seconds from 1 to 9223372036`},
		{"a count below the minimum", "authz.jwks.http.retries", "0",
			`AUTHZ_JWKS_HTTP_RETRIES="0": expected an integer of at least 1`},
		{"a count in words", "authz.entitlements.http.retries", "three",
			`AUTHZ_ENTITLEMENTS_HTTP_RETRIES="three": expected an integer of at least 1`},
		{"yes for a boolean", "authz.jwks.bootstrap.required", "yes",
			`AUTHZ_JWKS_BOOTSTRAP_REQUIRED="yes": expected true or false`},
		{"1 for a boolean", "authz.jwks.bootstrap.required", "1",
			`AUTHZ_JWKS_BOOTSTRAP_REQUIRED="1": expected true or false`},
		{"a misspelled boolean", "authz.jwks.bootstrap.required", "ture",
			`AUTHZ_JWKS_BOOTSTRAP_REQUIRED="ture": expected true or false`},
		{"an unknown log level", "logging.level.root", "verbose",
			`LOGGING_LEVEL_ROOT="verbose": expected one of debug, info, warn, error, fatal`},
		{"a space before the log level", "logging.level.root", " info",
			`LOGGING_LEVEL_ROOT=" info": expected one of debug, info, warn, error, fatal`},
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
		{"seconds with a plus sign", "authz.m2m.renew.before.seconds", "+30",
			func(c config) any { return c.M2M.RenewBefore }, 30 * time.Second},
		{"the minimum of a count", "authz.jwks.http.retries", "1",
			func(c config) any { return c.Authn.HTTPRetries }, 1},
		{"false in capitals", "authz.jwks.bootstrap.required", "FALSE",
			func(c config) any { return c.Authn.Required }, false},
		{"true in mixed case", "authz.jwks.bootstrap.required", "True",
			func(c config) any { return c.Authn.Required }, true},
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

func TestLoadConfig_EmptyValuesTakeTheDefaults(t *testing.T) {
	// load adds a new token file on each call, so both calls name this one.
	file := tokenFile(t)
	empty := map[string]string{
		"authz.pap.client.token.file":             file,
		"authz.jwks.bootstrap.required":           "",
		"authz.jwks.http.timeout":                 "",
		"authz.jwks.http.retries":                 "",
		"authz.trusted.providers.reload.interval": "",
		"authz.pap.client.pull.interval":          "",
		"authz.m2m.renew.before.seconds":          "",
		"authz.entitlements.http.timeout":         "",
		"authz.entitlements.http.retries":         "",
		"logging.level.root":                      "",
		"kubernetes.m2m.enabled":                  "",
	}
	if got, want := mustLoad(t, empty), mustLoad(t, map[string]string{"authz.pap.client.token.file": file}); got != want {
		t.Errorf("loadConfig() with the variables empty = %+v, want the defaults %+v", got, want)
	}
}

func TestLoadConfig_RefusesEveryInvalidValueInOneError(t *testing.T) {
	got := refusal(t, map[string]string{"authz.jwks.http.timeout": "0", "logging.level.root": "verbose"})
	want := `AUTHZ_JWKS_HTTP_TIMEOUT="0": expected an integer number of seconds from 1 to 9223372036; ` +
		`LOGGING_LEVEL_ROOT="verbose": expected one of debug, info, warn, error, fatal`
	if got != want {
		t.Errorf("loadConfig() with two invalid values refused with %q, want %q", got, want)
	}
}

func TestLoadConfig_PinsTheEntitlementsPIPOnlyWithAURL(t *testing.T) {
	for _, tt := range []struct {
		name   string
		values map[string]string
		want   *pips.EntitlementsConfig
	}{
		{"no URL", map[string]string{"authz.entitlements.http.timeout": "2"}, nil},
		{"a blank URL", map[string]string{"authz.entitlements.url": "   "}, nil},
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

func TestLoadConfig_KubernetesM2MReadsTheTokenFileAlone(t *testing.T) {
	file := tokenFile(t)
	cfg := mustLoad(t, map[string]string{
		"kubernetes.m2m.enabled":      "TRUE",
		"authz.m2m.token.url":         "http://idp/token",
		"authz.pap.client.token.file": file,
	})
	if cfg.M2M.TokenURL != "" || cfg.M2M.TokenFile != file {
		t.Errorf("loadConfig() with KUBERNETES_M2M_ENABLED=TRUE took the token from %q and %q, want the file %q alone",
			cfg.M2M.TokenURL, cfg.M2M.TokenFile, file)
	}
}

func TestLoadConfig_WithoutKubernetesM2MTheTokenEndpointAloneIsRead(t *testing.T) {
	cfg := mustLoad(t, map[string]string{
		"authz.m2m.token.url":         "http://idp/token",
		"authz.pap.client.token.file": filepath.Join(t.TempDir(), "missing"),
	})
	if cfg.M2M.TokenURL != "http://idp/token" {
		t.Errorf("loadConfig() without KUBERNETES_M2M_ENABLED took the token endpoint %q, want http://idp/token", cfg.M2M.TokenURL)
	}
}

func TestLoadConfig_RefusesATokenSourceItCannotUse(t *testing.T) {
	directory := t.TempDir()
	missing := filepath.Join(directory, "missing")
	for _, tt := range []struct {
		name   string
		values map[string]string
		want   string
	}{
		{"no token endpoint without KUBERNETES_M2M_ENABLED", map[string]string{"authz.m2m.token.url": ""},
			`AUTHZ_M2M_TOKEN_URL="": expected the token endpoint of the agent's realm, which KUBERNETES_M2M_ENABLED=false, the default, requires`},
		{"a misspelled KUBERNETES_M2M_ENABLED and no token endpoint", map[string]string{"kubernetes.m2m.enabled": "ture", "authz.m2m.token.url": ""},
			`KUBERNETES_M2M_ENABLED="ture": expected true or false`},
		{"no token file with KUBERNETES_M2M_ENABLED", map[string]string{"kubernetes.m2m.enabled": "true", "authz.pap.client.token.file": missing},
			`AUTHZ_PAP_CLIENT_TOKEN_FILE="` + missing + `": no such file or directory, and KUBERNETES_M2M_ENABLED=true sends the token in this file`},
		{"an empty token file with KUBERNETES_M2M_ENABLED", map[string]string{"kubernetes.m2m.enabled": "true", "authz.pap.client.token.file": ""},
			`AUTHZ_PAP_CLIENT_TOKEN_FILE="": no such file or directory, and KUBERNETES_M2M_ENABLED=true sends the token in this file`},
		{"a directory for the token file with KUBERNETES_M2M_ENABLED", map[string]string{"kubernetes.m2m.enabled": "true", "authz.pap.client.token.file": directory},
			`AUTHZ_PAP_CLIENT_TOKEN_FILE="` + directory + `": is a directory, and KUBERNETES_M2M_ENABLED=true sends the token in this file`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := refusal(t, tt.values); got != tt.want {
				t.Errorf("loadConfig(%v) refused with %q, want %q", tt.values, got, tt.want)
			}
		})
	}
}

// The chart passes its LOG_LEVEL value as LOGGING_LEVEL_ROOT, and
// KUBERNETES_M2M_ENABLED and each AUTHZ_ value under its own name. A keyword of the schema that this test
// does not compare with the agent fails it.
func TestLoadConfig_AgreesWithTheChartSchemaAtEachBound(t *testing.T) {
	checks := chartChecks(t)
	if len(checks) == 0 {
		t.Fatal("the chart schema has no checked AUTHZ_ value, no KUBERNETES_M2M_ENABLED, and no LOG_LEVEL")
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
	var checks []chartCheck
	for name, property := range schema.Properties {
		variable, passed := chartVariable(name)
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

// chartVariable is the environment variable to which the chart passes the
// value name; passed is false for a value the chart passes to no variable
// of the agent.
func chartVariable(name string) (variable string, passed bool) {
	switch {
	case name == "LOG_LEVEL":
		return "LOGGING_LEVEL_ROOT", true
	case name == "KUBERNETES_M2M_ENABLED", strings.HasPrefix(name, "AUTHZ_"):
		return name, true
	}
	return "", false
}

// boundValues are the values on both sides of each bound of property;
// checked is false for a property that is not a scalar or that a string
// type alone describes.
func boundValues(t *testing.T, name string, property map[string]json.RawMessage) (check chartCheck, checked bool) {
	t.Helper()
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
	if kind != "integer" && kind != "boolean" && kind != "string" {
		return chartCheck{}, false
	}
	for keyword := range property {
		if !comparedKeywords[keyword] {
			t.Errorf("%s: the chart schema checks it with %q, which this test does not compare with the agent", name, keyword)
		}
	}
	switch {
	case kind == "integer":
		return integerBounds(minimum, maximum), true
	case kind == "boolean":
		return chartCheck{accepted: []string{"true", "false"}, refused: []string{"yes"}}, true
	case len(enum) > 0:
		return chartCheck{accepted: enum, refused: []string{enum[0] + "x"}}, true
	}
	return chartCheck{}, false
}

// integerBounds are the values on both sides of minimum and maximum, either
// of which may be absent, and a fraction, which no integer check accepts.
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
	}
	return check
}
