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

// mustLoad is loadConfig over values; a refused value fails the test.
func mustLoad(t *testing.T, values map[string]string) config {
	t.Helper()
	cfg, err := loadConfig(fromMap(values))
	if err != nil {
		t.Fatalf("loadConfig(%v) error = %v, want none", values, err)
	}
	return cfg
}

// refusal is the error of loadConfig over values; a configuration that
// loadConfig accepts fails the test.
func refusal(t *testing.T, values map[string]string) string {
	t.Helper()
	_, err := loadConfig(fromMap(values))
	if err == nil {
		t.Fatalf("loadConfig(%v) error = nil, want a refusal", values)
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

// TestLoadConfig_LoopsOnTheServicesOwn: on its own the service runs every
// loop from its default place, and each key of the loops is read from its
// variable.
func TestLoadConfig_LoopsOnTheServicesOwn(t *testing.T) {
	cfg := mustLoad(t, map[string]string{})
	wantAuthn := authn.Config{File: "/etc/authz/trusted-providers.json", Required: true, HTTPTimeout: 5 * time.Second, HTTPRetries: 3,
		TenantManagerURL: "", ReloadInterval: 30 * time.Second}
	if cfg.Authn != wantAuthn {
		t.Errorf("default trusted providers = %+v, want %+v", cfg.Authn, wantAuthn)
	}
	wantPull := pull.Config{Interval: 30 * time.Second, HTTPTimeout: 30 * time.Second}
	if cfg.Pull != wantPull {
		t.Errorf("default pull = %+v, want %+v", cfg.Pull, wantPull)
	}
	wantM2M := m2m.Config{ClientIDFile: "/etc/secret/username", ClientSecretFile: "/etc/secret/password", RenewBefore: 60 * time.Second,
		TokenFile: "/var/run/secrets/tokens/netcracker/token", WatchInterval: 15 * time.Second}
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
	empty := map[string]string{
		"authz.jwks.bootstrap.required":           "",
		"authz.jwks.http.timeout":                 "",
		"authz.jwks.http.retries":                 "",
		"authz.trusted.providers.reload.interval": "",
		"authz.pap.client.pull.interval":          "",
		"authz.m2m.renew.before.seconds":          "",
		"authz.entitlements.http.timeout":         "",
		"authz.entitlements.http.retries":         "",
		"logging.level.root":                      "",
	}
	if got, want := mustLoad(t, empty), mustLoad(t, nil); got != want {
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

// The chart passes its LOG_LEVEL value as LOGGING_LEVEL_ROOT and each
// AUTHZ_ value under its own name. A keyword of the schema that this test
// does not compare with the agent fails it.
func TestLoadConfig_AgreesWithTheChartSchemaAtEachBound(t *testing.T) {
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
	compared := map[string]bool{
		"$id": true, "title": true, "description": true, "default": true, "examples": true, "envSpecific": true, "internal": true,
		"type": true, "minimum": true, "maximum": true, "enum": true,
	}
	checked := 0
	for name, property := range schema.Properties {
		variable := name
		switch {
		case name == "LOG_LEVEL":
			variable = "LOGGING_LEVEL_ROOT"
		case !strings.HasPrefix(name, "AUTHZ_"):
			continue
		}
		decode := func(keyword string, into any) {
			if value, ok := property[keyword]; ok {
				if err := json.Unmarshal(value, into); err != nil {
					t.Fatalf("%s: %s: %v", name, keyword, err)
				}
			}
		}
		var kind string
		var minimum, maximum *int64
		var enum []string
		decode("type", &kind)
		decode("minimum", &minimum)
		decode("maximum", &maximum)
		decode("enum", &enum)
		if kind != "integer" && kind != "boolean" && kind != "string" {
			continue
		}
		for keyword := range property {
			if !compared[keyword] {
				t.Errorf("%s: the chart schema checks it with %q, which this test does not compare with the agent", name, keyword)
			}
		}
		var accepted, refused []string
		switch {
		case kind == "integer":
			refused = append(refused, "1.5")
			if minimum != nil {
				accepted, refused = append(accepted, strconv.FormatInt(*minimum, 10)), append(refused, strconv.FormatInt(*minimum-1, 10))
			} else {
				accepted = append(accepted, "-1")
			}
			if maximum != nil {
				accepted, refused = append(accepted, strconv.FormatInt(*maximum, 10)), append(refused, strconv.FormatInt(*maximum+1, 10))
			}
		case kind == "boolean":
			accepted, refused = []string{"true", "false"}, []string{"yes"}
		case len(enum) > 0:
			accepted, refused = enum, []string{enum[0] + "x"}
		default:
			continue
		}
		checked++
		key := strings.ToLower(strings.ReplaceAll(variable, "_", "."))
		for _, value := range accepted {
			if _, err := loadConfig(fromMap(map[string]string{key: value})); err != nil {
				t.Errorf("loadConfig() with %s=%q, which the chart schema accepts, refused it: %v", variable, value, err)
			}
		}
		for _, value := range refused {
			if _, err := loadConfig(fromMap(map[string]string{key: value})); err == nil || !strings.Contains(err.Error(), variable+"=") {
				t.Errorf("loadConfig() with %s=%q, which the chart schema refuses, returned %v, want an error that names %s", variable, value, err, variable)
			}
		}
	}
	if checked == 0 {
		t.Fatal("the chart schema has no checked AUTHZ_ value and no LOG_LEVEL")
	}
}
