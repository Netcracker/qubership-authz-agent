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
	"strconv"
	"strings"
	"testing"
	"time"

	"authz-agent/components/authz-agent/internal/authn"
	"authz-agent/components/authz-agent/internal/m2m"
	"authz-agent/components/authz-agent/internal/pull"
	"authz-agent/internal/regobuiltins"
)

// mustLoad is loadConfig over values, failing the test on an error.
func mustLoad(t *testing.T, values map[string]string) config {
	t.Helper()
	cfg, err := loadConfig(fromMap(values))
	if err != nil {
		t.Fatalf("loadConfig(%v): %v", values, err)
	}
	return cfg
}

func fromMap(values map[string]string) lookup {
	return func(key, fallback string) string {
		if v, ok := values[key]; ok {
			return v
		}
		return fallback
	}
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
// loop from its default place, and each key of the loops is read with the
// spellings the pap-client accepted.
func TestLoadConfig_LoopsOnTheServicesOwn(t *testing.T) {
	cfg := mustLoad(t, map[string]string{})
	wantAuthn := authn.Config{File: "/etc/authz/trusted-providers.json", Required: true, HTTPTimeout: 5 * time.Second, HTTPRetries: 3,
		TenantManagerURL: "http://tenant-manager:8080", ReloadInterval: 30 * time.Second}
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
		"authz.jwks.bootstrap.required":           "off",
		"authz.jwks.http.timeout":                 "2",
		"authz.jwks.http.retries":                 "20",
		"authz.trusted.providers.reload.interval": "0",
		"authz.tenant.manager.url":                "",
		"authz.pap.client.source.url":             "http://policy-admin:18090/",
		"authz.pap.client.pull.interval":          "2",
		"authz.pap.client.token.file":             "/t",
		"authz.m2m.token.url":                     "http://idp/token",
		"authz.m2m.client.id.file":                "/id",
		"authz.m2m.client.secret.file":            "/secret",
		"authz.m2m.renew.before.seconds":          "30",
	})
	if cfg.Authn.File != "/p.json" || cfg.Authn.Required || cfg.Authn.HTTPTimeout != 2*time.Second || cfg.Authn.HTTPRetries != 20 ||
		cfg.Authn.ReloadInterval != 0 || cfg.Authn.TenantManagerURL != "" {
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

// TestLoadConfig_RefusesAValueItsKeyDoesNotAccept: a value outside what its
// variable accepts fails the start, and the error names the variable and
// the value.
func TestLoadConfig_RefusesAValueItsKeyDoesNotAccept(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"authz.pip.timeout", "0"},
		{"authz.pip.timeout", "00"},
		{"authz.pip.timeout", "-1"},
		{"authz.pip.timeout", "9223372037"},
		{"authz.jwks.http.timeout", "soon"},
		{"authz.jwks.http.timeout", "0"},
		{"authz.jwks.http.retries", "0"},
		{"authz.jwks.http.retries", "2147483648"},
		{"authz.jwks.bootstrap.required", "maybe"},
		{"authz.jwks.bootstrap.required", ""},
		{"authz.pap.client.pull.interval", "-1"},
		{"authz.trusted.providers.reload.interval", "1.5"},
		{"authz.m2m.renew.before.seconds", "-1"},
		{"authz.default.tenant", ""},
		{"authz.default.tenant", "  "},
		{"authz.http.addr", ""},
		{"authz.http.addr", "8181"},
		{"authz.public.addr", "0.0.0.0:0"},
		{"authz.public.addr", "0.0.0.0:65536"},
		{"authz.public.addr", "0.0.0.0:http"},
		{"authz.m2m.client.id.file", ""},
		{"authz.m2m.client.secret.file", ""},
		{"authz.entitlements.url", "ent:8080"},
		{"authz.tenant.manager.url", "ftp://tenant-manager"},
		{"authz.pap.client.source.url", "http://"},
		{"authz.m2m.token.url", "/auth/realms/x/protocol/openid-connect/token"},
		{"logging.level.root", "verbose"},
		{"logging.level.root", " debug"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			_, err := loadConfig(fromMap(map[string]string{tc.key: tc.value}))
			value := tc.value
			if tc.key != "logging.level.root" {
				value = strings.TrimSpace(value)
			}
			want := envName(tc.key) + " is " + strconv.Quote(value) + "; expected "
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("loadConfig with %s=%q: error %v, want one containing %q", envName(tc.key), tc.value, err, want)
			}
		})
	}
}

// TestLoadConfig_AcceptsTheBoundsOfEachKind: the smallest and the largest
// value each kind of setting accepts, and the empty value where it switches
// a feature off.
func TestLoadConfig_AcceptsTheBoundsOfEachKind(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"authz.pip.timeout", "1"},
		{"authz.pip.timeout", "9223372036"},
		{"authz.pap.client.pull.interval", "0"},
		{"authz.trusted.providers.reload.interval", "0"},
		{"authz.m2m.renew.before.seconds", "0"},
		{"authz.jwks.http.retries", "1"},
		{"authz.jwks.http.retries", "2147483647"},
		{"authz.jwks.bootstrap.required", "OFF"},
		{"authz.http.addr", ":1"},
		{"authz.http.addr", "[::1]:65535"},
		{"authz.trusted.providers.file", ""},
		{"authz.pap.client.token.file", ""},
		{"authz.tenant.manager.url", ""},
		{"authz.entitlements.url", "https://ent"},
		{"logging.level.root", "DEBUG"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			if _, err := loadConfig(fromMap(map[string]string{tc.key: tc.value})); err != nil {
				t.Errorf("loadConfig with %s=%q: %v, want no error", envName(tc.key), tc.value, err)
			}
		})
	}
}

// TestLoadConfig_NamesEveryRefusedVariable: one failed start reports every
// variable at fault, not only the first one read.
func TestLoadConfig_NamesEveryRefusedVariable(t *testing.T) {
	_, err := loadConfig(fromMap(map[string]string{
		"authz.pip.timeout":    "0",
		"authz.default.tenant": "",
	}))
	for _, want := range []string{`AUTHZ_PIP_TIMEOUT is "0"`, `AUTHZ_DEFAULT_TENANT is ""`} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("loadConfig error %v, want one containing %s", err, want)
		}
	}
}

// TestLoadConfig_DecisionPath: the default tenant, the timeout of a PIP
// call, and the entitlements service, each by default and from the
// environment.
func TestLoadConfig_DecisionPath(t *testing.T) {
	cfg := mustLoad(t, map[string]string{})
	if cfg.DefaultTenant != "default" || cfg.PIPTimeout != regobuiltins.DefaultTimeout || cfg.EntitlementsURL != "" {
		t.Errorf("defaults: tenant %q, timeout %v, entitlements %q; want default, %v, none",
			cfg.DefaultTenant, cfg.PIPTimeout, cfg.EntitlementsURL, regobuiltins.DefaultTimeout)
	}
	cfg = mustLoad(t, map[string]string{
		"authz.default.tenant":   " acme ",
		"authz.pip.timeout":      "5",
		"authz.entitlements.url": " http://ent:8080 ",
	})
	if cfg.DefaultTenant != "acme" || cfg.PIPTimeout != 5*time.Second || cfg.EntitlementsURL != "http://ent:8080" {
		t.Errorf("from env: tenant %q, timeout %v, entitlements %q; want acme, 5s, http://ent:8080",
			cfg.DefaultTenant, cfg.PIPTimeout, cfg.EntitlementsURL)
	}
}
