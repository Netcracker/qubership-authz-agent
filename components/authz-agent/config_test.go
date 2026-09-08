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
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"authz-agent/components/authz-agent/internal/authn"
	"authz-agent/components/authz-agent/internal/m2m"
	"authz-agent/components/authz-agent/internal/pull"
)

func fromMap(values map[string]string) lookup {
	return func(key, fallback string) string {
		if v, ok := values[key]; ok {
			return v
		}
		return fallback
	}
}

// TestLoadConfig_EnvironmentOnly: without OPA arguments the settings come
// from the environment keys, with the service defaults behind them.
func TestLoadConfig_EnvironmentOnly(t *testing.T) {
	cfg, err := loadConfig(nil, fromMap(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != "0.0.0.0:8181" || cfg.PublicAddr != "0.0.0.0:8080" || cfg.PapClientURL != "" {
		t.Fatalf("default addresses: %+v", cfg)
	}
	if cfg.Authorization || cfg.DecisionLogs.URL != "" || len(cfg.DataDirs) != 0 {
		t.Fatalf("defaults: %+v", cfg)
	}
	cfg, err = loadConfig(nil, fromMap(map[string]string{
		"authz.http.addr":              ":9090",
		"authz.public.addr":            ":9091",
		"authz.pap.client.url":         "http://pap-client:8182",
		"authz.data.dirs":              "/a, /b",
		"authz.data.ignore":            "..*",
		"authz.data.api.authorization": "true",
		"authz.decision.log.url":       "http://collector:8183",
		"authz.decision.log.headers":   "x-request-id,x-authz-original-path",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != ":9090" || cfg.PublicAddr != ":9091" || cfg.PapClientURL != "http://pap-client:8182" {
		t.Fatalf("addresses from env: %+v", cfg)
	}
	if !cfg.Authorization || len(cfg.DataDirs) != 2 || cfg.Ignore[0] != "..*" {
		t.Fatalf("env values: %+v", cfg)
	}
	if cfg.DecisionLogs.URL != "http://collector:8183" || len(cfg.DecisionLogs.Headers) != 2 || cfg.DecisionLogs.Labels["id"] != "authz-agent" {
		t.Fatalf("decision logs from env: %+v", cfg.DecisionLogs)
	}
}

// TestLoadConfig_LoopsOnTheServicesOwn: on its own the service runs every
// loop from its default place, and each key of the loops is read with the
// spellings the pap-client accepted.
func TestLoadConfig_LoopsOnTheServicesOwn(t *testing.T) {
	cfg, err := loadConfig(nil, fromMap(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	wantAuthn := authn.Config{File: "/etc/authz/trusted-providers.json", Required: true, HTTPTimeout: 5 * time.Second, HTTPRetries: 3,
		TenantManagerURL: "http://tenant-manager:8080", ReloadInterval: 30 * time.Second}
	if cfg.StandIn || cfg.Authn != wantAuthn {
		t.Errorf("default trusted providers = %+v, want %+v", cfg.Authn, wantAuthn)
	}
	wantPull := pull.Config{Interval: 30 * time.Second, MountDir: "/etc/authz/policies", HTTPTimeout: 30 * time.Second}
	if cfg.Pull != wantPull {
		t.Errorf("default pull = %+v, want %+v", cfg.Pull, wantPull)
	}
	wantM2M := m2m.Config{ClientIDFile: "/etc/secret/username", ClientSecretFile: "/etc/secret/password", RenewBefore: 60 * time.Second,
		TokenFile: "/etc/authz/ac-token/token", WatchInterval: 15 * time.Second}
	if cfg.M2M != wantM2M {
		t.Errorf("default m2m = %+v, want %+v", cfg.M2M, wantM2M)
	}
	if cfg.OPAAuthTokenFile != "" || cfg.DecisionLogFile != "" {
		t.Errorf("default secret file %q and decision log file %q, want none", cfg.OPAAuthTokenFile, cfg.DecisionLogFile)
	}
	cfg, err = loadConfig(nil, fromMap(map[string]string{
		"authz.trusted.providers.file":            "/p.json",
		"authz.jwks.bootstrap.required":           "off",
		"authz.jwks.http.timeout":                 "2",
		"authz.jwks.http.retries":                 "20",
		"authz.trusted.providers.reload.interval": "0",
		"authz.tenant.manager.url":                "",
		"authz.pap.client.source.url":             "http://policy-admin:18090/",
		"authz.pap.client.pull.interval":          "2",
		"authz.policy.mount.dir":                  "/mount",
		"authz.pap.client.token.file":             "/t",
		"authz.m2m.token.url":                     "http://idp/token",
		"authz.m2m.client.id.file":                "/id",
		"authz.m2m.client.secret.file":            "/secret",
		"authz.m2m.renew.before.seconds":          "30",
		"authz.opa.auth.token.file":               "/opa-token",
		"authz.decision.log.file":                 "/var/log/authz/decision-logs.jsonl",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Authn.File != "/p.json" || cfg.Authn.Required || cfg.Authn.HTTPTimeout != 2*time.Second || cfg.Authn.HTTPRetries != 20 ||
		cfg.Authn.ReloadInterval != 0 || cfg.Authn.TenantManagerURL != "" {
		t.Errorf("trusted providers from env = %+v", cfg.Authn)
	}
	if cfg.Pull.SourceURL != "http://policy-admin:18090" || cfg.Pull.Interval != 2*time.Second || cfg.Pull.MountDir != "/mount" {
		t.Errorf("pull from env = %+v", cfg.Pull)
	}
	if cfg.M2M.TokenURL != "http://idp/token" || cfg.M2M.ClientIDFile != "/id" || cfg.M2M.ClientSecretFile != "/secret" ||
		cfg.M2M.RenewBefore != 30*time.Second || cfg.M2M.TokenFile != "/t" {
		t.Errorf("m2m from env = %+v", cfg.M2M)
	}
	if cfg.OPAAuthTokenFile != "/opa-token" || cfg.DecisionLogFile != "/var/log/authz/decision-logs.jsonl" {
		t.Errorf("secret file %q and decision log file %q from env", cfg.OPAAuthTokenFile, cfg.DecisionLogFile)
	}
}

// TestLoadConfig_MalformedNumbersKeepTheDefaults: a duration, a count, or
// a flag that does not parse keeps its default rather than switching a
// loop off.
func TestLoadConfig_MalformedNumbersKeepTheDefaults(t *testing.T) {
	cfg, err := loadConfig(nil, fromMap(map[string]string{
		"authz.jwks.http.timeout":        "soon",
		"authz.jwks.http.retries":        "0",
		"authz.jwks.bootstrap.required":  "maybe",
		"authz.pap.client.pull.interval": "-1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Authn.HTTPTimeout != authn.DefaultHTTPTimeout || cfg.Authn.HTTPRetries != authn.DefaultHTTPRetries || !cfg.Authn.Required || cfg.Pull.Interval != pull.DefaultInterval {
		t.Errorf("malformed values: %+v %+v, want the defaults", cfg.Authn, cfg.Pull)
	}
}

// TestLoadConfig_StandInLeavesTheLoopsToThePod: under OPA's command line
// the trusted providers and the token file default to off, since the Pod's
// other containers run them, and the environment can still turn them on;
// the policy pull is off whatever the environment says.
func TestLoadConfig_StandInLeavesTheLoopsToThePod(t *testing.T) {
	cfg, err := loadConfig([]string{"run", "--addr=:1"}, fromMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.StandIn || cfg.Authn.File != "" || cfg.M2M.TokenFile != "" || cfg.M2M.TokenURL != "" || cfg.Pull != (pull.Config{}) {
		t.Errorf("stand-in loops = providers %q token file %q token URL %q pull %+v, want all off", cfg.Authn.File, cfg.M2M.TokenFile, cfg.M2M.TokenURL, cfg.Pull)
	}
	cfg, err = loadConfig([]string{"run", "--addr=:1"}, fromMap(map[string]string{
		"authz.trusted.providers.file": "/p.json",
		"authz.pap.client.source.url":  "http://source",
		"authz.policy.mount.dir":       "/mount",
		"authz.pap.client.token.file":  "/t",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Authn.File != "/p.json" || cfg.M2M.TokenFile != "/t" || cfg.Pull != (pull.Config{}) {
		t.Errorf("stand-in loops from env = providers %q token file %q pull %+v, want the providers and the token file on and the pull off", cfg.Authn.File, cfg.M2M.TokenFile, cfg.Pull)
	}
}

// TestLoadConfig_OPAArguments: the chart's OPA command line maps onto the
// same settings, including the decision log target from the OPA config
// file, and brings the stand-in defaults for the public surface and the
// pap-client relay.
func TestLoadConfig_OPAArguments(t *testing.T) {
	dir := t.TempDir()
	opaConfig := filepath.Join(dir, "opa-config.yaml")
	if err := os.WriteFile(opaConfig, []byte(`decision_logs:
  service: decision-log-collector
  request_context:
    http:
      headers:
        - x-request-id
services:
  decision-log-collector:
    url: http://127.0.0.1:8183
`), 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"run", "--server", "--addr", "0.0.0.0:8181", "--ignore=..*", "--authorization=basic",
		"--authentication=token", "--log-level", "debug", "--config-file", opaConfig, "/etc/opa/policies", "/etc/opa/data"}
	cfg, err := loadConfig(args, fromMap(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != "0.0.0.0:8181" || !cfg.Authorization || cfg.Ignore[0] != "..*" {
		t.Fatalf("flags: %+v", cfg)
	}
	if cfg.PublicAddr != "0.0.0.0:8280" || cfg.PapClientURL != "http://127.0.0.1:8182" {
		t.Fatalf("stand-in defaults for the chart's Pod: public=%q pap-client=%q", cfg.PublicAddr, cfg.PapClientURL)
	}
	if len(cfg.DataDirs) != 2 || cfg.DataDirs[1] != "/etc/opa/data" {
		t.Fatalf("data directories = %v, want the two positional arguments; a flag's value must not become one", cfg.DataDirs)
	}
	if cfg.DecisionLogs.URL != "http://127.0.0.1:8183" || cfg.DecisionLogs.Headers[0] != "x-request-id" || cfg.DecisionLogs.Labels["id"] != "authz-agent" {
		t.Fatalf("decision logs from the OPA config: %+v", cfg.DecisionLogs)
	}
}

// TestLoadConfig_OPAArgumentsKeepTheEnvironmentsAddresses: under OPA's
// command line the stand-in defaults yield to a public address and a
// pap-client URL set in the environment.
func TestLoadConfig_OPAArgumentsKeepTheEnvironmentsAddresses(t *testing.T) {
	cfg, err := loadConfig([]string{"run", "--addr=:1"}, fromMap(map[string]string{
		"authz.public.addr":    ":2",
		"authz.pap.client.url": "http://pap-client:9",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != ":1" || cfg.PublicAddr != ":2" || cfg.PapClientURL != "http://pap-client:9" {
		t.Fatalf("addresses = %q %q %q, want :1 :2 http://pap-client:9", cfg.Addr, cfg.PublicAddr, cfg.PapClientURL)
	}
}

// TestLoadConfig_RejectsUnknownFlagAndBrokenConfig: an OPA flag the service
// does not honor fails loudly instead of silently changing behavior, and so
// does a decision log service without a URL.
func TestLoadConfig_RejectsUnknownFlagAndBrokenConfig(t *testing.T) {
	if _, err := loadConfig([]string{"run", "--watch"}, fromMap(nil)); err == nil {
		t.Fatal("unknown flag must fail")
	}
	dir := t.TempDir()
	broken := filepath.Join(dir, "opa.yaml")
	if err := os.WriteFile(broken, []byte("decision_logs:\n  service: gone\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig([]string{"run", "--config-file", broken}, fromMap(nil)); err == nil {
		t.Fatal("service without URL must fail")
	}
	if _, err := loadConfig([]string{"run", "--config-file", filepath.Join(dir, "missing.yaml")}, fromMap(nil)); err == nil {
		t.Fatal("missing config file must fail")
	}
	if _, err := loadConfig([]string{"run", "--config-file", broken + ".bad"}, fromMap(nil)); err == nil {
		t.Fatal("unreadable config must fail")
	}
	noLogs := filepath.Join(dir, "nologs.yaml")
	if err := os.WriteFile(noLogs, []byte("nd_builtin_cache: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig([]string{"run", "--config-file=" + noLogs, "--addr=:1"}, fromMap(nil))
	if err != nil || cfg.DecisionLogs.URL != "" || cfg.Addr != ":1" {
		t.Fatalf("config without decision logs: %+v err=%v", cfg, err)
	}
}

// TestLoadConfig_OPAReporting: the reporting bounds of the OPA config
// become the upload's interval and size limit, nd_builtin_cache decides
// whether the builtin calls are recorded, and every setting the service
// does not read is named.
func TestLoadConfig_OPAReporting(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "opa-config.yaml")
	if err := os.WriteFile(file, []byte(`nd_builtin_cache: true
decision_logs:
  service: collector
  reporting:
    min_delay_seconds: 0
    max_delay_seconds: 2
    upload_size_limit_bytes: 65536
  request_context:
    http:
      headers:
        - x-request-id
  mask_decision: /system/log/mask
distributed_tracing:
  type: grpc
services:
  collector:
    url: http://127.0.0.1:8183
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig([]string{"run", "--config-file", file}, fromMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DecisionLogs.FlushInterval != 2*time.Second || cfg.DecisionLogs.MaxUploadBytes != 65536 {
		t.Errorf("reporting = every %s, %d bytes; want every 2s, 65536 bytes", cfg.DecisionLogs.FlushInterval, cfg.DecisionLogs.MaxUploadBytes)
	}
	if !cfg.NDBuiltinCache {
		t.Error("nd_builtin_cache: true must record the builtin calls")
	}
	want := []string{"decision_logs.mask_decision", "distributed_tracing"}
	if !reflect.DeepEqual(cfg.IgnoredOPAKeys, want) {
		t.Errorf("ignored settings = %v, want %v", cfg.IgnoredOPAKeys, want)
	}

	off := filepath.Join(dir, "off.yaml")
	if err := os.WriteFile(off, []byte("decision_logs:\n  service: collector\nservices:\n  collector:\n    url: http://c:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = loadConfig([]string{"run", "--config-file", off}, fromMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NDBuiltinCache {
		t.Error("a config file without nd_builtin_cache must not record the builtin calls, as OPA does not")
	}
	if cfg.DecisionLogs.FlushInterval != 0 || cfg.DecisionLogs.MaxUploadBytes != 0 || len(cfg.IgnoredOPAKeys) != 0 {
		t.Errorf("a file without reporting = %+v and ignored %v, want the uploader's own defaults and nothing ignored", cfg.DecisionLogs, cfg.IgnoredOPAKeys)
	}
}

// TestLoadConfig_NDBuiltinCacheOnTheServicesOwn: without an OPA config file
// the builtin calls are recorded, since the decision logs of the chart's
// Pod carry them.
func TestLoadConfig_NDBuiltinCacheOnTheServicesOwn(t *testing.T) {
	cfg, err := loadConfig(nil, fromMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.NDBuiltinCache {
		t.Error("the service on its own must record the builtin calls")
	}
}
