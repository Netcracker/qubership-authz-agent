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
	"testing"
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
	if cfg.Addr != "0.0.0.0:8080" || cfg.Authorization || cfg.DecisionLogs.URL != "" || len(cfg.DataDirs) != 0 {
		t.Fatalf("defaults: %+v", cfg)
	}
	cfg, err = loadConfig(nil, fromMap(map[string]string{
		"authz.http.addr":              ":9090",
		"authz.data.dirs":              "/a, /b",
		"authz.data.ignore":            "..*",
		"authz.data.api.authorization": "true",
		"authz.decision.log.url":       "http://collector:8183",
		"authz.decision.log.headers":   "x-request-id,x-authz-original-path",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != ":9090" || !cfg.Authorization || len(cfg.DataDirs) != 2 || cfg.Ignore[0] != "..*" {
		t.Fatalf("env values: %+v", cfg)
	}
	if cfg.DecisionLogs.URL != "http://collector:8183" || len(cfg.DecisionLogs.Headers) != 2 || cfg.DecisionLogs.Labels["id"] != "authz-agent" {
		t.Fatalf("decision logs from env: %+v", cfg.DecisionLogs)
	}
}

// TestLoadConfig_OPAArguments: the chart's OPA command line maps onto the
// same settings, including the decision log target from the OPA config file.
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
		"--authentication=token", "--config-file", opaConfig, "/etc/opa/policies", "/etc/opa/data"}
	cfg, err := loadConfig(args, fromMap(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != "0.0.0.0:8181" || !cfg.Authorization || cfg.Ignore[0] != "..*" {
		t.Fatalf("flags: %+v", cfg)
	}
	if len(cfg.DataDirs) != 2 || cfg.DataDirs[1] != "/etc/opa/data" {
		t.Fatalf("positional dirs: %v", cfg.DataDirs)
	}
	if cfg.DecisionLogs.URL != "http://127.0.0.1:8183" || cfg.DecisionLogs.Headers[0] != "x-request-id" || cfg.DecisionLogs.Labels["id"] != "authz-agent" {
		t.Fatalf("decision logs from the OPA config: %+v", cfg.DecisionLogs)
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
