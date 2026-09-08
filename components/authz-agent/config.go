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
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"authz-agent/components/authz-agent/internal/decisionlog"
)

// config is what the service needs to start. Every value comes from the
// environment through configloader (AUTHZ_HTTP_ADDR is `authz.http.addr`,
// and so on); the OPA-style command line of the chart's OPA container
// overrides it while the service stands in for that container.
type config struct {
	// Addr is the listen address.
	Addr string
	// DataDirs seed the store at start, as `opa run <dir>` would.
	DataDirs []string
	// Ignore lists file name patterns skipped in DataDirs.
	Ignore []string
	// Authorization guards the data API with data.system.authz.allow.
	Authorization bool
	// DecisionLogs configures the uploader; an empty URL disables it.
	DecisionLogs decisionlog.Config
}

// lookup reads one configuration key; configloader in main, a map in tests.
type lookup func(key, fallback string) string

// loadConfig builds the configuration from the environment and, when args
// look like the OPA command line (`run --server --addr ... <dirs>`), from
// those arguments: the flags and directories the chart passes to the OPA
// container map onto the same settings, so the same image can replace that
// container without a chart change.
func loadConfig(args []string, get lookup) (config, error) {
	cfg := config{
		Addr:          get("authz.http.addr", "0.0.0.0:8080"),
		Authorization: get("authz.data.api.authorization", "false") == "true",
		DecisionLogs: decisionlog.Config{
			URL:    get("authz.decision.log.url", ""),
			Labels: map[string]string{"id": "authz-agent"},
		},
	}
	if dirs := get("authz.data.dirs", ""); dirs != "" {
		cfg.DataDirs = splitList(dirs)
	}
	if ignore := get("authz.data.ignore", ""); ignore != "" {
		cfg.Ignore = splitList(ignore)
	}
	if headers := get("authz.decision.log.headers", ""); headers != "" {
		cfg.DecisionLogs.Headers = splitList(headers)
	}
	if len(args) == 0 || args[0] != "run" {
		return cfg, nil
	}
	var opaConfigFile string
	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--server", arg == "--authentication=token", strings.HasPrefix(arg, "--log-level"):
			// Accepted for compatibility; the service is always a server and
			// identifies callers by their bearer token.
		case arg == "--addr" && i+1 < len(args):
			i++
			cfg.Addr = args[i]
		case strings.HasPrefix(arg, "--addr="):
			cfg.Addr = strings.TrimPrefix(arg, "--addr=")
		case strings.HasPrefix(arg, "--ignore="):
			cfg.Ignore = append(cfg.Ignore, strings.TrimPrefix(arg, "--ignore="))
		case arg == "--authorization=basic":
			cfg.Authorization = true
		case arg == "--config-file" && i+1 < len(args):
			i++
			opaConfigFile = args[i]
		case strings.HasPrefix(arg, "--config-file="):
			opaConfigFile = strings.TrimPrefix(arg, "--config-file=")
		case strings.HasPrefix(arg, "-"):
			return config{}, fmt.Errorf("unsupported OPA argument %q", arg)
		default:
			cfg.DataDirs = append(cfg.DataDirs, arg)
		}
	}
	if opaConfigFile != "" {
		logs, err := decisionLogsFromOPAConfig(opaConfigFile)
		if err != nil {
			return config{}, err
		}
		logs.Labels = cfg.DecisionLogs.Labels
		cfg.DecisionLogs = logs
	}
	return cfg, nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// opaConfig is the part of OPA's configuration file the service honors: the
// decision log service and the request headers recorded per decision.
type opaConfig struct {
	DecisionLogs opaDecisionLogs       `yaml:"decision_logs"`
	Services     map[string]opaService `yaml:"services"`
}

type opaDecisionLogs struct {
	Service        string            `yaml:"service"`
	RequestContext opaRequestContext `yaml:"request_context"`
}

type opaRequestContext struct {
	HTTP opaHTTPContext `yaml:"http"`
}

type opaHTTPContext struct {
	Headers []string `yaml:"headers"`
}

type opaService struct {
	URL string `yaml:"url"`
}

// decisionLogsFromOPAConfig reads the decision log target from an OPA
// configuration file. A file without a decision log service disables
// logging.
func decisionLogsFromOPAConfig(path string) (decisionlog.Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return decisionlog.Config{}, fmt.Errorf("read OPA config: %w", err)
	}
	var parsed opaConfig
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		return decisionlog.Config{}, fmt.Errorf("parse OPA config %s: %w", path, err)
	}
	cfg := decisionlog.Config{Headers: parsed.DecisionLogs.RequestContext.HTTP.Headers}
	if service := parsed.DecisionLogs.Service; service != "" {
		svc, ok := parsed.Services[service]
		if !ok || svc.URL == "" {
			return decisionlog.Config{}, fmt.Errorf("OPA config %s: decision log service %q has no URL", path, service)
		}
		cfg.URL = svc.URL
	}
	return cfg, nil
}
