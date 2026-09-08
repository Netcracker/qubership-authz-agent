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
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"authz-agent/components/authz-agent/internal/authn"
	"authz-agent/components/authz-agent/internal/decisionlog"
	"authz-agent/components/authz-agent/internal/m2m"
	"authz-agent/components/authz-agent/internal/pull"
)

// config is what the service needs to start. Every value comes from the
// environment through configloader (AUTHZ_HTTP_ADDR is `authz.http.addr`,
// and so on); the OPA-style command line of the chart's OPA container
// overrides it while the service stands in for that container.
type config struct {
	// Addr is the listen address of the OPA-compatible surface.
	Addr string
	// PublicAddr is the listen address of the surface the clients call.
	PublicAddr string
	// StandIn is set when the service was started with OPA's command line
	// and stands in for the OPA container of the chart's Pod: the Pod's
	// other containers run the loops, and the service relays to them.
	StandIn bool
	// PapClientURL is the base URL of the pap-client that still answers
	// /health for the Pod; empty when there is none.
	PapClientURL string
	// DataDirs seed the store at start, as `opa run <dir>` would.
	DataDirs []string
	// Ignore lists file name patterns skipped in DataDirs.
	Ignore []string
	// Authorization guards the data API with data.system.authz.allow.
	Authorization bool
	// OPAAuthTokenFile names the file whose token the guard lets write,
	// loaded as data.opa_auth_secret; empty loads none.
	OPAAuthTokenFile string
	// DecisionLogs configures the delivery: an empty URL disables the
	// upload, and DecisionLogFile stores the decisions instead.
	DecisionLogs decisionlog.Config
	// DecisionLogFile stores the decisions in the service instead of
	// uploading them; empty uploads.
	DecisionLogFile string
	// NDBuiltinCache records the non-deterministic builtin calls of a
	// decision, the PIP requests and their responses, into its event, as
	// OPA's nd_builtin_cache does.
	NDBuiltinCache bool
	// IgnoredOPAKeys names the settings of the OPA configuration file the
	// service does not honor, for the warning that says so.
	IgnoredOPAKeys []string
	// Authn configures the trusted providers; an empty File disables them.
	Authn authn.Config
	// Pull configures the policy pull; [pull.Config] says what disables
	// it. It is empty while standing in: the Pod's pap-client pulls.
	Pull pull.Config
	// M2M configures the agent's own token; empty TokenURL and TokenFile
	// disable it.
	M2M m2m.Config
}

// lookup reads one configuration key; configloader in main, a map in tests.
type lookup func(key, fallback string) string

// loadConfig builds the configuration from the environment and, when args
// look like the OPA command line (`run --server --addr ... <dirs>`), from
// those arguments: the flags and directories the chart passes to the OPA
// container map onto the same settings, so the same image can replace that
// container without a chart change. In that Pod, Envoy holds port 8080 and
// the pap-client answers on 8182, so the public surface defaults to port
// 8280 and the relay to the pap-client unless the environment sets them;
// the trusted providers and the token file stay off unless the environment
// turns them on, and the policy pull never runs.
func loadConfig(args []string, get lookup) (config, error) {
	standIn := len(args) > 0 && args[0] == "run"
	// A loop's default applies to the service on its own; standing in for
	// the OPA container, the same key is off unless set.
	own := func(value string) string {
		if standIn {
			return ""
		}
		return value
	}
	cfg := config{
		NDBuiltinCache:   true,
		Addr:             get("authz.http.addr", "0.0.0.0:8181"),
		PublicAddr:       get("authz.public.addr", "0.0.0.0:8080"),
		StandIn:          standIn,
		PapClientURL:     get("authz.pap.client.url", ""),
		Authorization:    get("authz.data.api.authorization", "false") == "true",
		OPAAuthTokenFile: get("authz.opa.auth.token.file", ""),
		DecisionLogs: decisionlog.Config{
			URL:    get("authz.decision.log.url", ""),
			Labels: map[string]string{"id": "authz-agent"},
		},
		DecisionLogFile: get("authz.decision.log.file", ""),
		Authn: authn.Config{
			File:             get("authz.trusted.providers.file", own(authn.DefaultFile)),
			Required:         boolean(get, "authz.jwks.bootstrap.required", true),
			HTTPTimeout:      seconds(get, "authz.jwks.http.timeout", authn.DefaultHTTPTimeout),
			HTTPRetries:      integer(get, "authz.jwks.http.retries", authn.DefaultHTTPRetries),
			TenantManagerURL: get("authz.tenant.manager.url", "http://tenant-manager:8080"),
			ReloadInterval:   seconds(get, "authz.trusted.providers.reload.interval", authn.DefaultReloadInterval),
		},
		Pull: pull.Config{
			SourceURL:   strings.TrimRight(get("authz.pap.client.source.url", ""), "/"),
			Interval:    seconds(get, "authz.pap.client.pull.interval", pull.DefaultInterval),
			MountDir:    get("authz.policy.mount.dir", pull.DefaultMountDir),
			HTTPTimeout: pull.DefaultHTTPTimeout,
		},
		M2M: m2m.Config{
			TokenURL:         get("authz.m2m.token.url", ""),
			ClientIDFile:     get("authz.m2m.client.id.file", m2m.DefaultClientIDFile),
			ClientSecretFile: get("authz.m2m.client.secret.file", m2m.DefaultClientSecretFile),
			RenewBefore:      seconds(get, "authz.m2m.renew.before.seconds", m2m.DefaultRenewBefore),
			TokenFile:        get("authz.pap.client.token.file", own(m2m.DefaultTokenFile)),
			WatchInterval:    m2m.DefaultWatchInterval,
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
	if !standIn {
		return cfg, nil
	}
	cfg.Pull = pull.Config{}
	if get("authz.public.addr", "") == "" {
		cfg.PublicAddr = "0.0.0.0:8280"
	}
	if cfg.PapClientURL == "" {
		cfg.PapClientURL = "http://127.0.0.1:8182"
	}
	var opaConfigFile string
	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--server", arg == "--authentication=token", strings.HasPrefix(arg, "--log-level="):
			// Accepted for compatibility; the service is always a server,
			// identifies callers by their bearer token, and logs through the
			// core library.
		case arg == "--log-level" && i+1 < len(args):
			// The value is consumed too: left behind it would read as a data
			// directory and fail the start with a name the error never
			// connects to this flag.
			i++
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
		parsed, err := opaSettingsFrom(opaConfigFile)
		if err != nil {
			return config{}, err
		}
		parsed.logs.Labels = cfg.DecisionLogs.Labels
		cfg.DecisionLogs = parsed.logs
		cfg.NDBuiltinCache = parsed.ndBuiltinCache
		cfg.IgnoredOPAKeys = parsed.ignored
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

// seconds reads a whole number of seconds; a value that is not one keeps
// the fallback, and 0 is kept as 0 for the keys where it means off.
func seconds(get lookup, key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(get(key, ""))
	if raw == "" {
		return fallback
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return fallback
	}
	return time.Duration(n) * time.Second
}

// integer reads a positive integer; anything else keeps the fallback.
func integer(get lookup, key string, fallback int) int {
	raw := strings.TrimSpace(get(key, ""))
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

// boolean reads true/false in the spellings the pap-client accepted;
// anything else keeps the fallback.
func boolean(get lookup, key string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(get(key, ""))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return fallback
}

// opaConfig is the part of OPA's configuration file the service honors:
// whether the non-deterministic builtin cache is recorded, and the decision
// log service, its reporting bounds, and the request headers recorded per
// decision.
type opaConfig struct {
	NDBuiltinCache bool                  `yaml:"nd_builtin_cache"`
	DecisionLogs   opaDecisionLogs       `yaml:"decision_logs"`
	Services       map[string]opaService `yaml:"services"`
}

type opaDecisionLogs struct {
	Service        string            `yaml:"service"`
	Reporting      opaReporting      `yaml:"reporting"`
	RequestContext opaRequestContext `yaml:"request_context"`
}

// opaReporting bounds the uploads. The service posts on a fixed interval
// rather than OPA's adaptive one, so max_delay_seconds is that interval and
// min_delay_seconds its floor.
type opaReporting struct {
	MinDelaySeconds      float64 `yaml:"min_delay_seconds"`
	MaxDelaySeconds      float64 `yaml:"max_delay_seconds"`
	UploadSizeLimitBytes int     `yaml:"upload_size_limit_bytes"`
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

// opaSettings is what the service takes from an OPA configuration file.
type opaSettings struct {
	logs           decisionlog.Config
	ndBuiltinCache bool
	ignored        []string
}

// honoredOPAKeys are the settings the service reads, by their path in the
// file, with `*` for a service's own name. A path that is a key here holds
// settings, and every one of its keys the list does not name is reported; a
// path with no list, such as the names under `services`, holds no settings
// of its own and is only walked through. So a setting the service cannot act
// on is not mistaken for one it applies.
var honoredOPAKeys = map[string][]string{
	"":                                   {"nd_builtin_cache", "decision_logs", "services"},
	"decision_logs":                      {"service", "reporting", "request_context"},
	"decision_logs.reporting":            {"min_delay_seconds", "max_delay_seconds", "upload_size_limit_bytes"},
	"decision_logs.request_context":      {"http"},
	"decision_logs.request_context.http": {"headers"},
	"services":                           nil,
	"services.*":                         {"url"},
}

// opaSettingsFrom reads an OPA configuration file. A file without a
// decision log service disables logging; a service without a URL is an
// error, since the decisions would go nowhere.
func opaSettingsFrom(path string) (opaSettings, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return opaSettings{}, fmt.Errorf("read OPA config: %w", err)
	}
	var parsed opaConfig
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		return opaSettings{}, fmt.Errorf("parse OPA config %s: %w", path, err)
	}
	reporting := parsed.DecisionLogs.Reporting
	out := opaSettings{
		ndBuiltinCache: parsed.NDBuiltinCache,
		logs: decisionlog.Config{
			Headers:        parsed.DecisionLogs.RequestContext.HTTP.Headers,
			FlushInterval:  flushInterval(reporting),
			MaxUploadBytes: reporting.UploadSizeLimitBytes,
		},
		ignored: ignoredOPAKeys(raw),
	}
	if service := parsed.DecisionLogs.Service; service != "" {
		svc, ok := parsed.Services[service]
		if !ok || svc.URL == "" {
			return opaSettings{}, fmt.Errorf("OPA config %s: decision log service %q has no URL", path, service)
		}
		out.logs.URL = svc.URL
	}
	return out, nil
}

// flushInterval is how often the queue is posted: max_delay_seconds, no
// shorter than min_delay_seconds. Zero leaves the uploader's default.
func flushInterval(reporting opaReporting) time.Duration {
	seconds := reporting.MaxDelaySeconds
	if seconds < reporting.MinDelaySeconds {
		seconds = reporting.MinDelaySeconds
	}
	return time.Duration(seconds * float64(time.Second))
}

// ignoredOPAKeys names the settings of the file the service does not read,
// by their path, sorted: a YAML document read into a map has no order to
// keep, and the warning should read the same on every start. A service's own
// name is a path rather than a setting, so what is reported under it is
// `services.<name>.credentials`, not the name.
func ignoredOPAKeys(raw []byte) []string {
	var document map[string]any
	if yaml.Unmarshal(raw, &document) != nil {
		return nil
	}
	var ignored []string
	// path is what the warning prints and pattern what honoredOPAKeys is
	// keyed by; the two differ under `services`, whose keys are names.
	var walk func(path, pattern string, node map[string]any)
	walk = func(path, pattern string, node map[string]any) {
		honored, holdsSettings := honoredOPAKeys[pattern]
		for key, value := range node {
			childPath, childPattern := key, key
			if path != "" {
				childPath = path + "." + key
			}
			switch {
			case pattern == "services":
				childPattern = "services.*"
			case pattern != "":
				childPattern = pattern + "." + key
			}
			if holdsSettings && honored != nil && !slices.Contains(honored, key) {
				ignored = append(ignored, childPath)
				continue
			}
			if nested, ok := value.(map[string]any); ok {
				walk(childPath, childPattern, nested)
			}
		}
	}
	walk("", "", document)
	slices.Sort(ignored)
	return ignored
}
