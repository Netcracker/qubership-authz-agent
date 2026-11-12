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
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"authz-agent/components/authz-agent/internal/authn"
	"authz-agent/components/authz-agent/internal/m2m"
	"authz-agent/components/authz-agent/internal/pull"
	"authz-agent/internal/pips"
)

// config is what the service needs to start. Every value comes from the
// environment through configloader: AUTHZ_HTTP_ADDR is `authz.http.addr`,
// and so on.
type config struct {
	// Addr is the listen address of the internal surface: the probes, the
	// metrics, and /api-version.
	Addr string
	// PublicAddr is the listen address of the surface the clients call.
	PublicAddr string
	// Authn configures the trusted providers; an empty File disables them.
	Authn authn.Config
	// Pull configures the policy pull; [pull.Config] says what disables it.
	Pull pull.Config
	// M2M configures the agent's own token; empty TokenURL and TokenFile
	// disable it.
	M2M m2m.Config
}

// lookup reads one configuration key; configloader in main, a map in tests.
type lookup func(key, fallback string) string

// logLevels are the values of LOGGING_LEVEL_ROOT the platform logger reads.
var logLevels = []string{"debug", "info", "warn", "error", "fatal"}

// maxSeconds is the largest whole number of seconds a [time.Duration] holds.
const maxSeconds = math.MaxInt64 / int64(time.Second)

// loadConfig builds the configuration from the environment. A number, a
// boolean, or a log level that is empty takes its default, as an unset one
// does. The error names every variable whose value is not of its type or
// out of its range, with the values that variable accepts.
func loadConfig(get lookup) (config, error) {
	s := settings{get: get}
	cfg := config{
		Addr:       get("authz.http.addr", "0.0.0.0:8181"),
		PublicAddr: get("authz.public.addr", "0.0.0.0:8080"),
		Authn: authn.Config{
			File:             get("authz.trusted.providers.file", authn.DefaultFile),
			Required:         s.boolean("authz.jwks.bootstrap.required", true),
			HTTPTimeout:      s.seconds("authz.jwks.http.timeout", 1, authn.DefaultHTTPTimeout),
			HTTPRetries:      s.integer("authz.jwks.http.retries", 1, authn.DefaultHTTPRetries),
			TenantManagerURL: get("authz.tenant.manager.url", ""),
			ReloadInterval:   s.seconds("authz.trusted.providers.reload.interval", 0, authn.DefaultReloadInterval),
		},
		Pull: pull.Config{
			SourceURL:   strings.TrimRight(get("authz.pap.client.source.url", ""), "/"),
			Interval:    s.seconds("authz.pap.client.pull.interval", 0, pull.DefaultInterval),
			HTTPTimeout: pull.DefaultHTTPTimeout,
		},
		M2M: m2m.Config{
			TokenURL:         get("authz.m2m.token.url", ""),
			ClientIDFile:     get("authz.m2m.client.id.file", m2m.DefaultClientIDFile),
			ClientSecretFile: get("authz.m2m.client.secret.file", m2m.DefaultClientSecretFile),
			RenewBefore:      s.seconds("authz.m2m.renew.before.seconds", 0, m2m.DefaultRenewBefore),
			TokenFile:        get("authz.pap.client.token.file", m2m.DefaultTokenFile),
			WatchInterval:    m2m.DefaultWatchInterval,
		},
	}
	// The entitlements timeout and retries are checked whether or not a URL
	// turns the PIP on, as the chart's values schema checks them.
	timeout := s.seconds("authz.entitlements.http.timeout", 1, pips.DefaultEntitlementsHTTPTimeout*time.Second)
	retries := s.integer("authz.entitlements.http.retries", 1, pips.DefaultEntitlementsHTTPRetries)
	if url := strings.TrimRight(strings.TrimSpace(get("authz.entitlements.url", "")), "/"); url != "" {
		cfg.Pull.Entitlements = &pips.EntitlementsConfig{URL: url, HTTPTimeoutSeconds: int(timeout / time.Second), HTTPRetries: retries}
	}
	// The platform logger reads LOGGING_LEVEL_ROOT itself and takes info
	// for a value it does not know.
	s.oneOf("logging.level.root", logLevels)
	if len(s.refused) > 0 {
		return config{}, errors.New(strings.Join(s.refused, "; "))
	}
	return cfg, nil
}

// settings reads the values that loadConfig checks, and records each value
// that it refuses. A value that is empty takes the fallback.
type settings struct {
	get     lookup
	refused []string
}

// seconds reads a whole number of seconds from minimum to [maxSeconds].
func (s *settings) seconds(key string, minimum int64, fallback time.Duration) time.Duration {
	raw := s.get(key, "")
	if raw == "" {
		return fallback
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < minimum || n > maxSeconds {
		s.refuse(key, raw, fmt.Sprintf("an integer number of seconds from %d to %d", minimum, maxSeconds))
		return fallback
	}
	return time.Duration(n) * time.Second
}

// integer reads an integer of at least minimum.
func (s *settings) integer(key string, minimum, fallback int) int {
	raw := s.get(key, "")
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < minimum {
		s.refuse(key, raw, fmt.Sprintf("an integer of at least %d", minimum))
		return fallback
	}
	return n
}

// boolean reads true or false without regard to case.
func (s *settings) boolean(key string, fallback bool) bool {
	raw := s.get(key, "")
	switch {
	case raw == "":
		return fallback
	case strings.EqualFold(raw, "true"):
		return true
	case strings.EqualFold(raw, "false"):
		return false
	}
	s.refuse(key, raw, "true or false")
	return fallback
}

// oneOf refuses a value that is not one of values without regard to case.
func (s *settings) oneOf(key string, values []string) {
	raw := s.get(key, "")
	if raw == "" {
		return
	}
	for _, v := range values {
		if strings.EqualFold(raw, v) {
			return
		}
	}
	s.refuse(key, raw, "one of "+strings.Join(values, ", "))
}

func (s *settings) refuse(key, raw, accepted string) {
	s.refused = append(s.refused, fmt.Sprintf("%s=%q: expected %s", variable(key), raw, accepted))
}

// variable is the environment variable from which configloader reads key.
func variable(key string) string {
	return strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
}
