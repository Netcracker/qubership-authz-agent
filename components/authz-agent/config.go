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
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"authz-agent/components/authz-agent/internal/authn"
	"authz-agent/components/authz-agent/internal/m2m"
	"authz-agent/components/authz-agent/internal/pull"
	"authz-agent/internal/pips"
)

// config is what the service needs to start. Every value that a setting
// controls comes from an environment variable, which [variable] names for
// each key: AUTHZ_HTTP_ADDR for authz.http.addr, and so on. Pull.HTTPTimeout
// and M2M.WatchInterval are fixed.
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

// lookup reads one configuration key: [get] in main, a map in tests.
type lookup func(key, fallback string) string

// logLevels are the values of LOGGING_LEVEL_ROOT the platform logger reads.
var logLevels = []string{"debug", "info", "warn", "error", "fatal"}

// maxSeconds is the largest whole number of seconds a [time.Duration] holds:
// 9223372036, about 292 years.
const maxSeconds = math.MaxInt64 / int64(time.Second)

// loadConfig builds the configuration from the environment. A number, a
// boolean, a log level, or a listen address that is empty takes its default,
// as an unset one does, and an empty URL turns its feature off. A file path is
// used as set, empty included, without a check. LOGGING_LEVEL_ROOT is only
// checked: the platform logger reads it itself. The error names every
// variable whose value is not of its form or out of its range, with the
// values that variable accepts.
func loadConfig(get lookup) (config, error) {
	s := settings{get: get}
	cfg := config{
		Addr:       s.address("authz.http.addr", "0.0.0.0:8181"),
		PublicAddr: s.address("authz.public.addr", "0.0.0.0:8080"),
		Authn: authn.Config{
			File:             get("authz.trusted.providers.file", authn.DefaultFile),
			Required:         s.boolean("authz.jwks.bootstrap.required", true),
			HTTPTimeout:      s.seconds("authz.jwks.http.timeout", 1, authn.DefaultHTTPTimeout),
			HTTPRetries:      s.integer("authz.jwks.http.retries", 1, authn.DefaultHTTPRetries),
			TenantManagerURL: s.httpURL("authz.tenant.manager.url"),
			ReloadInterval:   s.seconds("authz.trusted.providers.reload.interval", 0, authn.DefaultReloadInterval),
		},
		Pull: pull.Config{
			SourceURL:   strings.TrimRight(s.httpURL("authz.pap.client.source.url"), "/"),
			Interval:    s.seconds("authz.pap.client.pull.interval", 0, pull.DefaultInterval),
			HTTPTimeout: pull.DefaultHTTPTimeout,
		},
		M2M: m2m.Config{
			TokenURL:         s.httpURL("authz.m2m.token.url"),
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
	if url := strings.TrimRight(s.httpURL("authz.entitlements.url"), "/"); url != "" {
		cfg.Pull.Entitlements = &pips.EntitlementsConfig{URL: url, HTTPTimeoutSeconds: int(timeout / time.Second), HTTPRetries: retries}
	}
	// The platform logger reads LOGGING_LEVEL_ROOT itself and falls back to
	// info where the value is not a level name; fromList refuses such a value.
	s.fromList("logging.level.root", logLevels)
	if len(s.refused) > 0 {
		return config{}, errors.New(strings.Join(s.refused, "; "))
	}
	return cfg, nil
}

// settings reads the values that loadConfig checks, and records each value
// that it refuses. For an empty or refused value, a method returns its
// fallback; httpURL returns "", and fromList returns nothing.
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

// integer reads an integer from minimum to [math.MaxInt].
func (s *settings) integer(key string, minimum, fallback int) int {
	raw := s.get(key, "")
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < minimum {
		s.refuse(key, raw, fmt.Sprintf("an integer from %d to %d", minimum, math.MaxInt))
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

// fromList refuses a non-empty value that is not one of values without
// regard to case.
func (s *settings) fromList(key string, values []string) {
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

// address reads a listen address <host>:<port>, whose host is empty, an IP
// address, or a host name, and whose port is from 0 to 65535.
func (s *settings) address(key, fallback string) string {
	raw := s.get(key, "")
	if raw == "" {
		return fallback
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil || !listenHost(host) || !listenPort(port) {
		s.refuse(key, raw, "<host>:<port>, with the host empty, an IP address, or a host name and the port from 0 to 65535, such as "+fallback)
		return fallback
	}
	return raw
}

// listenHost reports whether host is empty, an IP address, or a host name.
// A host name, as this check reads one, is labels of letters, digits, and
// hyphens joined by dots, and may end in one more dot. No label is empty or
// starts or ends with a hyphen, and the last label is not all digits, so
// 999.1.1.1 is neither an IP address nor a host name.
func listenHost(host string) bool {
	if host == "" {
		return true
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	for _, label := range labels {
		if !hostLabel.MatchString(label) {
			return false
		}
	}
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

// hostLabel matches one label of a host name.
var hostLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`)

// listenPort reports whether port is a decimal number from 0 to 65535,
// without a sign.
func listenPort(port string) bool {
	_, err := strconv.ParseUint(port, 10, 16)
	return err == nil
}

// httpURL reads an http or https URL and returns it as given. The URL has a
// host, a port from 1 to 65535 where it has a port, and no user, query, or
// fragment, and uses only the characters RFC 3986 allows. The scheme is read
// without regard to case. httpURL returns "" for an empty or refused value. A
// refusal names the rule the value breaks and leaves the value out, because a
// URL can hold a password.
func (s *settings) httpURL(key string) string {
	raw := s.get(key, "")
	if raw == "" {
		return ""
	}
	if problem := urlProblem(raw); problem != "" {
		s.refused = append(s.refused, fmt.Sprintf("%s %s: expected an http or https URL with a host, "+
			"a port from 1 to 65535 if it has one, and no user, query, or fragment, in the characters RFC 3986 allows",
			variable(key), problem))
		return ""
	}
	return raw
}

// urlProblem names the first rule of the URL form that raw breaks, or
// returns "" for an http or https URL that keeps them all.
func urlProblem(raw string) string {
	if strings.Contains(raw, "?") {
		return "has a query"
	}
	if strings.Contains(raw, "#") {
		return "has a fragment"
	}
	if !urlText.MatchString(raw) {
		return "holds a space or another character outside RFC 3986"
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return "does not parse as a URL"
	case u.Scheme != "http" && u.Scheme != "https":
		return "has no http or https scheme"
	case u.Hostname() == "":
		return "has no host"
	case u.User != nil:
		return "has a user"
	case !urlPort(u.Port()):
		return "has a port outside 1 to 65535"
	}
	return ""
}

// urlText matches the characters RFC 3986 allows in a URI, except ? and #,
// which start a query and a fragment.
var urlText = regexp.MustCompile(`^[A-Za-z0-9\-._~:/\[\]@!$&'()*+,;=%]*$`)

// urlPort reports whether port, as [url.URL.Port] returns it, is empty or a
// decimal number from 1 to 65535.
func urlPort(port string) bool {
	if port == "" {
		return true
	}
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n > 0
}

func (s *settings) refuse(key, raw, accepted string) {
	s.refused = append(s.refused, fmt.Sprintf("%s=%q: expected %s", variable(key), raw, accepted))
}

// variable is the environment variable that holds key: AUTHZ_HTTP_ADDR for
// authz.http.addr.
func variable(key string) string {
	return strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
}
