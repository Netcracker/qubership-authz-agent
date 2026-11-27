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
	"net/url"
	"strconv"
	"strings"
	"time"

	"authz-agent/components/authz-agent/internal/authn"
	"authz-agent/components/authz-agent/internal/m2m"
	"authz-agent/components/authz-agent/internal/pull"
	"authz-agent/internal/regobuiltins"
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
	// DefaultTenant is the display name of the tenant a check request is
	// decided in when it names none; tenant-manager resolves it to the
	// tenant's ID.
	DefaultTenant string
	// PIPTimeout bounds one call of a PIP the generated policies make.
	PIPTimeout time.Duration
	// EntitlementsURL is the base URL of the entitlements service, which a
	// condition on subject.entitledResources calls; empty fails such a
	// condition's operand.
	EntitlementsURL string
}

// lookup reads one configuration key, returning fallback when the key is
// unset; configloader in main, a map in tests.
type lookup func(key, fallback string) string

// envName is the environment variable configloader reads for a key:
// authz.http.addr is AUTHZ_HTTP_ADDR.
func envName(key string) string {
	return strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
}

// loadConfig builds the configuration from the environment. Every key goes
// through the parser of its kind, and an unset key takes its default. The
// error names every variable whose value its parser refuses, so one failed
// start reports them all.
func loadConfig(get lookup) (config, error) {
	s := &settings{get: get}
	// The platform logger reads the level itself, before main runs, and
	// falls back to info on a value it does not know; the check refuses
	// that value at start instead.
	s.logLevel("logging.level.root", "info")
	cfg := config{
		Addr:       s.listenAddress("authz.http.addr", "0.0.0.0:8181"),
		PublicAddr: s.listenAddress("authz.public.addr", "0.0.0.0:8080"),
		Authn: authn.Config{
			File:             s.text("authz.trusted.providers.file", authn.DefaultFile),
			Required:         s.boolean("authz.jwks.bootstrap.required", true),
			HTTPTimeout:      s.seconds("authz.jwks.http.timeout", authn.DefaultHTTPTimeout, 1),
			HTTPRetries:      s.count("authz.jwks.http.retries", authn.DefaultHTTPRetries),
			TenantManagerURL: s.optionalURL("authz.tenant.manager.url", "http://tenant-manager:8080"),
			ReloadInterval:   s.seconds("authz.trusted.providers.reload.interval", authn.DefaultReloadInterval, 0),
		},
		Pull: pull.Config{
			SourceURL:   strings.TrimRight(s.optionalURL("authz.pap.client.source.url", ""), "/"),
			Interval:    s.seconds("authz.pap.client.pull.interval", pull.DefaultInterval, 0),
			HTTPTimeout: pull.DefaultHTTPTimeout,
		},
		M2M: m2m.Config{
			TokenURL:         s.optionalURL("authz.m2m.token.url", ""),
			ClientIDFile:     s.nonEmpty("authz.m2m.client.id.file", m2m.DefaultClientIDFile, "a file name"),
			ClientSecretFile: s.nonEmpty("authz.m2m.client.secret.file", m2m.DefaultClientSecretFile, "a file name"),
			RenewBefore:      s.seconds("authz.m2m.renew.before.seconds", m2m.DefaultRenewBefore, 0),
			TokenFile:        s.text("authz.pap.client.token.file", m2m.DefaultTokenFile),
			WatchInterval:    m2m.DefaultWatchInterval,
		},
		DefaultTenant:   s.nonEmpty("authz.default.tenant", "default", "a tenant display name"),
		PIPTimeout:      s.seconds("authz.pip.timeout", regobuiltins.DefaultTimeout, 1),
		EntitlementsURL: s.optionalURL("authz.entitlements.url", ""),
	}
	if len(s.problems) > 0 {
		return config{}, errors.New("invalid configuration: " + strings.Join(s.problems, "; "))
	}
	return cfg, nil
}

// settings reads the keys of one configuration and keeps a problem for
// every value that the parser of its key refuses.
type settings struct {
	get      lookup
	problems []string
}

// text returns the value of key with the white space around it removed;
// any value is accepted, the empty one included.
func (s *settings) text(key, fallback string) string {
	return strings.TrimSpace(s.get(key, fallback))
}

// refuse records that key holds value, which is not one of the values
// described by expected.
func (s *settings) refuse(key, value, expected string) {
	s.problems = append(s.problems, fmt.Sprintf("%s is %q; expected %s", envName(key), value, expected))
}

// nonEmpty returns the value of key, refusing the empty one; what names the
// kind of value expected.
func (s *settings) nonEmpty(key, fallback, what string) string {
	v := s.text(key, fallback)
	if v == "" {
		s.refuse(key, v, what+", not empty")
	}
	return v
}

// listenAddress returns the value of key as a host:port listen address
// whose port is a number from 1 to 65535; the host may be empty.
func (s *settings) listenAddress(key, fallback string) string {
	v := s.text(key, fallback)
	_, port, err := net.SplitHostPort(v)
	if n, perr := strconv.ParseUint(port, 10, 16); err != nil || perr != nil || n == 0 {
		s.refuse(key, v, "host:port with a port from 1 to 65535, such as 0.0.0.0:8080")
	}
	return v
}

// optionalURL returns the value of key, empty or an absolute http or https
// URL with a host.
func (s *settings) optionalURL(key, fallback string) string {
	v := s.text(key, fallback)
	if v == "" {
		return v
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		s.refuse(key, v, "an http or https URL, such as http://host:8080, or empty")
	}
	return v
}

// maxSeconds is the largest number of seconds a time.Duration holds.
const maxSeconds = math.MaxInt64 / int64(time.Second)

// seconds returns the value of key as a duration, written as a whole number
// of seconds from minimum to maxSeconds.
func (s *settings) seconds(key string, fallback time.Duration, minimum int64) time.Duration {
	v := s.text(key, strconv.FormatInt(int64(fallback/time.Second), 10))
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < minimum || n > maxSeconds {
		s.refuse(key, v, fmt.Sprintf("a whole number of seconds from %d to %d", minimum, maxSeconds))
		return fallback
	}
	return time.Duration(n) * time.Second
}

// count returns the value of key as a whole number from 1 to
// math.MaxInt32.
func (s *settings) count(key string, fallback int) int {
	v := s.text(key, strconv.Itoa(fallback))
	n, err := strconv.ParseInt(v, 10, 32)
	if err != nil || n < 1 {
		s.refuse(key, v, fmt.Sprintf("a whole number from 1 to %d", math.MaxInt32))
		return fallback
	}
	return int(n)
}

// boolean returns the value of key in the spellings the pap-client
// accepted, matched without regard to case.
func (s *settings) boolean(key string, fallback bool) bool {
	v := s.text(key, strconv.FormatBool(fallback))
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	s.refuse(key, v, "one of true, false, yes, no, on, off, 1, 0")
	return fallback
}

// logLevel checks the value of key against the level names the platform
// logger accepts, matched without regard to case. White space around the
// value is refused rather than removed, because that logger keeps it.
func (s *settings) logLevel(key, fallback string) {
	v := s.get(key, fallback)
	switch strings.ToLower(v) {
	case "debug", "info", "warn", "error", "fatal":
		return
	}
	s.refuse(key, v, "one of debug, info, warn, error, fatal")
}
