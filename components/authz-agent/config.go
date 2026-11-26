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
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
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
	// M2M configures the agent's own token: from TokenURL, or from TokenFile
	// when TokenURL is empty.
	M2M m2m.Config
	// Mode is the value of M2M_AUTH_MODE in lower case, legacy where it is
	// unset or empty.
	Mode string
}

// lookup reads one configuration key: [get] in main, a map in tests.
type lookup func(key, fallback string) string

// logLevels are the values of LOGGING_LEVEL_ROOT the platform logger reads.
var logLevels = []string{"debug", "info", "warn", "error", "fatal"}

// rootLevelKey and logLevelKey are the keys under which the platform logger
// reads the root log level, from LOGGING_LEVEL_ROOT and from LOG_LEVEL.
const (
	rootLevelKey = "logging.level.root"
	logLevelKey  = "log.level"
)

// maxSeconds is the largest whole number of seconds a [time.Duration] holds:
// 9223372036, about 292 years.
const maxSeconds = math.MaxInt64 / int64(time.Second)

// The configuration keys of the token that the agent sends: authModeKey of
// M2M_AUTH_MODE, which the platform's deployer passes to every service and
// which chooses the token; tokenURLKey of AUTHZ_OUTGOING_TOKEN_URL, the token
// endpoint of the agent's client credentials token; and tokenFileKey of
// AUTHZ_PAP_CLIENT_TOKEN_FILE, the agent's token file.
const (
	authModeKey  = "m2m.auth.mode"
	tokenURLKey  = "authz.outgoing.token.url"
	tokenFileKey = "authz.pap.client.token.file"
)

// The values of M2M_AUTH_MODE. legacy sends the agent's client credentials
// token, k8s the content of its token file, and hybrid the content of that
// file where its path exists at the start and the client credentials token
// where it does not.
const (
	legacyMode = "legacy"
	hybridMode = "hybrid"
	k8sMode    = "k8s"
)

// authModes lists the values of M2M_AUTH_MODE.
var authModes = []string{legacyMode, hybridMode, k8sMode}

// deploymentFiles are the paths at which a deployment puts the files of the
// agent's token. loadConfig takes each path where the variable that names the
// file is unset or empty.
type deploymentFiles struct {
	TokenFile, ClientIDFile, ClientSecretFile string
}

// defaultFiles are the paths at which the chart mounts those files.
var defaultFiles = deploymentFiles{
	TokenFile:        m2m.DefaultTokenFile,
	ClientIDFile:     m2m.DefaultClientIDFile,
	ClientSecretFile: m2m.DefaultClientSecretFile,
}

// maxRetries is the largest number of attempts per request that
// AUTHZ_JWKS_HTTP_RETRIES and AUTHZ_ENTITLEMENTS_HTTP_RETRIES accept. The
// chart's values schema has the same maximum.
const maxRetries = 100

// loadConfig builds the configuration from the environment. A number, a
// boolean, a value from a list, or a listen address that is empty takes its
// default, as an unset one does, and so does the path of the token file or of a
// client credentials file, which takes its default from files. An empty URL
// turns its feature off, except AUTHZ_OUTGOING_TOKEN_URL where the agent sends
// its client credentials token. The path of the trusted providers file is used
// as set, empty included. LOGGING_LEVEL_ROOT and LOG_LEVEL are only checked:
// the platform logger reads them itself. The error names every variable whose
// value is not of its form or out of its range, with the values that variable
// accepts. It also names, with the reason, each input that the agent cannot use
// for the token that M2M_AUTH_MODE chooses: an unset or empty
// AUTHZ_OUTGOING_TOKEN_URL, a file that [m2m.CheckFile] refuses, and in hybrid
// mode a token file path that os.Stat neither finds nor reports missing. With a
// refused M2M_AUTH_MODE it names none of them. It names LOG_LEVEL whenever that
// variable is not empty.
func loadConfig(get lookup, files deploymentFiles) (config, error) {
	s := settings{get: get}
	cfg := config{
		Addr:       s.address("authz.http.addr", "0.0.0.0:8181"),
		PublicAddr: s.address("authz.public.addr", "0.0.0.0:8080"),
		Authn: authn.Config{
			File:             get("authz.trusted.providers.file", authn.DefaultFile),
			Required:         s.boolean("authz.jwks.bootstrap.required", true),
			HTTPTimeout:      s.seconds("authz.jwks.http.timeout", 1, authn.DefaultHTTPTimeout),
			HTTPRetries:      s.integer("authz.jwks.http.retries", 1, maxRetries, authn.DefaultHTTPRetries),
			TenantManagerURL: s.httpURL("authz.tenant.manager.url"),
			ReloadInterval:   s.seconds("authz.trusted.providers.reload.interval", 0, authn.DefaultReloadInterval),
		},
		Pull: pull.Config{
			SourceURL:   strings.TrimRight(s.httpURL("authz.pap.client.source.url"), "/"),
			Interval:    s.seconds("authz.pap.client.pull.interval", 0, pull.DefaultInterval),
			HTTPTimeout: pull.DefaultHTTPTimeout,
		},
		M2M: m2m.Config{
			TokenURL:         s.httpURL(tokenURLKey),
			ClientIDFile:     cmp.Or(get("authz.outgoing.client.id.file", ""), files.ClientIDFile),
			ClientSecretFile: cmp.Or(get("authz.outgoing.client.secret.file", ""), files.ClientSecretFile),
			RenewBefore:      s.seconds("authz.outgoing.renew.before.seconds", 0, m2m.DefaultRenewBefore),
			TokenFile:        cmp.Or(get(tokenFileKey, ""), files.TokenFile),
			WatchInterval:    m2m.DefaultWatchInterval,
		},
	}
	// The entitlements timeout and retries are checked whether or not a URL
	// turns the PIP on, as the chart's values schema checks them.
	timeout := s.seconds("authz.entitlements.http.timeout", 1, pips.DefaultEntitlementsHTTPTimeout*time.Second)
	retries := s.integer("authz.entitlements.http.retries", 1, maxRetries, pips.DefaultEntitlementsHTTPRetries)
	if url := strings.TrimRight(s.httpURL("authz.entitlements.url"), "/"); url != "" {
		cfg.Pull.Entitlements = &pips.EntitlementsConfig{URL: url, HTTPTimeoutSeconds: int(timeout / time.Second), HTTPRetries: retries}
	}
	// A refused M2M_AUTH_MODE chooses no token, so no input of a token is
	// checked. A token endpoint that is not an http or https URL has been
	// refused already, whichever token the mode chooses.
	refusedBefore := len(s.refused)
	cfg.Mode = cmp.Or(s.fromList(authModeKey, authModes), legacyMode)
	if len(s.refused) == refusedBefore {
		s.outgoingToken(&cfg.M2M, cfg.Mode)
	}
	// The platform logger reads LOGGING_LEVEL_ROOT itself and falls back to
	// info where the value is not a level name; fromList refuses such a value.
	s.fromList(rootLevelKey, logLevels)
	// The logger falls back to LOG_LEVEL where LOGGING_LEVEL_ROOT is unset or
	// empty. To keep one name for the root level, a non-empty LOG_LEVEL is
	// refused even beside a valid LOGGING_LEVEL_ROOT.
	if raw := s.get(logLevelKey, ""); raw != "" {
		s.refuse(logLevelKey, raw, "no value, "+rootLevelRefusal)
	}
	if len(s.refused) > 0 {
		return config{}, errors.New(strings.Join(s.refused, "; "))
	}
	return cfg, nil
}

// settings reads the values that loadConfig checks, and records each value
// that it refuses. For an empty or refused value, a method returns its
// fallback; httpURL and fromList return "".
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

// integer reads an integer from minimum to maximum.
func (s *settings) integer(key string, minimum, maximum, fallback int) int {
	raw := s.get(key, "")
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < minimum || n > maximum {
		s.refuse(key, raw, fmt.Sprintf("an integer from %d to %d", minimum, maximum))
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

// fromList returns the member of values that the value of key matches
// without regard to case, and refuses a non-empty value that matches none.
func (s *settings) fromList(key string, values []string) string {
	raw := s.get(key, "")
	if raw == "" {
		return ""
	}
	for _, v := range values {
		if strings.EqualFold(raw, v) {
			return v
		}
	}
	s.refuse(key, raw, "one of "+strings.Join(values, ", "))
	return ""
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

// outgoingToken has cfg send the token that mode chooses, and refuses each of
// that token's inputs that the agent cannot use. It empties cfg.TokenURL
// where the token is the content of cfg.TokenFile. In hybrid mode the token
// file is present where [os.Stat], which follows symbolic links, finds the
// path, and absent where it reports that the path does not exist. Any other
// error of os.Stat is refused, since the agent can then tell neither that the
// file is present nor that it is absent.
func (s *settings) outgoingToken(cfg *m2m.Config, mode string) {
	switch mode {
	case k8sMode:
		cfg.TokenURL = ""
		s.requireFile(tokenFileKey, cfg.TokenFile, "M2M_AUTH_MODE=k8s sends the token in this file")
	case hybridMode:
		_, err := os.Stat(cfg.TokenFile)
		switch {
		case err == nil:
			cfg.TokenURL = ""
			s.requireFile(tokenFileKey, cfg.TokenFile, "M2M_AUTH_MODE=hybrid sends the token in this file, since the path exists")
		case errors.Is(err, fs.ErrNotExist):
			s.clientCredentials(cfg, fmt.Sprintf("while M2M_AUTH_MODE is hybrid and %s does not exist", cfg.TokenFile), "")
		default:
			s.refused = append(s.refused, fmt.Sprintf("%s=%q: %s, and M2M_AUTH_MODE=hybrid needs the path either to hold the token or not to exist",
				variable(tokenFileKey), cfg.TokenFile, reason(err)))
		}
	default:
		s.clientCredentials(cfg, "while M2M_AUTH_MODE is legacy, which is its default",
			fmt.Sprintf("; M2M_AUTH_MODE=k8s sends the token in %s instead", cfg.TokenFile))
	}
}

// clientCredentials refuses an unset or empty AUTHZ_OUTGOING_TOKEN_URL and
// each client credentials file of cfg that the agent cannot use. condition
// says when the agent sends its client credentials token. other ends the
// refusal of the endpoint and names the other token, or is empty where there
// is none.
func (s *settings) clientCredentials(cfg *m2m.Config, condition, other string) {
	// The raw value is tested, so that a token endpoint of the wrong form,
	// refused where it was read, is not refused again as missing.
	if s.get(tokenURLKey, "") == "" {
		s.refuse(tokenURLKey, "", "the http or https URL of the token endpoint, required "+condition+other)
	}
	s.requireFile("authz.outgoing.client.id.file", cfg.ClientIDFile, "the agent reads the client id from this file "+condition)
	s.requireFile("authz.outgoing.client.secret.file", cfg.ClientSecretFile, "the agent reads the client secret from this file "+condition)
}

// requireFile refuses path, the value of key, unless [m2m.CheckFile] accepts
// the file it names. The refusal gives the reason, followed by use, which says
// what the agent reads the file for.
func (s *settings) requireFile(key, path, use string) {
	if err := m2m.CheckFile(path); err != nil {
		s.refused = append(s.refused, fmt.Sprintf("%s=%q: %s, and %s", variable(key), path, reason(err), use))
	}
}

// reason is the text of err without the path that an [*fs.PathError]
// carries, which a refusal names already.
func reason(err error) string {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err.Error()
	}
	return err.Error()
}

// tokenChoice is the line that the agent logs at the start in hybrid mode,
// where nothing else in the deployment shows which token the agent sends, and
// "" in any other mode.
func (c config) tokenChoice() string {
	switch {
	case c.Mode != hybridMode:
		return ""
	case c.M2M.TokenURL == "":
		return fmt.Sprintf("M2M_AUTH_MODE is hybrid and %s exists, so the agent sends the token in that file", c.M2M.TokenFile)
	}
	return fmt.Sprintf("M2M_AUTH_MODE is hybrid and %s does not exist, so the agent sends its client credentials token from %s",
		c.M2M.TokenFile, c.M2M.TokenURL)
}

func (s *settings) refuse(key, raw, accepted string) {
	s.refused = append(s.refused, fmt.Sprintf("%s=%q: expected %s", variable(key), raw, accepted))
}

// rootLevelRefusal is the reason a variable other than LOGGING_LEVEL_ROOT
// may not set the root log level.
const rootLevelRefusal = "since the agent reads the root log level from LOGGING_LEVEL_ROOT alone"

// otherRootLevelNames returns a refusal for each variable in environ that
// changes what the platform logger reads as the root log level, except
// LOGGING_LEVEL_ROOT and LOG_LEVEL, which loadConfig checks itself. Each entry
// of environ has the form NAME=value. The logger reads the level through
// configloader, which folds a name to lower case and its underscores to dots.
// So the logger reads log_level as it reads LOG_LEVEL, and configloader nests
// a name that adds an underscore and a suffix to another, such as
// LOGGING_LEVEL_ROOT_X, under the key of the shorter one, which then holds no
// value. Such a variable is refused whatever its value, the empty string
// included, since configloader keeps only one of two names that fold onto
// one key.
func otherRootLevelNames(environ []string) []string {
	var refused []string
	for _, entry := range environ {
		name, value, _ := strings.Cut(entry, "=")
		key := strings.ReplaceAll(strings.ToLower(name), "_", ".")
		root := key == logLevelKey || key == rootLevelKey || strings.HasPrefix(key, rootLevelKey+".")
		if !root || name == "LOG_LEVEL" || name == "LOGGING_LEVEL_ROOT" {
			continue
		}
		refused = append(refused, fmt.Sprintf("%s=%q: expected no variable of this name, %s", name, value, rootLevelRefusal))
	}
	return refused
}

// variable is the environment variable that holds key: AUTHZ_HTTP_ADDR for
// authz.http.addr.
func variable(key string) string {
	return strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
}
