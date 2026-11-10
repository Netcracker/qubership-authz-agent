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

// Package tenant finds the key of the policy data of the default tenant of a
// deployment, the tenant of a request that names none. The deployment names
// the tenant, and tenant-manager, where there is one, translates the name into
// that key (ADR-0093 R11, R13). A service creates a [Default] with
// [NewDefault], starts [Default.Run] in its own goroutine, and is not ready
// until [Default.Ready] is closed.
package tenant

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"
)

// DefaultName is the name of the default tenant of a deployment that names
// none.
const DefaultName = "default"

const (
	// lookupPath is the tenant-manager endpoint that returns, as a plain-text
	// body, the identifier of the tenant whose name its dns query parameter
	// holds (?dns=default).
	lookupPath = "/api/v4/tenant-manager/registration/tenants"
	// maxResponseBytes bounds the response body of tenant-manager, which is one
	// identifier.
	maxResponseBytes = 1024
	// maxNameBytes bounds a name used as given, in bytes.
	maxNameBytes = 128
	// requestTimeout bounds one request to tenant-manager.
	requestTimeout = 5 * time.Second
	// firstRetryDelay is the pause after the first failed attempt. Each later
	// pause doubles, up to maxRetryDelay.
	firstRetryDelay = time.Second
	maxRetryDelay   = 10 * time.Second
)

// tenantShape is the accepted form of a name sent to tenant-manager and of the
// identifier it returns.
var tenantShape = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// Logger receives the records of a [Default]: Infof gets one when the key
// becomes known, and Warnf gets one for each attempt of [Default.Run] that
// fails before its context ends, on the goroutine of Run. Both take
// [fmt.Printf] arguments.
type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}

type discard struct{}

func (discard) Infof(string, ...any) {
	// The message is dropped: Config.Log is nil.
}

func (discard) Warnf(string, ...any) {
	// The message is dropped: Config.Log is nil.
}

// Config describes the default tenant of a deployment.
type Config struct {
	// Name is the name of the default tenant, [DefaultName] when empty. A name
	// sent to tenant-manager holds 1 to 128 ASCII letters, digits, '.', '_',
	// and '-'. A name used as given, without tenant-manager, is 1 to 128 bytes
	// of UTF-8 text without control characters.
	Name string
	// ManagerURL is the address of tenant-manager: an absolute http or https
	// URL with a host and without a user, a query, or a fragment. White space
	// around it is ignored. When it is empty or blank, the key is Name as given
	// (ADR-0093 R14).
	ManagerURL string
	// Transport sends the request to tenant-manager, and it is where the
	// service adds its own token. An error from it, such as no token yet,
	// fails the attempt, so the service stays not ready until the token comes.
	// Nil means [http.DefaultTransport].
	Transport http.RoundTripper
	// Log receives the diagnostics; nil discards them.
	Log Logger
}

// Default is the default tenant of a deployment. It is safe for concurrent
// use.
type Default struct {
	name string
	// endpoint is the translation request, "" without tenant-manager.
	endpoint string
	client   *http.Client
	log      Logger
	// key holds the key once it is known, and ready is closed when key is
	// stored.
	key   atomic.Pointer[string]
	ready chan struct{}
}

// NewDefault returns the Default that cfg describes. It sends no request, and
// it fails when cfg breaks a rule of [Config]. Without tenant-manager the
// returned Default is ready at once.
func NewDefault(cfg Config) (*Default, error) {
	name := cfg.Name
	if name == "" {
		name = DefaultName
	}
	d := &Default{name: name, log: cfg.Log, ready: make(chan struct{})}
	if d.log == nil {
		d.log = discard{}
	}
	address := strings.TrimSpace(cfg.ManagerURL)
	if address == "" {
		if !usableAsGiven(name) {
			return nil, fmt.Errorf("default tenant %s: a name used as given is the key of the policy data, and it has to be 1 to %d bytes of UTF-8 text without control characters, such as a line break left over from the configuration", short(name), maxNameBytes)
		}
		d.store(name)
		d.log.Infof("default tenant: %q, used as given, because no tenant-manager URL is set", name)
		return d, nil
	}
	if !tenantShape.MatchString(name) {
		return nil, fmt.Errorf("default tenant %s: a name sent to tenant-manager holds 1 to 128 ASCII letters, digits, '.', '_', and '-'", short(name))
	}
	base, err := managerBase(address)
	if err != nil {
		return nil, err
	}
	d.endpoint = base + lookupPath + "?dns=" + url.QueryEscape(name)
	d.client = &http.Client{
		Transport: cfg.Transport,
		Timeout:   requestTimeout,
		// The answer has to come from the address the configuration names, and
		// Transport may add the token to any request it sends, so a 3xx fails
		// the attempt.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return d, nil
}

// managerBase returns raw without a trailing slash, and an error when raw
// breaks the rule of [Config.ManagerURL]. The error does not quote raw,
// because a URL that names a user can hold a password.
func managerBase(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" ||
		u.User != nil || strings.ContainsAny(raw, "?#") {
		return "", errors.New("tenant-manager URL has to be an absolute http or https URL with a host and without a user, a query, or a fragment")
	}
	return strings.TrimRight(raw, "/"), nil
}

// usableAsGiven reports whether name is 1 to maxNameBytes bytes of UTF-8 text
// without control characters.
func usableAsGiven(name string) bool {
	if name == "" || len(name) > maxNameBytes || !utf8.ValidString(name) {
		return false
	}
	return !strings.ContainsFunc(name, unicode.IsControl)
}

// store keeps key and closes ready, and reports whether it did: only the first
// key is kept.
func (d *Default) store(key string) bool {
	if !d.key.CompareAndSwap(nil, &key) {
		return false
	}
	close(d.ready)
	return true
}

// Ready returns a channel that is closed once the key is known. A caller that
// must not block reads it in a select with a default case.
func (d *Default) Ready() <-chan struct{} { return d.ready }

// ID returns the key of the policy data of the default tenant: the identifier
// tenant-manager returns for the name, or, when [Config.ManagerURL] is empty or
// blank, the name itself. It returns "" until the key is known, and the key
// once [Default.Ready] is closed.
func (d *Default) ID() string {
	if key := d.key.Load(); key != nil {
		return *key
	}
	return ""
}

// Run asks tenant-manager for the key until it gets one or ctx ends, pausing 1
// second after the first failed attempt, then twice as long each time, up to 10
// seconds. A response without an identifier fails the attempt, an unknown
// tenant included, so a misspelled name leaves the service not ready with a
// warning for each attempt. Run blocks until then, and returns at once when the
// key is already known.
func (d *Default) Run(ctx context.Context) {
	delay := firstRetryDelay
	for d.key.Load() == nil {
		key, err := d.translate(ctx)
		if err == nil {
			if d.store(key) {
				d.log.Infof("default tenant: tenant-manager translates %q to %q", d.name, key)
			}
			return
		}
		if ctx.Err() != nil {
			return
		}
		d.log.Warnf("default tenant: %v; the service is not ready, retrying in %s", err, delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, maxRetryDelay)
	}
}

// translate sends one request to tenant-manager. It fails when the request
// fails, when the status is not 2xx, a redirect included, when the body is
// longer than maxResponseBytes, and when the body, white space around it
// trimmed, does not have the form of an identifier.
func (d *Default) translate(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "text/plain")
	resp, err := d.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("tenant-manager: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("tenant-manager GET %s: read the response body: %w", d.endpoint, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("tenant-manager GET %s: HTTP 404: tenant-manager knows no tenant of this name, or the URL does not lead to tenant-manager, so check the name of the default tenant and the tenant-manager URL", d.endpoint)
	}
	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		target := "without a Location"
		if location := resp.Header.Get("Location"); location != "" {
			target = "to " + short(location)
		}
		return "", fmt.Errorf("tenant-manager GET %s: HTTP %d %s: redirects are not followed, so set the tenant-manager URL to the address that answers", d.endpoint, resp.StatusCode, target)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("tenant-manager GET %s: HTTP %d", d.endpoint, resp.StatusCode)
	}
	if len(body) > maxResponseBytes {
		return "", fmt.Errorf("tenant-manager GET %s: the response body is longer than %d bytes", d.endpoint, maxResponseBytes)
	}
	id := strings.TrimSpace(string(body))
	if !tenantShape.MatchString(id) {
		return "", fmt.Errorf("tenant-manager GET %s: the response body %s is not 1 to 128 ASCII letters, digits, '.', '_', and '-'", d.endpoint, short(id))
	}
	return id, nil
}

// short quotes s for a message, cut to 64 bytes with the cut marked: s can be
// the text of a response, and a message goes into a log line.
func short(s string) string {
	const limit = 64
	if len(s) > limit {
		return fmt.Sprintf("%q...", s[:limit])
	}
	return fmt.Sprintf("%q", s)
}
