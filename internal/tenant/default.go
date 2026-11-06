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

// Package tenant finds the default tenant of a deployment, the tenant of a
// request that names none. The deployment names it, and tenant-manager, where
// there is one, translates the name into the identifier of the tenant. A
// service creates a [Default] with [NewDefault], calls [Default.Run], and is
// not ready until [Default.Ready] reports true.
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
)

// DefaultName is the name of the default tenant of a deployment that names
// none.
const DefaultName = "default"

const (
	// lookupPath is the tenant-manager endpoint that returns the identifier of
	// the tenant its dns query parameter names, as a plain-text body.
	lookupPath = "/api/v4/tenant-manager/registration/tenants"
	// maxResponseBytes bounds the answer of tenant-manager, which is one
	// identifier.
	maxResponseBytes = 1024
	// requestTimeout bounds one request to tenant-manager.
	requestTimeout = 5 * time.Second
	// firstRetryDelay is the pause after the first failed attempt. Each later
	// pause doubles, up to maxRetryDelay.
	firstRetryDelay = time.Second
	maxRetryDelay   = 10 * time.Second
)

// tenantShape is the accepted form of a tenant name and of an identifier.
var tenantShape = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// Logger receives the diagnostics.
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
	// Name is the name of the default tenant, [DefaultName] when empty. It
	// holds 1 to 128 ASCII letters, digits, '.', '_', and '-'.
	Name string
	// ManagerURL is the address of tenant-manager: an absolute http or https
	// URL with a host and without a user, a query, or a fragment. When it is
	// empty, the identifier is Name as given, which is what a deployment
	// without tenant-manager gets.
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
	// id holds the identifier once it is known.
	id atomic.Pointer[string]
}

// NewDefault returns the Default that cfg describes. It sends no request, and
// it fails when cfg breaks a rule of [Config]. Without tenant-manager the
// returned Default is ready at once.
func NewDefault(cfg Config) (*Default, error) {
	name := cfg.Name
	if name == "" {
		name = DefaultName
	}
	if !tenantShape.MatchString(name) {
		return nil, fmt.Errorf("default tenant %s: a tenant name holds 1 to 128 ASCII letters, digits, '.', '_', and '-'", short(name))
	}
	d := &Default{name: name, log: cfg.Log}
	if d.log == nil {
		d.log = discard{}
	}
	if cfg.ManagerURL == "" {
		d.log.Infof("default tenant: %q, used as given, because no tenant-manager URL is set", name)
		d.id.Store(&name)
		return d, nil
	}
	base, err := managerBase(cfg.ManagerURL)
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

// Ready reports whether the identifier is known.
func (d *Default) Ready() bool { return d.id.Load() != nil }

// ID returns the identifier of the default tenant: the answer of tenant-manager,
// or the name as given without it. It returns "" until [Default.Ready] reports
// true.
func (d *Default) ID() string {
	if id := d.id.Load(); id != nil {
		return *id
	}
	return ""
}

// Run asks tenant-manager for the identifier until it gets one or ctx ends,
// pausing 1 second after the first failed attempt, then twice as long each
// time, up to 10 seconds. An answer without an identifier fails the attempt, an
// unknown tenant included, so a misspelled name leaves the service not ready
// with a warning for each attempt. Run returns at once when the identifier is
// already known.
func (d *Default) Run(ctx context.Context) {
	delay := firstRetryDelay
	for !d.Ready() {
		id, err := d.translate(ctx)
		if err == nil {
			d.log.Infof("default tenant: tenant-manager translates %q to %q", d.name, id)
			d.id.Store(&id)
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
		return "", fmt.Errorf("tenant-manager GET %s: read the answer: %w", d.endpoint, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("tenant-manager GET %s: HTTP 404: tenant-manager has no tenant of this name, so check the name of the default tenant", d.endpoint)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("tenant-manager GET %s: HTTP %d", d.endpoint, resp.StatusCode)
	}
	if len(body) > maxResponseBytes {
		return "", fmt.Errorf("tenant-manager GET %s: the answer is longer than %d bytes", d.endpoint, maxResponseBytes)
	}
	id := strings.TrimSpace(string(body))
	if !tenantShape.MatchString(id) {
		return "", fmt.Errorf("tenant-manager GET %s: the answer %s is not 1 to 128 ASCII letters, digits, '.', '_', and '-'", d.endpoint, short(id))
	}
	return id, nil
}

// short quotes s for a message, cut to 64 bytes with the cut marked: s can be
// the text of an answer, and a message goes into a log line.
func short(s string) string {
	const limit = 64
	if len(s) > limit {
		return fmt.Sprintf("%q...", s[:limit])
	}
	return fmt.Sprintf("%q", s)
}
