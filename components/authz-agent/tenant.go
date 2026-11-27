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
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// tenantLookupPath resolves a tenant's display name to its ID; the
// endpoint answers with the ID as a bare text body.
const tenantLookupPath = "/api/v4/tenant-manager/registration/tenants"

// tenantID is the accepted shape of an ID tenant-manager answers with.
var tenantID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// defaultTenant is the tenant a check request that names none is decided
// in. It starts as the configured display name and becomes the tenant's ID
// once tenant-manager resolves the name; until then a request without a
// tenant is denied whatever the policy data holds under the display name,
// and /ready answers 503.
type defaultTenant struct {
	name     string
	baseURL  string
	client   *http.Client
	log      tenantLog
	id       atomic.Pointer[string]
	resolved atomic.Bool
}

// tenantLog receives the transitions of the lookup.
type tenantLog interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}

func newDefaultTenant(name, tenantManagerURL string, log tenantLog) *defaultTenant {
	d := &defaultTenant{name: name, baseURL: strings.TrimRight(strings.TrimSpace(tenantManagerURL), "/"),
		client: &http.Client{Timeout: 10 * time.Second}, log: log}
	d.id.Store(&name)
	return d
}

// Get returns the ID of the default tenant, or its display name before it
// is resolved.
func (d *defaultTenant) Get() string { return *d.id.Load() }

// Unresolved returns the display name while a tenant-manager URL is set and
// tenant-manager has not resolved the name yet, and "" otherwise.
func (d *defaultTenant) Unresolved() string {
	if d.baseURL == "" || d.name == "" || d.resolved.Load() {
		return ""
	}
	return d.name
}

// Run resolves the display name until tenant-manager answers or ctx ends.
// The first attempt is immediate; the pause after a failed one starts at a
// second and doubles up to maxPause. Without a tenant-manager URL the name
// is the ID.
//
// While the name is unresolved, /ready reports the state, and Run logs only
// its changes: one warning for each way the lookup fails, as [lookupState]
// names it, and a debug line when the lookup fails again in a way it has
// already warned of. A lookup that alternates between two failures thus
// writes two warnings. An info line on resolution ends the state and says
// how long it lasted. A lookup that fails because ctx ended logs nothing.
func (d *defaultTenant) Run(ctx context.Context, maxPause time.Duration) {
	if d.baseURL == "" || d.name == "" {
		return
	}
	var firstFailure time.Time
	warned := map[string]bool{}
	var previous string
	for attempt := 0; ; attempt++ {
		id, err := d.lookup(ctx)
		if err == nil {
			d.id.Store(&id)
			d.resolved.Store(true)
			if attempt == 0 {
				d.log.Infof("default tenant: AUTHZ_DEFAULT_TENANT %q resolved to %q via tenant-manager", d.name, id)
			} else {
				d.log.Infof("default tenant: AUTHZ_DEFAULT_TENANT %q resolved to %q via tenant-manager "+
					"after %d failed attempts over %s",
					d.name, id, attempt, time.Since(firstFailure).Round(time.Millisecond))
			}
			return
		}
		if ctx.Err() != nil {
			return
		}
		if attempt == 0 {
			firstFailure = time.Now()
		}
		state := lookupState(err)
		switch {
		case !warned[state]:
			warned[state] = true
			d.log.Warnf("default tenant: AUTHZ_DEFAULT_TENANT %q is not resolved via tenant-manager at "+
				"AUTHZ_TENANT_MANAGER_URL %s: %v; retrying with a pause that doubles from a second up to %s, "+
				"and warning again only when it fails in a way not reported yet; until it resolves, the service is "+
				"not ready, and a check request without tenant_id or Tenant is denied",
				d.name, redacted(d.baseURL), err, maxPause)
		case state != previous:
			d.log.Debugf("default tenant: AUTHZ_DEFAULT_TENANT %q is not resolved via tenant-manager, "+
				"which fails again as warned before: %v", d.name, err)
		}
		previous = state
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryPause(attempt, maxPause)):
		}
	}
}

// lookupError is a failed lookup. state names how it failed, and stays the
// same while tenant-manager keeps failing the same way; err varies with
// details such as the local port of a reset connection.
type lookupError struct {
	state string
	err   error
}

func (e *lookupError) Error() string { return e.err.Error() }
func (e *lookupError) Unwrap() error { return e.err }

// lookupState names the way a lookup failed, which Run warns of once. The
// name comes from a closed set, so that one steady failure keeps one name
// however its text varies (a local port, the current time of an expired
// certificate, a stream ID): the answer tenant-manager gave, the kind of a
// DNS failure, the reason a certificate is invalid, an errno, EOF, a
// timeout, or else the type of the innermost cause, never its text.
func lookupState(err error) string {
	if le, ok := errors.AsType[*lookupError](err); ok {
		return le.state
	}
	if dns, ok := errors.AsType[*net.DNSError](err); ok {
		switch {
		case dns.IsNotFound:
			return "DNS: no such host"
		case dns.IsTimeout:
			return "DNS: timeout"
		default:
			return "DNS: lookup failed"
		}
	}
	if cert, ok := errors.AsType[x509.CertificateInvalidError](err); ok {
		return fmt.Sprintf("invalid certificate, reason %d", cert.Reason)
	}
	if errno, ok := errors.AsType[syscall.Errno](err); ok {
		return errno.Error()
	}
	for _, sentinel := range []error{io.ErrUnexpectedEOF, io.EOF} {
		if errors.Is(err, sentinel) {
			return sentinel.Error()
		}
	}
	if t, ok := errors.AsType[interface {
		error
		Timeout() bool
	}](err); ok && t.Timeout() || errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	for {
		next := errors.Unwrap(err)
		if next == nil {
			return fmt.Sprintf("%T", err)
		}
		err = next
	}
}

// retryPause is the pause after the failed attempt numbered attempt, from 0:
// a second, doubled after each attempt, and maxPause at most.
func retryPause(attempt int, maxPause time.Duration) time.Duration {
	return min(time.Second<<min(attempt, 30), maxPause)
}

// redacted is raw with the password of its user info masked, for a log line.
func redacted(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Redacted()
}

func (d *defaultTenant) lookup(ctx context.Context) (string, error) {
	endpoint := fmt.Sprintf("%s%s?dns=%s", d.baseURL, tenantLookupPath, url.QueryEscape(d.name))
	shown := redacted(endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", &lookupError{state: fmt.Sprintf("HTTP %d", resp.StatusCode),
			err: fmt.Errorf("%s: HTTP %d", shown, resp.StatusCode)}
	}
	id := strings.TrimSpace(string(body))
	if !tenantID.MatchString(id) {
		return "", &lookupError{state: "not a tenant ID",
			err: fmt.Errorf("%s: the answer %.80q is not a tenant ID", shown, id)}
	}
	return id, nil
}
