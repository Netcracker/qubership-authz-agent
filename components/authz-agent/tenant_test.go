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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// tenantManager answers the lookup of the display name acme with answers
// in turn, the last one from then on, and counts the lookups.
func tenantManager(t *testing.T, answers ...string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(n.Add(1)) - 1
		if r.URL.Path != tenantLookupPath || r.URL.Query().Get("dns") != "acme" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		a := answers[min(i, len(answers)-1)]
		if a == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(a + "\n"))
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

// The default tenant is its display name, and Unresolved names it, until
// tenant-manager resolves it, which Run retries until it does.
func TestDefaultTenant_IsResolvedOnceTenantManagerAnswers(t *testing.T) {
	srv, lookups := tenantManager(t, "", "0b9e-acme")
	d := newDefaultTenant("acme", srv.URL+"/", quiet{})
	if got, unresolved := d.Get(), d.Unresolved(); got != "acme" || unresolved != "acme" {
		t.Fatalf("Get, Unresolved before Run = %q, %q, want the display name acme for both", got, unresolved)
	}

	d.Run(context.Background(), time.Millisecond)

	if got := d.Get(); got != "0b9e-acme" || lookups.Load() != 2 {
		t.Errorf("Get after Run = %q after %d lookups, want 0b9e-acme after 2", got, lookups.Load())
	}
	if got := d.Unresolved(); got != "" {
		t.Errorf("Unresolved after Run = %q, want \"\"", got)
	}
}

// An answer that is not a tenant ID leaves the display name in place.
func TestDefaultTenant_RefusesAnAnswerThatIsNotAnID(t *testing.T) {
	srv, _ := tenantManager(t, `{"id": "x"}`)
	d := newDefaultTenant("acme", srv.URL, quiet{})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	d.Run(ctx, time.Millisecond)

	if got, unresolved := d.Get(), d.Unresolved(); got != "acme" || unresolved != "acme" {
		t.Errorf("Get, Unresolved = %q, %q, want the display name acme for both", got, unresolved)
	}
}

// Without a tenant-manager URL the display name is the ID, and nothing is
// left to resolve.
func TestDefaultTenant_WithoutTenantManagerKeepsTheName(t *testing.T) {
	d := newDefaultTenant("acme", " ", quiet{})
	if got := d.Unresolved(); got != "" {
		t.Errorf("Unresolved before Run = %q, want \"\"", got)
	}
	d.Run(context.Background(), time.Millisecond)
	if got := d.Get(); got != "acme" {
		t.Errorf("Get = %q, want acme", got)
	}
}

// After a failed lookup Run pauses a second, then doubles the pause up to
// its maximum.
func TestRetryPause(t *testing.T) {
	var got []time.Duration
	for attempt := range 6 {
		got = append(got, retryPause(attempt, 10*time.Second))
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second, 10 * time.Second}
	if !slices.Equal(got, want) {
		t.Errorf("retryPause(0..5, 10s) = %v, want %v", got, want)
	}
	if got := retryPause(0, time.Millisecond); got != time.Millisecond {
		t.Errorf("retryPause(0, 1ms) = %v, want 1ms", got)
	}
	if got := retryPause(1000, 10*time.Second); got != 10*time.Second {
		t.Errorf("retryPause(1000, 10s) = %v, want 10s", got)
	}
}

// tenantLines records what the lookup logs.
type tenantLines struct{ debugs, infos, warns []string }

func (l *tenantLines) Debugf(format string, args ...any) {
	l.debugs = append(l.debugs, fmt.Sprintf(format, args...))
}
func (l *tenantLines) Infof(format string, args ...any) {
	l.infos = append(l.infos, fmt.Sprintf(format, args...))
}
func (l *tenantLines) Warnf(format string, args ...any) {
	l.warns = append(l.warns, fmt.Sprintf(format, args...))
}

// scriptedLookups makes d answer its lookup number i, from 0, with
// answer(i): a status with the body "0b9e-acme", or an error.
func scriptedLookups(d *defaultTenant, answer func(i int) (int, error)) {
	var n atomic.Int32
	d.client.Transport = roundTripper(func(r *http.Request) (*http.Response, error) {
		status, err := answer(int(n.Add(1)) - 1)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("0b9e-acme")), Request: r}, nil
	})
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// refused is a refused connection whose text carries the local port, which
// differs on each attempt.
func refused(port int) error {
	return &net.OpError{Op: "dial", Net: "tcp",
		Source: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: port},
		Addr:   &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 8080},
		Err:    &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}
}

func TestDefaultTenant_WarnsOnceWhileTheLookupFailsTheSameWay(t *testing.T) {
	var log tenantLines
	d := newDefaultTenant("acme", "http://tenant-manager:8080", &log)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scriptedLookups(d, func(i int) (int, error) {
		if i == 20 {
			cancel()
		}
		return http.StatusNotFound, nil
	})

	d.Run(ctx, time.Millisecond)

	if len(log.warns) != 1 {
		t.Fatalf("warnings after 20 lookups answered 404 = %q, want one", log.warns)
	}
	for _, name := range []string{"AUTHZ_DEFAULT_TENANT", "AUTHZ_TENANT_MANAGER_URL", "HTTP 404"} {
		if !strings.Contains(log.warns[0], name) {
			t.Errorf("warning %q does not name %s", log.warns[0], name)
		}
	}
	if len(log.infos) != 0 {
		t.Errorf("info lines with the name unresolved = %q, want none", log.infos)
	}
}

func TestDefaultTenant_WarnsAgainOnlyWhenTheLookupFailsDifferently(t *testing.T) {
	var log tenantLines
	d := newDefaultTenant("acme", "http://tenant-manager:8080", &log)
	scriptedLookups(d, func(i int) (int, error) {
		switch {
		case i < 10:
			return 0, refused(40000 + i)
		case i < 15:
			return http.StatusNotFound, nil
		default:
			return http.StatusOK, nil
		}
	})

	d.Run(context.Background(), time.Millisecond)

	if len(log.warns) != 2 || !strings.Contains(log.warns[0], "connection refused") || !strings.Contains(log.warns[1], "HTTP 404") {
		t.Errorf("warnings after 10 refused connections and 5 answers 404 = %q, "+
			"want one naming the refused connection and one naming HTTP 404", log.warns)
	}
	if len(log.infos) != 1 || !strings.Contains(log.infos[0], `resolved to "0b9e-acme"`) ||
		!strings.Contains(log.infos[0], "after 15 failed attempts over ") {
		t.Errorf("info lines on resolution = %q, want one with the ID and after 15 failed attempts", log.infos)
	}
}

func TestDefaultTenant_ResolvedOnTheFirstAttemptLogsNoFailure(t *testing.T) {
	var log tenantLines
	d := newDefaultTenant("acme", "http://tenant-manager:8080", &log)
	scriptedLookups(d, func(int) (int, error) { return http.StatusOK, nil })

	d.Run(context.Background(), time.Millisecond)

	if len(log.warns) != 0 || len(log.infos) != 1 || strings.Contains(log.infos[0], "failed attempts") {
		t.Errorf("warnings, infos = %q, %q, want no warning and one info that counts no failed attempt", log.warns, log.infos)
	}
}

func TestDefaultTenant_WarnsOnceForEachWayTheLookupFails(t *testing.T) {
	var log tenantLines
	d := newDefaultTenant("acme", "http://agent:s3cret@tenant-manager:8080", &log)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scriptedLookups(d, func(i int) (int, error) {
		if i == 20 {
			cancel()
		}
		return []int{http.StatusServiceUnavailable, http.StatusNotFound}[i%2], nil
	})

	d.Run(ctx, time.Millisecond)

	if len(log.warns) != 2 || !strings.Contains(log.warns[0], "HTTP 503") || !strings.Contains(log.warns[1], "HTTP 404") {
		t.Errorf("warnings after 20 lookups answered 503 and 404 in turn = %q, want one naming HTTP 503 and one naming HTTP 404", log.warns)
	}
	if len(log.debugs) != 18 || !strings.Contains(log.debugs[0], "HTTP 503") {
		t.Errorf("%d debug lines %q; want 18, one for each return to a failure warned of, the first naming HTTP 503",
			len(log.debugs), log.debugs)
	}
	for _, w := range log.warns {
		if strings.Contains(w, "s3cret") {
			t.Errorf("warning %q shows the password of AUTHZ_TENANT_MANAGER_URL", w)
		}
	}
}

func TestLookupState_NamesOneFailureOnceHoweverItsTextVaries(t *testing.T) {
	get := func(cause error) error {
		return &url.Error{Op: "Get", URL: "http://tenant-manager:8080/x", Err: cause}
	}
	verifying := func(cause error) error { return &tls.CertificateVerificationError{Err: cause} }
	expired := func(at string) error {
		return verifying(x509.CertificateInvalidError{Reason: x509.Expired,
			Detail: "current time " + at + " is after 2026-01-01T00:00:00Z"})
	}
	dnsServerDown := func(port int) error {
		return &net.DNSError{Err: fmt.Sprintf("read udp 10.0.0.5:%d->10.0.0.10:53: read: connection refused", port),
			Name: "tenant-manager", Server: "10.0.0.10:53"}
	}
	for _, tc := range []struct {
		name string
		a, b error
		same bool
	}{
		{"a refused connection from two local ports", get(refused(40000)), get(refused(40001)), true},
		{"an expired certificate at two times", get(expired("2026-11-27T10:00:00Z")), get(expired("2026-11-27T10:00:10Z")), true},
		{"an unreachable DNS server from two local ports", get(dnsServerDown(51234)), get(dnsServerDown(51235)), true},
		{"a client timeout and a dial timeout", get(timeoutText("awaiting headers")), get(timeoutText("dialing")), true},
		{"a reset stream with two stream IDs", get(streamReset(3)), get(streamReset(5)), true},
		{"a refused connection and a reset one", get(refused(40000)),
			get(&net.OpError{Op: "read", Net: "tcp", Err: &os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET}}), false},
		{"an unexpected EOF and an EOF", get(io.ErrUnexpectedEOF), get(io.EOF), false},
		{"an unknown certificate authority and an expired certificate",
			get(verifying(x509.UnknownAuthorityError{})), get(expired("2026-11-27T10:00:00Z")), false},
		{"a certificate for another host and an unknown certificate authority",
			get(verifying(x509.HostnameError{Host: "tenant-manager"})), get(verifying(x509.UnknownAuthorityError{})), false},
		{"an unknown host and an unreachable DNS server",
			get(&net.DNSError{Err: "no such host", Name: "tenant-manager", IsNotFound: true}), get(dnsServerDown(51234)), false},
		{"a timeout and a refused connection", get(timeoutText("awaiting headers")), get(refused(40000)), false},
		{"HTTP 404 and HTTP 503", &lookupError{state: "HTTP 404", err: io.EOF}, &lookupError{state: "HTTP 503", err: io.EOF}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := lookupState(tc.a), lookupState(tc.b)
			if (a == b) != tc.same {
				t.Errorf("lookupState = %q and %q, want them equal: %t", a, b, tc.same)
			}
		})
	}
}

// timeoutText is a timeout whose text varies, as the client's timeout
// carries the step it interrupted.
type timeoutText string

func (e timeoutText) Error() string { return "Client.Timeout exceeded while " + string(e) }
func (timeoutText) Timeout() bool   { return true }

// streamReset is an error with no cause whose text carries a counter, as a
// reset HTTP/2 stream names its stream ID.
type streamReset int

func (e streamReset) Error() string {
	return fmt.Sprintf("stream error: stream ID %d; INTERNAL_ERROR", int(e))
}

func TestDefaultTenant_StoppedDuringALookupLogsNothing(t *testing.T) {
	var log tenantLines
	d := newDefaultTenant("acme", "http://tenant-manager:8080", &log)
	ctx, cancel := context.WithCancel(context.Background())
	scriptedLookups(d, func(int) (int, error) {
		cancel()
		return 0, context.Canceled
	})

	d.Run(ctx, time.Millisecond)

	if len(log.warns)+len(log.debugs)+len(log.infos) != 0 {
		t.Errorf("lines after a lookup that ended with ctx = %q %q %q, want none", log.warns, log.debugs, log.infos)
	}
}
