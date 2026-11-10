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

package tenant

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"testing/synctest"
	"time"

	"authz-agent/internal/token/outbound"
)

const (
	// managerURL is the address of tenant-manager in the tests.
	managerURL = "http://tenant-manager:8080"
	// lookupURL is the request of the default name to managerURL.
	lookupURL = managerURL + "/api/v4/tenant-manager/registration/tenants?dns=default"
	// uuid is an identifier of the form tenant-manager answers with.
	uuid = "6f1c2a9e-3b4d-4e8f-9a1b-2c3d4e5f6a7b"
)

// reply is what fakeManager answers.
type reply struct {
	status   int
	body     string
	location string
	// err fails the request, and bodyErr fails the read after body.
	err, bodyErr error
	// reader, when set, is the body in place of body.
	reader io.Reader
}

// fakeManager answers in memory, so a test runs on the fake clock of a synctest
// bubble, where a real socket never counts as idle.
type fakeManager struct {
	mu sync.Mutex
	// next is the reply to the next request and to every later one.
	next reply
	// block, when set, holds every request until its context ends.
	block bool
	// gate, when set, holds every request until it is closed.
	gate chan struct{}
	// urls and accepts hold the address and the Accept header of each request,
	// and times the time it arrived.
	urls, accepts []string
	times         []time.Time
}

func (f *fakeManager) answerWith(r reply) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next = r
}

func (f *fakeManager) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.urls...)
}

func (f *fakeManager) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.urls = append(f.urls, r.URL.String())
	f.accepts = append(f.accepts, r.Header.Get("Accept"))
	f.times = append(f.times, time.Now())
	next, block, gate := f.next, f.block, f.gate
	f.mu.Unlock()
	if block {
		<-r.Context().Done()
		return nil, r.Context().Err()
	}
	if gate != nil {
		<-gate
	}
	if next.err != nil {
		return nil, next.err
	}
	header := http.Header{}
	if next.location != "" {
		header.Set("Location", next.location)
	}
	body := next.reader
	if body == nil {
		body = strings.NewReader(next.body)
	}
	if next.bodyErr != nil {
		body = io.MultiReader(body, iotest.ErrReader(next.bodyErr))
	}
	return &http.Response{StatusCode: next.status, Header: header, Body: io.NopCloser(body), Request: r}, nil
}

// countingReader counts the bytes read from r.
type countingReader struct {
	r    io.Reader
	read atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read.Add(int64(n))
	return n, err
}

// recorder keeps the diagnostics.
type recorder struct {
	mu           sync.Mutex
	infos, warns []string
}

func (r *recorder) Infof(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.infos = append(r.infos, fmt.Sprintf(format, args...))
}

func (r *recorder) Warnf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.warns = append(r.warns, fmt.Sprintf(format, args...))
}

func newDefault(t *testing.T, cfg Config) *Default {
	t.Helper()
	d, err := NewDefault(cfg)
	if err != nil {
		t.Fatalf("NewDefault() error = %v", err)
	}
	return d
}

// isReady reports whether d.Ready() is closed, without waiting.
func isReady(d *Default) bool {
	select {
	case <-d.Ready():
		return true
	default:
		return false
	}
}

// runBriefly calls d.Run with one minute on the fake clock of a synctest
// bubble, so a regression that keeps it retrying reaches the assertions of the
// test and not the timeout of go test.
func runBriefly(t *testing.T, d *Default) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		d.Run(ctx)
	})
}

func TestNewDefault_UsesTheNameAsGivenWithoutTenantManager(t *testing.T) {
	longest := strings.Repeat("a", 128)
	twoByteLetters := strings.Repeat("é", 64)
	tests := []struct {
		name   string
		tenant string
		want   string
	}{
		{"no name", "", "default"},
		{"letters", "acme", "acme"},
		{"one character", "a", "a"},
		{"every sign tenant-manager takes", "a.b_c-d", "a.b_c-d"},
		{"digits and upper case", "Tenant42", "Tenant42"},
		{"128 bytes", longest, longest},
		{"a colon and an at sign", "a:b@c", "a:b@c"},
		{"a space", "a b", "a b"},
		{"a slash", "a/b", "a/b"},
		{"a letter outside ASCII", "café", "café"},
		{"128 bytes of two-byte letters", twoByteLetters, twoByteLetters},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newDefault(t, Config{Name: tt.tenant})
			if !isReady(d) {
				t.Errorf("Ready() is open before Run, want closed")
			}
			if got := d.ID(); got != tt.want {
				t.Errorf("ID() = %q, want %q", got, tt.want)
			}
		})
	}
}

// White space is not an address: a deployment that blanks the setting with a
// space or a line break has no tenant-manager, and its name is used as given,
// even one tenant-manager would not take.
func TestNewDefault_ReadsABlankManagerURLAsNoTenantManager(t *testing.T) {
	for _, address := range []string{" ", "\t\n"} {
		t.Run(fmt.Sprintf("%q", address), func(t *testing.T) {
			manager := &fakeManager{}
			d := newDefault(t, Config{Name: "a b", ManagerURL: address, Transport: manager})
			runBriefly(t, d)
			if got := d.ID(); got != "a b" {
				t.Errorf("ID() = %q, want %q", got, "a b")
			}
			if got := manager.requests(); len(got) != 0 {
				t.Errorf("Run() sent %q, want no request", got)
			}
		})
	}
}

func TestDefault_RunSendsNoRequestWithoutTenantManager(t *testing.T) {
	manager := &fakeManager{}
	d := newDefault(t, Config{Transport: manager})
	runBriefly(t, d)
	if got := manager.requests(); len(got) != 0 {
		t.Errorf("Run() sent %q, want no request", got)
	}
}

func TestNewDefault_RefusesANameTenantManagerDoesNotTake(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"129 characters", strings.Repeat("a", 129)},
		{"a space", "a b"},
		{"a slash", "a/b"},
		{"a letter outside ASCII", "caf\u00e9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewDefault(Config{Name: tt.value, ManagerURL: managerURL}); err == nil {
				t.Errorf("NewDefault(Name: %q, ManagerURL: %q) error = nil, want an error", tt.value, managerURL)
			}
		})
	}
}

// A name used as given is the key of the policy data, so a control character
// or broken UTF-8, such as a line break left over from the configuration, is
// refused at start.
func TestNewDefault_RefusesANameThatCannotBeUsedAsGiven(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"129 bytes", strings.Repeat("a", 129)},
		{"128 bytes of two-byte letters and one more byte", strings.Repeat("\u00e9", 64) + "a"},
		{"a line break", "a\nb"},
		{"a tab", "a\tb"},
		{"DEL", "a\x7fb"},
		{"a C1 control character", "a\u0085b"},
		{"broken UTF-8", "a\xffb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewDefault(Config{Name: tt.value}); err == nil {
				t.Errorf("NewDefault(Name: %q) error = nil, want an error", tt.value)
			}
		})
	}
}

// The error of a refused name reaches the log of a failed start, so it quotes
// the name and cuts it after 64 bytes with the cut marked.
func TestNewDefault_QuotesTheRefusedNameInItsError(t *testing.T) {
	tests := []struct {
		name   string
		tenant string
		quoted string
	}{
		{"a short name", "a/b", `"a/b"`},
		{"64 bytes", strings.Repeat("a", 63) + "/", `"` + strings.Repeat("a", 63) + `/"`},
		{"65 bytes", strings.Repeat("a", 64) + "/", `"` + strings.Repeat("a", 64) + `"...`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewDefault(Config{Name: tt.tenant, ManagerURL: managerURL})
			if err == nil {
				t.Fatalf("NewDefault(Name: %q) error = nil, want an error", tt.tenant)
			}
			if want := "default tenant " + tt.quoted + ": "; !strings.HasPrefix(err.Error(), want) {
				t.Errorf("NewDefault(Name: %q) error = %q, want it to start with %q", tt.tenant, err, want)
			}
		})
	}
}

// The error reaches the log of a failed start, so it quotes no part of the URL,
// which can hold a password.
func TestNewDefault_RefusesAnInvalidManagerURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"no scheme", "tenant-manager:8080"},
		{"another scheme", "ftp://tenant-manager"},
		{"no host", "http://"},
		{"a port with no host name", "http://:8080"},
		{"a relative path", "/tenant-manager"},
		{"a user with a password", "http://user:secret@tenant-manager"},
		{"a query", "http://tenant-manager?secret=1"},
		{"an empty query", "http://tenant-manager?"},
		{"a fragment", "http://tenant-manager#secret"},
		{"an empty fragment", "http://tenant-manager#"},
		{"an address that does not parse", "http://user:secret@tenant-manager:port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewDefault(Config{ManagerURL: tt.url})
			if err == nil {
				t.Fatalf("NewDefault(ManagerURL: %q) error = nil, want an error", tt.url)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Errorf("NewDefault(ManagerURL: %q) error %q quotes the URL", tt.url, err)
			}
		})
	}
}

func TestDefault_RunAsksTenantManagerForTheName(t *testing.T) {
	const path = "/api/v4/tenant-manager/registration/tenants?dns="
	tests := []struct {
		name       string
		managerURL string
		tenant     string
		want       string
	}{
		{"default name", managerURL, "", managerURL + path + "default"},
		{"named tenant", managerURL, "acme", managerURL + path + "acme"},
		{"trailing slash", managerURL + "/", "acme", managerURL + path + "acme"},
		{"white space around the URL", " " + managerURL + "\n", "acme", managerURL + path + "acme"},
		{"https and a path", "https://gateway/tenants/", "acme", "https://gateway/tenants" + path + "acme"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := &fakeManager{next: reply{status: http.StatusOK, body: uuid}}
			d := newDefault(t, Config{Name: tt.tenant, ManagerURL: tt.managerURL, Transport: manager})
			runBriefly(t, d)
			got := manager.requests()
			if len(got) != 1 || got[0] != tt.want {
				t.Fatalf("Run() sent %q, want one request to %q", got, tt.want)
			}
			if got := manager.accepts[0]; got != "text/plain" {
				t.Errorf("Accept header = %q, want %q", got, "text/plain")
			}
		})
	}
}

func TestDefault_ReadyWaitsForTheAnswer(t *testing.T) {
	manager := &fakeManager{next: reply{status: http.StatusOK, body: uuid}}
	d := newDefault(t, Config{ManagerURL: managerURL, Transport: manager})
	if isReady(d) {
		t.Error("Ready() is closed before Run, want open")
	}
	if got := d.ID(); got != "" {
		t.Errorf("ID() = %q before Run, want empty", got)
	}
	runBriefly(t, d)
	if !isReady(d) {
		t.Error("Ready() is open after the answer, want closed")
	}
}

// Ready closes once however many calls of Run get the key: both calls here
// send their request before either gets the response.
func TestDefault_TwoRunsAtOnceCloseReadyOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := make(chan struct{})
		manager := &fakeManager{next: reply{status: http.StatusOK, body: uuid}, gate: gate}
		log := &recorder{}
		d := newDefault(t, Config{ManagerURL: managerURL, Transport: manager, Log: log})
		go d.Run(t.Context())
		go d.Run(t.Context())
		synctest.Wait()
		if got := manager.requests(); len(got) != 2 {
			t.Fatalf("requests before the response = %q, want two", got)
		}
		close(gate)
		synctest.Wait()
		if got := d.ID(); got != uuid {
			t.Errorf("ID() = %q, want %q", got, uuid)
		}
		if len(log.infos) != 1 {
			t.Errorf("records = %q, want one", log.infos)
		}
	})
}

// The other tests answer through fakeManager, whose body needs no open
// connection; this one reads the body from a socket, as a deployment does.
func TestDefault_RunReadsTheIdentifierOverAConnection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, uuid)
	}))
	t.Cleanup(srv.Close)
	log := &recorder{}
	d := newDefault(t, Config{ManagerURL: srv.URL, Log: log})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	d.Run(ctx)
	if got := d.ID(); got != uuid {
		t.Errorf("ID() = %q, want %q; warnings: %q", got, uuid, log.warns)
	}
}

func TestDefault_RunAsksOnlyUntilItHasTheIdentifier(t *testing.T) {
	manager := &fakeManager{next: reply{status: http.StatusOK, body: uuid}}
	d := newDefault(t, Config{ManagerURL: managerURL, Transport: manager})
	runBriefly(t, d)
	runBriefly(t, d)
	if got := manager.requests(); len(got) != 1 {
		t.Errorf("two calls of Run sent %q, want one request", got)
	}
}

func TestDefault_TakesTheIdentifierFromTheAnswer(t *testing.T) {
	longest := strings.Repeat("a", 128)
	tests := []struct {
		name   string
		answer reply
		want   string
	}{
		{"UUID", reply{status: http.StatusOK, body: uuid}, uuid},
		{"one character", reply{status: http.StatusOK, body: "a"}, "a"},
		{"trailing newline", reply{status: http.StatusOK, body: uuid + "\n"}, uuid},
		{"leading space", reply{status: http.StatusOK, body: " " + uuid}, uuid},
		{"status 201", reply{status: http.StatusCreated, body: uuid}, uuid},
		{"status 299", reply{status: 299, body: uuid}, uuid},
		{"128 characters", reply{status: http.StatusOK, body: longest}, longest},
		{"1024 bytes", reply{status: http.StatusOK, body: uuid + strings.Repeat(" ", 1024-len(uuid))}, uuid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := &fakeManager{next: tt.answer}
			d := newDefault(t, Config{ManagerURL: managerURL, Transport: manager})
			runBriefly(t, d)
			if got := d.ID(); got != tt.want {
				t.Errorf("ID() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Each case fails the first attempt, and Run gets the identifier on the next
// one.
func TestDefault_RetriesAfterAnAnswerThatGivesNoIdentifier(t *testing.T) {
	tests := []struct {
		name   string
		answer reply
	}{
		{"unknown tenant", reply{status: http.StatusNotFound}},
		{"token refused", reply{status: http.StatusUnauthorized}},
		{"server error", reply{status: http.StatusInternalServerError}},
		{"identifier beside a failure status", reply{status: http.StatusServiceUnavailable, body: uuid}},
		{"redirect", reply{status: http.StatusFound, location: "http://elsewhere/", body: uuid}},
		{"status 300", reply{status: http.StatusMultipleChoices, body: uuid}},
		{"status below 200", reply{status: http.StatusSwitchingProtocols, body: uuid}},
		{"no token yet", reply{err: outbound.ErrNoToken}},
		{"no connection", reply{err: errors.New("connection refused")}},
		{"answer cut short", reply{status: http.StatusOK, body: uuid, bodyErr: errors.New("connection reset")}},
		{"empty answer", reply{status: http.StatusOK}},
		{"URL", reply{status: http.StatusOK, body: "http://elsewhere/"}},
		{"slash", reply{status: http.StatusOK, body: "a/b"}},
		{"space inside", reply{status: http.StatusOK, body: "a b"}},
		{"129 characters", reply{status: http.StatusOK, body: strings.Repeat("a", 129)}},
		{"1025 bytes", reply{status: http.StatusOK, body: uuid + strings.Repeat(" ", 1025-len(uuid))}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { checkRetriesAfter(t, tt.answer) })
	}
}

// checkRetriesAfter runs a Default against a tenant-manager that gives answer
// on the first attempt and an identifier on the second.
func checkRetriesAfter(t *testing.T, answer reply) {
	synctest.Test(t, func(t *testing.T) {
		manager := &fakeManager{next: answer}
		log := &recorder{}
		d := newDefault(t, Config{ManagerURL: managerURL, Transport: manager, Log: log})
		go d.Run(t.Context())
		synctest.Wait()
		if isReady(d) {
			t.Fatalf("Ready() is closed after the answer, ID() = %q, want open", d.ID())
		}
		if len(log.warns) != 1 {
			t.Fatalf("warnings after one attempt = %q, want one", log.warns)
		}
		if got := log.warns[0]; !strings.HasPrefix(got, "default tenant: tenant-manager") {
			t.Errorf("warning %q does not start with the source of the failure", got)
		}
		if got := manager.requests(); len(got) != 1 || got[0] != lookupURL {
			t.Errorf("requests after one attempt = %q, want one to %q", got, lookupURL)
		}
		manager.answerWith(reply{status: http.StatusOK, body: uuid})
		time.Sleep(time.Second)
		synctest.Wait()
		if got := d.ID(); got != uuid {
			t.Errorf("ID() after the good answer = %q, want %q", got, uuid)
		}
	})
}

func TestDefault_RunReadsNoMoreOfAnAnswerThanOneByteOverTheLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		body := &countingReader{r: strings.NewReader(strings.Repeat("a", 1<<20))}
		manager := &fakeManager{next: reply{status: http.StatusOK, reader: body}}
		d := newDefault(t, Config{ManagerURL: managerURL, Transport: manager})
		go d.Run(t.Context())
		synctest.Wait()
		if got := body.read.Load(); got > 1025 {
			t.Errorf("bytes read = %d, want at most 1025", got)
		}
	})
}

func TestDefault_RunPausesLongerAfterEachFailedAttempt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		manager := &fakeManager{next: reply{status: http.StatusNotFound}}
		d := newDefault(t, Config{ManagerURL: managerURL, Transport: manager})
		go d.Run(t.Context())
		time.Sleep(35*time.Second + time.Millisecond)
		synctest.Wait()
		want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second, 10 * time.Second}
		if got := len(manager.times); got != len(want)+1 {
			t.Fatalf("attempts = %d, want %d", got, len(want)+1)
		}
		for i, pause := range want {
			if got := manager.times[i+1].Sub(manager.times[i]); got != pause {
				t.Errorf("pause %d = %s, want %s", i+1, got, pause)
			}
		}
	})
}

func TestDefault_RunGivesUpOnARequestAfterFiveSeconds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		manager := &fakeManager{block: true}
		d := newDefault(t, Config{ManagerURL: managerURL, Transport: manager})
		go d.Run(t.Context())
		time.Sleep(6*time.Second + time.Millisecond)
		synctest.Wait()
		if got := len(manager.times); got != 2 {
			t.Fatalf("attempts = %d, want 2", got)
		}
		if got, want := manager.times[1].Sub(manager.times[0]), 6*time.Second; got != want {
			t.Errorf("second attempt came after %s, want %s: 5 s of the request and a pause of 1 s", got, want)
		}
	})
}

func TestDefault_RunStopsWhenItsContextEnds(t *testing.T) {
	tests := []struct {
		name     string
		manager  *fakeManager
		warnings int
	}{
		{"during a pause", &fakeManager{next: reply{status: http.StatusNotFound}}, 1},
		{"during a request", &fakeManager{block: true}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				log := &recorder{}
				d := newDefault(t, Config{ManagerURL: managerURL, Transport: tt.manager, Log: log})
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan struct{})
				go func() {
					d.Run(ctx)
					close(done)
				}()
				synctest.Wait()
				cancel()
				<-done
				if isReady(d) {
					t.Error("Ready() is closed after the context ended, want open")
				}
				if got := len(log.warns); got != tt.warnings {
					t.Errorf("warnings = %d, want %d: %q", got, tt.warnings, log.warns)
				}
				if got := tt.manager.requests(); len(got) != 1 {
					t.Errorf("requests = %d, want 1", len(got))
				}
			})
		})
	}
}

// When the service does not become ready, the log is all an operator has:
// every warning has to name what failed, both causes of a 404, and that the
// service waits, and the record of success has to name the identifier, so a
// substituted one can be checked against tenant-manager.
func TestDefault_RunWarnsOnEachFailedAttemptAndRecordsTheTranslation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		manager := &fakeManager{next: reply{status: http.StatusNotFound}}
		log := &recorder{}
		d := newDefault(t, Config{ManagerURL: managerURL, Transport: manager, Log: log})
		go d.Run(t.Context())
		time.Sleep(time.Second)
		synctest.Wait()
		manager.answerWith(reply{status: http.StatusOK, body: uuid})
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if len(log.warns) != 2 {
			t.Fatalf("warnings = %q, want two", log.warns)
		}
		for i, pause := range []string{"retrying in 1s", "retrying in 2s"} {
			checkNames(t, log.warns[i], lookupURL, "HTTP 404", "no tenant of this name", "the tenant-manager URL", "not ready", pause)
		}
		if len(log.infos) != 1 {
			t.Fatalf("records = %q, want one", log.infos)
		}
		checkNames(t, log.infos[0], `"default"`, uuid)
	})
}

// checkNames reports each of parts that line does not hold.
func checkNames(t *testing.T, line string, parts ...string) {
	t.Helper()
	for _, part := range parts {
		if !strings.Contains(line, part) {
			t.Errorf("log line %q does not name %q", line, part)
		}
	}
}

// The response body is the text of another service, and the warning goes into
// a log line, so the warning quotes the body, escapes a line break, and cuts
// the text after 64 bytes with the cut marked.
func TestDefault_RunQuotesTheRefusedResponseBodyInItsWarning(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		quoted string
	}{
		{"a short body", "a/b", `the response body "a/b" is not`},
		{"a line break and a long body", "a\nb" + strings.Repeat("c", 500), `the response body "a\nb` + strings.Repeat("c", 61) + `"... is not`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				manager := &fakeManager{next: reply{status: http.StatusOK, body: tt.body}}
				log := &recorder{}
				d := newDefault(t, Config{ManagerURL: managerURL, Transport: manager, Log: log})
				go d.Run(t.Context())
				synctest.Wait()
				if len(log.warns) != 1 {
					t.Fatalf("warnings = %q, want one", log.warns)
				}
				if got := log.warns[0]; !strings.Contains(got, tt.quoted) {
					t.Errorf("warning %q does not hold %q", got, tt.quoted)
				}
			})
		})
	}
}

// A refused redirect leaves the service not ready until the URL changes, so
// the warning of every 3xx says that redirects are not followed and names the
// address the redirect points to; a 4xx says nothing about redirects.
func TestDefault_RunNamesTheTargetOfARefusedRedirect(t *testing.T) {
	const target = "https://tenant-manager:8443/api"
	tests := []struct {
		name   string
		answer reply
		want   string
	}{
		{"300 without a Location", reply{status: http.StatusMultipleChoices}, `HTTP 300 without a Location: redirects are not followed`},
		{"301", reply{status: http.StatusMovedPermanently, location: target}, `HTTP 301 to "` + target + `": redirects are not followed`},
		{"399", reply{status: 399, location: target}, `HTTP 399 to "` + target + `": redirects are not followed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstWarning(t, tt.answer); !strings.Contains(got, tt.want) {
				t.Errorf("warning %q does not hold %q", got, tt.want)
			}
		})
	}
	t.Run("400", func(t *testing.T) {
		if got := firstWarning(t, reply{status: http.StatusBadRequest, location: target}); strings.Contains(got, "redirect") {
			t.Errorf("warning %q speaks of a redirect after HTTP 400", got)
		}
	})
}

// firstWarning runs a Default against a tenant-manager that gives answer, and
// returns the warning of the first attempt.
func firstWarning(t *testing.T, answer reply) string {
	t.Helper()
	var warning string
	synctest.Test(t, func(t *testing.T) {
		log := &recorder{}
		d := newDefault(t, Config{ManagerURL: managerURL, Transport: &fakeManager{next: answer}, Log: log})
		go d.Run(t.Context())
		synctest.Wait()
		if len(log.warns) != 1 {
			t.Fatalf("warnings = %q, want one", log.warns)
		}
		warning = log.warns[0]
	})
	return warning
}

// Without a tenant-manager URL, NewDefault logs the name it uses, so a
// deployment that lost the URL by mistake shows it in the log.
func TestNewDefault_RecordsThatTheNameIsUsedAsGiven(t *testing.T) {
	log := &recorder{}
	newDefault(t, Config{Name: "acme", Log: log})
	if len(log.infos) != 1 || !strings.Contains(log.infos[0], `"acme"`) || !strings.Contains(log.infos[0], "no tenant-manager URL") {
		t.Errorf("records = %q, want one that names the tenant and the missing URL", log.infos)
	}
}
