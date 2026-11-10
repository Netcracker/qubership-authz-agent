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
	next, block := f.next, f.block
	f.mu.Unlock()
	if block {
		<-r.Context().Done()
		return nil, r.Context().Err()
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
	tests := []struct {
		name   string
		tenant string
		want   string
	}{
		{"no name", "", "default"},
		{"letters", "acme", "acme"},
		{"one character", "a", "a"},
		{"every allowed sign", "a.b_c-d", "a.b_c-d"},
		{"digits and upper case", "Tenant42", "Tenant42"},
		{"128 characters", longest, longest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newDefault(t, Config{Name: tt.tenant})
			if !d.Ready() {
				t.Errorf("Ready() = false before Run, want true")
			}
			if got := d.ID(); got != tt.want {
				t.Errorf("ID() = %q, want %q", got, tt.want)
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

func TestNewDefault_RefusesAnInvalidName(t *testing.T) {
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
		for _, address := range []string{"", managerURL} {
			t.Run(tt.name+" with manager URL "+address, func(t *testing.T) {
				if _, err := NewDefault(Config{Name: tt.value, ManagerURL: address}); err == nil {
					t.Errorf("NewDefault(Name: %q, ManagerURL: %q) error = nil, want an error", tt.value, address)
				}
			})
		}
	}
}

// The name reaches the log of a failed start, so its error cuts a long name and
// marks the cut.
func TestNewDefault_CutsALongNameInItsError(t *testing.T) {
	_, err := NewDefault(Config{Name: strings.Repeat("a", 500)})
	if err == nil {
		t.Fatal("NewDefault() error = nil, want an error")
	}
	if got := err.Error(); strings.Contains(got, strings.Repeat("a", 65)) || !strings.Contains(got, `"...`) {
		t.Errorf("NewDefault() error = %q, want the name cut to 64 bytes with the cut marked", got)
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
	if d.Ready() {
		t.Error("Ready() = true before Run, want false")
	}
	if got := d.ID(); got != "" {
		t.Errorf("ID() = %q before Run, want empty", got)
	}
	runBriefly(t, d)
	if !d.Ready() {
		t.Error("Ready() = false after the answer, want true")
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

// Each answer fails one attempt, and the next attempt gets a good answer, so
// the service becomes ready once tenant-manager repairs itself.
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
		if d.Ready() {
			t.Fatalf("Ready() = true after the answer, ID() = %q, want false", d.ID())
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
				if d.Ready() {
					t.Error("Ready() = true after the context ended, want false")
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

// The reader of a stuck start holds the log: every warning has to name what
// failed and that the service waits, and the record of success has to name the
// answer, so a substituted identifier can be checked against tenant-manager.
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
			checkNames(t, log.warns[i], lookupURL, "HTTP 404", "no tenant of this name", "not ready", pause)
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

// The answer is the text of another service, and the warning goes into a log
// line, so the warning escapes a line break and cuts the text with a mark.
func TestDefault_RunEscapesAndCutsAnAnswerInItsWarning(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		answer := "a\nb" + strings.Repeat("c", 500)
		manager := &fakeManager{next: reply{status: http.StatusOK, body: answer}}
		log := &recorder{}
		d := newDefault(t, Config{ManagerURL: managerURL, Transport: manager, Log: log})
		go d.Run(t.Context())
		synctest.Wait()
		if len(log.warns) != 1 {
			t.Fatalf("warnings = %q, want one", log.warns)
		}
		got := log.warns[0]
		if strings.Contains(got, "\n") {
			t.Errorf("warning %q holds a raw line break", got)
		}
		if strings.Contains(got, strings.Repeat("c", 62)) || !strings.Contains(got, `"...`) {
			t.Errorf("warning %q does not cut the answer to 64 bytes with the cut marked", got)
		}
	})
}

// A deployment that lost its tenant-manager URL takes the name without a word
// unless this record says so.
func TestNewDefault_RecordsThatTheNameIsUsedAsGiven(t *testing.T) {
	log := &recorder{}
	newDefault(t, Config{Name: "acme", Log: log})
	if len(log.infos) != 1 || !strings.Contains(log.infos[0], `"acme"`) || !strings.Contains(log.infos[0], "no tenant-manager URL") {
		t.Errorf("records = %q, want one that names the tenant and the missing URL", log.infos)
	}
}
