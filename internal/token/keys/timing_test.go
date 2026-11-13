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

package keys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// fakeTransport answers the requests of a Keycloak and of providers in memory,
// so that the tests of this package run on the fake clock of a synctest bubble,
// where a real socket never counts as idle. Every provider publishes the JWKS
// jwks, and so does every realm unless realms is set.
type fakeTransport struct {
	mu sync.Mutex
	// jwks is the JWKS of every provider, and of every realm unless realms is
	// set.
	jwks []byte
	// realms, when non-nil, holds the keys of each realm of keycloakHost by
	// the name as it appears in an address, and a realm it does not hold
	// answers 404.
	realms map[string][]json.RawMessage
	// discoveries lists the escaped path of every discovery request, in order.
	discoveries []string
	// down, when true, fails every request.
	down bool
	// status, when it holds a host, answers every request to that host with
	// that status.
	status map[string]int
	// hold, when non-nil, holds every JWKS response until it is closed.
	hold chan struct{}
	// fetches counts the JWKS requests, and active those that run now.
	fetches, active int
	// fetched holds the time of the last JWKS request to each address.
	fetched map[string]time.Time
}

func newFakeTransport(t *testing.T) *fakeTransport {
	t.Helper()
	jwks, err := json.Marshal(map[string]any{"keys": []json.RawMessage{ecJWK(t, "k1", nil)}})
	if err != nil {
		t.Fatal(err)
	}
	return &fakeTransport{jwks: jwks, status: map[string]int{}, fetched: map[string]time.Time{}}
}

func (f *fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	path := r.URL.EscapedPath()
	f.mu.Lock()
	down, status := f.down, f.status[r.URL.Host]
	discovery := strings.HasSuffix(path, "/.well-known/openid-configuration")
	if discovery {
		f.discoveries = append(f.discoveries, path)
	}
	jwks, known := f.jwks, true
	if f.realms != nil && r.URL.Host == keycloakHost {
		realm, _, _ := strings.Cut(strings.TrimPrefix(path, realmsPath), "/")
		var keys []json.RawMessage
		if keys, known = f.realms[realm]; known {
			jwks, _ = json.Marshal(map[string]any{"keys": keys})
		}
	}
	f.mu.Unlock()
	switch {
	case down:
		return nil, errors.New("connection refused")
	case status != 0:
		return &http.Response{StatusCode: status, Body: http.NoBody}, nil
	case !known:
		return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody}, nil
	case discovery:
		address, _ := strings.CutSuffix(r.URL.String(), "/.well-known/openid-configuration")
		body, err := json.Marshal(map[string]string{"jwks_uri": address + "/jwks"})
		return response(body), err
	}
	f.mu.Lock()
	f.fetches++
	f.active++
	f.fetched[r.URL.String()] = time.Now()
	hold := f.hold
	f.mu.Unlock()
	if hold != nil {
		select {
		case <-hold:
		case <-r.Context().Done():
		}
	}
	f.mu.Lock()
	f.active--
	f.mu.Unlock()
	return response(jwks), nil
}

func response(body []byte) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body)))}
}

// publish sets jwks to a JWKS that lists keys.
func (f *fakeTransport) publish(t *testing.T, keys ...json.RawMessage) {
	t.Helper()
	jwks, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jwks = jwks
}

// keycloakHost is the host of the Keycloak of [newKeycloakTransport], and
// keycloakURL its address.
const (
	keycloakHost = "keycloak.test"
	keycloakURL  = "http://" + keycloakHost
)

// newKeycloakTransport returns a fakeTransport whose Keycloak holds no realm
// yet.
func newKeycloakTransport(t *testing.T) *fakeTransport {
	t.Helper()
	f := newFakeTransport(t)
	f.realms = map[string][]json.RawMessage{}
	return f
}

// publishRealm sets the keys of realm, creating it.
func (f *fakeTransport) publishRealm(realm string, keys ...json.RawMessage) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.realms[realm] = keys
}

// removeRealm makes realm answer 404, as a realm deleted from Keycloak does.
func (f *fakeTransport) removeRealm(realm string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.realms, realm)
}

// loadCount returns how many discovery requests have arrived.
func (f *fakeTransport) loadCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.discoveries)
}

// loadsOf returns how many discovery requests asked for realm.
func (f *fakeTransport) loadsOf(realm string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	want := realmsPath + realm + "/.well-known/openid-configuration"
	count := 0
	for _, path := range f.discoveries {
		if path == want {
			count++
		}
	}
	return count
}

// paths returns the escaped path of every discovery request, in order.
func (f *fakeTransport) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.discoveries)
}

// keycloakSet returns a Set of opts whose Keycloak is the one of kc.
func keycloakSet(t *testing.T, kc *fakeTransport, opts Options) *Set {
	t.Helper()
	return bubbleSetOf(t, Config{Keycloak: &Keycloak{URL: keycloakURL}}, opts, kc)
}

// setStatus answers every request to host with status, or with the JWKS again
// when status is 0.
func (f *fakeTransport) setStatus(host string, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status[host] = status
}

func (f *fakeTransport) setHold(hold chan struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hold = hold
}

func (f *fakeTransport) count() (fetches, active int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetches, f.active
}

func (f *fakeTransport) fetchTimes() map[string]time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return maps.Clone(f.fetched)
}

// bubbleSet returns a Set that requires the realm cloud-common of a Keycloak
// reached through transport, with no other option set.
func bubbleSet(t *testing.T, transport http.RoundTripper, log Logger) *Set {
	t.Helper()
	cfg := Config{Keycloak: &Keycloak{URL: "http://keycloak.test", RequiredRealms: []string{"cloud-common"}}}
	return bubbleSetOf(t, cfg, Options{Log: log}, transport)
}

// bubbleSetOf returns a Set of cfg and opts whose every source is reached
// through transport.
func bubbleSetOf(t *testing.T, cfg Config, opts Options, transport http.RoundTripper) *Set {
	t.Helper()
	set := mustNew(t, cfg, opts)
	if set.keycloakClient != nil {
		set.keycloakClient.Transport = transport
	}
	for _, src := range set.providers {
		src.fetcher.client.Transport = transport
	}
	return set
}

// providerOf is a provider of the fake host idp.test.
func providerOf(id string) Provider { return Provider{ID: id, Issuer: "http://idp.test"} }

// runSet starts Run with a context of its own and returns the function that
// ends it and waits for Run to return.
func runSet(t *testing.T, set *Set) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		set.Run(ctx)
		close(done)
	}()
	return func() {
		cancel()
		<-done
	}
}

func TestLookupOrReload_WaitsThreeSecondsForAReloadByDefault(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := newFakeTransport(t)
		set := bubbleSet(t, transport, nil)
		if err := set.Refresh(t.Context()); err != nil {
			t.Fatalf("Refresh() error = %v", err)
		}
		hold := make(chan struct{})
		transport.setHold(hold)
		start := time.Now()
		_, err := set.LookupOrReload(t.Context(), Query{Issuer: iss("cloud-common"), KID: "rotated"})
		if !errors.Is(err, ErrKeyUnknown) {
			t.Errorf("LookupOrReload() error = %v, want %v", err, ErrKeyUnknown)
		}
		if got := time.Since(start); got != 3*time.Second {
			t.Errorf("LookupOrReload() returned after %s, want 3s", got)
		}
		close(hold)
		synctest.Wait()
	})
}

// The hourly reload of a source falls at most 6 minutes after the hour, a tenth
// of the interval.
func TestRun_ReloadsEveryHourByDefault(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := newFakeTransport(t)
		set := bubbleSet(t, transport, nil)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			set.Run(ctx)
			close(done)
		}()
		time.Sleep(time.Hour - time.Second)
		synctest.Wait()
		if got, _ := transport.count(); got != 1 {
			t.Errorf("JWKS requests a second before the hour = %d, want 1", got)
		}
		time.Sleep(6*time.Minute + 2*time.Second)
		synctest.Wait()
		if got, _ := transport.count(); got != 2 {
			t.Errorf("JWKS requests a second after the hour and 6 minutes = %d, want 2", got)
		}
		cancel()
		<-done
	})
}

// The delays are random, so ten sources show that each draws its own. A delay
// shared by two sources gives them one time.
func TestRun_ReloadsEachSourceAtATimeOfItsOwnWithinATenthOfTheInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := newFakeTransport(t)
		names := make([]string, 10)
		for i := range names {
			names[i] = fmt.Sprintf("realm-%d", i)
		}
		set := mustNew(t, Config{Keycloak: &Keycloak{URL: "http://keycloak.test", RequiredRealms: names}}, Options{})
		set.keycloakClient.Transport = transport
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		started := time.Now()
		go func() {
			set.Run(ctx)
			close(done)
		}()
		time.Sleep(time.Hour + 6*time.Minute + time.Second)
		synctest.Wait()
		cancel()
		<-done
		seen := map[time.Time]string{}
		for address, at := range transport.fetchTimes() {
			if delay := at.Sub(started) - time.Hour; delay < 0 || delay >= 6*time.Minute {
				t.Errorf("reload of %s fell %s after the hour, want at least 0s and less than 6m0s", address, delay)
			}
			if other, ok := seen[at]; ok {
				t.Errorf("%s and %s reloaded at the same time", other, address)
			}
			seen[at] = address
		}
		if len(seen) != len(names) {
			t.Errorf("sources reloaded = %d, want %d", len(seen), len(names))
		}
	})
}

// The interval is not the default, so a bound fixed at 6 minutes fails the test.
func TestRun_BoundsTheJitterByATenthOfTheInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		set := bubbleSet(t, newFakeTransport(t), nil)
		set.opts.RefreshInterval = 30 * time.Minute
		var limits []time.Duration
		set.opts.jitter = func(limit time.Duration) time.Duration {
			limits = append(limits, limit)
			return 0
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			set.Run(ctx)
			close(done)
		}()
		time.Sleep(30*time.Minute + time.Second)
		cancel()
		<-done
		if want := []time.Duration{3 * time.Minute}; !slices.Equal(limits, want) {
			t.Errorf("jitter limits = %v, want %v", limits, want)
		}
	})
}

// The jitter is an hour here, so the first load is the only request the run
// can make before its context ends.
func TestRun_StopsWaitingForTheJitterWhenItsContextEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := newFakeTransport(t)
		set := bubbleSet(t, transport, nil)
		set.opts.jitter = func(time.Duration) time.Duration { return time.Hour }
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			set.Run(ctx)
			close(done)
		}()
		time.Sleep(time.Hour + time.Second)
		started := time.Now()
		cancel()
		<-done
		if got := time.Since(started); got != 0 {
			t.Errorf("Run() returned %s after its context ended, want 0s", got)
		}
		if got, _ := transport.count(); got != 1 {
			t.Errorf("JWKS requests = %d, want the 1 of the first load", got)
		}
	})
}

// The attempts run at 0, 1, 3, 7, 15, 25, 35, and 45 s, so 46 s hold eight
// pauses, and the ones after the fourth stay at the limit of 10 s.
func TestRun_DoublesThePauseBetweenAttemptsUpToTenSeconds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := newFakeTransport(t)
		transport.down = true
		log := &warnRecorder{}
		set := bubbleSet(t, transport, log)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			set.Run(ctx)
			close(done)
		}()
		time.Sleep(46 * time.Second)
		cancel()
		<-done
		var pauses []string
		for _, w := range log.warnings {
			if _, pause, ok := strings.Cut(w, "retrying in "); ok {
				pauses = append(pauses, pause)
			}
		}
		want := []string{"1s", "2s", "4s", "8s", "10s", "10s", "10s", "10s"}
		if !slices.Equal(pauses, want) {
			t.Errorf("pauses = %q, want %q", pauses, want)
		}
	})
}

// Ten realms wait on their JWKS responses, and synctest.Wait returns once all
// that can run are held.
func TestRefresh_FetchesAtMostEightSourcesAtATime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := newFakeTransport(t)
		set := bubbleSet(t, transport, nil)
		for i := range 9 {
			if _, err := lookupRealm(t, set, fmt.Sprintf("realm-%d", i)); err != nil {
				t.Fatalf("LookupOrReload(realm-%d) error = %v", i, err)
			}
		}
		hold := make(chan struct{})
		transport.setHold(hold)
		done := make(chan error, 1)
		go func() { done <- set.Refresh(t.Context()) }()
		synctest.Wait()
		if _, active := transport.count(); active != 8 {
			t.Errorf("JWKS requests running at once = %d, want 8", active)
		}
		close(hold)
		if err := <-done; err != nil {
			t.Errorf("Refresh() error = %v", err)
		}
	})
}

func TestRun_ReloadsOnTheInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := newFakeTransport(t)
		transport.publish(t, ecJWK(t, "old", nil))
		provider := providerOf("realm")
		set := bubbleSetOf(t, Config{Providers: []Provider{provider}}, Options{}, transport)
		if err := set.Refresh(t.Context()); err != nil {
			t.Fatalf("Refresh() error = %v", err)
		}
		transport.publish(t, ecJWK(t, "new", nil))
		stop := runSet(t, set)
		defer stop()
		time.Sleep(time.Hour + 6*time.Minute + time.Second)
		synctest.Wait()
		if !loaded(set, provider, "new") {
			t.Errorf("Lookup(%q) after the hourly reload found nothing, want the new key", "new")
		}
	})
}

// A required source fails in each of the two ways a reload reports, and then
// recovers. The attempts run at 0 s and 1 s, and the third at 3 s finds the
// key. Ready stays false until then, and nothing ends Run.
func TestRun_RetriesARequiredSourceUntilItHasAKey(t *testing.T) {
	tests := []struct {
		name    string
		fail    func(t *testing.T, transport *fakeTransport)
		cause   string
		recover func(t *testing.T, transport *fakeTransport)
	}{
		{
			"provider that answers 503",
			func(_ *testing.T, transport *fakeTransport) {
				transport.setStatus("idp.test", http.StatusServiceUnavailable)
			},
			"HTTP 503",
			func(_ *testing.T, transport *fakeTransport) { transport.setStatus("idp.test", 0) },
		},
		{
			"JWKS without a usable key",
			func(t *testing.T, transport *fakeTransport) {
				transport.publish(t, ecJWK(t, "enc", map[string]any{"use": "enc"}))
			},
			"no usable signing key",
			func(t *testing.T, transport *fakeTransport) { transport.publish(t, ecJWK(t, "k1", nil)) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				transport := newFakeTransport(t)
				tt.fail(t, transport)
				log := &warnRecorder{}
				set := bubbleSetOf(t, Config{Providers: []Provider{providerOf("realm")}}, Options{Log: log}, transport)
				stop := runSet(t, set)
				defer stop()
				time.Sleep(1500 * time.Millisecond)
				synctest.Wait()
				if got := log.count(tt.cause); got != 2 {
					t.Errorf("warnings that name %q after two attempts = %d, want 2; warnings: %q", tt.cause, got, log.warnings)
				}
				if set.Ready() {
					t.Errorf("Ready() = true while the provider has no keys, want false")
				}
				tt.recover(t, transport)
				time.Sleep(2 * time.Second)
				synctest.Wait()
				if !set.Ready() {
					t.Errorf("Ready() after the attempt at 3 s = false, want true")
				}
			})
		})
	}
}

// The pause before the next attempt lasts an hour, so only the end of the
// context can end it.
func TestRun_ReturnsWhenItsContextEndsDuringARetryPause(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := newFakeTransport(t)
		transport.setStatus("idp.test", http.StatusServiceUnavailable)
		log := &warnRecorder{}
		set := bubbleSetOf(t, Config{Providers: []Provider{providerOf("realm")}}, Options{firstRetryDelay: time.Hour, Log: log}, transport)
		stop := runSet(t, set)
		synctest.Wait()
		if got := log.count("retrying in 1h0m0s"); got != 1 {
			t.Errorf("warnings about the pause of an hour = %d, want 1; warnings: %q", got, log.warnings)
		}
		started := time.Now()
		stop()
		if got := time.Since(started); got != 0 {
			t.Errorf("Run() returned %s after its context ended, want 0s", got)
		}
	})
}

func TestRun_LogsAScheduledReloadThatFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := newFakeTransport(t)
		log := &warnRecorder{}
		set := bubbleSetOf(t, Config{Providers: []Provider{providerOf("realm")}}, Options{Log: log}, transport)
		if err := set.Refresh(t.Context()); err != nil {
			t.Fatalf("Refresh() error = %v", err)
		}
		transport.setStatus("idp.test", http.StatusServiceUnavailable)
		stop := runSet(t, set)
		defer stop()
		time.Sleep(time.Hour + 6*time.Minute + time.Second)
		synctest.Wait()
		if got := log.count("trusted providers: reload: "); got != 1 {
			t.Errorf("warnings about the hourly reload = %d, want 1; warnings: %q", got, log.warnings)
		}
	})
}

// The JWKS response is held, so the reload the call starts is still running
// when the call returns, and it loads the key once the response arrives.
func TestLookupOrReload_StopsWaitingWhenItsContextEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := newFakeTransport(t)
		provider := providerOf("realm")
		set := bubbleSetOf(t, Config{Providers: []Provider{provider}}, Options{}, transport)
		if err := set.Refresh(t.Context()); err != nil {
			t.Fatalf("Refresh() error = %v", err)
		}
		transport.publish(t, ecJWK(t, "k1", nil), ecJWK(t, "key-2", nil))
		hold := make(chan struct{})
		transport.setHold(hold)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		started := time.Now()
		if _, err := set.LookupOrReload(ctx, Query{Issuer: provider.Issuer, KID: "key-2"}); !errors.Is(err, ErrKeyUnknown) {
			t.Errorf("LookupOrReload(%q) with an ended context error = %v while the reload was held, want %v", "key-2", err, ErrKeyUnknown)
		}
		if got := time.Since(started); got != 0 {
			t.Errorf("LookupOrReload() with an ended context returned after %s, want 0s", got)
		}
		close(hold)
		synctest.Wait()
		if !loaded(set, provider, "key-2") {
			t.Errorf("Lookup(%q) after the held reload ended found nothing, want the key", "key-2")
		}
	})
}

// The JWKS response is held past ReloadWait, and the context of the call lasts.
func TestLookupOrReload_StopsWaitingAfterTheReloadWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := newFakeTransport(t)
		provider := providerOf("realm")
		set := bubbleSetOf(t, Config{Providers: []Provider{provider}}, Options{ReloadWait: 20 * time.Millisecond}, transport)
		if err := set.Refresh(t.Context()); err != nil {
			t.Fatalf("Refresh() error = %v", err)
		}
		transport.publish(t, ecJWK(t, "k1", nil), ecJWK(t, "key-2", nil))
		hold := make(chan struct{})
		transport.setHold(hold)
		started := time.Now()
		if _, err := set.LookupOrReload(t.Context(), Query{Issuer: provider.Issuer, KID: "key-2"}); !errors.Is(err, ErrKeyUnknown) {
			t.Errorf("LookupOrReload(%q) error = %v while the reload was held, want %v", "key-2", err, ErrKeyUnknown)
		}
		if got := time.Since(started); got != 20*time.Millisecond {
			t.Errorf("LookupOrReload() returned after %s, want the ReloadWait of 20ms", got)
		}
		close(hold)
		synctest.Wait()
		if !loaded(set, provider, "key-2") {
			t.Errorf("Lookup(%q) after the held reload ended found nothing, want the key", "key-2")
		}
	})
}

// The callers start together, and the JWKS response is held until all of them
// wait, so a second load would show as a second request.
func TestLookupOrReload_CallersOfANewRealmShareOneLoad(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := newFakeTransport(t)
		set := bubbleSetOf(t, Config{Keycloak: &Keycloak{URL: "http://keycloak.test"}}, Options{}, transport)
		hold := make(chan struct{})
		transport.setHold(hold)
		errs := make([]error, 32)
		var wg sync.WaitGroup
		for i := range errs {
			wg.Go(func() { _, errs[i] = lookupRealm(t, set, "tenant-1") })
		}
		synctest.Wait()
		close(hold)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Errorf("LookupOrReload() in goroutine %d error = %v", i, err)
			}
		}
		if fetches, _ := transport.count(); fetches != 1 {
			t.Errorf("JWKS requests = %d, want 1", fetches)
		}
	})
}

// Run loads the required realm, and the provider stays down until the test
// lets it answer: readiness needs both. The provider's next attempt runs at 1 s.
func TestRun_LoadsARequiredRealmAndReadinessWaitsForEveryRequiredSource(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := newFakeTransport(t)
		transport.setStatus("idp.test", http.StatusServiceUnavailable)
		cfg := Config{
			Keycloak:  &Keycloak{URL: "http://keycloak.test", RequiredRealms: []string{"cloud-common"}},
			Providers: []Provider{providerOf("trusted")},
		}
		set := bubbleSetOf(t, cfg, Options{}, transport)
		stop := runSet(t, set)
		defer stop()
		synctest.Wait()
		key, err := set.Lookup(Query{Issuer: iss("cloud-common"), KID: "k1"})
		if err != nil {
			t.Errorf("Lookup(the key of the required realm) error = %v, want none", err)
		}
		if want := (Source{Realm: "cloud-common"}); key.Source != want {
			t.Errorf("Lookup(the key of the required realm).Source = %+v, want %+v", key.Source, want)
		}
		if set.Ready() {
			t.Errorf("Ready() = true while the provider is down, want false")
		}
		transport.setStatus("idp.test", 0)
		time.Sleep(time.Second)
		synctest.Wait()
		if !set.Ready() {
			t.Errorf("Ready() after the provider answered = false, want true")
		}
	})
}

// The issuer of the provider also has the form of a realm of the Keycloak, and
// the Keycloak is not asked.
func TestLookupOrReload_PrefersAProviderToARealmOfTheSameIssuer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		provider := Provider{ID: "external", Issuer: "https://idp.example/auth/realms/external", JWKSURI: "http://idp.test/jwks"}
		set := bubbleSetOf(t, Config{Keycloak: &Keycloak{URL: keycloakURL}, Providers: []Provider{provider}}, testOptions(), kc)
		key, err := set.LookupOrReload(t.Context(), Query{Issuer: provider.Issuer, KID: "k1"})
		if err != nil {
			t.Fatalf("LookupOrReload() error = %v", err)
		}
		if got := key.Source.ID(); got != "external" {
			t.Errorf("Source.ID() = %q, want %q", got, "external")
		}
		if got := kc.loadCount(); got != 0 {
			t.Errorf("discovery requests = %d, want 0", got)
		}
	})
}

// The provider publishes key-2 after the first load, as a rotation does;
// key-1 is the control that the first load already loaded, which comes back
// without a request.
func TestLookupOrReload_ReloadsForAKIDNoLoadedKeyHas(t *testing.T) {
	tests := []struct {
		name        string
		kid         string
		discoveries int
	}{
		{"kid of the first load", "key-1", 1},
		{"kid published after the first load", "key-2", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				transport := newFakeTransport(t)
				transport.publish(t, ecJWK(t, "key-1", nil))
				provider := providerOf("realm")
				set := bubbleSetOf(t, Config{Providers: []Provider{provider}}, testOptions(), transport)
				if err := set.Refresh(t.Context()); err != nil {
					t.Fatalf("Refresh() error = %v", err)
				}
				transport.publish(t, ecJWK(t, "key-1", nil), ecJWK(t, "key-2", nil))
				key, err := set.LookupOrReload(t.Context(), Query{Issuer: provider.Issuer, KID: tt.kid})
				if err != nil {
					t.Fatalf("LookupOrReload(%q) error = %v, want none", tt.kid, err)
				}
				if key.ID != tt.kid || key.Source.Provider == nil || key.Source.Provider.ID != "realm" || key.JWK == nil {
					t.Errorf("LookupOrReload(%q) = key %q of %+v with JWK %v, want key %q of provider %q", tt.kid, key.ID, key.Source, key.JWK, tt.kid, "realm")
				}
				if got := transport.loadCount(); got != tt.discoveries {
					t.Errorf("discovery requests after LookupOrReload(%q) = %d, want %d", tt.kid, got, tt.discoveries)
				}
			})
		})
	}
}

// The provider publishes key-2 after the first on-demand load, within the
// minute in which no other one starts. The discovery requests count every
// load, the one of Refresh included.
func TestLookupOrReload_ReloadsAProviderAtMostOnceAMinute(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := newFakeTransport(t)
		transport.publish(t, ecJWK(t, "key-1", nil))
		provider := providerOf("realm")
		set := bubbleSetOf(t, Config{Providers: []Provider{provider}}, testOptions(), transport)
		if err := set.Refresh(t.Context()); err != nil {
			t.Fatalf("Refresh() error = %v", err)
		}
		lookup := func(kid string, wantFound bool, wantDiscoveries int) {
			t.Helper()
			_, err := set.LookupOrReload(t.Context(), Query{Issuer: provider.Issuer, KID: kid})
			if got := transport.loadCount(); (err == nil) != wantFound || got != wantDiscoveries {
				t.Errorf("LookupOrReload(%q) error = %v with %d discovery requests, want found = %t with %d", kid, err, got, wantFound, wantDiscoveries)
			}
		}
		lookup("unknown", false, 2)
		transport.publish(t, ecJWK(t, "key-1", nil), ecJWK(t, "key-2", nil))
		time.Sleep(59 * time.Second)
		lookup("key-2", false, 2)
		time.Sleep(time.Second)
		lookup("key-2", true, 3)
	})
}

func TestLookupOrReload_WarnsWhenTheReloadFails(t *testing.T) {
	tests := []struct {
		name   string
		status int
		warned bool
	}{
		{"provider that answers 503", http.StatusServiceUnavailable, true},
		{"provider that answers", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				transport := newFakeTransport(t)
				log := &warnRecorder{}
				opts := testOptions()
				opts.Log = log
				set := bubbleSetOf(t, Config{Providers: []Provider{providerOf("realm")}}, opts, transport)
				if err := set.Refresh(t.Context()); err != nil {
					t.Fatalf("Refresh() error = %v", err)
				}
				transport.setStatus("idp.test", tt.status)
				_, _ = set.LookupOrReload(t.Context(), Query{Issuer: "http://idp.test", KID: "unknown"})
				if got := log.matches("on-demand load", `provider "realm"`); got != tt.warned {
					t.Errorf("warned = %t, want %t; warnings: %q", got, tt.warned, log.warnings)
				}
			})
		})
	}
}

// spinUntil lets the other goroutines of the bubble run until cond holds. A
// goroutine that waits for a mutex is not durably blocked, so synctest.Wait does
// not return while one does, and this loop stands in for it.
func spinUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for range 1000000 {
		if cond() {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("%s did not happen", what)
}

// The Set keeps 1000 realms by default. The realms load ten a minute, so the
// fake clock moves a minute after every ten.
func TestLookupOrReload_KeepsAThousandRealmsByDefault(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		set := keycloakSet(t, kc, Options{})
		for i := range 1000 {
			realm := fmt.Sprintf("tenant-%d", i)
			kc.publishRealm(realm, ecJWK(t, "k1", nil))
			if _, err := lookupRealm(t, set, realm); err != nil {
				t.Fatalf("LookupOrReload(realm %s) error = %v", realm, err)
			}
			if i%maxLoadsPerMinute == maxLoadsPerMinute-1 {
				time.Sleep(time.Minute)
			}
		}
		kc.publishRealm("tenant-1000", ecJWK(t, "k1", nil))
		if _, err := lookupRealm(t, set, "tenant-1000"); !errors.Is(err, ErrKeyUnknown) {
			t.Errorf("LookupOrReload(realm tenant-1000) error = %v, want %v", err, ErrKeyUnknown)
		}
		if got := kc.loadsOf("tenant-1000"); got != 0 {
			t.Errorf("discovery requests for realm tenant-1000 = %d, want 0", got)
		}
	})
}

// lookupRealmWhileHolding looks up realm while the test holds the mutex of the
// onDemand of realm held. A search of dropFailedRealms takes that mutex for each
// realm it meets that is not required and never loaded a usable key, so a lookup
// that runs the search waits for it, and the test fails.
func lookupRealmWhileHolding(t *testing.T, set *Set, held, realm string) error {
	t.Helper()
	src, ok := set.knownRealm(held)
	if !ok {
		t.Fatalf("the Set holds no realm %s", held)
	}
	src.onDemand.mu.Lock()
	release := sync.OnceFunc(src.onDemand.mu.Unlock)
	defer release()
	result := make(chan error, 1)
	go func() {
		_, err := lookupRealm(t, set, realm)
		result <- err
	}()
	var err error
	spinUntil(t, "the lookup of realm "+realm+" without a search", func() bool {
		select {
		case err = <-result:
			return true
		default:
			return false
		}
	})
	return err
}

// The Set holds realm a with keys and realm ghost, whose load failed 30 s ago,
// at a limit of two, so the Set can drop ghost only at 60 s.
func TestLookupOrReload_RefusesARealmAtTheLimitWithoutASearchBeforeOneIsDue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.publishRealm("a", ecJWK(t, "k1", nil))
		opts := testOptions()
		opts.maxRealms = 2
		set := keycloakSet(t, kc, opts)
		if _, err := lookupRealm(t, set, "a"); err != nil {
			t.Fatalf("LookupOrReload(realm a) error = %v", err)
		}
		_, _ = lookupRealm(t, set, "ghost")
		time.Sleep(30 * time.Second)
		if err := lookupRealmWhileHolding(t, set, "ghost", "c"); !errors.Is(err, ErrKeyUnknown) {
			t.Errorf("LookupOrReload(realm c) error = %v, want %v", err, ErrKeyUnknown)
		}
	})
}

// The load of realm ghost hangs past its minute, so the Set cannot drop ghost
// while it runs. The lookup of ghost waits the 3 s of ReloadWait, so the token
// of realm c comes at 64 s. It searches for realms to drop and finds none, and
// the next search waits a second, so the token of realm d right after it is
// refused without one.
func TestLookupOrReload_RefusesARealmAtTheLimitWithoutASearchWhileALoadOutlastsItsMinute(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.publishRealm("a", ecJWK(t, "k1", nil))
		kc.publishRealm("ghost", ecJWK(t, "k1", nil))
		opts := testOptions()
		opts.maxRealms = 2
		opts.HTTPTimeout = 5 * time.Minute
		set := keycloakSet(t, kc, opts)
		if _, err := lookupRealm(t, set, "a"); err != nil {
			t.Fatalf("LookupOrReload(realm a) error = %v", err)
		}
		hold := make(chan struct{})
		defer close(hold)
		kc.setHold(hold)
		_, _ = lookupRealm(t, set, "ghost")
		time.Sleep(61 * time.Second)
		if _, err := lookupRealm(t, set, "c"); !errors.Is(err, ErrKeyUnknown) {
			t.Fatalf("LookupOrReload(realm c) error = %v, want %v", err, ErrKeyUnknown)
		}
		if err := lookupRealmWhileHolding(t, set, "ghost", "d"); !errors.Is(err, ErrKeyUnknown) {
			t.Errorf("LookupOrReload(realm d) error = %v, want %v", err, ErrKeyUnknown)
		}
	})
}

// The search at 60 s dropped realm old and kept realm young, which is due at
// 90 s, so the token of realm d at 70 s is refused without a search.
func TestLookupOrReload_RefusesARealmAtTheLimitWithoutASearchBeforeTheNextFailedRealmIsDue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		set, _ := youngFailedRealmAtTheLimit(t)
		time.Sleep(10 * time.Second)
		if err := lookupRealmWhileHolding(t, set, "young", "d"); !errors.Is(err, ErrKeyUnknown) {
			t.Errorf("LookupOrReload(realm d) at 70 s error = %v, want %v", err, ErrKeyUnknown)
		}
	})
}

// The required realm and the provider fail beside three of the four realms that
// tokens named. Realms b and d are deleted from Keycloak and keep their keys,
// and realm c publishes only an encryption key and has no keys left.
func TestRefresh_GivesEachProviderAndRequiredRealmALineAndSumsUpTheRealmsTokensNamed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		named := []string{"a", "b", "c", "d"}
		for _, realm := range append([]string{"cloud-common"}, named...) {
			kc.publishRealm(realm, ecJWK(t, "k1", nil))
		}
		cfg := Config{
			Keycloak:  &Keycloak{URL: keycloakURL, RequiredRealms: []string{"cloud-common"}},
			Providers: []Provider{providerOf("idp")},
		}
		set := bubbleSetOf(t, cfg, testOptions(), kc)
		for _, realm := range named {
			if _, err := lookupRealm(t, set, realm); err != nil {
				t.Fatalf("LookupOrReload(realm %s) error = %v", realm, err)
			}
		}
		if err := set.Refresh(t.Context()); err != nil {
			t.Fatalf("Refresh() error = %v", err)
		}
		for _, realm := range []string{"cloud-common", "b", "d"} {
			kc.removeRealm(realm)
		}
		kc.publishRealm("c", ecJWK(t, "enc", map[string]any{"use": "enc"}))
		kc.setStatus("idp.test", http.StatusServiceUnavailable)
		err := set.Refresh(t.Context())
		if err == nil {
			t.Fatal("Refresh() error = nil, want the failures")
		}
		want := []string{
			`provider "idp" keeps its previous keys: `,
			`realm "cloud-common" keeps its previous keys: `,
			`3 of 4 realms that tokens named did not reload, 1 of them without keys; the first by name: realm "b" keeps its previous keys: `,
		}
		lines := strings.Split(err.Error(), "\n")
		if len(lines) != len(want) {
			t.Fatalf("Refresh() error = %q, want %d lines", err, len(want))
		}
		for i, prefix := range want {
			if !strings.HasPrefix(lines[i], prefix) {
				t.Errorf("line %d of the Refresh() error = %q, want the prefix %q", i+1, lines[i], prefix)
			}
		}
	})
}
