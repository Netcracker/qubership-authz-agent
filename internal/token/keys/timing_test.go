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
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// fakeTransport answers Keycloak's requests in memory, so that the tests in
// this file run on the fake clock of a synctest bubble, where a real socket
// never counts as idle. Every realm has the one key jwks.
type fakeTransport struct {
	jwks []byte
	// down, when true, fails every request.
	down bool

	mu sync.Mutex
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
	return &fakeTransport{jwks: jwks, fetched: map[string]time.Time{}}
}

func (f *fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if f.down {
		return nil, errors.New("connection refused")
	}
	if address, ok := strings.CutSuffix(r.URL.String(), "/.well-known/openid-configuration"); ok {
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
	return response(f.jwks), nil
}

func response(body []byte) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body)))}
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
	set := mustNew(t, cfg, Options{Log: log})
	set.keycloakClient.Transport = transport
	return set
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
