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
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeKeycloak serves, under /auth/realms/<realm>, an OIDC discovery document
// and a JWKS at /jwks for every realm it holds, and answers 404 for any other
// realm. Every change takes effect on the next request.
type fakeKeycloak struct {
	srv *httptest.Server

	mu sync.Mutex
	// realms holds the keys of each realm by the name as it appears in a URL.
	realms map[string][]json.RawMessage
	// status, when non-zero, answers every request.
	status int
	// loads lists the escaped path of every discovery request, in order.
	loads []string
	// gate, when non-nil, holds every JWKS response until it is closed.
	gate chan struct{}
	// holding counts the JWKS responses that a gate has held.
	holding int
}

func newKeycloak(t *testing.T) *fakeKeycloak {
	t.Helper()
	kc := &fakeKeycloak{realms: map[string][]json.RawMessage{}}
	kc.srv = httptest.NewServer(kc)
	t.Cleanup(kc.srv.Close)
	return kc
}

func (kc *fakeKeycloak) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.EscapedPath()
	realm, rest, _ := strings.Cut(strings.TrimPrefix(path, realmsPath), "/")
	kc.mu.Lock()
	keys, known := kc.realms[realm]
	status, gate := kc.status, kc.gate
	discovery := rest == ".well-known/openid-configuration"
	if discovery {
		kc.loads = append(kc.loads, path)
	}
	switch {
	case status != 0:
		kc.mu.Unlock()
		w.WriteHeader(status)
		return
	case !known:
		kc.mu.Unlock()
		http.NotFound(w, r)
		return
	case discovery:
		kc.mu.Unlock()
		body, _ := json.Marshal(map[string]string{"jwks_uri": kc.srv.URL + realmsPath + realm + "/jwks"})
		_, _ = w.Write(body)
		return
	}
	if gate != nil {
		kc.holding++
	}
	kc.mu.Unlock()
	if gate != nil {
		<-gate
	}
	body, _ := json.Marshal(map[string]any{"keys": keys})
	_, _ = w.Write(body)
}

// publish sets the keys of realm, creating it.
func (kc *fakeKeycloak) publish(realm string, keys ...json.RawMessage) {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	kc.realms[realm] = keys
}

// remove makes realm answer 404, as a realm deleted from Keycloak does.
func (kc *fakeKeycloak) remove(realm string) {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	delete(kc.realms, realm)
}

func (kc *fakeKeycloak) setStatus(status int) {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	kc.status = status
}

func (kc *fakeKeycloak) setGate(gate chan struct{}) {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	kc.gate = gate
}

func (kc *fakeKeycloak) held() int {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	return kc.holding
}

// loadCount returns how many discovery requests have arrived.
func (kc *fakeKeycloak) loadCount() int {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	return len(kc.loads)
}

// loadsOf returns how many discovery requests asked for realm.
func (kc *fakeKeycloak) loadsOf(realm string) int {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	want := realmsPath + realm + "/.well-known/openid-configuration"
	count := 0
	for _, path := range kc.loads {
		if path == want {
			count++
		}
	}
	return count
}

func (kc *fakeKeycloak) paths() []string {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	return slices.Clone(kc.loads)
}

// iss is the iss of a token of realm. Its host is not the host of any fake:
// a token names the realm, and the configuration names the server.
func iss(realm string) string { return "https://public.example" + realmsPath + realm }

// manualClock is a settable Options.now.
type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func newManualClock() *manualClock {
	return &manualClock{now: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// keycloakSet returns a Set of kc with the clock of a new manualClock.
func keycloakSet(t *testing.T, kc *fakeKeycloak, opts Options) (*Set, *manualClock) {
	t.Helper()
	clock := newManualClock()
	opts.now = clock.Now
	return mustNew(t, Config{Keycloak: &Keycloak{URL: kc.srv.URL}}, opts), clock
}

// lookupRealm asks for key k1 of realm.
func lookupRealm(t *testing.T, set *Set, realm string) (Key, error) {
	t.Helper()
	return set.LookupOrReload(t.Context(), Query{Issuer: iss(realm), KID: "k1"})
}

func TestRealmOf_TakesThePartOfIssAfterTheLastSlash(t *testing.T) {
	tests := []struct {
		name, iss, want string
		wantOK          bool
	}{
		{"realm", "https://kc.example/auth/realms/cloud-common", "cloud-common", true},
		{"another host and a port", "http://10.0.0.1:8080/auth/realms/tenant-1", "tenant-1", true},
		{"a path after the realm", "https://kc.example/auth/realms/a/b", "b", true},
		{"name of 255 bytes", "https://kc.example/auth/realms/" + strings.Repeat("x", 255), strings.Repeat("x", 255), true},
		{"name of 256 bytes", "https://kc.example/auth/realms/" + strings.Repeat("x", 256), "", false},
		{"percent-encoded name", "https://kc.example/auth/realms/a%20b", "a b", true},
		{"percent-encoded dots", "https://kc.example/auth/realms/%2e%2e", "", false},
		{"percent-encoded slash", "https://kc.example/auth/realms/a%2Fb", "", false},
		{"broken percent escape", "https://kc.example/auth/realms/a%zz", "", false},
		{"no /auth/realms/", "https://kc.example/realms/a", "", false},
		{"empty iss", "", "", false},
		{"trailing slash", "https://kc.example/auth/realms/a/", "", false},
		{"nothing after /auth/realms/", "https://kc.example/auth/realms/", "", false},
		{"dot", "https://kc.example/auth/realms/.", "", false},
		{"dot dot", "https://kc.example/auth/realms/..", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := realmOf(tt.iss)
			if ok != tt.wantOK || (ok && got != tt.want) {
				t.Errorf("realmOf(%q) = %q, %t; want %q, %t", tt.iss, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// The iss names public.example, and the Set holds the address of the fake. The
// second lookup is the control that the first one loaded the realm for good.
func TestLookupOrReload_LoadsARealmFromTheConfiguredKeycloakWhateverHostTheIssNames(t *testing.T) {
	kc := newKeycloak(t)
	kc.publish("tenant-1", ecJWK(t, "k1", nil))
	set, _ := keycloakSet(t, kc, testOptions())
	key, err := lookupRealm(t, set, "tenant-1")
	if err != nil {
		t.Fatalf("LookupOrReload() error = %v", err)
	}
	if got, want := key.Provider.ID, "realm/tenant-1"; got != want {
		t.Errorf("Provider.ID = %q, want %q", got, want)
	}
	if _, err := lookupRealm(t, set, "tenant-1"); err != nil {
		t.Errorf("second LookupOrReload() error = %v", err)
	}
	if got, want := kc.paths(), []string{"/auth/realms/tenant-1/.well-known/openid-configuration"}; !slices.Equal(got, want) {
		t.Errorf("discovery requests = %q, want %q", got, want)
	}
}

// Both realms publish the kid k1, so only the realm tells the two keys apart.
func TestLookupOrReload_KeepsTheKeysOfTwoRealmsApart(t *testing.T) {
	kc := newKeycloak(t)
	kc.publish("a", ecJWK(t, "k1", nil))
	kc.publish("b", ecJWK(t, "k1", nil))
	set, _ := keycloakSet(t, kc, testOptions())
	for _, realm := range []string{"a", "b"} {
		key, err := lookupRealm(t, set, realm)
		if err != nil {
			t.Errorf("LookupOrReload(realm %q) error = %v", realm, err)
			continue
		}
		if got, want := key.Provider.ID, "realm/"+realm; got != want {
			t.Errorf("LookupOrReload(realm %q).Provider.ID = %q, want %q", realm, got, want)
		}
	}
}

// Every name stays one path segment on the server, whatever it holds.
func TestLookupOrReload_EscapesTheRealmNameInTheAddress(t *testing.T) {
	tests := []struct {
		name, realm, want string
	}{
		{"question mark", "a?b=c", "/auth/realms/a%3Fb=c/.well-known/openid-configuration"},
		{"hash", "a#b", "/auth/realms/a%23b/.well-known/openid-configuration"},
		{"space", "a b", "/auth/realms/a%20b/.well-known/openid-configuration"},
		{"space the iss encodes", "a%20b", "/auth/realms/a%20b/.well-known/openid-configuration"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc := newKeycloak(t)
			set, _ := keycloakSet(t, kc, testOptions())
			if _, err := lookupRealm(t, set, tt.realm); !errors.Is(err, ErrKeyUnknown) {
				t.Errorf("LookupOrReload(realm %q) error = %v, want %v", tt.realm, err, ErrKeyUnknown)
			}
			if got := kc.paths(); !slices.Equal(got, []string{tt.want}) {
				t.Errorf("discovery requests = %q, want %q", got, []string{tt.want})
			}
		})
	}
}

func TestLookupOrReload_AcceptsAKeycloakURLWithATrailingSlash(t *testing.T) {
	kc := newKeycloak(t)
	kc.publish("tenant-1", ecJWK(t, "k1", nil))
	set := mustNew(t, Config{Keycloak: &Keycloak{URL: kc.srv.URL + "/"}}, testOptions())
	if _, err := lookupRealm(t, set, "tenant-1"); err != nil {
		t.Errorf("LookupOrReload() error = %v", err)
	}
	if got, want := kc.paths(), []string{"/auth/realms/tenant-1/.well-known/openid-configuration"}; !slices.Equal(got, want) {
		t.Errorf("discovery requests = %q, want %q", got, want)
	}
}

func TestLookupOrReload_RefusesAnIssuerNoConfigurationCovers(t *testing.T) {
	kc := newKeycloak(t)
	withKeycloak, _ := keycloakSet(t, kc, testOptions())
	idp := newIdP(t, ecJWK(t, "k1", nil))
	withoutKeycloak := mustLoad(t, testOptions(), issuer("provider", idp))
	tests := []struct {
		name string
		set  *Set
		iss  string
	}{
		{"iss without /auth/realms/", withKeycloak, "https://idp.example/oidc"},
		{"empty iss", withKeycloak, ""},
		{"realm that is a dot segment", withKeycloak, "https://kc.example/auth/realms/.."},
		{"realm without a configured Keycloak", withoutKeycloak, iss("tenant-1")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.set.LookupOrReload(t.Context(), Query{Issuer: tt.iss, KID: "k1"})
			if !errors.Is(err, ErrIssuerUnknown) {
				t.Errorf("LookupOrReload(issuer %q) error = %v, want %v", tt.iss, err, ErrIssuerUnknown)
			}
			if got := kc.loadCount(); got != 0 {
				t.Errorf("discovery requests after LookupOrReload(issuer %q) = %d, want 0", tt.iss, got)
			}
		})
	}
}

func TestLookup_DoesNotLoadARealmNoTokenNamedThroughLookupOrReload(t *testing.T) {
	kc := newKeycloak(t)
	kc.publish("tenant-1", ecJWK(t, "k1", nil))
	set, _ := keycloakSet(t, kc, testOptions())
	if _, err := set.Lookup(Query{Issuer: iss("tenant-1"), KID: "k1"}); !errors.Is(err, ErrKeyUnknown) {
		t.Errorf("Lookup() error = %v, want %v", err, ErrKeyUnknown)
	}
	if got := kc.loadCount(); got != 0 {
		t.Errorf("discovery requests after Lookup() = %d, want 0", got)
	}
}

// The callers start together, and the JWKS response is held until the first
// load has reached it.
func TestLookupOrReload_CallersOfANewRealmShareOneLoad(t *testing.T) {
	kc := newKeycloak(t)
	kc.publish("tenant-1", ecJWK(t, "k1", nil))
	gate := make(chan struct{})
	kc.setGate(gate)
	set, _ := keycloakSet(t, kc, testOptions())
	start := make(chan struct{})
	errs := make([]error, 32)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Go(func() {
			<-start
			_, errs[i] = lookupRealm(t, set, "tenant-1")
		})
	}
	close(start)
	waitFor(t, "the JWKS request of the first load", func() bool { return kc.held() == 1 })
	close(gate)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("LookupOrReload() in goroutine %d error = %v", i, err)
		}
	}
	if got := kc.loadsOf("tenant-1"); got != 1 {
		t.Errorf("discovery requests = %d, want 1", got)
	}
}

// A realm that does not exist answers 404. The second lookup, 59 s later, sends
// no request, and the third, a minute after the first, does.
func TestLookupOrReload_AsksAgainForARealmThatFailedOnlyAfterAMinute(t *testing.T) {
	kc := newKeycloak(t)
	set, clock := keycloakSet(t, kc, testOptions())
	tests := []struct {
		at   time.Duration
		want int
	}{{0, 1}, {59 * time.Second, 1}, {60 * time.Second, 2}}
	var elapsed time.Duration
	for _, tt := range tests {
		clock.advance(tt.at - elapsed)
		elapsed = tt.at
		if _, err := lookupRealm(t, set, "ghost"); !errors.Is(err, ErrKeyUnknown) {
			t.Errorf("LookupOrReload() at %s error = %v, want %v", tt.at, err, ErrKeyUnknown)
		}
		if got := kc.loadsOf("ghost"); got != tt.want {
			t.Errorf("discovery requests by %s = %d, want %d", tt.at, got, tt.want)
		}
	}
}

// startLoads uses up the ceiling with n realms that do not exist.
func startLoads(t *testing.T, set *Set, n int) {
	t.Helper()
	for i := range n {
		_, _ = lookupRealm(t, set, fmt.Sprintf("invented-%d", i))
	}
}

// Ten invented realms use up the ceiling, so the real realm waits until the
// oldest load is a minute old.
func TestLookupOrReload_StartsAtMostTenLoadsAMinute(t *testing.T) {
	kc := newKeycloak(t)
	kc.publish("tenant-1", ecJWK(t, "k1", nil))
	set, clock := keycloakSet(t, kc, testOptions())
	startLoads(t, set, 10)
	if got := kc.loadCount(); got != 10 {
		t.Fatalf("discovery requests for 10 realms = %d, want 10", got)
	}
	for _, step := range []time.Duration{0, 59 * time.Second} {
		clock.advance(step)
		if _, err := lookupRealm(t, set, "tenant-1"); !errors.Is(err, ErrKeyUnknown) {
			t.Errorf("LookupOrReload() %s after the ceiling was reached: error = %v, want %v", step, err, ErrKeyUnknown)
		}
		if got := kc.loadsOf("tenant-1"); got != 0 {
			t.Errorf("discovery requests %s after the ceiling was reached = %d, want 0", step, got)
		}
	}
	clock.advance(time.Second)
	if _, err := lookupRealm(t, set, "tenant-1"); err != nil {
		t.Errorf("LookupOrReload() a minute after the ceiling was reached: error = %v", err)
	}
}

// The first load of the realm is a minute old, so its spacing allows a reload,
// and the nine loads at 30 s and the one at 60 s hold every slot of the ceiling.
// Thirty seconds later those nine are a minute old, and the reload goes ahead.
func TestLookupOrReload_ACeilingOfLoadsCoversTheReloadOfAKnownRealm(t *testing.T) {
	kc := newKeycloak(t)
	kc.publish("tenant-1", ecJWK(t, "k1", nil))
	set, clock := keycloakSet(t, kc, testOptions())
	if _, err := lookupRealm(t, set, "tenant-1"); err != nil {
		t.Fatalf("LookupOrReload() error = %v", err)
	}
	clock.advance(30 * time.Second)
	startLoads(t, set, 9)
	clock.advance(30 * time.Second)
	_, _ = lookupRealm(t, set, "invented-last")
	q := Query{Issuer: iss("tenant-1"), KID: "rotated"}
	if _, err := set.LookupOrReload(t.Context(), q); !errors.Is(err, ErrKeyUnknown) {
		t.Errorf("LookupOrReload(%+v) error = %v, want %v", q, err, ErrKeyUnknown)
	}
	if got := kc.loadsOf("tenant-1"); got != 1 {
		t.Errorf("discovery requests at the ceiling = %d, want 1", got)
	}
	clock.advance(30 * time.Second)
	kc.publish("tenant-1", ecJWK(t, "rotated", nil))
	if _, err := set.LookupOrReload(t.Context(), q); err != nil {
		t.Errorf("LookupOrReload(%+v) after the ceiling cleared: error = %v", q, err)
	}
}

// Twenty lookups within the minute after the load of the realm send no request,
// so they leave nine slots of the ceiling for new realms.
func TestLookupOrReload_ALookupTheSpacingRefusesTakesNoSlotOfTheCeiling(t *testing.T) {
	kc := newKeycloak(t)
	kc.publish("tenant-1", ecJWK(t, "k1", nil))
	set, _ := keycloakSet(t, kc, testOptions())
	if _, err := lookupRealm(t, set, "tenant-1"); err != nil {
		t.Fatalf("LookupOrReload() error = %v", err)
	}
	for range 20 {
		_, _ = set.LookupOrReload(t.Context(), Query{Issuer: iss("tenant-1"), KID: "unknown"})
	}
	startLoads(t, set, 9)
	if got := kc.loadCount(); got != 10 {
		t.Errorf("discovery requests = %d, want 10: the load of the realm and 9 new realms", got)
	}
}

func TestLookupOrReload_WarnsWhenTheCeilingRefusesAReload(t *testing.T) {
	kc := newKeycloak(t)
	kc.publish("tenant-1", ecJWK(t, "k1", nil))
	log := &warnRecorder{}
	opts := testOptions()
	opts.Log = log
	set, clock := keycloakSet(t, kc, opts)
	if _, err := lookupRealm(t, set, "tenant-1"); err != nil {
		t.Fatalf("LookupOrReload() error = %v", err)
	}
	clock.advance(30 * time.Second)
	startLoads(t, set, 9)
	clock.advance(30 * time.Second)
	_, _ = lookupRealm(t, set, "invented-last")
	_, _ = set.LookupOrReload(t.Context(), Query{Issuer: iss("tenant-1"), KID: "rotated"})
	if got := log.count(`provider "realm/tenant-1" is not reloaded`); got != 1 {
		t.Errorf("warnings about the refused reload = %d, want 1; warnings: %q", got, log.warnings)
	}
}

func TestLookupOrReload_WarnsOnceAMinuteWhileTheCeilingRefusesRealms(t *testing.T) {
	kc := newKeycloak(t)
	log := &warnRecorder{}
	opts := testOptions()
	opts.Log = log
	set, clock := keycloakSet(t, kc, opts)
	startLoads(t, set, 10)
	const warning = "key loads in the last minute"
	_, _ = lookupRealm(t, set, "other-1")
	_, _ = lookupRealm(t, set, "other-2")
	if got := log.count(warning); got != 1 {
		t.Errorf("warnings about the ceiling after two refused realms = %d, want 1", got)
	}
	clock.advance(time.Minute)
	startLoads(t, set, 10)
	_, _ = lookupRealm(t, set, "other-3")
	if got := log.count(warning); got != 2 {
		t.Errorf("warnings about the ceiling a minute later = %d, want 2", got)
	}
}

func TestLookupOrReload_KeepsNoMoreRealmsThanTheLimit(t *testing.T) {
	kc := newKeycloak(t)
	for _, realm := range []string{"a", "b", "c"} {
		kc.publish(realm, ecJWK(t, "k1", nil))
	}
	log := &warnRecorder{}
	opts := testOptions()
	opts.Log = log
	opts.maxRealms = 2
	set, clock := keycloakSet(t, kc, opts)
	for _, realm := range []string{"a", "b"} {
		if _, err := lookupRealm(t, set, realm); err != nil {
			t.Fatalf("LookupOrReload(realm %q) error = %v", realm, err)
		}
	}
	clock.advance(time.Hour)
	if _, err := lookupRealm(t, set, "c"); !errors.Is(err, ErrKeyUnknown) {
		t.Errorf("LookupOrReload(realm %q) error = %v, want %v", "c", err, ErrKeyUnknown)
	}
	if got := kc.loadsOf("c"); got != 0 {
		t.Errorf("discovery requests for realm %q = %d, want 0", "c", got)
	}
	if got := log.count(`realm "c" is not loaded`); got != 1 {
		t.Errorf("warnings about realm %q = %d, want 1; warnings: %q", "c", got, log.warnings)
	}
}

// One place of two holds a realm with keys, and the other a realm that failed.
// A new realm takes the place of the failed one a minute after its load.
func TestLookupOrReload_ANewRealmTakesThePlaceOfARealmThatFailedAMinuteAgo(t *testing.T) {
	kc := newKeycloak(t)
	kc.publish("a", ecJWK(t, "k1", nil))
	kc.publish("b", ecJWK(t, "k1", nil))
	opts := testOptions()
	opts.maxRealms = 2
	set, clock := keycloakSet(t, kc, opts)
	if _, err := lookupRealm(t, set, "a"); err != nil {
		t.Fatalf("LookupOrReload(realm %q) error = %v", "a", err)
	}
	_, _ = lookupRealm(t, set, "ghost")
	clock.advance(59 * time.Second)
	if _, err := lookupRealm(t, set, "b"); !errors.Is(err, ErrKeyUnknown) {
		t.Errorf("LookupOrReload(realm %q) 59 s after the failure: error = %v, want %v", "b", err, ErrKeyUnknown)
	}
	clock.advance(time.Second)
	if _, err := lookupRealm(t, set, "b"); err != nil {
		t.Errorf("LookupOrReload(realm %q) a minute after the failure: error = %v", "b", err)
	}
}

// The realm that loaded keys answers 404 from then on, and its keys stay, also
// when the Set drops the realms that failed.
func TestRefresh_ARealmThatDisappearsKeepsItsKeys(t *testing.T) {
	kc := newKeycloak(t)
	kc.publish("tenant-1", ecJWK(t, "k1", nil))
	set, clock := keycloakSet(t, kc, testOptions())
	if _, err := lookupRealm(t, set, "tenant-1"); err != nil {
		t.Fatalf("LookupOrReload() error = %v", err)
	}
	kc.remove("tenant-1")
	if err := set.Refresh(t.Context()); err == nil || !strings.Contains(err.Error(), "keeps its previous keys") {
		t.Errorf("Refresh() error = %v, want an error saying the realm keeps its keys", err)
	}
	clock.advance(time.Hour)
	_, _ = lookupRealm(t, set, "ghost")
	if _, err := set.Lookup(Query{Issuer: iss("tenant-1"), KID: "k1"}); err != nil {
		t.Errorf("Lookup() after the realm disappeared: error = %v", err)
	}
}

// The realm that never loaded is asked once more at 59 s, and not at 60 s.
func TestRefresh_DropsARealmThatFailedAMinuteAgo(t *testing.T) {
	kc := newKeycloak(t)
	set, clock := keycloakSet(t, kc, testOptions())
	_, _ = lookupRealm(t, set, "ghost")
	clock.advance(59 * time.Second)
	if err := set.Refresh(t.Context()); err == nil {
		t.Errorf("Refresh() at 59 s error = nil, want the 404 of the realm")
	}
	if got := kc.loadsOf("ghost"); got != 2 {
		t.Errorf("discovery requests at 59 s = %d, want 2", got)
	}
	clock.advance(time.Second)
	if err := set.Refresh(t.Context()); err != nil {
		t.Errorf("Refresh() at 60 s error = %v, want none", err)
	}
	if got := kc.loadsOf("ghost"); got != 2 {
		t.Errorf("discovery requests at 60 s = %d, want 2", got)
	}
}

func TestRefresh_ReloadsTheRealmsThatTokensNamed(t *testing.T) {
	kc := newKeycloak(t)
	kc.publish("tenant-1", ecJWK(t, "k1", nil))
	set, _ := keycloakSet(t, kc, testOptions())
	if _, err := lookupRealm(t, set, "tenant-1"); err != nil {
		t.Fatalf("LookupOrReload() error = %v", err)
	}
	kc.publish("tenant-1", ecJWK(t, "k2", nil))
	if err := set.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	for kid, want := range map[string]bool{"k2": true, "k1": false} {
		_, err := set.Lookup(Query{Issuer: iss("tenant-1"), KID: kid})
		if got := err == nil; got != want {
			t.Errorf("Lookup(%q) found = %t, want %t", kid, got, want)
		}
	}
}

func TestReady_WaitsForTheRequiredRealmAndNotForAnyOther(t *testing.T) {
	tests := []struct {
		name     string
		required []string
		want     bool
	}{
		{"realm that is required and still down", []string{"cloud-common"}, false},
		{"no required realm", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc := newKeycloak(t)
			kc.setStatus(http.StatusServiceUnavailable)
			set := mustNew(t, Config{Keycloak: &Keycloak{URL: kc.srv.URL, RequiredRealms: tt.required}}, testOptions())
			_, _ = lookupRealm(t, set, "tenant-1")
			if got := set.Ready(); got != tt.want {
				t.Errorf("Ready() = %t, want %t", got, tt.want)
			}
		})
	}
}

// Run loads the required realm, and the provider stays down until the test
// lets it answer: readiness needs both.
func TestRun_LoadsARequiredRealmAndReadinessWaitsForEveryRequiredSource(t *testing.T) {
	kc := newKeycloak(t)
	kc.publish("cloud-common", ecJWK(t, "k1", nil))
	idp := newIdP(t, ecJWK(t, "k8s-1", nil))
	idp.setStatus(http.StatusServiceUnavailable)
	cfg := Config{
		Keycloak:  &Keycloak{URL: kc.srv.URL, RequiredRealms: []string{"cloud-common"}},
		Providers: []Provider{issuer("trusted", idp)},
	}
	set := mustNew(t, cfg, testOptions())
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		set.Run(ctx)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()
	waitFor(t, "the keys of the required realm", func() bool {
		_, err := set.Lookup(Query{Issuer: iss("cloud-common"), KID: "k1"})
		return err == nil
	})
	if set.Ready() {
		t.Errorf("Ready() = true while the provider is down, want false")
	}
	idp.setStatus(0)
	waitFor(t, "Ready() to return true", set.Ready)
}

func TestNew_RefusesAnUnusableKeycloakCAFile(t *testing.T) {
	_, err := New(Config{Keycloak: &Keycloak{URL: "https://kc.example", CAFile: writeFile(t, "ca.pem", "not a certificate")}}, testOptions())
	if err == nil || !containsAll(err.Error(), "keycloak", "caFile") {
		t.Errorf("New() error = %v, want an error naming keycloak and caFile", err)
	}
}
