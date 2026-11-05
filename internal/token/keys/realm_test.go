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
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// iss is the iss of a token of realm. Its host is not the host of any fake:
// a token names the realm, and the configuration names the server.
func iss(realm string) string { return "https://public.example" + realmsPath + realm }

// lookupRealm asks for key k1 of realm.
func lookupRealm(t *testing.T, set *Set, realm string) (Key, error) {
	t.Helper()
	return set.LookupOrReload(t.Context(), Query{Issuer: iss(realm), KID: "k1"})
}

func TestSource_IDNamesARealmByItsNameAndAProviderByItsID(t *testing.T) {
	tests := []struct {
		name   string
		source Source
		want   string
	}{
		{"realm", Source{Realm: "tenant 1"}, "realm/tenant 1"},
		{"provider", Source{Provider: &Provider{ID: "idp"}}, "idp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.source.ID(); got != tt.want {
				t.Errorf("ID() = %q, want %q", got, tt.want)
			}
		})
	}
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
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.publishRealm("tenant-1", ecJWK(t, "k1", nil))
		set := keycloakSet(t, kc, testOptions())
		key, err := lookupRealm(t, set, "tenant-1")
		if err != nil {
			t.Fatalf("LookupOrReload() error = %v", err)
		}
		if got, want := key.Source, (Source{Realm: "tenant-1"}); got != want {
			t.Errorf("Source = %+v, want %+v", got, want)
		}
		if _, err := lookupRealm(t, set, "tenant-1"); err != nil {
			t.Errorf("second LookupOrReload() error = %v", err)
		}
		if got, want := kc.paths(), []string{"/auth/realms/tenant-1/.well-known/openid-configuration"}; !slices.Equal(got, want) {
			t.Errorf("discovery requests = %q, want %q", got, want)
		}
	})
}

// Both realms publish the kid k1, so only the realm tells the two keys apart.
func TestLookupOrReload_KeepsTheKeysOfTwoRealmsApart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.publishRealm("a", ecJWK(t, "k1", nil))
		kc.publishRealm("b", ecJWK(t, "k1", nil))
		set := keycloakSet(t, kc, testOptions())
		for _, realm := range []string{"a", "b"} {
			key, err := lookupRealm(t, set, realm)
			if err != nil {
				t.Errorf("LookupOrReload(realm %q) error = %v", realm, err)
				continue
			}
			if got, want := key.Source, (Source{Realm: realm}); got != want {
				t.Errorf("LookupOrReload(realm %q).Source = %+v, want %+v", realm, got, want)
			}
		}
	})
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
			synctest.Test(t, func(t *testing.T) {
				kc := newKeycloakTransport(t)
				set := keycloakSet(t, kc, testOptions())
				if _, err := lookupRealm(t, set, tt.realm); !errors.Is(err, ErrKeyUnknown) {
					t.Errorf("LookupOrReload(realm %q) error = %v, want %v", tt.realm, err, ErrKeyUnknown)
				}
				if got := kc.paths(); !slices.Equal(got, []string{tt.want}) {
					t.Errorf("discovery requests = %q, want %q", got, []string{tt.want})
				}
			})
		})
	}
}

func TestLookupOrReload_AcceptsAKeycloakURLWithATrailingSlash(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.publishRealm("tenant-1", ecJWK(t, "k1", nil))
		set := bubbleSetOf(t, Config{Keycloak: &Keycloak{URL: keycloakURL + "/"}}, testOptions(), kc)
		if _, err := lookupRealm(t, set, "tenant-1"); err != nil {
			t.Errorf("LookupOrReload() error = %v", err)
		}
		if got, want := kc.paths(), []string{"/auth/realms/tenant-1/.well-known/openid-configuration"}; !slices.Equal(got, want) {
			t.Errorf("discovery requests = %q, want %q", got, want)
		}
	})
}

func TestLookupOrReload_RefusesAnIssuerNoConfigurationCovers(t *testing.T) {
	kc := newKeycloakTransport(t)
	withKeycloak := keycloakSet(t, kc, testOptions())
	withoutKeycloak := bubbleSetOf(t, Config{Providers: []Provider{providerOf("provider")}}, testOptions(), kc)
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
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.publishRealm("tenant-1", ecJWK(t, "k1", nil))
		set := keycloakSet(t, kc, testOptions())
		if _, err := set.Lookup(Query{Issuer: iss("tenant-1"), KID: "k1"}); !errors.Is(err, ErrKeyUnknown) {
			t.Errorf("Lookup() error = %v, want %v", err, ErrKeyUnknown)
		}
		if got := kc.loadCount(); got != 0 {
			t.Errorf("discovery requests after Lookup() = %d, want 0", got)
		}
	})
}

// The first load of a realm meets an outage of Keycloak, the case an operator
// has to tell from invented tokens. The lookup at 59 s has only that answer.
func TestLookupOrReload_ReportsKeysAsUnavailableWhenTheFirstLoadOfARealmFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.setStatus(keycloakHost, http.StatusServiceUnavailable)
		set := keycloakSet(t, kc, testOptions())
		if _, err := lookupRealm(t, set, "tenant-1"); !errors.Is(err, ErrKeysUnavailable) {
			t.Errorf("LookupOrReload() on the first load: error = %v, want %v", err, ErrKeysUnavailable)
		}
		time.Sleep(59 * time.Second)
		if _, err := lookupRealm(t, set, "tenant-1"); !errors.Is(err, ErrKeysUnavailable) {
			t.Errorf("LookupOrReload() at 59 s: error = %v, want %v", err, ErrKeysUnavailable)
		}
	})
}

// A realm that does not exist answers 404. The second lookup, 59 s later, sends
// no request, and the third, a minute after the first, does.
func TestLookupOrReload_AsksAgainForARealmThatFailedOnlyAfterAMinute(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		set := keycloakSet(t, kc, testOptions())
		tests := []struct {
			at   time.Duration
			want int
		}{{0, 1}, {59 * time.Second, 1}, {60 * time.Second, 2}}
		var elapsed time.Duration
		for _, tt := range tests {
			time.Sleep(tt.at - elapsed)
			elapsed = tt.at
			if _, err := lookupRealm(t, set, "ghost"); !errors.Is(err, ErrKeyUnknown) {
				t.Errorf("LookupOrReload() at %s error = %v, want %v", tt.at, err, ErrKeyUnknown)
			}
			if got := kc.loadsOf("ghost"); got != tt.want {
				t.Errorf("discovery requests by %s = %d, want %d", tt.at, got, tt.want)
			}
		}
	})
}

// startLoads uses up the limit of loads with n realms that do not exist.
func startLoads(t *testing.T, set *Set, n int) {
	t.Helper()
	for i := range n {
		_, _ = lookupRealm(t, set, fmt.Sprintf("invented-%d", i))
	}
}

// Ten invented realms use up the limit of loads, so the real realm waits until the
// oldest load is a minute old.
func TestLookupOrReload_StartsAtMostTenLoadsAMinute(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.publishRealm("tenant-1", ecJWK(t, "k1", nil))
		set := keycloakSet(t, kc, testOptions())
		startLoads(t, set, 10)
		if got := kc.loadCount(); got != 10 {
			t.Fatalf("discovery requests for 10 realms = %d, want 10", got)
		}
		for _, step := range []time.Duration{0, 59 * time.Second} {
			time.Sleep(step)
			if _, err := lookupRealm(t, set, "tenant-1"); !errors.Is(err, ErrKeysUnavailable) {
				t.Errorf("LookupOrReload() %s after the limit of loads was reached: error = %v, want %v", step, err, ErrKeysUnavailable)
			}
			if got := kc.loadsOf("tenant-1"); got != 0 {
				t.Errorf("discovery requests %s after the limit of loads was reached = %d, want 0", step, got)
			}
		}
		time.Sleep(time.Second)
		if _, err := lookupRealm(t, set, "tenant-1"); err != nil {
			t.Errorf("LookupOrReload() a minute after the limit of loads was reached: error = %v", err)
		}
	})
}

// The first load of the realm is a minute old, so its spacing allows a reload,
// and the nine loads at 30 s and the one at 60 s hold every slot of the limit of loads.
// Thirty seconds later those nine are a minute old, and the reload goes ahead.
func TestLookupOrReload_TheLimitOfLoadsCoversTheReloadOfAKnownRealm(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.publishRealm("tenant-1", ecJWK(t, "k1", nil))
		set := keycloakSet(t, kc, testOptions())
		if _, err := lookupRealm(t, set, "tenant-1"); err != nil {
			t.Fatalf("LookupOrReload() error = %v", err)
		}
		time.Sleep(30 * time.Second)
		startLoads(t, set, 9)
		time.Sleep(30 * time.Second)
		_, _ = lookupRealm(t, set, "invented-last")
		q := Query{Issuer: iss("tenant-1"), KID: "rotated"}
		if _, err := set.LookupOrReload(t.Context(), q); !errors.Is(err, ErrKeysUnavailable) {
			t.Errorf("LookupOrReload(%+v) error = %v, want %v", q, err, ErrKeysUnavailable)
		}
		if got := kc.loadsOf("tenant-1"); got != 1 {
			t.Errorf("discovery requests at the limit of loads = %d, want 1", got)
		}
		time.Sleep(30 * time.Second)
		kc.publishRealm("tenant-1", ecJWK(t, "rotated", nil))
		if _, err := set.LookupOrReload(t.Context(), q); err != nil {
			t.Errorf("LookupOrReload(%+v) after the limit of loads cleared: error = %v", q, err)
		}
	})
}

// Twenty lookups within the minute after the load of the realm send no request,
// so they leave nine slots of the limit of loads for new realms.
func TestLookupOrReload_ALookupTheSpacingRefusesTakesNoSlotOfTheLimitOfLoads(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.publishRealm("tenant-1", ecJWK(t, "k1", nil))
		set := keycloakSet(t, kc, testOptions())
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
	})
}

func TestLookupOrReload_WarnsWhenTheLimitOfLoadsRefusesAReload(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.publishRealm("tenant-1", ecJWK(t, "k1", nil))
		log := &warnRecorder{}
		opts := testOptions()
		opts.Log = log
		set := keycloakSet(t, kc, opts)
		if _, err := lookupRealm(t, set, "tenant-1"); err != nil {
			t.Fatalf("LookupOrReload() error = %v", err)
		}
		time.Sleep(30 * time.Second)
		startLoads(t, set, 9)
		time.Sleep(30 * time.Second)
		_, _ = lookupRealm(t, set, "invented-last")
		_, _ = set.LookupOrReload(t.Context(), Query{Issuer: iss("tenant-1"), KID: "rotated"})
		if got := log.count(`realm "tenant-1" is not reloaded`); got != 1 {
			t.Errorf("warnings about the refused reload = %d, want 1; warnings: %q", got, log.warnings)
		}
	})
}

func TestLookupOrReload_WarnsOnceAMinuteWhileTheLimitOfLoadsRefusesRealms(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		log := &warnRecorder{}
		opts := testOptions()
		opts.Log = log
		set := keycloakSet(t, kc, opts)
		startLoads(t, set, 10)
		const warning = "on-demand loads in the last minute"
		_, _ = lookupRealm(t, set, "other-1")
		_, _ = lookupRealm(t, set, "other-2")
		if got := log.count(warning); got != 1 {
			t.Errorf("warnings about the limit of loads after two refused realms = %d, want 1", got)
		}
		time.Sleep(time.Minute)
		startLoads(t, set, 10)
		_, _ = lookupRealm(t, set, "other-3")
		if got := log.count(warning); got != 2 {
			t.Errorf("warnings about the limit of loads a minute later = %d, want 2", got)
		}
	})
}

func TestLookupOrReload_KeepsNoMoreRealmsThanTheLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		for _, realm := range []string{"a", "b", "c"} {
			kc.publishRealm(realm, ecJWK(t, "k1", nil))
		}
		log := &warnRecorder{}
		opts := testOptions()
		opts.Log = log
		opts.maxRealms = 2
		set := keycloakSet(t, kc, opts)
		for _, realm := range []string{"a", "b"} {
			if _, err := lookupRealm(t, set, realm); err != nil {
				t.Fatalf("LookupOrReload(realm %q) error = %v", realm, err)
			}
		}
		time.Sleep(time.Hour)
		if _, err := lookupRealm(t, set, "c"); !errors.Is(err, ErrKeysUnavailable) {
			t.Errorf("LookupOrReload(realm %q) error = %v, want %v", "c", err, ErrKeysUnavailable)
		}
		if got := kc.loadsOf("c"); got != 0 {
			t.Errorf("discovery requests for realm %q = %d, want 0", "c", got)
		}
		if got := log.count(`realm "c" is not loaded`); got != 1 {
			t.Errorf("warnings about realm %q = %d, want 1; warnings: %q", "c", got, log.warnings)
		}
	})
}

// One place of two holds a realm with keys, and the other a realm that failed.
// A new realm takes the place of the failed one a minute after its load.
func TestLookupOrReload_ANewRealmTakesThePlaceOfARealmThatFailedAMinuteAgo(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.publishRealm("a", ecJWK(t, "k1", nil))
		kc.publishRealm("b", ecJWK(t, "k1", nil))
		opts := testOptions()
		opts.maxRealms = 2
		set := keycloakSet(t, kc, opts)
		if _, err := lookupRealm(t, set, "a"); err != nil {
			t.Fatalf("LookupOrReload(realm %q) error = %v", "a", err)
		}
		_, _ = lookupRealm(t, set, "ghost")
		time.Sleep(59 * time.Second)
		if _, err := lookupRealm(t, set, "b"); !errors.Is(err, ErrKeysUnavailable) {
			t.Errorf("LookupOrReload(realm %q) 59 s after the failure: error = %v, want %v", "b", err, ErrKeysUnavailable)
		}
		time.Sleep(time.Second)
		if _, err := lookupRealm(t, set, "b"); err != nil {
			t.Errorf("LookupOrReload(realm %q) a minute after the failure: error = %v", "b", err)
		}
	})
}

// Realms ghost-1 and ghost-2 fail together and take both places, so realms a
// and b fit a minute later only when the search drops both.
func TestLookupOrReload_DropsEveryRealmThatFailedAMinuteAgo(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.publishRealm("a", ecJWK(t, "k1", nil))
		kc.publishRealm("b", ecJWK(t, "k1", nil))
		opts := testOptions()
		opts.maxRealms = 2
		set := keycloakSet(t, kc, opts)
		_, _ = lookupRealm(t, set, "ghost-1")
		_, _ = lookupRealm(t, set, "ghost-2")
		time.Sleep(time.Minute)
		for _, realm := range []string{"a", "b"} {
			if _, err := lookupRealm(t, set, realm); err != nil {
				t.Errorf("LookupOrReload(realm %s) a minute after the failures: error = %v", realm, err)
			}
		}
	})
}

// youngFailedRealmAtTheLimit returns a Set at a limit of two realms, 60 s into
// the synctest bubble that calls it. Realm old failed at 0 s and realm young at
// 30 s. Realm b loaded keys at 60 s, when the search dropped old and kept young,
// which is due at 90 s. Realms c and d exist on the Keycloak.
func youngFailedRealmAtTheLimit(t *testing.T) (*Set, *fakeTransport) {
	t.Helper()
	kc := newKeycloakTransport(t)
	for _, realm := range []string{"b", "c", "d"} {
		kc.publishRealm(realm, ecJWK(t, "k1", nil))
	}
	opts := testOptions()
	opts.maxRealms = 2
	set := keycloakSet(t, kc, opts)
	_, _ = lookupRealm(t, set, "old")
	time.Sleep(30 * time.Second)
	_, _ = lookupRealm(t, set, "young")
	time.Sleep(30 * time.Second)
	if _, err := lookupRealm(t, set, "b"); err != nil {
		t.Fatalf("LookupOrReload(realm b) at 60 s error = %v, want the place of realm old", err)
	}
	return set, kc
}

// Realms old, mid, and young fail 20 s apart at a limit of three. The search at
// 60 s drops old and keeps mid, due at 80 s, and young, due at 100 s, so realm
// c takes the place of mid at 80 s.
func TestLookupOrReload_DropsTheEarlierOfTwoKeptRealmsAtItsMinute(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.publishRealm("b", ecJWK(t, "k1", nil))
		kc.publishRealm("c", ecJWK(t, "k1", nil))
		opts := testOptions()
		opts.maxRealms = 3
		set := keycloakSet(t, kc, opts)
		for _, realm := range []string{"old", "mid", "young"} {
			_, _ = lookupRealm(t, set, realm)
			time.Sleep(20 * time.Second)
		}
		if _, err := lookupRealm(t, set, "b"); err != nil {
			t.Fatalf("LookupOrReload(realm b) at 60 s error = %v, want the place of realm old", err)
		}
		time.Sleep(20 * time.Second)
		if _, err := lookupRealm(t, set, "c"); err != nil {
			t.Errorf("LookupOrReload(realm c) at 80 s error = %v, want the place of realm mid", err)
		}
	})
}

func TestLookupOrReload_KeepsARealmThatFailedLaterUntilItsOwnMinute(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		set, kc := youngFailedRealmAtTheLimit(t)
		time.Sleep(29 * time.Second)
		_, _ = lookupRealm(t, set, "young")
		if got := kc.loadsOf("young"); got != 1 {
			t.Errorf("discovery requests for realm young by 89 s = %d, want 1", got)
		}
		if _, err := lookupRealm(t, set, "c"); !errors.Is(err, ErrKeysUnavailable) {
			t.Errorf("LookupOrReload(realm c) at 89 s error = %v, want %v", err, ErrKeysUnavailable)
		}
		time.Sleep(time.Second)
		if _, err := lookupRealm(t, set, "c"); err != nil {
			t.Errorf("LookupOrReload(realm c) at 90 s error = %v, want the place of realm young", err)
		}
	})
}

// The Set holds two realms that loaded keys, so it drops neither, and the third
// realm is refused for the realm limit. Its tokens start no load, so they leave
// the limit of loads to the rotation of a held realm in the same minute.
func TestLookupOrReload_ARealmRefusedForTheRealmLimitTakesNoLoad(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.publishRealm("tenant-1", ecJWK(t, "k1", nil))
		kc.publishRealm("tenant-2", ecJWK(t, "k1", nil))
		opts := testOptions()
		opts.maxRealms = 2
		set := keycloakSet(t, kc, opts)
		for _, realm := range []string{"tenant-1", "tenant-2"} {
			if _, err := lookupRealm(t, set, realm); err != nil {
				t.Fatalf("LookupOrReload(realm %s) error = %v", realm, err)
			}
		}
		time.Sleep(time.Minute)
		for range maxLoadsPerMinute {
			if _, err := lookupRealm(t, set, "tenant-3"); !errors.Is(err, ErrKeysUnavailable) {
				t.Fatalf("LookupOrReload(realm tenant-3) error = %v, want %v", err, ErrKeysUnavailable)
			}
		}
		kc.publishRealm("tenant-1", ecJWK(t, "k1", nil), ecJWK(t, "k2", nil))
		if _, err := set.LookupOrReload(t.Context(), Query{Issuer: iss("tenant-1"), KID: "k2"}); err != nil {
			t.Errorf("LookupOrReload(the rotated key of realm tenant-1) error = %v, want none", err)
		}
	})
}

// The realm that loaded keys answers 404 from then on, and its keys stay, also
// when the Set drops the realms that failed. The error names it as a realm.
func TestRefresh_ARealmThatDisappearsKeepsItsKeys(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.publishRealm("tenant-1", ecJWK(t, "k1", nil))
		set := keycloakSet(t, kc, testOptions())
		if _, err := lookupRealm(t, set, "tenant-1"); err != nil {
			t.Fatalf("LookupOrReload() error = %v", err)
		}
		kc.removeRealm("tenant-1")
		if err := set.Refresh(t.Context()); err == nil || !strings.Contains(err.Error(), `realm "tenant-1" keeps its previous keys`) {
			t.Errorf("Refresh() error = %v, want an error saying the realm keeps its keys", err)
		}
		time.Sleep(time.Hour)
		_, _ = lookupRealm(t, set, "ghost")
		if _, err := set.Lookup(Query{Issuer: iss("tenant-1"), KID: "k1"}); err != nil {
			t.Errorf("Lookup() after the realm disappeared: error = %v", err)
		}
	})
}

// A realm that holds keys existed a moment ago, so its 404 says nothing about the
// key a token asks for, while the 404 of a realm that holds none is how a token
// with an invented realm ends. The load runs a minute after the first one, when
// a token may start it.
func TestLookupOrReload_TakesA404AsAnAnswerOnlyForARealmWithNoKeys(t *testing.T) {
	tests := []struct {
		name  string
		realm string
		want  error
	}{
		{"realm that holds keys", "tenant-1", ErrKeysUnavailable},
		{"realm that holds none", "ghost", ErrKeyUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				kc := newKeycloakTransport(t)
				kc.publishRealm("tenant-1", ecJWK(t, "k1", nil))
				set := keycloakSet(t, kc, testOptions())
				if _, err := lookupRealm(t, set, "tenant-1"); err != nil {
					t.Fatalf("LookupOrReload() error = %v", err)
				}
				kc.removeRealm("tenant-1")
				time.Sleep(time.Minute)
				_, err := set.LookupOrReload(t.Context(), Query{Issuer: iss(tt.realm), KID: "rotated"})
				if !errors.Is(err, tt.want) {
					t.Errorf("LookupOrReload(realm %s) error = %v, want %v", tt.realm, err, tt.want)
				}
			})
		})
	}
}

// A JWKS without a usable key removed the keys of the realm, so the realm holds
// none when the 404 arrives, although it loaded keys once.
func TestLookupOrReload_TakesA404AsAnAnswerForARealmThatLostItsKeys(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.publishRealm("tenant-1", ecJWK(t, "k1", nil))
		set := keycloakSet(t, kc, testOptions())
		if _, err := lookupRealm(t, set, "tenant-1"); err != nil {
			t.Fatalf("LookupOrReload() error = %v", err)
		}
		kc.publishRealm("tenant-1", ecJWK(t, "enc", map[string]any{"use": "enc"}))
		if err := set.Refresh(t.Context()); err == nil {
			t.Fatalf("Refresh() error = nil, want the JWKS without a usable key")
		}
		kc.removeRealm("tenant-1")
		time.Sleep(time.Minute)
		if _, err := lookupRealm(t, set, "tenant-1"); !errors.Is(err, ErrKeyUnknown) {
			t.Errorf("LookupOrReload() error = %v, want %v", err, ErrKeyUnknown)
		}
	})
}

// The realm that never loaded is asked once more at 59 s, and not at 60 s.
func TestRefresh_DropsARealmThatFailedAMinuteAgo(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		set := keycloakSet(t, kc, testOptions())
		_, _ = lookupRealm(t, set, "ghost")
		time.Sleep(59 * time.Second)
		if err := set.Refresh(t.Context()); err == nil {
			t.Errorf("Refresh() at 59 s error = nil, want the 404 of the realm")
		}
		if got := kc.loadsOf("ghost"); got != 2 {
			t.Errorf("discovery requests at 59 s = %d, want 2", got)
		}
		time.Sleep(time.Second)
		if err := set.Refresh(t.Context()); err != nil {
			t.Errorf("Refresh() at 60 s error = %v, want none", err)
		}
		if got := kc.loadsOf("ghost"); got != 2 {
			t.Errorf("discovery requests at 60 s = %d, want 2", got)
		}
	})
}

func TestRefresh_ReloadsTheRealmsThatTokensNamed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.publishRealm("tenant-1", ecJWK(t, "k1", nil))
		set := keycloakSet(t, kc, testOptions())
		if _, err := lookupRealm(t, set, "tenant-1"); err != nil {
			t.Fatalf("LookupOrReload() error = %v", err)
		}
		kc.publishRealm("tenant-1", ecJWK(t, "k2", nil))
		if err := set.Refresh(t.Context()); err != nil {
			t.Fatalf("Refresh() error = %v", err)
		}
		for kid, want := range map[string]bool{"k2": true, "k1": false} {
			_, err := set.Lookup(Query{Issuer: iss("tenant-1"), KID: kid})
			if got := err == nil; got != want {
				t.Errorf("Lookup(%q) found = %t, want %t", kid, got, want)
			}
		}
	})
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
			synctest.Test(t, func(t *testing.T) {
				kc := newKeycloakTransport(t)
				kc.setStatus(keycloakHost, http.StatusServiceUnavailable)
				set := bubbleSetOf(t, Config{Keycloak: &Keycloak{URL: keycloakURL, RequiredRealms: tt.required}}, testOptions(), kc)
				_, _ = lookupRealm(t, set, "tenant-1")
				if got := set.Ready(); got != tt.want {
					t.Errorf("Ready() = %t, want %t", got, tt.want)
				}
			})
		})
	}
}

func TestNew_RefusesAnUnusableKeycloakCAFile(t *testing.T) {
	_, err := New(Config{Keycloak: &Keycloak{URL: "https://kc.example", CAFile: writeFile(t, "ca.pem", "not a certificate")}}, testOptions())
	if err == nil || !containsAll(err.Error(), "keycloak", "caFile") {
		t.Errorf("New() error = %v, want an error naming keycloak and caFile", err)
	}
}
