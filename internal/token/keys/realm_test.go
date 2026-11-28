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

// iss is the iss of a token of realm at the address that keycloakProvider
// trusts. Its host is not the host of the Keycloak: the token names the realm,
// and the configuration names the server.
func iss(realm string) string { return "https://public.example" + realmsPath + realm }

// lookupRealm asks for key k1 of realm.
func lookupRealm(t *testing.T, set *Set, realm string) (Key, error) {
	t.Helper()
	return set.LookupOrReload(t.Context(), Query{Issuer: iss(realm), KID: "k1"})
}

func TestSource_IDNamesARealmByItsNameAndASingleProviderByItsID(t *testing.T) {
	tests := []struct {
		name   string
		source Source
		want   string
	}{
		{"realm", Source{Provider: &Provider{ID: IdentityProviderID}, Realm: "tenant 1"}, "realm/tenant 1"},
		{"single provider", Source{Provider: &Provider{ID: KubernetesID}}, "kubernetes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.source.ID(); got != tt.want {
				t.Errorf("ID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSource_KubernetesHoldsOnlyForTheProviderKubernetes(t *testing.T) {
	tests := []struct {
		name   string
		source Source
		want   bool
	}{
		{"provider kubernetes", Source{Provider: &Provider{ID: KubernetesID}}, true},
		{"single provider identity-provider", Source{Provider: &Provider{ID: IdentityProviderID}}, false},
		{"realm of provider identity-provider", Source{Provider: &Provider{ID: IdentityProviderID}, Realm: "tenant-1"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.source.Kubernetes(); got != tt.want {
				t.Errorf("Kubernetes() of %s = %t, want %t", tt.source.label(), got, tt.want)
			}
		})
	}
}

// The provider trusts https://kc.example:8443/auth/realms/{realm}. Lookup sends
// no request, so a matched iss gets ErrKeyUnknown for a realm the Set does not
// hold yet, and any other iss ErrIssuerUnknown.
func TestLookup_MatchesTheIssOfAnIssuerTemplateAsAWholeURL(t *testing.T) {
	provider := keycloakProvider()
	provider.IssuerTemplate = "https://kc.example:8443/auth/realms/{realm}"
	set := mustNew(t, Config{Providers: []Provider{provider}}, testOptions())
	const base = "https://kc.example:8443/auth/realms/"
	tests := []struct {
		name, iss string
		want      error
	}{
		{"realm", base + "tenant-1", ErrKeyUnknown},
		{"percent-encoded name", base + "a%20b", ErrKeyUnknown},
		{"name of 255 bytes", base + strings.Repeat("x", 255), ErrKeyUnknown},
		{"name with a character outside ASCII", base + "t%C3%BC", ErrKeyUnknown},
		{"scheme in upper case", "HTTPS://kc.example:8443/auth/realms/tenant-1", ErrIssuerUnknown},
		{"host in upper case", "https://KC.example:8443/auth/realms/tenant-1", ErrIssuerUnknown},
		{"no port", "https://kc.example/auth/realms/tenant-1", ErrIssuerUnknown},
		{"another host", "https://other.example:8443/auth/realms/tenant-1", ErrIssuerUnknown},
		{"path without /auth", "https://kc.example:8443/realms/tenant-1", ErrIssuerUnknown},
		{"trailing slash", base + "tenant-1/", ErrIssuerUnknown},
		{"segment after the realm", base + "a/b", ErrIssuerUnknown},
		{"empty name", base, ErrIssuerUnknown},
		{"empty iss", "", ErrIssuerUnknown},
		{"name of 256 bytes", base + strings.Repeat("x", 256), ErrIssuerUnknown},
		{"dot", base + ".", ErrIssuerUnknown},
		{"dot dot", base + "..", ErrIssuerUnknown},
		{"percent-encoded dots", base + "%2e%2e", ErrIssuerUnknown},
		{"percent-encoded slash", base + "a%2Fb", ErrIssuerUnknown},
		{"question mark", base + "a?b", ErrIssuerUnknown},
		{"percent-encoded question mark", base + "a%3Fb", ErrIssuerUnknown},
		{"hash", base + "a#b", ErrIssuerUnknown},
		{"percent-encoded control character", base + "a%01b", ErrIssuerUnknown},
		{"percent-encoded DEL", base + "a%7Fb", ErrIssuerUnknown},
		{"percent-encoded C1 control character", base + "a%C2%85b", ErrIssuerUnknown},
		{"broken percent escape", base + "a%zz", ErrIssuerUnknown},
		{"percent-encoded byte that is not UTF-8", base + "a%FFb", ErrIssuerUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := set.Lookup(Query{Issuer: tt.iss, KID: "k1"}); !errors.Is(err, tt.want) {
				t.Errorf("Lookup(issuer %q) error = %v, want %v", tt.iss, err, tt.want)
			}
		})
	}
}

func TestLookup_MatchesAnIssuerTemplateWithASegmentAfterTheRealm(t *testing.T) {
	provider := keycloakProvider()
	provider.IssuerTemplate = "https://kc.example/tenants/{realm}/issuer"
	set := mustNew(t, Config{Providers: []Provider{provider}}, testOptions())
	tests := []struct {
		name, iss string
		want      error
	}{
		{"realm", "https://kc.example/tenants/a/issuer", ErrKeyUnknown},
		{"two segments in place of the realm", "https://kc.example/tenants/a/b/issuer", ErrIssuerUnknown},
		{"another last segment of the same length", "https://kc.example/tenants/a/issuex", ErrIssuerUnknown},
		{"prefix and suffix that overlap", "https://kc.example/tenants/issuer", ErrIssuerUnknown},
		{"trailing slash", "https://kc.example/tenants/a/issuer/", ErrIssuerUnknown},
		{"nothing in place of the realm", "https://kc.example/tenants//issuer", ErrIssuerUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := set.Lookup(Query{Issuer: tt.iss, KID: "k1"}); !errors.Is(err, tt.want) {
				t.Errorf("Lookup(issuer %q) error = %v, want %v", tt.iss, err, tt.want)
			}
		})
	}
}

// The iss names public.example, and the jwksUri names the Keycloak. The second
// lookup sends no request, because the first one loaded the realm for good.
func TestLookupOrReload_LoadsARealmFromTheJWKSURIOfItsProvider(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.publishRealm("tenant-1", ecJWK(t, "k1", nil))
		set := keycloakSet(t, kc, testOptions())
		key, err := lookupRealm(t, set, "tenant-1")
		if err != nil {
			t.Fatalf("LookupOrReload() error = %v", err)
		}
		if key.Source.Realm != "tenant-1" || key.Source.Provider == nil || key.Source.Provider.ID != IdentityProviderID {
			t.Errorf("Source = %+v, want the realm tenant-1 of provider %q", key.Source, IdentityProviderID)
		}
		if _, err := lookupRealm(t, set, "tenant-1"); err != nil {
			t.Errorf("second LookupOrReload() error = %v", err)
		}
		if got, want := kc.urls(), []string{keycloakURL + jwksPath("tenant-1")}; !slices.Equal(got, want) {
			t.Errorf("JWKS requests = %q, want %q", got, want)
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
			if got := key.Source.Realm; got != realm {
				t.Errorf("LookupOrReload(realm %q).Source.Realm = %q", realm, got)
			}
		}
	})
}

// Every name stays one path segment on the server, whatever it holds.
func TestLookupOrReload_EscapesTheRealmNameInTheAddress(t *testing.T) {
	tests := []struct {
		name, realm, want string
	}{
		{"space", "a b", jwksPath("a%20b")},
		{"space the iss encodes", "a%20b", jwksPath("a%20b")},
		{"percent sign", "100%25", jwksPath("100%25")},
		{"character outside ASCII", "t\u00fc", jwksPath("t%C3%BC")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				kc := newKeycloakTransport(t)
				set := keycloakSet(t, kc, testOptions())
				_, _ = lookupRealm(t, set, tt.realm)
				if got := kc.paths(); !slices.Equal(got, []string{tt.want}) {
					t.Errorf("JWKS requests for the realm %q = %q, want %q", tt.realm, got, []string{tt.want})
				}
			})
		})
	}
}

func TestLookupOrReload_RefusesAnIssuerNoProviderMatches(t *testing.T) {
	kc := newKeycloakTransport(t)
	withRealms := keycloakSet(t, kc, testOptions())
	withoutRealms := bubbleSetOf(t, Config{Providers: []Provider{providerOf(KubernetesID)}}, testOptions(), kc)
	tests := []struct {
		name string
		set  *Set
		iss  string
	}{
		{"iss of another server", withRealms, "https://idp.example/oidc"},
		{"empty iss", withRealms, ""},
		{"realm that is a dot segment", withRealms, iss("..")},
		{"realm without a realms provider", withoutRealms, iss("tenant-1")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.set.LookupOrReload(t.Context(), Query{Issuer: tt.iss, KID: "k1"})
			if !errors.Is(err, ErrIssuerUnknown) {
				t.Errorf("LookupOrReload(issuer %q) error = %v, want %v", tt.iss, err, ErrIssuerUnknown)
			}
			if got := kc.loadCount(); got != 0 {
				t.Errorf("JWKS requests after LookupOrReload(issuer %q) = %d, want 0", tt.iss, got)
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
			t.Errorf("JWKS requests after Lookup() = %d, want 0", got)
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
				t.Errorf("JWKS requests by %s = %d, want %d", tt.at, got, tt.want)
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
			t.Fatalf("JWKS requests for 10 realms = %d, want 10", got)
		}
		for _, step := range []time.Duration{0, 59 * time.Second} {
			time.Sleep(step)
			if _, err := lookupRealm(t, set, "tenant-1"); !errors.Is(err, ErrKeyUnknown) {
				t.Errorf("LookupOrReload() %s after the limit of loads was reached: error = %v, want %v", step, err, ErrKeyUnknown)
			}
			if got := kc.loadsOf("tenant-1"); got != 0 {
				t.Errorf("JWKS requests %s after the limit of loads was reached = %d, want 0", step, got)
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
		if _, err := set.LookupOrReload(t.Context(), q); !errors.Is(err, ErrKeyUnknown) {
			t.Errorf("LookupOrReload(%+v) error = %v, want %v", q, err, ErrKeyUnknown)
		}
		if got := kc.loadsOf("tenant-1"); got != 1 {
			t.Errorf("JWKS requests at the limit of loads = %d, want 1", got)
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
			t.Errorf("JWKS requests = %d, want 10: the load of the realm and 9 new realms", got)
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
		if got := log.count(`realm "tenant-1" of provider "identity-provider" is not reloaded`); got != 1 {
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
		const warning = `on-demand loads of provider "identity-provider" in the last minute`
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
		if _, err := lookupRealm(t, set, "c"); !errors.Is(err, ErrKeyUnknown) {
			t.Errorf("LookupOrReload(realm %q) error = %v, want %v", "c", err, ErrKeyUnknown)
		}
		if got := kc.loadsOf("c"); got != 0 {
			t.Errorf("JWKS requests for realm %q = %d, want 0", "c", got)
		}
		if got := log.count(`realm "c" of provider "identity-provider" is not loaded`); got != 1 {
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
		if _, err := lookupRealm(t, set, "b"); !errors.Is(err, ErrKeyUnknown) {
			t.Errorf("LookupOrReload(realm %q) 59 s after the failure: error = %v, want %v", "b", err, ErrKeyUnknown)
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
			t.Errorf("JWKS requests for realm young by 89 s = %d, want 1", got)
		}
		if _, err := lookupRealm(t, set, "c"); !errors.Is(err, ErrKeyUnknown) {
			t.Errorf("LookupOrReload(realm c) at 89 s error = %v, want %v", err, ErrKeyUnknown)
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
			if _, err := lookupRealm(t, set, "tenant-3"); !errors.Is(err, ErrKeyUnknown) {
				t.Fatalf("LookupOrReload(realm tenant-3) error = %v, want %v", err, ErrKeyUnknown)
			}
		}
		kc.publishRealm("tenant-1", ecJWK(t, "k1", nil), ecJWK(t, "k2", nil))
		if _, err := set.LookupOrReload(t.Context(), Query{Issuer: iss("tenant-1"), KID: "k2"}); err != nil {
			t.Errorf("LookupOrReload(the rotated key of realm tenant-1) error = %v, want none", err)
		}
	})
}

// Realm lost loaded a key and then publishes only an encryption key, so the
// reload removes its keys; realm ghost never loaded. A minute later, at the
// limit of two realms, realm c takes the place of ghost and realm d finds none.
func TestLookupOrReload_ARealmThatLostItsKeysKeepsItsPlace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		for _, realm := range []string{"lost", "c", "d"} {
			kc.publishRealm(realm, ecJWK(t, "k1", nil))
		}
		opts := testOptions()
		opts.maxRealms = 2
		set := keycloakSet(t, kc, opts)
		if _, err := lookupRealm(t, set, "lost"); err != nil {
			t.Fatalf("LookupOrReload(realm lost) error = %v", err)
		}
		_, _ = lookupRealm(t, set, "ghost")
		kc.publishRealm("lost", ecJWK(t, "enc", map[string]any{"use": "enc"}))
		_ = set.Refresh(t.Context())
		if _, err := set.Lookup(Query{Issuer: iss("lost"), KID: "k1"}); !errors.Is(err, ErrKeyUnknown) {
			t.Fatalf("Lookup(the key of realm lost) after a reload of only an encryption key: error = %v, want %v", err, ErrKeyUnknown)
		}
		time.Sleep(time.Minute)
		if _, err := lookupRealm(t, set, "c"); err != nil {
			t.Errorf("LookupOrReload(realm c) at 60 s error = %v, want the place of realm ghost", err)
		}
		if _, err := lookupRealm(t, set, "d"); !errors.Is(err, ErrKeyUnknown) {
			t.Errorf("LookupOrReload(realm d) at 60 s error = %v, want %v for the limit of realms", err, ErrKeyUnknown)
		}
	})
}

// The realm that loaded keys answers 404 from then on, and its keys stay, also
// when the Set drops the realms that failed. The error names it as a realm, and
// a token of another kid gets ErrKeyUnknown, as a token of any realm that
// holds keys does.
func TestRefresh_ARealmThatDisappearsKeepsItsKeys(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.publishRealm("tenant-1", ecJWK(t, "k1", nil))
		set := keycloakSet(t, kc, testOptions())
		if _, err := lookupRealm(t, set, "tenant-1"); err != nil {
			t.Fatalf("LookupOrReload() error = %v", err)
		}
		kc.removeRealm("tenant-1")
		if err := set.Refresh(t.Context()); err == nil || !strings.Contains(err.Error(), `realm "tenant-1" of provider "identity-provider" keeps its previous keys`) {
			t.Errorf("Refresh() error = %v, want an error saying the realm keeps its keys", err)
		}
		time.Sleep(time.Hour)
		_, _ = lookupRealm(t, set, "ghost")
		if _, err := set.Lookup(Query{Issuer: iss("tenant-1"), KID: "k1"}); err != nil {
			t.Errorf("Lookup(k1) after the realm disappeared: error = %v", err)
		}
		if _, err := set.Lookup(Query{Issuer: iss("tenant-1"), KID: "k2"}); !errors.Is(err, ErrKeyUnknown) {
			t.Errorf("Lookup(k2) after the realm disappeared: error = %v, want %v", err, ErrKeyUnknown)
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
			t.Errorf("JWKS requests at 59 s = %d, want 2", got)
		}
		time.Sleep(time.Second)
		if err := set.Refresh(t.Context()); err != nil {
			t.Errorf("Refresh() at 60 s error = %v, want none", err)
		}
		if got := kc.loadsOf("ghost"); got != 2 {
			t.Errorf("JWKS requests at 60 s = %d, want 2", got)
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
				set := bubbleSetOf(t, Config{Providers: []Provider{keycloakProvider(tt.required...)}}, testOptions(), kc)
				_, _ = lookupRealm(t, set, "tenant-1")
				if got := set.Ready(); got != tt.want {
					t.Errorf("Ready() = %t, want %t", got, tt.want)
				}
			})
		})
	}
}

// Ten invented realms use up the limit of loads of the provider
// identity-provider. The provider kubernetes then publishes a new key, which
// its token loads, and a new realm of identity-provider loads nothing.
func TestLookupOrReload_KeepsTheLimitOfLoadsOfEachProviderApart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kc := newKeycloakTransport(t)
		kc.publishRealm("tenant-1", ecJWK(t, "k1", nil))
		k8s := providerOf(KubernetesID)
		set := bubbleSetOf(t, Config{Providers: []Provider{keycloakProvider(), k8s}}, testOptions(), kc)
		if err := set.Refresh(t.Context()); err != nil {
			t.Fatalf("Refresh() error = %v", err)
		}
		startLoads(t, set, maxLoadsPerMinute)
		kc.publish(t, ecJWK(t, "k1", nil), ecJWK(t, "rotated", nil))
		if _, err := set.LookupOrReload(t.Context(), Query{Issuer: k8s.Issuer, KID: "rotated"}); err != nil {
			t.Errorf("LookupOrReload(the rotated key of provider kubernetes) error = %v, want none", err)
		}
		if _, err := lookupRealm(t, set, "tenant-1"); !errors.Is(err, ErrKeyUnknown) {
			t.Errorf("LookupOrReload(realm tenant-1) error = %v, want %v", err, ErrKeyUnknown)
		}
		if got := kc.loadsOf("tenant-1"); got != 0 {
			t.Errorf("JWKS requests for realm tenant-1 = %d, want 0", got)
		}
	})
}
