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
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// realmID is the identifier tenant-manager returns for the tenant acme, in
// the UUID form Keycloak names a tenant realm by.
const realmID = "6f1c2a9e-3b4d-4e8f-9a1b-2c3d4e5f6a7b"

// fakeTenantManager serves the tenant-manager lookup: GET
// /api/v4/tenant-manager/registration/tenants?dns=<name> returns the body
// listed for the name, and 404 for a name it does not list. A field set
// before a request, or through a method, takes effect on that request.
type fakeTenantManager struct {
	srv *httptest.Server

	mu     sync.Mutex
	bodies map[string]string
	// status, when non-zero, answers every request, with statusBody.
	status     int
	statusBody string
	// failures is how many of the next requests get 503.
	failures int
	// redirect, when set, sends every request to it with a 302.
	redirect string
	// names lists the dns values of the requests, in order.
	names []string
}

func newTenantManager(t *testing.T, bodies map[string]string) *fakeTenantManager {
	t.Helper()
	tm := &fakeTenantManager{bodies: bodies}
	tm.srv = httptest.NewServer(tm)
	t.Cleanup(tm.srv.Close)
	return tm
}

func (tm *fakeTenantManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if r.URL.Path != tenantLookupPath {
		http.NotFound(w, r)
		return
	}
	name := r.URL.Query().Get("dns")
	tm.names = append(tm.names, name)
	switch {
	case tm.redirect != "":
		http.Redirect(w, r, tm.redirect+r.URL.RequestURI(), http.StatusFound)
	case tm.status != 0:
		w.WriteHeader(tm.status)
		_, _ = w.Write([]byte(tm.statusBody))
	case tm.failures > 0:
		tm.failures--
		w.WriteHeader(http.StatusServiceUnavailable)
	default:
		body, ok := tm.bodies[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}
}

func (tm *fakeTenantManager) asked() []string {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return append([]string(nil), tm.names...)
}

func (tm *fakeTenantManager) setStatus(status int) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.status = status
}

// acmeConfig is the provider tenant-acme, the tenant realm of acme under
// /auth/realms/ of idp, with tenant-manager at tm.
func acmeConfig(idp *fakeIdP, tm *fakeTenantManager) Config {
	return Config{Providers: []Provider{tenantIssuer("tenant-acme", "/auth/realms/acme", idp)}, TenantManagerURL: tm.srv.URL}
}

// recordingLogger keeps every message it receives.
type recordingLogger struct {
	mu       sync.Mutex
	messages []string
}

func (l *recordingLogger) Infof(format string, args ...any) { l.record(format, args) }
func (l *recordingLogger) Warnf(format string, args ...any) { l.record(format, args) }

func (l *recordingLogger) record(format string, args []any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.messages = append(l.messages, fmt.Sprintf(format, args...))
}

func (l *recordingLogger) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.messages...)
}

// The IdP serves each realm only under /auth/realms/<identifier>, so a key
// loads only when the tenant name in the issuer was replaced by the answer.
func TestLoad_ResolvesATenantRealmThroughTenantManager(t *testing.T) {
	realm128 := strings.Repeat("a", 128)
	tests := []struct {
		name   string
		tenant string
		suffix string
		answer string
		realm  string
	}{
		{"UUID identifier", "acme", "", realmID, realmID},
		{"identifier with a trailing newline", "acme", "", realmID + "\n", realmID},
		{"identifier padded to exactly 1024 bytes", "acme", "", realmID + strings.Repeat(" ", maxTenantResponseBytes-len(realmID)), realmID},
		{"identifier of 128 characters", "acme", "", realm128, realm128},
		{"issuer with a trailing slash", "acme", "/", realmID, realmID},
		{"tenant name of letters, digits, '.', '_', and '-'", "Acme_corp.v2-x", "", realmID, realmID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newRealmIdP(t, "/auth/realms/"+tt.realm, ecJWK(t, "k1", nil))
			tm := newTenantManager(t, map[string]string{tt.tenant: tt.answer})
			cfg := Config{
				Providers:        []Provider{tenantIssuer("tenant-acme", "/auth/realms/"+tt.tenant+tt.suffix, idp)},
				TenantManagerURL: tm.srv.URL,
			}
			set, err := Load(context.Background(), cfg, testOptions())
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if _, ok := set.Lookup("k1"); !ok {
				t.Errorf("Lookup(%q) found nothing, want the key of realm %q", "k1", tt.realm)
			}
			if got, want := tm.asked(), []string{tt.tenant}; !reflect.DeepEqual(got, want) {
				t.Errorf("tenant-manager lookups = %q, want %q", got, want)
			}
		})
	}
}

func TestLoad_FailsWhenTenantManagerDoesNotResolveTheTenant(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, tm *fakeTenantManager)
	}{
		{"unknown tenant", func(t *testing.T, tm *fakeTenantManager) { delete(tm.bodies, "acme") }},
		{"tenant-manager answers 500", func(t *testing.T, tm *fakeTenantManager) { tm.status = http.StatusInternalServerError }},
		{"tenant-manager answers 503 with a realm-shaped body", func(t *testing.T, tm *fakeTenantManager) {
			tm.status, tm.statusBody = http.StatusServiceUnavailable, "unavailable"
		}},
		{"empty identifier", func(t *testing.T, tm *fakeTenantManager) { tm.bodies["acme"] = "" }},
		{"identifier that is a URL", func(t *testing.T, tm *fakeTenantManager) { tm.bodies["acme"] = "http://idp.example/auth/realms/other" }},
		{"identifier with a slash", func(t *testing.T, tm *fakeTenantManager) { tm.bodies["acme"] = realmID + "/../other" }},
		{"identifier of one dot", func(t *testing.T, tm *fakeTenantManager) { tm.bodies["acme"] = "." }},
		{"identifier of two dots", func(t *testing.T, tm *fakeTenantManager) { tm.bodies["acme"] = ".." }},
		{"identifier of 129 characters", func(t *testing.T, tm *fakeTenantManager) { tm.bodies["acme"] = strings.Repeat("a", 129) }},
		{"identifier padded past 1024 bytes", func(t *testing.T, tm *fakeTenantManager) {
			tm.bodies["acme"] = realmID + strings.Repeat(" ", maxTenantResponseBytes+1-len(realmID))
		}},
		{"redirect to a tenant-manager that would resolve it", func(t *testing.T, tm *fakeTenantManager) {
			tm.redirect = newTenantManager(t, map[string]string{"acme": realmID}).srv.URL
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newRealmIdP(t, "/auth/realms/"+realmID, ecJWK(t, "k1", nil))
			tm := newTenantManager(t, map[string]string{"acme": realmID})
			tt.setup(t, tm)
			opts := testOptions()
			opts.StartupTimeout = 200 * time.Millisecond
			_, err := Load(context.Background(), acmeConfig(idp, tm), opts)
			if err == nil || !containsAll(err.Error(), `provider "tenant-acme"`, `tenant "acme"`) {
				t.Errorf("Load() error = %v, want an error naming provider %q and tenant %q", err, "tenant-acme", "acme")
			}
		})
	}
}

func TestLoad_RetriesTenantManagerUntilItAnswers(t *testing.T) {
	idp := newRealmIdP(t, "/auth/realms/"+realmID, ecJWK(t, "k1", nil))
	tm := newTenantManager(t, map[string]string{"acme": realmID})
	tm.failures = 2
	set, err := Load(context.Background(), acmeConfig(idp, tm), testOptions())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if _, ok := set.Lookup("k1"); !ok {
		t.Errorf("Lookup(%q) found nothing, want the key loaded after two failed lookups", "k1")
	}
}

// The cloud-common issuer ends in a segment that would pass as a tenant name,
// and only the provider marked as a tenant realm is looked up.
func TestLoad_QueriesTenantManagerOnlyForATenantRealm(t *testing.T) {
	common := newRealmIdP(t, "/auth/realms/cloud-common", ecJWK(t, "c1", nil))
	tenant := newRealmIdP(t, "/auth/realms/"+realmID, ecJWK(t, "t1", nil))
	tm := newTenantManager(t, map[string]string{"acme": realmID, "cloud-common": "other"})
	cfg := acmeConfig(tenant, tm)
	cfg.Providers = append(cfg.Providers, Provider{ID: "cloud-common", Issuer: common.srv.URL + "/auth/realms/cloud-common"})
	if _, err := Load(context.Background(), cfg, testOptions()); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got, want := tm.asked(), []string{"acme"}; !reflect.DeepEqual(got, want) {
		t.Errorf("tenant-manager lookups = %q, want %q", got, want)
	}
}

// An operator compares this line with tenant-manager to spot a substituted
// realm.
func TestLoad_LogsTheRealmATenantResolvedTo(t *testing.T) {
	idp := newRealmIdP(t, "/auth/realms/"+realmID, ecJWK(t, "k1", nil))
	tm := newTenantManager(t, map[string]string{"acme": realmID})
	log := &recordingLogger{}
	opts := testOptions()
	opts.Log = log
	if _, err := Load(context.Background(), acmeConfig(idp, tm), opts); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := []string{`provider "tenant-acme"`, `tenant "acme"`, `realm "` + realmID + `"`}
	for _, line := range log.all() {
		if containsAll(line, want...) {
			return
		}
	}
	t.Errorf("log = %q, want a line with %q", log.all(), want)
}

// After the load, tenant-manager fails every request and the IdP rotates its
// key; the reload still reaches the realm Load resolved.
func TestRefresh_KeepsTheRealmLoadResolved(t *testing.T) {
	idp := newRealmIdP(t, "/auth/realms/"+realmID, ecJWK(t, "k1", nil))
	tm := newTenantManager(t, map[string]string{"acme": realmID})
	set, err := Load(context.Background(), acmeConfig(idp, tm), testOptions())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	tm.setStatus(http.StatusInternalServerError)
	idp.publish(ecJWK(t, "k2", nil))

	if err := set.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if _, ok := set.Lookup("k2"); !ok {
		t.Errorf("Lookup(%q) found nothing, want the rotated key of realm %q", "k2", realmID)
	}
	if got, want := tm.asked(), []string{"acme"}; !reflect.DeepEqual(got, want) {
		t.Errorf("tenant-manager lookups = %q, want %q", got, want)
	}
}

func TestRealmIssuer_ReplacesOnlyTheLastPathSegment(t *testing.T) {
	tests := []struct {
		name   string
		issuer string
		want   string
	}{
		{"plain path", "https://idp.example:8443/auth/realms/acme", "https://idp.example:8443/auth/realms/" + realmID},
		{"trailing slash", "https://idp.example/auth/realms/acme/", "https://idp.example/auth/realms/" + realmID},
		{"escaped prefix", "https://idp.example/auth%2Dx/realms/acme", "https://idp.example/auth%2Dx/realms/" + realmID},
		{"query", "https://idp.example/auth/realms/acme?x=1", "https://idp.example/auth/realms/" + realmID + "?x=1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := realmIssuer(tt.issuer, realmID); got != tt.want {
				t.Errorf("realmIssuer(%q, %q) = %q, want %q", tt.issuer, realmID, got, tt.want)
			}
		})
	}
}
