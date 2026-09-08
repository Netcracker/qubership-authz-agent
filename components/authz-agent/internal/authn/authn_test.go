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

package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// store records every Put.
type store struct {
	mu   sync.Mutex
	puts []put
}

type put struct {
	path  []string
	value any
}

func (s *store) Put(_ context.Context, path []string, value any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.puts = append(s.puts, put{path: path, value: value})
	return nil
}

func (s *store) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.puts)
}

// last decodes the last published document through JSON, as the engine
// stores it.
func (s *store) last(t *testing.T) document {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.puts) == 0 {
		t.Fatal("nothing was published")
	}
	raw, err := json.Marshal(s.puts[len(s.puts)-1].value)
	if err != nil {
		t.Fatal(err)
	}
	var doc document
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// document is the shape of data.authn.
type document struct {
	TrustedProviders struct {
		ByID map[string]map[string]any `json:"byId"`
	} `json:"trustedProviders"`
	JwksByKid map[string][]struct {
		ProviderID string `json:"providerId"`
		Alg        string `json:"alg"`
		Kty        string `json:"kty"`
		JWKSJSON   string `json:"jwksJson"`
	} `json:"jwksByKid"`
}

type quiet struct{}

func (quiet) Infof(string, ...any) {}
func (quiet) Warnf(string, ...any) {}

// idp serves OIDC discovery and a JWKS for the realms it knows: k1 as the
// signing key of realm a, an encryption key and a key without a kid that
// no index may carry, and realm b with k2.
func idp(t *testing.T) *httptest.Server {
	t.Helper()
	keys := map[string][]map[string]any{
		"a": {
			{"kid": "k1", "kty": "RSA", "alg": "RS256", "use": "sig", "n": "n1", "e": "AQAB"},
			{"kid": "enc1", "kty": "RSA", "use": "enc", "n": "n2", "e": "AQAB"},
			{"kty": "RSA", "n": "n3", "e": "AQAB"},
		},
		"b": {{"kid": "k2", "kty": "EC", "alg": "ES256", "crv": "P-256"}},
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var realm, rest string
		if _, after, ok := strings.Cut(r.URL.Path, "/realms/"); ok {
			realm, rest, _ = strings.Cut(after, "/")
		}
		if _, known := keys[realm]; !known {
			http.NotFound(w, r)
			return
		}
		switch rest {
		case ".well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": srv.URL + "/realms/" + realm + "/keys"})
		case "keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys[realm]})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func providersFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trusted-providers.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newManager(t *testing.T, file string, required bool, tenantManager string) (*Manager, *store) {
	t.Helper()
	st := &store{}
	m := New(Config{File: file, Required: required, HTTPTimeout: 2 * time.Second, HTTPRetries: 1, TenantManagerURL: tenantManager}, st, quiet{})
	return m, st
}

// TestBootstrap_PublishesTheKeysByKid: every provider's signing keys land
// under their kid with the provider they came from, one single-key JWKS
// each; keys without a kid and encryption keys are left out; the providers
// are indexed by id without their fetch address.
func TestBootstrap_PublishesTheKeysByKid(t *testing.T) {
	srv := idp(t)
	jwksFile := filepath.Join(t.TempDir(), "b.json")
	if err := os.WriteFile(jwksFile, []byte(`{"keys":[{"kid":"k2","kty":"EC","alg":"ES256"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	file := providersFile(t, fmt.Sprintf(`{"providers":[
		{"id":"a","issuer":"%s/realms/a","audiences":["x"],"required":true,"allowMissingAud":true},
		{"id":"b","jwksUri":"file://%s"}]}`, srv.URL, jwksFile))
	m, st := newManager(t, file, true, "")

	status := m.Bootstrap(context.Background())
	want := Status{Mode: "strict", ConfiguredCount: 2, SuccessCount: 2, Providers: []ProviderResult{
		{ID: "a", Result: "success", Required: true}, {ID: "b", Result: "success"}}}
	status.CompletedAt = ""
	if !reflect.DeepEqual(status, want) {
		t.Errorf("Bootstrap() status = %+v, want %+v", status, want)
	}
	if got := m.Status(); got.CompletedAt == "" {
		t.Errorf("Status().CompletedAt = %q, want a timestamp", got.CompletedAt)
	}
	doc := st.last(t)
	wantByID := map[string]map[string]any{
		"a": {"id": "a", "audiences": []any{"x"}, "required": true, "allowMissingAud": true},
		"b": {"id": "b"},
	}
	if !reflect.DeepEqual(doc.TrustedProviders.ByID, wantByID) {
		t.Errorf("trustedProviders.byId = %v, want %v", doc.TrustedProviders.ByID, wantByID)
	}
	if kids := keysOf(doc.JwksByKid); !reflect.DeepEqual(kids, []string{"k1", "k2"}) {
		t.Fatalf("jwksByKid kids = %v, want [k1 k2]", kids)
	}
	k1 := doc.JwksByKid["k1"]
	if len(k1) != 1 || k1[0].ProviderID != "a" || k1[0].Alg != "RS256" || k1[0].Kty != "RSA" {
		t.Errorf("jwksByKid.k1 = %+v, want one RS256 RSA candidate of provider a", k1)
	}
	var single struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal([]byte(k1[0].JWKSJSON), &single); err != nil || len(single.Keys) != 1 || single.Keys[0]["kid"] != "k1" {
		t.Errorf("jwksByKid.k1 jwksJson = %s, want a JWKS with the one key k1", k1[0].JWKSJSON)
	}
	if k2 := doc.JwksByKid["k2"]; len(k2) != 1 || k2[0].ProviderID != "b" {
		t.Errorf("jwksByKid.k2 = %+v, want one candidate of provider b", k2)
	}
}

// TestBootstrap_AFailedProviderKeepsTheOthers: a provider that cannot be
// fetched is recorded as a failure with its reason, and the keys of the
// others are published all the same.
func TestBootstrap_AFailedProviderKeepsTheOthers(t *testing.T) {
	srv := idp(t)
	file := providersFile(t, fmt.Sprintf(`{"providers":[
		{"id":"down","issuer":"%s/realms/down"},
		{"id":"a","issuer":"%s/realms/a"}]}`, srv.URL, srv.URL))
	m, st := newManager(t, file, false, "")

	status := m.Bootstrap(context.Background())
	if status.SuccessCount != 1 || status.FailureCount != 1 || status.ConfiguredCount != 2 || status.Mode != "permissive" {
		t.Errorf("Bootstrap() counts = %+v, want 1 success and 1 failure of 2 in permissive mode", status)
	}
	if down := status.Providers[0]; down.ID != "down" || down.Result != "failure" || !strings.Contains(down.FailureReason, "unable to fetch OIDC discovery document") {
		t.Errorf("the result of down = %+v, want a failure with the discovery reason", down)
	}
	if kids := keysOf(st.last(t).JwksByKid); !reflect.DeepEqual(kids, []string{"k1"}) {
		t.Errorf("jwksByKid kids = %v, want [k1]", kids)
	}
}

// TestBootstrap_InvalidEntries: an entry with both forms, or with none, or
// without an id fails on its own with the reason, and the other entries
// still bootstrap.
func TestBootstrap_InvalidEntries(t *testing.T) {
	srv := idp(t)
	file := providersFile(t, fmt.Sprintf(`{"providers":[
		{"id":"both","issuer":"%s/realms/a","jwksUri":"file:///x"},
		{"id":"neither"},
		{"issuer":"%s/realms/a"},
		{"id":"a","issuer":"%s/realms/a"}]}`, srv.URL, srv.URL, srv.URL))
	m, _ := newManager(t, file, false, "")

	status := m.Bootstrap(context.Background())
	if status.SuccessCount != 1 || status.FailureCount != 3 {
		t.Fatalf("Bootstrap() counts = %+v, want 1 success and 3 failures", status)
	}
	reasons := map[string]string{}
	for _, p := range status.Providers {
		reasons[p.ID] = p.FailureReason
	}
	for id, want := range map[string]string{"both": "sets both", "neither": "sets neither", "provider-2": "missing required field 'id'"} {
		if !strings.Contains(reasons[id], want) {
			t.Errorf("failure reason of %s = %q, want it to contain %q", id, reasons[id], want)
		}
	}
}

// TestBootstrap_ConfigErrors: a file that is missing, carries an unknown
// field, or names an id twice is a configuration error that publishes
// nothing.
func TestBootstrap_ConfigErrors(t *testing.T) {
	cases := []struct {
		name, content, want string
	}{
		{"an unknown field", `{"providers":[{"id":"a","issuer":"http://x","algorithms":["RS256"]}]}`, "failed to parse"},
		{"an id used twice", `{"providers":[{"id":"a","issuer":"http://x"},{"id":"a","issuer":"http://y"}]}`, "more than once"},
		{"a missing file", "", "missing file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "absent.json")
			if tc.content != "" {
				file = providersFile(t, tc.content)
			}
			m, st := newManager(t, file, true, "")
			status := m.Bootstrap(context.Background())
			if !strings.Contains(status.ConfigError, tc.want) || status.Mode != "strict" || status.Providers == nil {
				t.Errorf("Bootstrap() = %+v, want a strict status whose configError contains %q and an empty providers list", status, tc.want)
			}
			if st.count() != 0 {
				t.Errorf("published %d documents, want none", st.count())
			}
		})
	}
}

// TestBootstrap_NoProviders: an empty list publishes an empty index, so a
// token verifies against nothing.
func TestBootstrap_NoProviders(t *testing.T) {
	m, st := newManager(t, providersFile(t, `{"providers":[]}`), true, "")
	status := m.Bootstrap(context.Background())
	if status.ConfiguredCount != 0 || status.ConfigError != "" || status.SuccessCount != 0 {
		t.Errorf("Bootstrap() = %+v, want zero counts and no error", status)
	}
	doc := st.last(t)
	if len(doc.TrustedProviders.ByID) != 0 || len(doc.JwksByKid) != 0 {
		t.Errorf("published %+v, want empty indexes", doc)
	}
}

// TestBootstrap_ResolvesTheRealmDisplayName: an issuer that ends in a
// tenant's display name is retried under the realm name tenant-manager
// answers, after discovery under the display name failed.
func TestBootstrap_ResolvesTheRealmDisplayName(t *testing.T) {
	srv := idp(t)
	tenantManager := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == tenantLookupPath && r.URL.Query().Get("dns") == "default" {
			_, _ = w.Write([]byte("a\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer tenantManager.Close()
	file := providersFile(t, fmt.Sprintf(`{"providers":[{"id":"default","issuer":"%s/realms/default"}]}`, srv.URL))
	m, st := newManager(t, file, true, tenantManager.URL)

	status := m.Bootstrap(context.Background())
	if status.SuccessCount != 1 {
		t.Fatalf("Bootstrap() = %+v, want the provider bootstrapped through the resolved realm", status)
	}
	if kids := keysOf(st.last(t).JwksByKid); !reflect.DeepEqual(kids, []string{"k1"}) {
		t.Errorf("jwksByKid kids = %v, want [k1]", kids)
	}
}

// TestReload: an unchanged file publishes nothing; a change that meets the
// threshold is published and recorded; a change that does not meet it, or
// leaves a required provider out, is refused and leaves the previous keys
// and status in place.
func TestReload(t *testing.T) {
	srv := idp(t)
	only := func(ids ...string) string {
		var entries []string
		for _, id := range ids {
			entries = append(entries, fmt.Sprintf(`{"id":%q,"issuer":"%s/realms/%s"}`, id, srv.URL, strings.TrimSuffix(id, "!")))
		}
		return `{"providers":[` + strings.Join(entries, ",") + `]}`
	}
	file := providersFile(t, only("a"))
	m, st := newManager(t, file, true, "")
	m.Bootstrap(context.Background())

	if changed, err := m.Reload(context.Background()); changed || err != nil {
		t.Fatalf("Reload() on an unchanged file = %v, %v; want false, nil", changed, err)
	}
	if err := os.WriteFile(file, []byte(only("a", "down")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Reload(context.Background()); err == nil || !strings.Contains(err.Error(), "strict mode requires 2") {
		t.Fatalf("Reload() in strict mode with a provider down = %v, want the threshold error", err)
	}
	if st.count() != 1 || m.Status().ConfiguredCount != 1 {
		t.Errorf("after the refused reload: %d documents published and status %+v; want the bootstrap's document and status", st.count(), m.Status())
	}

	permissive, st2 := newManager(t, file, false, "")
	permissive.Bootstrap(context.Background())
	if err := os.WriteFile(file, []byte(only("a", "b")), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := permissive.Reload(context.Background()); !changed || err != nil {
		t.Fatalf("Reload() with a good change = %v, %v; want true, nil", changed, err)
	}
	if kids := keysOf(st2.last(t).JwksByKid); !reflect.DeepEqual(kids, []string{"k1", "k2"}) || permissive.Status().SuccessCount != 2 {
		t.Errorf("after the reload: kids %v and status %+v; want [k1 k2] and 2 successes", kids, permissive.Status())
	}
	requiredDown := fmt.Sprintf(`{"providers":[{"id":"a","issuer":"%s/realms/a"},{"id":"down","issuer":"%s/realms/down","required":true}]}`, srv.URL, srv.URL)
	if err := os.WriteFile(file, []byte(requiredDown), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := permissive.Reload(context.Background()); err == nil || !strings.Contains(err.Error(), "required providers down did not bootstrap") {
		t.Fatalf("Reload() with a required provider down = %v, want the required error", err)
	}
	if st2.count() != 2 {
		t.Errorf("published %d documents after the refused reload, want 2", st2.count())
	}
}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		name    string
		status  Status
		healthy bool
		message string
		missing []string
	}{
		{"a configuration error", Status{Mode: "strict", ConfigError: "missing file"}, false, "trusted providers configuration is invalid", nil},
		{"strict with every provider", Status{Mode: "strict", ConfiguredCount: 2, SuccessCount: 2}, true, "", nil},
		{"strict with one of two", Status{Mode: "strict", ConfiguredCount: 2, SuccessCount: 1}, false, "bootstrap threshold not met", nil},
		{"permissive with one of four", Status{Mode: "permissive", ConfiguredCount: 4, SuccessCount: 1}, true, "", nil},
		{"permissive with none", Status{Mode: "permissive", ConfiguredCount: 4, SuccessCount: 0}, false, "bootstrap threshold not met", nil},
		{"permissive with a required provider missing", Status{Mode: "permissive", ConfiguredCount: 2, SuccessCount: 1,
			Providers: []ProviderResult{{ID: "cloud-common", Result: "failure", Required: true}, {ID: "x", Result: "success"}}},
			false, "required identity providers did not bootstrap", []string{"cloud-common"}},
		{"permissive with the required provider up and an optional one down", Status{Mode: "permissive", ConfiguredCount: 2, SuccessCount: 1,
			Providers: []ProviderResult{{ID: "cloud-common", Result: "success", Required: true}, {ID: "x", Result: "failure"}}},
			true, "", nil},
		{"strict names the required provider before the threshold", Status{Mode: "strict", ConfiguredCount: 2, SuccessCount: 1,
			Providers: []ProviderResult{{ID: "cloud-common", Result: "failure", Required: true}, {ID: "x", Result: "success"}}},
			false, "required identity providers did not bootstrap", []string{"cloud-common"}},
		{"no providers in permissive mode", Status{Mode: "permissive"}, true, "", nil},
		{"no providers in strict mode", Status{Mode: "strict"}, true, "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			healthy, message, _, details := Evaluate(tc.status)
			if healthy != tc.healthy || message != tc.message {
				t.Errorf("Evaluate(%+v) = %v %q, want %v %q", tc.status, healthy, message, tc.healthy, tc.message)
			}
			var missing []string
			if details != nil {
				missing = details.MissingRequired
			}
			if !reflect.DeepEqual(missing, tc.missing) {
				t.Errorf("Evaluate(%+v) missing = %v, want %v", tc.status, missing, tc.missing)
			}
		})
	}
}

func keysOf[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}
