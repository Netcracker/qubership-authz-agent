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

package pull

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"authz-agent/internal/pips"
)

// policySets is a v3 policy-sets response with one SIMPLIFIED policy set of
// one rule and one DEFAULT policy set, which the converter skips.
const policySets = `{
  "hash": "hash-ps-v1",
  "lastModificationTimestamp": "2026-01-01T00:00:00",
  "policySets": [
    {
      "policySetId": "ps-1", "name": "Test PS", "type": "SIMPLIFIED", "domain": "TestDomain", "status": "ACTIVE",
      "target": "resourceType == 'TestResource'", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "default",
      "policies": [{
        "policyId": "pol-1", "target": "subject.roles CONTAINS 'ROLE_TEST'", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
        "rules": [{"ruleId": "rule-1", "target": "operation == 'READ'", "condition": null, "effect": "ALLOW"}]
      }]
    },
    {
      "policySetId": "ps-default", "name": "Default type PS", "type": "DEFAULT", "domain": "OtherDomain", "status": "ACTIVE",
      "target": "resourceType == 'Other'", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "default", "policies": []
    }
  ]
}`

// pipsResponse is a v3 PIPs response with one TOKEN PIP and one FILTERED
// PIP, which the converter skips.
const pipsResponse = `{
  "hash": "hash-pip-v1",
  "lastModificationTimestamp": "2026-01-01T00:00:00",
  "pips": [
    {"name": "subject.azp", "pipType": "TOKEN", "claim": "azp", "domain": "TestDomain", "tenantId": "default"},
    {"name": "subject.filtered", "pipType": "FILTERED", "domain": "TestDomain", "tenantId": "default"}
  ]
}`

const simplePolicies = `[{"component": "TestDomain", "resourceType": "TestResource", "operation": "READ", "roles": ["ROLE_TEST"]}]`

const simplePIPs = `[{"name": "subject.azp", "pipType": "TOKEN", "claim": "azp"}]`

type store struct {
	mu   sync.Mutex
	puts map[string][]any
}

func (s *store) Put(_ context.Context, path []string, value any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.puts == nil {
		s.puts = map[string][]any{}
	}
	key := strings.Join(path, "/")
	s.puts[key] = append(s.puts[key], value)
	return nil
}

func (s *store) count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.puts[path])
}

// last decodes the last document stored at path through JSON.
func (s *store) last(t *testing.T, path string) map[string]any {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	values := s.puts[path]
	if len(values) == 0 {
		t.Fatalf("nothing stored at %s", path)
	}
	raw, err := json.Marshal(values[len(values)-1])
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

type tokens struct {
	token string
	ready chan struct{}
}

func readyTokens(token string) *tokens {
	ready := make(chan struct{})
	close(ready)
	return &tokens{token: token, ready: ready}
}

func (t *tokens) Token() string          { return t.token }
func (t *tokens) Ready() <-chan struct{} { return t.ready }

type quiet struct{}

func (quiet) Infof(string, ...any) {}
func (quiet) Warnf(string, ...any) {}

// source serves the v3 responses and records the Authorization header of
// the last request and the number of requests.
func source(t *testing.T, status int) (*httptest.Server, *string, *int) {
	t.Helper()
	var authorization string
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		authorization = r.Header.Get("Authorization")
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("Accept = %q, want application/json", r.Header.Get("Accept"))
		}
		w.WriteHeader(status)
		switch r.URL.Path {
		case "/access/v3/config/policySets":
			_, _ = w.Write([]byte(policySets))
		case "/access/v3/config/pips":
			_, _ = w.Write([]byte(pipsResponse))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &authorization, &requests
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out after 3s waiting for %s", what)
}

// TestRun_LoadsTheSource: the first pull fetches both documents with the
// bearer token, converts them, stores data.policies and data.pips, and
// reports the policies loaded with the conversion counts.
func TestRun_LoadsTheSource(t *testing.T) {
	srv, authorization, _ := source(t, http.StatusOK)
	st := &store{}
	p := New(Config{SourceURL: srv.URL, Interval: time.Hour}, st, readyTokens("tok"), quiet{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	waitFor(t, "the first load", func() bool { return p.Status().PoliciesLoaded })
	status := p.Status()
	want := Conversion{PolicySets: 1, Rules: 1, Policies: 1}
	if status.Conversion == nil || *status.Conversion != want || status.FirstSuccessAt == "" || status.Reason != "" {
		t.Errorf("Status() = %+v, want conversion %+v with a first success time", status, want)
	}
	if *authorization != "Bearer tok" {
		t.Errorf("Authorization sent = %q, want Bearer tok", *authorization)
	}
	if st.count("policies") != 1 || st.count("pips") != 1 {
		t.Fatalf("stored %d policies and %d pips documents, want one each", st.count("policies"), st.count("pips"))
	}
	policies := st.last(t, "policies")
	if len(policies) == 0 {
		t.Errorf("data.policies = %v, want the normalized document", policies)
	}
	byName, _ := st.last(t, "pips")["byName"].(map[string]any)
	if _, ok := byName["subject.azp"]; !ok || len(byName) != 1 {
		t.Errorf("data.pips.byName = %v, want subject.azp alone", byName)
	}
}

// TestPullOnce_KeepsTheDocumentsOnFailure: a source that fails leaves the
// store untouched and returns the error, and so does a source whose
// documents cannot be converted.
func TestPullOnce_KeepsTheDocumentsOnFailure(t *testing.T) {
	failing, _, _ := source(t, http.StatusInternalServerError)
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"policySets": "no"`))
	}))
	defer broken.Close()
	for name, url := range map[string]string{"an HTTP 500": failing.URL, "a body that is not JSON": broken.URL} {
		t.Run(name, func(t *testing.T) {
			st := &store{}
			p := New(Config{SourceURL: url, Interval: time.Hour}, st, nil, quiet{})
			if err := p.PullOnce(context.Background()); err == nil {
				t.Fatal("PullOnce() = nil, want an error")
			}
			if st.count("policies") != 0 || st.count("pips") != 0 || p.Status().PoliciesLoaded {
				t.Errorf("after the failure: %d policies, %d pips, status %+v; want nothing stored and not loaded", st.count("policies"), st.count("pips"), p.Status())
			}
		})
	}
}

// TestPullOnce_WithoutTokens: with no token source the fetch carries no
// Authorization header.
func TestPullOnce_WithoutTokens(t *testing.T) {
	srv, authorization, _ := source(t, http.StatusOK)
	p := New(Config{SourceURL: srv.URL, Interval: time.Hour}, &store{}, nil, quiet{})
	if err := p.PullOnce(context.Background()); err != nil {
		t.Fatalf("PullOnce() = %v", err)
	}
	if *authorization != "" {
		t.Errorf("Authorization sent = %q, want none", *authorization)
	}
}

// TestRun_Disabled: without a source, or with a zero interval, with or
// without a mount, the status reports the policies as loaded with the
// reason, so readiness does not wait.
func TestRun_Disabled(t *testing.T) {
	cases := []struct {
		name   string
		cfg    Config
		reason string
	}{
		{"no source", Config{Interval: time.Second}, "pull disabled: source URL empty"},
		{"a zero interval", Config{SourceURL: "http://source", Interval: 0}, "pull disabled: interval is 0"},
		{"a mount with a zero interval", Config{MountDir: t.TempDir(), Interval: 0}, "mount watcher disabled: interval is 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := &store{}
			p := New(tc.cfg, st, nil, quiet{})
			p.Run(context.Background())
			if status := p.Status(); !status.PoliciesLoaded || status.Reason != tc.reason {
				t.Errorf("Status() = %+v, want loaded with reason %q", status, tc.reason)
			}
			if st.count("policies") != 0 {
				t.Errorf("stored %d policies documents, want none", st.count("policies"))
			}
		})
	}
}

// TestRun_Mount: a mount directory wins over the source, which is never
// asked; its files are loaded when they appear and reloaded when either
// changes, and left alone otherwise.
func TestRun_Mount(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(MountPoliciesFile, simplePolicies)
	write(MountPIPsFile, simplePIPs)
	srv, _, requests := source(t, http.StatusOK)
	st := &store{}
	p := New(Config{SourceURL: srv.URL, MountDir: dir, Interval: 20 * time.Millisecond}, st, nil, quiet{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	waitFor(t, "the mount to load", func() bool { return p.Status().PoliciesLoaded })
	if st.count("policies") != 1 || st.count("pips") != 1 {
		t.Fatalf("stored %d policies and %d pips documents, want one each", st.count("policies"), st.count("pips"))
	}
	time.Sleep(60 * time.Millisecond)
	if st.count("policies") != 1 {
		t.Errorf("stored %d policies documents with the files unchanged, want 1", st.count("policies"))
	}
	write(MountPoliciesFile, `[{"component": "TestDomain", "resourceType": "Order", "operation": "DELETE", "roles": ["ROLE_MANAGER"]}]`)
	waitFor(t, "the changed mount to reload", func() bool { return st.count("policies") == 2 })
	if st.count("pips") != 2 {
		t.Errorf("stored %d pips documents after the change, want 2", st.count("pips"))
	}
	if changed, err := p.ApplyMount(ctx); changed || err != nil {
		t.Errorf("ApplyMount() after the reload = %v, %v; want false, nil", changed, err)
	}
	if *requests != 0 {
		t.Errorf("the source saw %d requests, want none with a mount", *requests)
	}
}

// TestLoad_PinsTheEntitlements: the entitlements PIP of the deployment is
// added to the PIP document as it is stored.
func TestLoad_PinsTheEntitlements(t *testing.T) {
	srv, _, _ := source(t, http.StatusOK)
	st := &store{}
	p := New(Config{SourceURL: srv.URL, Interval: time.Hour, Entitlements: &pips.EntitlementsConfig{URL: "http://entitlements:8080", HTTPTimeoutSeconds: 2, HTTPRetries: 3}}, st, nil, quiet{})
	if err := p.PullOnce(context.Background()); err != nil {
		t.Fatalf("PullOnce() = %v", err)
	}
	remote, _ := st.last(t, "pips")["remote"].(map[string]any)
	entitlements, _ := remote["entitlements"].(map[string]any)
	if !reflect.DeepEqual(entitlements["url"], "http://entitlements:8080") {
		t.Errorf("data.pips.remote.entitlements = %v, want the pinned URL", entitlements)
	}
}
