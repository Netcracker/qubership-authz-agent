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

package namespaces

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"authz-agent/internal/token/keys"
	"authz-agent/internal/token/verify"
)

// composite is a topology with a baseline and two satellites; the satellite
// solo has no peer.
const composite = `{
  "cloudProvider": "OnPrem",
  "composite": {
    "baseline": {"controller": "bg-ctl", "origin": "base-origin", "peer": "base-peer"},
    "satellites": [
      {"origin": "sat-origin", "peer": "sat-peer"},
      {"origin": "solo"}
    ]
  }
}`

// writeTopology writes content to a topology file in a new directory and
// returns its path.
func writeTopology(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// clock is a settable time source for Options.now.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// The service's own namespace, own, is not in the topology and is the
// control: a parsed topology replaces it rather than adding to it.
func TestAllowlist_AllowsTheOriginAndPeerOfEveryDomain(t *testing.T) {
	a := New(Options{TopologyFile: writeTopology(t, composite), Namespace: "own"})
	tests := []struct {
		namespace string
		want      bool
	}{
		{"base-origin", true},
		{"base-peer", true},
		{"sat-origin", true},
		{"sat-peer", true},
		{"solo", true},
		{"bg-ctl", false},
		{"own", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := a.Allows(tt.namespace); got != tt.want {
			t.Errorf("Allows(%q) = %t, want %t", tt.namespace, got, tt.want)
		}
	}
}

func TestAllowlist_AllowsTheSatellitesOfACompositeWithoutABaseline(t *testing.T) {
	a := New(Options{TopologyFile: writeTopology(t, `{"composite": {"satellites": [null, {"origin": "sat-origin"}]}}`)})
	if !a.Allows("sat-origin") {
		t.Errorf("Allows(%q) = false, want true", "sat-origin")
	}
}

func TestAllowlist_AllowsItsOwnNamespaceAloneWithoutATopology(t *testing.T) {
	tests := []struct {
		name string
		file string
	}{
		{"missing file", filepath.Join(t.TempDir(), "absent")},
		{"file that is not JSON", writeTopology(t, "composite: yes")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := New(Options{TopologyFile: tt.file, Namespace: "own"})
			if !a.Allows("own") {
				t.Errorf("Allows(%q) = false, want true", "own")
			}
			if a.Allows("base-origin") {
				t.Errorf("Allows(%q) = true, want false", "base-origin")
			}
		})
	}
}

func TestAllowlist_AllowsNoneWithoutATopologyOrAnOwnNamespace(t *testing.T) {
	a := New(Options{TopologyFile: filepath.Join(t.TempDir(), "absent")})
	if a.Allows("") {
		t.Errorf("Allows(%q) = true, want false", "")
	}
}

func TestAllowlist_AllowsNoneForATopologyWithoutAComposite(t *testing.T) {
	a := New(Options{TopologyFile: writeTopology(t, `{"cloudProvider": "OnPrem"}`), Namespace: "own"})
	if a.Allows("own") {
		t.Errorf("Allows(%q) = true, want false", "own")
	}
}

func TestAllowlist_ReadsTheFileAgainOnceTheTTLPasses(t *testing.T) {
	path := writeTopology(t, `{"composite": {"baseline": {"origin": "first"}}}`)
	c := &clock{now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	a := New(Options{TopologyFile: path, now: c.Now})
	if !a.Allows("first") {
		t.Fatalf("Allows(%q) = false before the change, want true", "first")
	}
	if err := os.WriteFile(path, []byte(`{"composite": {"baseline": {"origin": "second"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c.advance(19 * time.Second)
	if a.Allows("second") {
		t.Errorf("Allows(%q) 19 s after the read = true, want false: the first read is still in use", "second")
	}
	c.advance(time.Second)
	if !a.Allows("second") {
		t.Errorf("Allows(%q) 20 s after the read = false, want true", "second")
	}
}

// recordingLogger keeps every warning it receives.
type recordingLogger struct {
	mu       sync.Mutex
	messages []string
}

func (l *recordingLogger) Warnf(format string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.messages = append(l.messages, format)
}

func (l *recordingLogger) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.messages)
}

// The file stays missing across three reads; the fallback is reported once.
func TestAllowlist_WarnsOnceWhileTheTopologyIsMissing(t *testing.T) {
	log := &recordingLogger{}
	c := &clock{now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	a := New(Options{TopologyFile: filepath.Join(t.TempDir(), "absent"), Namespace: "own", Log: log, now: c.Now})
	for range 3 {
		a.Allows("own")
		c.advance(DefaultTTL)
	}
	if got := log.count(); got != 1 {
		t.Errorf("warnings = %d, want 1", got)
	}
}

func TestAllowlist_WarnsAgainWhenTheTopologyGoesAwayAgain(t *testing.T) {
	log := &recordingLogger{}
	c := &clock{now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	path := filepath.Join(t.TempDir(), "data")
	a := New(Options{TopologyFile: path, Namespace: "own", Log: log, now: c.Now})
	a.Allows("own")
	if err := os.WriteFile(path, []byte(composite), 0o600); err != nil {
		t.Fatal(err)
	}
	c.advance(DefaultTTL)
	a.Allows("own")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	c.advance(DefaultTTL)
	a.Allows("own")
	if got := log.count(); got != 2 {
		t.Errorf("warnings = %d, want 2: one for each time the file went missing", got)
	}
}

func TestAllowlist_IsSafeForConcurrentUse(t *testing.T) {
	c := &clock{now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	a := New(Options{TopologyFile: writeTopology(t, composite), now: c.Now})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 50 {
				if !a.Allows("base-origin") {
					t.Errorf("Allows(%q) = false, want true", "base-origin")
					return
				}
				c.advance(time.Second)
			}
		})
	}
	wg.Wait()
}

func TestAllowlist_AdmitChecksTheTokensOfTheNamedProviders(t *testing.T) {
	a := New(Options{TopologyFile: writeTopology(t, composite), Namespace: "own"})
	admit := a.Admit("kubernetes")
	tests := []struct {
		name     string
		provider string
		claims   map[string]any
		want     verify.Code
	}{
		{"allowed namespace", "kubernetes",
			map[string]any{"kubernetes.io": map[string]any{"namespace": "sat-peer"}}, ""},
		{"namespace outside the topology", "kubernetes",
			map[string]any{"kubernetes.io": map[string]any{"namespace": "own"}}, verify.CodeNamespaceNotAllowed},
		{"no kubernetes.io claim", "kubernetes",
			map[string]any{"sub": "system:serviceaccount:own:agent"}, verify.CodeNamespaceNotAllowed},
		{"namespace that is not a string", "kubernetes",
			map[string]any{"kubernetes.io": map[string]any{"namespace": 5}}, verify.CodeNamespaceNotAllowed},
		{"another provider's token", "cloud-common",
			map[string]any{"kubernetes.io": map[string]any{"namespace": "own"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := &verify.Token{Provider: &keys.Provider{ID: tt.provider}, Claims: tt.claims}
			var got verify.Code
			if err := admit(tok); err != nil {
				got = err.Code
			}
			if got != tt.want {
				t.Errorf("Admit() code = %q, want %q", got, tt.want)
			}
		})
	}
}
