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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"

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

// Allows keeps answering from the file as New read it: the change is
// allowed only once reload reads the file again.
func TestAllowlist_KeepsTheNamespacesUntilTheFileIsReadAgain(t *testing.T) {
	path := writeTopology(t, `{"composite": {"baseline": {"origin": "first"}}}`)
	a := New(Options{TopologyFile: path})
	if err := os.WriteFile(path, []byte(`{"composite": {"baseline": {"origin": "second"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !a.Allows("first") {
		t.Errorf("Allows(%q) before the file is read again = false, want true", "first")
	}
	if a.Allows("second") {
		t.Errorf("Allows(%q) before the file is read again = true, want false", "second")
	}
	a.reload()
	if !a.Allows("second") {
		t.Errorf("Allows(%q) after the file is read again = false, want true", "second")
	}
	if a.Allows("first") {
		t.Errorf("Allows(%q) after the file is read again = true, want false", "first")
	}
}

func TestAllowlist_RunReadsTheFileAgainOnTheInterval(t *testing.T) {
	path := writeTopology(t, `{"composite": {"baseline": {"origin": "first"}}}`)
	a := New(Options{TopologyFile: path, RefreshInterval: 10 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	if err := os.WriteFile(path, []byte(`{"composite": {"baseline": {"origin": "second"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !a.Allows("second") {
		if time.Now().After(deadline) {
			t.Fatalf("Allows(%q) is still false 5 s after the change; Allows(%q) = %t", "second", "first", a.Allows("first"))
		}
		time.Sleep(5 * time.Millisecond)
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
	a := New(Options{TopologyFile: filepath.Join(t.TempDir(), "absent"), Namespace: "own", Log: log})
	a.reload()
	a.reload()
	if got := log.count(); got != 1 {
		t.Errorf("warnings = %d, want 1", got)
	}
}

func TestAllowlist_WarnsAgainWhenTheTopologyGoesAwayAgain(t *testing.T) {
	log := &recordingLogger{}
	path := filepath.Join(t.TempDir(), "data")
	a := New(Options{TopologyFile: path, Namespace: "own", Log: log})
	if err := os.WriteFile(path, []byte(composite), 0o600); err != nil {
		t.Fatal(err)
	}
	a.reload()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	a.reload()
	if got := log.count(); got != 2 {
		t.Errorf("warnings = %d, want 2: one for each time the file went missing", got)
	}
}

// Run with -race: eight readers call Allows while the file is read again
// fifty times.
func TestAllowlist_IsSafeForConcurrentUse(t *testing.T) {
	a := New(Options{TopologyFile: writeTopology(t, composite)})
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 50 {
			a.reload()
		}
	})
	for range 8 {
		wg.Go(func() {
			for range 50 {
				if !a.Allows("base-origin") {
					t.Errorf("Allows(%q) = false, want true", "base-origin")
					return
				}
			}
		})
	}
	wg.Wait()
}

// oneKey is a verify.KeyFinder that publishes one key.
type oneKey struct{ key keys.Key }

func (o oneKey) Lookup(kid string) (keys.Key, bool) { return o.key, kid == o.key.ID }

// verifierFor returns a Verifier that trusts one EC key of provider and runs
// admit, and a function that signs a token with that key whose claims are an
// unexpired iat and exp plus fields.
func verifierFor(t *testing.T, provider string, admit func(*verify.Token) *verify.Error) (*verify.Verifier, func(fields map[string]any) string) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := jwk.Import(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	key := keys.Key{Provider: &keys.Provider{ID: provider}, ID: "k1", JWK: public}
	v := verify.New(oneKey{key}, verify.Options{Admit: admit})
	sign := func(fields map[string]any) string {
		now := time.Now()
		claims := map[string]any{"iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
		maps.Copy(claims, fields)
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		headers := jws.NewHeaders()
		if err := headers.Set(jws.KeyIDKey, key.ID); err != nil {
			t.Fatal(err)
		}
		token, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), private, jws.WithProtectedHeaders(headers)))
		if err != nil {
			t.Fatal(err)
		}
		return string(token)
	}
	return v, sign
}

func TestAllowlist_AdmitChecksTheTokensOfTheNamedProviders(t *testing.T) {
	a := New(Options{TopologyFile: writeTopology(t, composite), Namespace: "own"})
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
		{"kubernetes.io that is a string", "kubernetes",
			map[string]any{"kubernetes.io": "sat-peer"}, verify.CodeNamespaceNotAllowed},
		{"namespace that is not a string", "kubernetes",
			map[string]any{"kubernetes.io": map[string]any{"namespace": 5}}, verify.CodeNamespaceNotAllowed},
		{"Namespace that differs in case", "kubernetes",
			map[string]any{"kubernetes.io": map[string]any{"Namespace": "sat-peer"}}, verify.CodeNamespaceNotAllowed},
		{"namespace outside the topology beside a Namespace inside it", "kubernetes",
			map[string]any{"kubernetes.io": json.RawMessage(`{"namespace": "own", "Namespace": "sat-peer"}`)}, verify.CodeNamespaceNotAllowed},
		{"namespace given twice, the last time as a number", "kubernetes",
			map[string]any{"kubernetes.io": json.RawMessage(`{"namespace": "sat-peer", "namespace": 5}`)}, verify.CodeNamespaceNotAllowed},
		{"another provider's token", "cloud-common",
			map[string]any{"kubernetes.io": map[string]any{"namespace": "own"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, sign := verifierFor(t, tt.provider, a.Admit("kubernetes"))
			_, err := v.Verify(sign(tt.claims))
			var got verify.Code
			var refused *verify.Error
			if errors.As(err, &refused) {
				got = refused.Code
			} else if err != nil {
				t.Fatalf("Verify() error = %v, want a *verify.Error or none", err)
			}
			if got != tt.want {
				t.Errorf("Verify() code = %q, want %q", got, tt.want)
			}
		})
	}
}
