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

package outbound

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// inTempDir returns name joined to a new temporary directory.
func inTempDir(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

// runInBackground runs run until the test ends, and waits for it to return.
func runInBackground(t *testing.T, run func(ctx context.Context)) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// waitFor polls cond every 5 ms for up to five seconds and fails the test
// with what when it never holds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after 5s waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// jwtExpiringAt returns an unsigned JWT whose exp claim is exp.
func jwtExpiringAt(t *testing.T, exp time.Time) string {
	t.Helper()
	return unsignedJWT(t, map[string]any{"sub": "authz-agent", "exp": exp.Unix()})
}

// unsignedJWT returns a JWT of claims with a placeholder signature.
func unsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"k1"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
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
	return slices.Clone(l.messages)
}

// staticSource is a Source with a fixed token.
type staticSource string

func (s staticSource) Token() string { return string(s) }
