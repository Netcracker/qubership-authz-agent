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

package decisionlog

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"

// TestStore_RedactsJWTSignatures: a JWT loses its signature wherever it
// occurs in a stored event, as a field value, inside a longer string, in
// a list, and as a map key; everything else is stored as it is.
func TestStore_RedactsJWTSignatures(t *testing.T) {
	st := NewStore(filepath.Join(t.TempDir(), "logs", "decision-logs.jsonl"))
	ev := Event{
		DecisionID: "d-1",
		Path:       "authorize",
		Input:      map[string]any{"authorizationToken": "Bearer " + token, "subject": "plain"},
		Result:     []any{"result " + token + " end"},
		NDBuiltinCache: map[string]any{
			"io.jwt.decode_verify": map[string]any{`["` + token + `",{}]`: []any{true}},
		},
		RequestContext: &RequestContext{HTTP: &HTTPRequestContext{Headers: map[string][]string{"authorization": {"Bearer " + token}}}},
	}
	if written, err := st.Append([]Event{ev}); err != nil || written != 1 {
		t.Fatalf("Append() = %d, %v", written, err)
	}
	data, err := st.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll() = %v", err)
	}
	line := strings.TrimSpace(string(data))
	if strings.Contains(line, "c2lnbmF0dXJl") {
		t.Errorf("stored line still carries the signature: %s", line)
	}
	redacted := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0"
	var stored struct {
		DecisionID string         `json:"decision_id"`
		Input      map[string]any `json:"input"`
		Result     []string       `json:"result"`
		NDBC       map[string]any `json:"nd_builtin_cache"`
		Context    map[string]any `json:"request_context"`
		Timestamp  string         `json:"timestamp"`
		Rest       map[string]any `json:"-"`
	}
	if err := json.Unmarshal([]byte(line), &stored); err != nil {
		t.Fatalf("stored line is not JSON: %v: %s", err, line)
	}
	if stored.DecisionID != "d-1" || stored.Input["subject"] != "plain" {
		t.Errorf("stored line = %s, want the other fields kept", line)
	}
	if stored.Input["authorizationToken"] != "Bearer "+redacted {
		t.Errorf("input.authorizationToken = %v, want Bearer %s", stored.Input["authorizationToken"], redacted)
	}
	if len(stored.Result) != 1 || stored.Result[0] != "result "+redacted+" end" {
		t.Errorf("result = %v, want the token inside the string redacted", stored.Result)
	}
	calls, _ := stored.NDBC["io.jwt.decode_verify"].(map[string]any)
	if _, ok := calls[`["`+redacted+`",{}]`]; !ok || len(calls) != 1 {
		t.Errorf("nd_builtin_cache keys = %v, want the key redacted", calls)
	}
}

// TestStore_ReadAllBeforeAppend: a store that never received an event
// reads as nothing rather than as an error.
func TestStore_ReadAllBeforeAppend(t *testing.T) {
	st := NewStore(filepath.Join(t.TempDir(), "decision-logs.jsonl"))
	if data, err := st.ReadAll(); err != nil || data != nil {
		t.Errorf("ReadAll() = %q, %v; want nil, nil", data, err)
	}
}

// TestStore_OpenDoesNotHoldTheAppendLock: a download streams from an open
// file and the queue keeps draining while it does. Reading the whole log under
// the lock stalled Append for as long as the read took, and the only reader of
// the queue is the loop that calls it, so decisions were dropped on a full
// channel with a warning as the only trace.
func TestStore_OpenDoesNotHoldTheAppendLock(t *testing.T) {
	st := NewStore(filepath.Join(t.TempDir(), "decision-logs.jsonl"))
	if _, err := st.Append([]Event{{DecisionID: "1"}}); err != nil {
		t.Fatal(err)
	}
	f, size, err := st.Open()
	if err != nil || f == nil {
		t.Fatalf("Open() = %v, %v", f, err)
	}
	defer func() { _ = f.Close() }()

	appended := make(chan error, 1)
	go func() {
		_, err := st.Append([]Event{{DecisionID: "2"}})
		appended <- err
	}()
	select {
	case err := <-appended:
		if err != nil {
			t.Fatalf("Append() while a download was open = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Append blocked while a download was open, so nothing drained the queue")
	}

	// The size taken at Open is what bounds the response, so the decision
	// appended behind it is not half-written into someone's download.
	body, err := io.ReadAll(io.LimitReader(f, size))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"decision_id":"1"`) || strings.Contains(string(body), `"decision_id":"2"`) {
		t.Errorf("the stream carries %q, want the decision that was there when it opened and not the one after it", body)
	}
}

// TestStore_AppendReportsWhatItWroteBeforeAFailure: a line already on disk
// stays there, so the count is what tells the caller where to resume. An
// event that cannot be encoded stands in for the full volume that is the
// reachable failure.
func TestStore_AppendReportsWhatItWroteBeforeAFailure(t *testing.T) {
	st := NewStore(filepath.Join(t.TempDir(), "decision-logs.jsonl"))
	batch := []Event{
		{DecisionID: "1"},
		{DecisionID: "2"},
		{DecisionID: "3", Input: make(chan int)},
		{DecisionID: "4"},
	}
	written, err := st.Append(batch)
	if err == nil {
		t.Fatal("Append() = nil, want the encoding error of the third event")
	}
	if written != 2 {
		t.Errorf("Append() wrote %d, want the two events before the failure", written)
	}
	data, _ := st.ReadAll()
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Errorf("stored lines = %q, want the two that were written", lines)
	}
}

// TestStore_AppendsOneLinePerEvent: events are appended in order, one line
// each, across appends.
func TestStore_AppendsOneLinePerEvent(t *testing.T) {
	st := NewStore(filepath.Join(t.TempDir(), "decision-logs.jsonl"))
	if _, err := st.Append([]Event{{DecisionID: "1"}, {DecisionID: "2"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Append([]Event{{DecisionID: "3"}}); err != nil {
		t.Fatal(err)
	}
	data, _ := st.ReadAll()
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 || !strings.Contains(lines[2], `"decision_id":"3"`) {
		t.Errorf("stored lines = %q, want three in order", lines)
	}
}

// TestLogger_DeliversToTheStore: with a store configured the logger is
// enabled without a collector, and the queued events reach the store on
// shutdown.
func TestLogger_DeliversToTheStore(t *testing.T) {
	st := NewStore(filepath.Join(t.TempDir(), "decision-logs.jsonl"))
	logs := New(Config{Store: st, FlushInterval: time.Hour}, nil)
	if !logs.Enabled() || logs.Store() != st {
		t.Fatal("a logger with a store must be enabled and expose it")
	}
	ctx, cancel := context.WithCancel(context.Background())
	go logs.Run(ctx)
	logs.Log(Event{DecisionID: "a"})
	logs.Log(Event{DecisionID: "b"})
	cancel()
	logs.Wait()
	data, _ := st.ReadAll()
	if lines := strings.Split(strings.TrimSpace(string(data)), "\n"); len(lines) != 2 {
		t.Errorf("stored %d lines, want 2", len(lines))
	}
}
