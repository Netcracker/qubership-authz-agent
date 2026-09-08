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
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// collector records every batch a test logger uploads.
type collector struct {
	mu      sync.Mutex
	batches [][]Event
	paths   []string
	status  int
}

func newCollector(t *testing.T) (*collector, *httptest.Server) {
	t.Helper()
	c := &collector{status: http.StatusOK}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") != "gzip" {
			t.Errorf("upload without gzip: %v", r.Header)
		}
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("gzip: %v", err)
			return
		}
		raw, _ := io.ReadAll(gz)
		var batch []Event
		if err := json.Unmarshal(raw, &batch); err != nil {
			t.Errorf("batch is not a JSON array: %v", err)
		}
		c.mu.Lock()
		c.batches = append(c.batches, batch)
		c.paths = append(c.paths, r.URL.Path)
		status := c.status
		c.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return c, srv
}

func (c *collector) events() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Event
	for _, b := range c.batches {
		out = append(out, b...)
	}
	return out
}

// TestLog_UploadsBatchesToLogs: queued events reach <URL>/logs as a gzip
// JSON array with the sequence number, timestamp, and labels filled in.
func TestLog_UploadsBatchesToLogs(t *testing.T) {
	c, srv := newCollector(t)
	l := New(Config{URL: srv.URL + "/", Labels: map[string]string{"id": "t"}, FlushInterval: 20 * time.Millisecond}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go l.Run(ctx)
	l.Log(Event{DecisionID: "d1", Path: "authorize", Result: map[string]any{"ok": true}})
	l.Log(Event{DecisionID: "d2", Path: "authorize"})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(c.events()) < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	l.Wait()
	got := c.events()
	if len(got) != 2 {
		t.Fatalf("uploaded %d events, want 2", len(got))
	}
	if c.paths[0] != "/logs" {
		t.Errorf("upload path = %s, want /logs", c.paths[0])
	}
	if got[0].RequestID != 1 || got[1].RequestID != 2 {
		t.Errorf("req_id = %d, %d; want 1, 2", got[0].RequestID, got[1].RequestID)
	}
	if got[0].Timestamp.IsZero() || got[0].Labels["id"] != "t" {
		t.Errorf("timestamp or labels not filled: %+v", got[0])
	}
}

// TestRun_DrainsOnShutdown: events queued right before the context ends are
// still uploaded, with a fresh deadline, so the last decision before a
// SIGTERM is not lost.
func TestRun_DrainsOnShutdown(t *testing.T) {
	c, srv := newCollector(t)
	l := New(Config{URL: srv.URL, FlushInterval: time.Hour}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go l.Run(ctx)
	l.Log(Event{DecisionID: "last", Path: "authorize"})
	cancel()
	l.Wait()
	if got := c.events(); len(got) != 1 || got[0].DecisionID != "last" {
		t.Fatalf("drained events = %+v, want the last decision", got)
	}
}

// TestRun_FlushesFullBatch: a batch is uploaded as soon as it reaches
// MaxBatch, before the flush interval.
func TestRun_FlushesFullBatch(t *testing.T) {
	c, srv := newCollector(t)
	l := New(Config{URL: srv.URL, MaxBatch: 2, FlushInterval: time.Hour}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.Run(ctx)
	l.Log(Event{DecisionID: "a"})
	l.Log(Event{DecisionID: "b"})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(c.events()) < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if len(c.events()) != 2 {
		t.Fatalf("full batch not flushed: %d events", len(c.events()))
	}
}

// TestUpload_FailureIsWarnedNotFatal: a collector error reaches the warn
// callback and the logger keeps running.
func TestUpload_FailureIsWarnedNotFatal(t *testing.T) {
	c, srv := newCollector(t)
	c.status = http.StatusInternalServerError
	var mu sync.Mutex
	var warnings []string
	l := New(Config{URL: srv.URL, FlushInterval: 10 * time.Millisecond}, func(format string, args ...any) {
		mu.Lock()
		warnings = append(warnings, format)
		mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	go l.Run(ctx)
	l.Log(Event{DecisionID: "x"})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(warnings)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	l.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(warnings) == 0 {
		t.Fatal("upload failure was not reported")
	}
}

// TestDisabled_LogIsANoop: without a URL nothing is queued and Run returns
// at once, so a deployment without a collector costs nothing.
func TestDisabled_LogIsANoop(t *testing.T) {
	l := New(Config{}, nil)
	if l.Enabled() {
		t.Fatal("logger without URL must be disabled")
	}
	l.Log(Event{DecisionID: "ignored"})
	if len(l.events) != 0 {
		t.Fatal("disabled logger queued an event")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l.Run(ctx)
	l.Wait()
}

// TestNewDecisionID_Shape: ids have the UUID layout OPA emits, so readers
// that pattern-match decision_id keep working.
func TestNewDecisionID_Shape(t *testing.T) {
	id := NewDecisionID()
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		t.Fatalf("decision id %q is not UUID-shaped", id)
	}
	if id == NewDecisionID() {
		t.Fatal("two ids must differ")
	}
}

// TestUpload_ChunksBySize: a batch whose events do not fit one body is
// posted in several, each under the size limit, and every event arrives
// once.
func TestUpload_ChunksBySize(t *testing.T) {
	var mu sync.Mutex
	var bodies []int
	var received []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read: %v", err)
			return
		}
		gz, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			t.Errorf("gzip: %v", err)
			return
		}
		var batch []Event
		if err := json.NewDecoder(gz).Decode(&batch); err != nil {
			t.Errorf("decode: %v", err)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		bodies = append(bodies, len(raw))
		for _, ev := range batch {
			received = append(received, ev.DecisionID)
		}
	}))
	defer srv.Close()

	const limit = 512
	logs := New(Config{URL: srv.URL, MaxUploadBytes: limit}, nil)
	var batch []Event
	var want []string
	for i := range 40 {
		id := fmt.Sprintf("d-%02d", i)
		// Random input, so the compressed body grows with every event.
		batch = append(batch, Event{DecisionID: id, Path: "authorize", Input: map[string]any{"filler": randomString(t, 400)}})
		want = append(want, id)
	}
	undelivered, err := logs.upload(context.Background(), batch)
	if err != nil || undelivered != nil {
		t.Fatalf("upload() = %v, %v; want everything delivered", undelivered, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) < 2 {
		t.Fatalf("posted %d bodies of %v bytes, want the batch split by the %d-byte limit", len(bodies), bodies, limit)
	}
	for i, size := range bodies[:len(bodies)-1] {
		// Only the event that crosses the limit ends its chunk, so a body
		// may pass it by that event's compressed size, not by a multiple.
		if size > 2*limit {
			t.Errorf("body %d is %d bytes, want no more than twice the %d-byte limit", i, size, limit)
		}
	}
	if !reflect.DeepEqual(received, want) {
		t.Errorf("the collector received %v, want every event once, in order", received)
	}
}

// TestUpload_KeepsWhatTheCollectorRefused: a collector that refuses one
// body leaves the events of that body and every later one for the next
// attempt, and the earlier ones are not sent twice.
func TestUpload_KeepsWhatTheCollectorRefused(t *testing.T) {
	var mu sync.Mutex
	var posts int
	var received []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		posts++
		refuse := posts == 2
		mu.Unlock()
		if refuse {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		gz, _ := gzip.NewReader(r.Body)
		var batch []Event
		_ = json.NewDecoder(gz).Decode(&batch)
		mu.Lock()
		defer mu.Unlock()
		for _, ev := range batch {
			received = append(received, ev.DecisionID)
		}
	}))
	defer srv.Close()

	logs := New(Config{URL: srv.URL, MaxUploadBytes: 1}, nil)
	batch := []Event{{DecisionID: "a"}, {DecisionID: "b"}, {DecisionID: "c"}}
	undelivered, err := logs.upload(context.Background(), batch)
	if err == nil {
		t.Fatal("upload() = nil, want the collector's refusal")
	}
	if want := []Event{{DecisionID: "b"}, {DecisionID: "c"}}; !reflect.DeepEqual(undelivered, want) {
		t.Errorf("undelivered = %v, want the refused event and the one after it", undelivered)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(received, []string{"a"}) {
		t.Errorf("the collector received %v, want only the body it accepted", received)
	}
}

// TestRun_RetriesTheRefusedBatch: a batch the collector refused is offered
// again on the next flush, together with what has arrived since.
func TestRun_RetriesTheRefusedBatch(t *testing.T) {
	var mu sync.Mutex
	var posts int
	var received []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		posts++
		refuse := posts == 1
		mu.Unlock()
		if refuse {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		gz, _ := gzip.NewReader(r.Body)
		var batch []Event
		_ = json.NewDecoder(gz).Decode(&batch)
		mu.Lock()
		defer mu.Unlock()
		for _, ev := range batch {
			received = append(received, ev.DecisionID)
		}
	}))
	defer srv.Close()

	logs := New(Config{URL: srv.URL, FlushInterval: 20 * time.Millisecond}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go logs.Run(ctx)
	logs.Log(Event{DecisionID: "first"})
	time.Sleep(60 * time.Millisecond)
	logs.Log(Event{DecisionID: "second"})

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		done := len(received) == 2
		mu.Unlock()
		if done {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(received, []string{"first", "second"}) {
		t.Errorf("the collector received %v, want the refused decision retried before the next one", received)
	}
}

// TestRun_ShutdownDoesNotResendADeliveryInFlight: a shutdown that arrives
// while an upload is on the wire lets it finish, so the decisions in it
// reach the collector once. The loop's context used to abort that upload,
// and the drain then offered the same decisions again, since a request cut
// off cannot be told from one the collector never received; the collector
// recorded d1 twice.
func TestRun_ShutdownDoesNotResendADeliveryInFlight(t *testing.T) {
	var mu sync.Mutex
	var received []string
	var held, once sync.Once
	inFlight := make(chan struct{})
	aborted := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The first upload is held on the wire, so that the shutdown lands
		// while it is there. A shutdown that aborts it closes the request
		// context, and the handler reports that through aborted; the
		// deferred call releases the main goroutine even where a check
		// below fails, which would otherwise wait until the package times
		// out and bury the message.
		defer held.Do(func() {
			close(inFlight)
			select {
			case <-r.Context().Done():
				once.Do(func() { close(aborted) })
			case <-release:
			}
		})
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("gzip: %v", err)
			return
		}
		var batch []Event
		if err := json.NewDecoder(gz).Decode(&batch); err != nil {
			t.Errorf("decode: %v", err)
			return
		}
		mu.Lock()
		for _, ev := range batch {
			received = append(received, ev.DecisionID)
		}
		mu.Unlock()
	}))
	defer srv.Close()

	logs := New(Config{URL: srv.URL, FlushInterval: 10 * time.Millisecond}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go logs.Run(ctx)
	logs.Log(Event{DecisionID: "d1"})

	<-inFlight
	cancel()
	select {
	case <-aborted:
		// The upload was cut off, and the resend it provokes is what the
		// assertion below reports.
	case <-time.After(500 * time.Millisecond):
		// The upload outlived the shutdown, so let it finish.
	}
	close(release)
	logs.Wait()

	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(received, []string{"d1"}) {
		t.Errorf("the collector received %v, want [d1] once", received)
	}
}

// TestDeliver_KeepsOnlyWhatTheStoreDidNotWrite: a store that fails part-way
// hands back the event it failed on and the ones after it. Handing back the
// whole batch put the decisions already on disk in the file a second time.
func TestDeliver_KeepsOnlyWhatTheStoreDidNotWrite(t *testing.T) {
	st := NewStore(filepath.Join(t.TempDir(), "decision-logs.jsonl"))
	logs := New(Config{Store: st}, nil)
	batch := []Event{
		{DecisionID: "1"},
		{DecisionID: "2"},
		{DecisionID: "3", Input: make(chan int)},
		{DecisionID: "4"},
	}
	undelivered, err := logs.deliver(context.Background(), batch)
	if err == nil {
		t.Fatal("deliver() = nil, want the store's encoding error")
	}
	var kept []string
	for _, ev := range undelivered {
		kept = append(kept, ev.DecisionID)
	}
	if !reflect.DeepEqual(kept, []string{"3", "4"}) {
		t.Errorf("deliver kept %v, want the event it failed on and the one after it", kept)
	}
	data, _ := st.ReadAll()
	if got := strings.Count(string(data), `"decision_id":"1"`); got != 1 {
		t.Errorf("decision 1 is in the file %d times, want once", got)
	}
}

// TestRun_ShutdownRetriesTheBatchOnceAndReturns: after the shutdown the
// batch a failed upload retained goes out once more, from the drain, and
// Run returns. A tick that fell due while the delivery ran used to be ready
// beside ctx.Done(), and select takes either of two ready cases, so the
// batch went out again on about half the shutdowns and each attempt cost a
// full Timeout. Ten shutdowns, because one of them is not conclusive.
func TestRun_ShutdownRetriesTheBatchOnceAndReturns(t *testing.T) {
	shutdown := func(t *testing.T) int {
		t.Helper()
		hung := make(chan struct{})
		reached := make(chan struct{})
		var mu sync.Mutex
		var uploads int
		var once sync.Once
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			uploads++
			mu.Unlock()
			once.Do(func() { close(reached) })
			<-hung
		}))
		// The handler is released before the server is closed, which waits
		// for the requests still in it.
		defer srv.Close()
		defer close(hung)

		logs := New(Config{
			URL:           srv.URL,
			FlushInterval: 5 * time.Millisecond,
			Timeout:       50 * time.Millisecond,
		}, nil)
		ctx, cancel := context.WithCancel(context.Background())
		go logs.Run(ctx)
		logs.Log(Event{DecisionID: "d1"})

		// The shutdown lands while the first upload is on the wire, so every
		// upload after it is a retry.
		<-reached
		cancel()
		done := make(chan struct{})
		go func() {
			logs.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Run has not returned five seconds after the shutdown, so nothing bounds an upload the collector never answers")
		}
		mu.Lock()
		defer mu.Unlock()
		return uploads
	}
	for i := range 10 {
		if got := shutdown(t); got != 2 {
			t.Fatalf("shutdown %d took %d uploads, want the one in flight and the drain's", i+1, got)
		}
	}
}

// randomString is filler that does not compress.
func randomString(t *testing.T, n int) string {
	t.Helper()
	raw := make([]byte, n/2)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}
