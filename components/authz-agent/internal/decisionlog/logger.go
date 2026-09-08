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

// Package decisionlog emits decision events in the shape of OPA's decision
// log plugin. A [Logger] queues them and either uploads them to a collector
// in gzip batches, so the collector and every reader of its output keep
// working with OPA out of the process, or appends them to a [Store] that
// serves them back as the collector did.
package decisionlog

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Config sets where and how events are delivered.
type Config struct {
	// URL is the collector's base URL; the events go to <URL>/logs.
	URL string
	// Store receives the events instead of the collector when set. With
	// neither Store nor URL, logging is off: decisions get no decision_id
	// and nothing is queued.
	Store *Store
	// Headers lists the request headers recorded into each event's
	// request_context, lowercase.
	Headers []string
	// Labels are attached to every event, as OPA's `labels` block.
	Labels map[string]string
	// MaxBatch and FlushInterval bound a batch by count and by time; zero
	// values take the defaults of 100 events and one second.
	MaxBatch      int
	FlushInterval time.Duration
	// MaxUploadBytes bounds one upload: a batch is posted in as many
	// gzipped chunks as it takes to keep each body under it, as OPA's
	// upload_size_limit_bytes does, so a collector with a body limit of its
	// own is not handed a batch it refuses. Zero takes OPA's default of
	// 32768. The bound is soft: the event that crosses it ends the chunk, so
	// a single event larger than the bound is posted alone.
	MaxUploadBytes int
	// MaxQueued bounds the events kept across a failed upload; the oldest
	// beyond it are dropped. Zero takes 1024, the size of the queue.
	MaxQueued int
	// Timeout bounds one upload; zero takes ten seconds.
	Timeout time.Duration
}

// Event is one decision, with the field names of OPA's decision log v1.
type Event struct {
	Labels         map[string]string `json:"labels"`
	DecisionID     string            `json:"decision_id"`
	Path           string            `json:"path"`
	Input          any               `json:"input,omitempty"`
	Result         any               `json:"result,omitempty"`
	NDBuiltinCache any               `json:"nd_builtin_cache,omitempty"`
	RequestedBy    string            `json:"requested_by,omitempty"`
	Timestamp      time.Time         `json:"timestamp"`
	RequestID      uint64            `json:"req_id,omitempty"`
	RequestContext *RequestContext   `json:"request_context,omitempty"`
}

// RequestContext carries the recorded request headers.
type RequestContext struct {
	HTTP *HTTPRequestContext `json:"http,omitempty"`
}

// HTTPRequestContext holds header values by lowercase name.
type HTTPRequestContext struct {
	Headers map[string][]string `json:"headers"`
}

// Logger queues events and uploads them from Run.
type Logger struct {
	cfg    Config
	events chan Event
	seq    atomic.Uint64
	client *http.Client
	done   chan struct{}
	warn   func(format string, args ...any)
}

// New returns a logger for cfg. warn receives upload failures; nil discards
// them.
func New(cfg Config, warn func(format string, args ...any)) *Logger {
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxUploadBytes <= 0 {
		cfg.MaxUploadBytes = 32768
	}
	if cfg.MaxQueued <= 0 {
		cfg.MaxQueued = 1024
	}
	if cfg.Labels == nil {
		cfg.Labels = map[string]string{}
	}
	if warn == nil {
		warn = func(string, ...any) {
			// A caller that passes no callback wants failures discarded.
		}
	}
	return &Logger{
		cfg:    cfg,
		events: make(chan Event, 1024),
		client: &http.Client{Timeout: cfg.Timeout},
		done:   make(chan struct{}),
		warn:   warn,
	}
}

// Enabled reports whether decisions are logged at all.
func (l *Logger) Enabled() bool { return l.cfg.Store != nil || l.cfg.URL != "" }

// Store is the store the events go to, nil when they are uploaded.
func (l *Logger) Store() *Store { return l.cfg.Store }

// Headers returns the request headers recorded per event, lowercase.
func (l *Logger) Headers() []string { return l.cfg.Headers }

// NewDecisionID returns a random UUID-shaped id, as OPA's decision_id.
func NewDecisionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	s := hex.EncodeToString(b[:])
	return strings.Join([]string{s[0:8], s[8:12], s[12:16], s[16:20], s[20:32]}, "-")
}

// Log queues ev, filling the sequence number, the timestamp, and the labels
// when the caller left them empty. A full queue drops the event and warns
// rather than blocking a decision.
func (l *Logger) Log(ev Event) {
	if !l.Enabled() {
		return
	}
	if ev.RequestID == 0 {
		ev.RequestID = l.seq.Add(1)
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if ev.Labels == nil {
		ev.Labels = l.cfg.Labels
	}
	select {
	case l.events <- ev:
	default:
		l.warn("decision log queue is full, dropping decision %s", ev.DecisionID)
	}
}

// Run delivers queued events until ctx ends, then drains the queue: the
// last decisions before a shutdown must reach the collector, as OPA's plugin
// flushes them too. A delivery that fails keeps its events for the next
// attempt, as OPA requeues a chunk it could not upload; the oldest are
// dropped once MaxQueued is reached.
//
// Cancelling ctx ends the loop and leaves a delivery already under way to
// finish under its own bound rather than aborting it. On the upload path
// that bound is Timeout, so Run returns up to two Timeouts after ctx ends,
// one for an upload in flight when it ended and one for the drain; on the
// store path it is however long those two writes take. Wait returns once
// Run is finished.
func (l *Logger) Run(ctx context.Context) {
	defer close(l.done)
	if !l.Enabled() {
		return
	}
	ticker := time.NewTicker(l.cfg.FlushInterval)
	defer ticker.Stop()
	var batch []Event
	flush := func() {
		if len(batch) == 0 {
			return
		}
		// A request cut off mid-flight cannot be told from one the collector
		// never received, so ctx ends the loop without aborting a delivery
		// already under way. Timeout bounds an upload instead; a store
		// takes no deadline, and the write is its own bound.
		deadline, cancel := context.WithTimeout(context.WithoutCancel(ctx), l.cfg.Timeout)
		undelivered, err := l.deliver(deadline, batch)
		cancel()
		if err != nil {
			l.warn("decision log delivery failed, keeping %d decisions for the next attempt: %v", len(undelivered), err)
		}
		batch = l.retained(undelivered)
	}
	for {
		select {
		case <-ctx.Done():
			for len(l.events) > 0 {
				batch = append(batch, <-l.events)
			}
			flush()
			return
		case ev := <-l.events:
			batch = append(batch, ev)
			if len(batch) >= l.cfg.MaxBatch {
				flush()
			}
		case <-ticker.C:
			if ctx.Err() != nil {
				// The tick was pending while the last delivery ran, and
				// both cases are ready now. The drain below finishes the
				// batch; flushing it here first would spend another
				// Timeout on it, and so would every tick after that.
				continue
			}
			flush()
		}
	}
}

// Wait blocks until Run has drained the queue after its context ended,
// which takes up to two Timeouts on the upload path.
func (l *Logger) Wait() { <-l.done }

// deliver hands a batch to the store, or uploads it, and returns the
// events that did not arrive.
func (l *Logger) deliver(ctx context.Context, batch []Event) ([]Event, error) {
	if l.cfg.Store != nil {
		written, err := l.cfg.Store.Append(batch)
		if err != nil {
			return batch[written:], err
		}
		return nil, nil
	}
	return l.upload(ctx, batch)
}

// retained is what is kept for the next attempt: the newest MaxQueued
// events. A backlog past that has to lose something, and the oldest
// decisions are the ones a reader is least likely to still want.
func (l *Logger) retained(events []Event) []Event {
	if len(events) <= l.cfg.MaxQueued {
		return events
	}
	dropped := len(events) - l.cfg.MaxQueued
	l.warn("decision log backlog is full, dropping the %d oldest decisions", dropped)
	return events[dropped:]
}

// upload posts the batch as gzip-compressed JSON arrays, the wire format of
// OPA's decision log plugin, one POST per chunk. It stops at the first
// chunk that fails and returns the events of that chunk and every chunk
// after it.
func (l *Logger) upload(ctx context.Context, batch []Event) ([]Event, error) {
	for len(batch) > 0 {
		body, taken, err := l.chunk(batch)
		if err != nil {
			// The event cannot be encoded, so no attempt can deliver it.
			l.warn("decision log encoding failed, dropping %d decisions: %v", taken, err)
			batch = batch[taken:]
			continue
		}
		if err := l.post(ctx, body); err != nil {
			return batch, err
		}
		batch = batch[taken:]
	}
	return nil, nil
}

// chunk encodes the longest prefix of batch whose compressed body stays
// under MaxUploadBytes, and returns the body with the number of events in
// it. The event that crosses the bound is part of the chunk, so a chunk is
// never empty.
func (l *Logger) chunk(batch []Event) (body *bytes.Buffer, taken int, err error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte("[")); err != nil {
		return nil, len(batch), err
	}
	for taken = 0; taken < len(batch); {
		raw, err := json.Marshal(batch[taken])
		if err != nil {
			if taken > 0 {
				break
			}
			return nil, 1, err
		}
		if taken > 0 {
			if _, err := gz.Write([]byte(",")); err != nil {
				return nil, len(batch), err
			}
		}
		if _, err := gz.Write(raw); err != nil {
			return nil, len(batch), err
		}
		taken++
		if err := gz.Flush(); err != nil {
			return nil, len(batch), err
		}
		if buf.Len() >= l.cfg.MaxUploadBytes {
			break
		}
	}
	if _, err := gz.Write([]byte("]")); err != nil {
		return nil, len(batch), err
	}
	if err := gz.Close(); err != nil {
		return nil, len(batch), err
	}
	return &buf, taken, nil
}

func (l *Logger) post(ctx context.Context, body *bytes.Buffer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(l.cfg.URL, "/")+"/logs", body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := l.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("collector answered %s", resp.Status)
	}
	return nil
}
