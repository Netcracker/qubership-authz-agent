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
// log plugin and uploads them in gzip batches, so the collector and every
// reader of its output keep working with OPA out of the process.
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

// Config sets where and how events are uploaded.
type Config struct {
	// URL is the collector's base URL; the events go to <URL>/logs. Empty
	// disables logging: decisions get no decision_id and nothing is queued.
	URL string
	// Headers lists the request headers recorded into each event's
	// request_context, lowercase.
	Headers []string
	// Labels are attached to every event, as OPA's `labels` block.
	Labels map[string]string
	// MaxBatch and FlushInterval bound a batch by size and by time; zero
	// values take the defaults of 100 events and one second.
	MaxBatch      int
	FlushInterval time.Duration
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
	if cfg.Labels == nil {
		cfg.Labels = map[string]string{}
	}
	if warn == nil {
		warn = func(string, ...any) {}
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
func (l *Logger) Enabled() bool { return l.cfg.URL != "" }

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

// Run uploads queued events until ctx ends, then drains the queue with its
// own deadline: the last decisions before a shutdown must reach the
// collector, as OPA's plugin flushes them too, and ctx is already cancelled
// by then. Wait returns once Run is finished.
func (l *Logger) Run(ctx context.Context) {
	defer close(l.done)
	if !l.Enabled() {
		return
	}
	ticker := time.NewTicker(l.cfg.FlushInterval)
	defer ticker.Stop()
	var batch []Event
	flush := func(ctx context.Context) {
		if len(batch) == 0 {
			return
		}
		if err := l.upload(ctx, batch); err != nil {
			l.warn("decision log upload failed: %v", err)
		}
		batch = nil
	}
	for {
		select {
		case <-ctx.Done():
			for len(l.events) > 0 {
				batch = append(batch, <-l.events)
			}
			final, cancel := context.WithTimeout(context.Background(), l.cfg.Timeout)
			flush(final)
			cancel()
			return
		case ev := <-l.events:
			batch = append(batch, ev)
			if len(batch) >= l.cfg.MaxBatch {
				flush(ctx)
			}
		case <-ticker.C:
			flush(ctx)
		}
	}
}

// Wait blocks until Run has drained the queue after its context ended.
func (l *Logger) Wait() { <-l.done }

// upload posts one gzip-compressed JSON array of events, the wire format of
// OPA's decision log plugin.
func (l *Logger) upload(ctx context.Context, batch []Event) error {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if err := json.NewEncoder(gz).Encode(batch); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(l.cfg.URL, "/")+"/logs", &buf)
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
