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

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// opaConfig is the part of the OPA configuration file the decision logger
// reads: which service receives the events and which request headers each
// event records.
type opaConfig struct {
	Services map[string]struct {
		URL string `yaml:"url"`
	} `yaml:"services"`
	DecisionLogs struct {
		Service        string `yaml:"service"`
		RequestContext struct {
			HTTP struct {
				Headers []string `yaml:"headers"`
			} `yaml:"http"`
		} `yaml:"request_context"`
	} `yaml:"decision_logs"`
}

// event mirrors the fields of OPA's decision log event that the collector
// stores and the suites read.
type event struct {
	Labels         map[string]string `json:"labels"`
	DecisionID     string            `json:"decision_id"`
	Path           string            `json:"path,omitempty"`
	Input          *any              `json:"input,omitempty"`
	Result         *any              `json:"result,omitempty"`
	NDBuiltinCache *any              `json:"nd_builtin_cache,omitempty"`
	RequestedBy    string            `json:"requested_by,omitempty"`
	Timestamp      time.Time         `json:"timestamp"`
	RequestID      uint64            `json:"req_id,omitempty"`
	RequestContext *requestContext   `json:"request_context,omitempty"`
}

type requestContext struct {
	HTTP struct {
		Headers map[string][]string `json:"headers"`
	} `json:"http"`
}

// decisionLogger batches events and uploads them to the collector the way
// OPA's decision log plugin does: a gzip-compressed JSON array, once a second
// at most.
type decisionLogger struct {
	url     string
	headers []string
	labels  map[string]string
	events  chan event
	seq     atomic.Uint64
	client  *http.Client
	done    chan struct{}
}

// newDecisionLogger reads the OPA configuration file; without a decision log
// service the logger drops every event.
func newDecisionLogger(configFile string) (*decisionLogger, error) {
	d := &decisionLogger{
		labels: map[string]string{"id": "opa-embedded", "version": "spike"},
		events: make(chan event, 1024),
		client: &http.Client{Timeout: 10 * time.Second},
		done:   make(chan struct{}),
	}
	if configFile == "" {
		return d, nil
	}
	raw, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	var cfg opaConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", configFile, err)
	}
	if svc, ok := cfg.Services[cfg.DecisionLogs.Service]; ok {
		d.url = strings.TrimSuffix(svc.URL, "/") + "/logs"
	}
	d.headers = cfg.DecisionLogs.RequestContext.HTTP.Headers
	return d, nil
}

func (d *decisionLogger) enabled() bool { return d.url != "" }

// newDecisionID returns a random id in the shape OPA uses.
func newDecisionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	s := hex.EncodeToString(b[:])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}

// log queues one event; a full queue drops it rather than slowing decisions.
func (d *decisionLogger) log(ev event) {
	if !d.enabled() {
		return
	}
	ev.RequestID = d.seq.Add(1)
	select {
	case d.events <- ev:
	default:
	}
}

// run uploads queued events until ctx ends, then drains the queue with its
// own deadline: the last decisions before a shutdown must reach the collector,
// as OPA's plugin flushes them too, and ctx is already cancelled by then.
func (d *decisionLogger) run(ctx context.Context) {
	defer close(d.done)
	if !d.enabled() {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var batch []event
	flush := func(ctx context.Context) {
		if len(batch) == 0 {
			return
		}
		if err := d.upload(ctx, batch); err != nil {
			logger.Warnf("decision log upload failed: %v", err)
		}
		batch = nil
	}
	for {
		select {
		case <-ctx.Done():
			for len(d.events) > 0 {
				batch = append(batch, <-d.events)
			}
			final, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			flush(final)
			cancel()
			return
		case ev := <-d.events:
			batch = append(batch, ev)
			if len(batch) >= 100 {
				flush(ctx)
			}
		case <-ticker.C:
			flush(ctx)
		}
	}
}

// wait blocks until run has drained the queue after ctx ended.
func (d *decisionLogger) wait() { <-d.done }

func (d *decisionLogger) upload(ctx context.Context, batch []event) error {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if err := json.NewEncoder(gz).Encode(batch); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("collector answered %d", resp.StatusCode)
	}
	return nil
}
