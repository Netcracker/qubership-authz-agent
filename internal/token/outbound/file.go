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
	"errors"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultFileInterval is how often a [FileSource] reads its file when
// [NewFileSource] gets no interval.
const DefaultFileInterval = 15 * time.Second

// FileSource holds the token read from one file. It reads the file again
// on every interval and whenever [FileSource.Reload] asks, and keeps the
// new content when it differs, so a token the kubelet or a [Writer]
// replaces takes effect without a restart. A missing or empty file leaves
// the previous token in place. It is safe for concurrent use.
type FileSource struct {
	path     string
	interval time.Duration
	log      Logger

	mu    sync.RWMutex
	token string
	ready chan struct{}
	once  sync.Once
	// reload holds a pending request from Reload.
	reload chan struct{}
}

// NewFileSource returns a source for the file at path, read every
// interval, or every [DefaultFileInterval] when interval is not positive. A
// nil log discards the diagnostics. [FileSource.Run] has to run for the
// source to hold a token.
func NewFileSource(path string, interval time.Duration, log Logger) *FileSource {
	if interval <= 0 {
		interval = DefaultFileInterval
	}
	if log == nil {
		log = discard{}
	}
	return &FileSource{path: path, interval: interval, log: log, ready: make(chan struct{}), reload: make(chan struct{}, 1)}
}

// Token returns the current token, or "" before the first one is read.
func (s *FileSource) Token() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.token
}

// Ready is closed once the source holds its first token.
func (s *FileSource) Ready() <-chan struct{} { return s.ready }

// Run reads the file at once, then every interval and whenever
// [FileSource.Reload] asks, until ctx ends.
func (s *FileSource) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		s.read()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.reload:
		}
	}
}

// Reload makes Run read the file now rather than at its next interval, for
// example right after a [Writer] has written a new token. It does not wait
// for the read.
func (s *FileSource) Reload() {
	select {
	case s.reload <- struct{}{}:
	default:
	}
}

func (s *FileSource) read() {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.log.Warnf("outbound token: %v", err)
		}
		return
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return
	}
	s.mu.Lock()
	changed := token != s.token
	s.token = token
	s.mu.Unlock()
	if changed {
		s.log.Infof("outbound token: read a new token from %s", s.path)
		s.once.Do(func() { close(s.ready) })
	}
}
