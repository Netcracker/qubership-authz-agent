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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

// jwtPattern finds a complete JWT anywhere in a string: base64url header,
// payload, and signature separated by dots. Every JWT header starts with
// `{"`, which is eyJ in base64url, so the prefix keeps the match away from
// other dotted strings.
var jwtPattern = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]*)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\b`)

// Store keeps decision events on disk as NDJSON, one event per line, and
// serves them back whole. Events are audit material, and a JWT copied out
// of one would be a working credential until it expires, so the signature
// is removed from every JWT before an event is stored: in field values such
// as input.authorizationToken, in strings that embed a token such as the
// serialized http.send arguments of nd_builtin_cache, and in map keys,
// since nd_builtin_cache keys a cached io.jwt.decode_verify call by the
// token itself.
type Store struct {
	path string
	mu   sync.Mutex
}

// NewStore returns a store on the file at path; the file and its
// directory are created on the first append.
func NewStore(path string) *Store {
	return &Store{path: path}
}

// Append writes the events, redacted, to the end of the file, and returns
// how many of them it wrote. One event is written at a time and nothing
// rolls back, so a full volume leaves the events before the failure on
// disk; the count is what lets the caller resume there rather than offer
// the whole batch again and record those decisions twice.
func (s *Store) Append(events []Event) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	for written, ev := range events {
		line, err := redacted(ev)
		if err != nil {
			return written, err
		}
		if err := enc.Encode(line); err != nil {
			return written, err
		}
	}
	return len(events), nil
}

// Open returns the log file and the number of bytes in it, for a reader that
// streams rather than holding the whole log in memory. The lock covers the
// open and the stat and not the transfer: appends only add to the end, so what
// the caller reads is a prefix, and taking the size while no append can run is
// what makes that prefix end on a line boundary. The caller closes the file.
// A log that has not been written yet returns a nil file.
func (s *Store) Open() (*os.File, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, info.Size(), nil
}

// ReadAll returns the file's whole content; nil before the first append. It
// holds the append lock for the length of the read, so nothing drains the
// decision queue while it runs: use Open for anything a request can reach.
func (s *Store) ReadAll() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

// redacted is the event as generic JSON with every JWT signature removed.
func redacted(ev Event) (any, error) {
	raw, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	return sanitize(generic), nil
}

func sanitize(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, nested := range typed {
			out[sanitizeString(key)] = sanitize(nested)
		}
		return out
	case []any:
		for i, nested := range typed {
			typed[i] = sanitize(nested)
		}
		return typed
	case string:
		return sanitizeString(typed)
	default:
		return value
	}
}

func sanitizeString(s string) string {
	return jwtPattern.ReplaceAllString(s, "${1}.${2}")
}
