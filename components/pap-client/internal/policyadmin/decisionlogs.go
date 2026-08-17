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

package policyadmin

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

const (
	DefaultDecisionLogIngestPath   = "/logs"
	DefaultDecisionLogDownloadPath = "/internal/v1/decision-logs"
	DefaultDecisionLogFile         = "/var/log/authz/decision-logs.jsonl"
)

var bearerJWTValuePattern = regexp.MustCompile(`^Bearer ([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$`)

// decisionLogStore persists OPA decision log events to an NDJSON file.
// All file I/O is protected by mu.
type decisionLogStore struct {
	path string
	mu   sync.Mutex
}

func newDecisionLogStore(path string) *decisionLogStore {
	return &decisionLogStore{path: path}
}

func sanitizeDecisionLogValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			typed[key] = sanitizeDecisionLogValue(nested)
		}
		return typed
	case []any:
		for i, nested := range typed {
			typed[i] = sanitizeDecisionLogValue(nested)
		}
		return typed
	case string:
		matches := bearerJWTValuePattern.FindStringSubmatch(typed)
		if len(matches) != 4 {
			return typed
		}
		return "Bearer " + matches[1] + "." + matches[2]
	default:
		return value
	}
}

// append writes each event in events as an NDJSON line to the log file.
// Events that cannot be marshalled are silently skipped.
func (s *decisionLogStore) append(events []any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}

	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	enc := json.NewEncoder(f)
	for _, ev := range events {
		_ = enc.Encode(ev)
	}
	return nil
}

// readAll returns the full NDJSON content of the log file.
// Returns nil, nil when the file does not exist yet.
func (s *decisionLogStore) readAll() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	return data, err
}

// handleDecisionLogIngest accepts OPA decision log batches.
// OPA sends POST {service.url}/logs with Content-Encoding: gzip and a JSON array body.
func (s *Service) handleDecisionLogIngest(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != s.decisionLogIngestPath {
		s.handleNotFound(w, r)
		return
	}

	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Message: "method not allowed"})
		return
	}

	body := r.Body
	defer func() { _ = body.Close() }()

	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(body)
		if err != nil {
			s.logger.Printf("decision log ingest: gzip open failed: %v", err)
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Message: "invalid gzip body"})
			return
		}
		defer func() { _ = gz.Close() }()
		body = gz
	}

	raw, err := io.ReadAll(io.LimitReader(body, s.limit+1))
	if err != nil {
		s.logger.Printf("decision log ingest: read failed: %v", err)
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Message: "failed to read body"})
		return
	}
	if int64(len(raw)) > s.limit {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Message: "request body too large"})
		return
	}

	var events []any
	if err := json.Unmarshal(raw, &events); err != nil {
		s.logger.Printf("decision log ingest: json parse failed: %v", err)
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Message: "invalid json"})
		return
	}

	for i, event := range events {
		events[i] = sanitizeDecisionLogValue(event)
	}

	if err := s.decisionLog.append(events); err != nil {
		s.logger.Printf("decision log ingest: persist failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Message: "failed to persist decision logs"})
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleDecisionLogDownload serves the accumulated NDJSON decision log file.
func (s *Service) handleDecisionLogDownload(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != s.decisionLogDownloadPath {
		s.handleNotFound(w, r)
		return
	}

	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Message: "method not allowed"})
		return
	}

	data, err := s.decisionLog.readAll()
	if err != nil {
		s.logger.Printf("decision log download: read failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Message: "failed to read decision logs"})
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	if len(data) > 0 {
		_, _ = w.Write(data)
	}
}
