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
	"compress/gzip"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	defaultListenAddr   = "0.0.0.0:8183"
	defaultIngestPath   = "/logs"
	defaultDownloadPath = "/internal/v1/decision-logs"
	defaultLogFile      = "/var/log/authz/decision-logs.jsonl"
	defaultRequestLimit = 5 << 20 // 5 MiB
)

// jwtPattern finds a complete JWT anywhere in a string: base64url header,
// payload and signature separated by dots. Every JWT header starts with `{"`,
// which is `eyJ` in base64url, so the prefix keeps the match away from other
// dotted strings. A `Bearer ` prefix, when present, is not part of the match
// and stays as it is.
var jwtPattern = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]*)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\b`)

func main() {
	logger := log.New(os.Stdout, "[decision-log-collector] ", log.LstdFlags)

	addr := getenv("DECISION_LOG_COLLECTOR_ADDR", defaultListenAddr)
	ingestPath := getenv("DECISION_LOG_INGEST_PATH", defaultIngestPath)
	downloadPath := getenv("DECISION_LOG_DOWNLOAD_PATH", defaultDownloadPath)
	logFile := getenv("DECISION_LOG_FILE", defaultLogFile)

	store := &logStore{path: logFile}

	mux := http.NewServeMux()
	mux.HandleFunc(ingestPath, ingestHandler(store, logger))
	mux.HandleFunc(downloadPath, downloadHandler(store, logger))
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/", notFoundHandler)

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	logger.Printf("starting on %s", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("server failed: %v", err)
	}
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// ── log store ──────────────────────────────────────────────────────────────

type logStore struct {
	path string
	mu   sync.Mutex
}

func (s *logStore) append(events []any) error {
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

func (s *logStore) readAll() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	return data, err
}

// ── sanitization ───────────────────────────────────────────────────────────
//
// Decision-log events are audit material, and a JWT copied out of one would be
// a working credential until it expires. The signature is dropped from every
// JWT before an event is stored: header and payload stay readable, the token
// is no longer usable. Tokens turn up in three places and all three are
// covered: field values such as input.authorizationToken; longer strings that
// embed a token, such as the serialised http.send arguments in
// nd_builtin_cache; and map keys, because nd_builtin_cache keys every cached
// call by its serialised arguments, so io.jwt.decode_verify entries are keyed
// by the token itself.

func sanitizeString(s string) string {
	return jwtPattern.ReplaceAllString(s, "${1}.${2}")
}

func sanitizeValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, nested := range typed {
			out[sanitizeString(key)] = sanitizeValue(nested)
		}
		return out
	case []any:
		for i, nested := range typed {
			typed[i] = sanitizeValue(nested)
		}
		return typed
	case string:
		return sanitizeString(typed)
	default:
		return value
	}
}

// ── handlers ───────────────────────────────────────────────────────────────

func ingestHandler(store *logStore, logger *log.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
			return
		}

		body := r.Body
		defer func() { _ = body.Close() }()

		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(body)
			if err != nil {
				logger.Printf("ingest: gzip open failed: %v", err)
				writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid gzip body"})
				return
			}
			defer func() { _ = gz.Close() }()
			body = gz
		}

		raw, err := io.ReadAll(io.LimitReader(body, defaultRequestLimit+1))
		if err != nil {
			logger.Printf("ingest: read failed: %v", err)
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "failed to read body"})
			return
		}
		if int64(len(raw)) > defaultRequestLimit {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "request body too large"})
			return
		}

		var events []any
		if err := json.Unmarshal(raw, &events); err != nil {
			logger.Printf("ingest: json parse failed: %v", err)
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid json"})
			return
		}

		for i, event := range events {
			events[i] = sanitizeValue(event)
		}

		if err := store.append(events); err != nil {
			logger.Printf("ingest: persist failed: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "failed to persist decision logs"})
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func downloadHandler(store *logStore, logger *log.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
			return
		}

		data, err := store.readAll()
		if err != nil {
			logger.Printf("download: read failed: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "failed to read decision logs"})
			return
		}

		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		if len(data) > 0 {
			_, _ = w.Write(data)
		}
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func notFoundHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusNotFound, map[string]string{"message": "not found"})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
