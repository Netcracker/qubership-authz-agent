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
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func assertStatus(t *testing.T, rr *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rr.Code != want {
		t.Fatalf("expected HTTP %d, got %d — body: %s", want, rr.Code, rr.Body.String())
	}
}

func newDecisionLogService(t *testing.T) (*Service, string) {
	t.Helper()
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "decision-logs.jsonl")
	svc := New(Config{
		DecisionLogFile:         logFile,
		DecisionLogIngestPath:   DefaultDecisionLogIngestPath,
		DecisionLogDownloadPath: DefaultDecisionLogDownloadPath,
		Logger:                  log.New(io.Discard, "", 0),
	})
	return svc, logFile
}

func gzipJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(raw); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func TestDecisionLogIngestAcceptsGzipBatch(t *testing.T) {
	t.Parallel()

	svc, logFile := newDecisionLogService(t)

	events := []any{
		map[string]any{"decision_id": "aaa", "path": "data/authorize", "result": true},
		map[string]any{"decision_id": "bbb", "path": "data/authorize", "result": false},
	}
	body := gzipJSON(t, events)

	req := httptest.NewRequest(http.MethodPost, DefaultDecisionLogIngestPath, bytes.NewReader(body))
	req.Header.Set("Content-Encoding", "gzip")
	rr := httptest.NewRecorder()

	svc.Handler().ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusOK)

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 NDJSON lines, got %d: %q", len(lines), string(data))
	}
	for _, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("invalid JSON line: %v — %q", err, line)
		}
	}
}

func TestDecisionLogIngestAcceptsPlainJSON(t *testing.T) {
	t.Parallel()

	svc, logFile := newDecisionLogService(t)

	events := []any{
		map[string]any{"decision_id": "ccc", "path": "data/authorize"},
	}
	raw, _ := json.Marshal(events)

	req := httptest.NewRequest(http.MethodPost, DefaultDecisionLogIngestPath, bytes.NewReader(raw))
	rr := httptest.NewRecorder()

	svc.Handler().ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusOK)

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !bytes.Contains(data, []byte("ccc")) {
		t.Fatalf("expected log to contain decision_id ccc, got %q", string(data))
	}
}

func TestDecisionLogIngestSanitizesBearerJWTValuesRecursively(t *testing.T) {
	t.Parallel()

	svc, logFile := newDecisionLogService(t)

	events := []any{
		map[string]any{
			"authorization": "Bearer aaa.bbb.ccc",
			"subject": map[string]any{
				"token":  "Bearer ddd.eee.fff",
				"opaque": "Bearer opaque-token",
			},
			"request_context": map[string]any{
				"http": map[string]any{
					"headers": map[string]any{
						"authorization": []any{"Bearer ggg.hhh.iii"},
					},
				},
			},
			"results": []any{
				"Bearer jjj.kkk.lll",
				map[string]any{"nested": "Bearer mmm.nnn.ooo"},
			},
		},
	}
	raw, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, DefaultDecisionLogIngestPath, bytes.NewReader(raw))
	rr := httptest.NewRecorder()

	svc.Handler().ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusOK)

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}

	var persisted map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &persisted); err != nil {
		t.Fatalf("unmarshal persisted decision log: %v", err)
	}

	if persisted["authorization"] != "Bearer aaa.bbb" {
		t.Fatalf("expected top-level JWT to be sanitized, got %#v", persisted["authorization"])
	}
	subject := persisted["subject"].(map[string]any)
	if subject["token"] != "Bearer ddd.eee" {
		t.Fatalf("expected nested JWT to be sanitized, got %#v", subject["token"])
	}
	if subject["opaque"] != "Bearer opaque-token" {
		t.Fatalf("expected opaque token to remain unchanged, got %#v", subject["opaque"])
	}
	results := persisted["results"].([]any)
	if results[0] != "Bearer jjj.kkk" {
		t.Fatalf("expected array JWT to be sanitized, got %#v", results[0])
	}
	nested := results[1].(map[string]any)
	if nested["nested"] != "Bearer mmm.nnn" {
		t.Fatalf("expected nested array JWT to be sanitized, got %#v", nested["nested"])
	}
}

func TestDecisionLogIngestRejectsWrongMethod(t *testing.T) {
	t.Parallel()

	svc, _ := newDecisionLogService(t)

	req := httptest.NewRequest(http.MethodGet, DefaultDecisionLogIngestPath, nil)
	rr := httptest.NewRecorder()

	svc.Handler().ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusMethodNotAllowed)
}

func TestDecisionLogIngestRejectsBadGzip(t *testing.T) {
	t.Parallel()

	svc, _ := newDecisionLogService(t)

	req := httptest.NewRequest(http.MethodPost, DefaultDecisionLogIngestPath, strings.NewReader("not-gzip"))
	req.Header.Set("Content-Encoding", "gzip")
	rr := httptest.NewRecorder()

	svc.Handler().ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusBadRequest)
}

func TestDecisionLogDownloadReturnsEmptyWhenNoLogs(t *testing.T) {
	t.Parallel()

	svc, _ := newDecisionLogService(t)

	req := httptest.NewRequest(http.MethodGet, DefaultDecisionLogDownloadPath, nil)
	rr := httptest.NewRecorder()

	svc.Handler().ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusOK)
	if rr.Body.Len() != 0 {
		t.Fatalf("expected empty body when no logs, got %q", rr.Body.String())
	}
}

func TestDecisionLogDownloadReturnsNDJSON(t *testing.T) {
	t.Parallel()

	svc, _ := newDecisionLogService(t)

	// Ingest two events.
	events := []any{
		map[string]any{"decision_id": "x1"},
		map[string]any{"decision_id": "x2"},
	}
	body := gzipJSON(t, events)
	ingestReq := httptest.NewRequest(http.MethodPost, DefaultDecisionLogIngestPath, bytes.NewReader(body))
	ingestReq.Header.Set("Content-Encoding", "gzip")
	svc.Handler().ServeHTTP(httptest.NewRecorder(), ingestReq)

	// Download and verify.
	req := httptest.NewRequest(http.MethodGet, DefaultDecisionLogDownloadPath, nil)
	rr := httptest.NewRecorder()

	svc.Handler().ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusOK)

	body2 := rr.Body.Bytes()
	if !bytes.Contains(body2, []byte("x1")) || !bytes.Contains(body2, []byte("x2")) {
		t.Fatalf("expected NDJSON with both events, got %q", string(body2))
	}
	lines := strings.Split(strings.TrimSpace(string(body2)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 NDJSON lines, got %d", len(lines))
	}
}

func TestDecisionLogDownloadRejectsWrongMethod(t *testing.T) {
	t.Parallel()

	svc, _ := newDecisionLogService(t)

	req := httptest.NewRequest(http.MethodPost, DefaultDecisionLogDownloadPath, nil)
	rr := httptest.NewRecorder()

	svc.Handler().ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusMethodNotAllowed)
}

// TestDecisionLogDownloadSucceedsWithoutToken locks in the always-
// unauthenticated posture of GET /internal/v1/decision-logs after the
// pap-client token header check was retired. The request sends no
// header and must still receive HTTP 200 plus a sensible body.
func TestDecisionLogDownloadSucceedsWithoutToken(t *testing.T) {
	t.Parallel()

	svc, _ := newDecisionLogService(t)

	req := httptest.NewRequest(http.MethodGet, DefaultDecisionLogDownloadPath, nil)
	rr := httptest.NewRecorder()

	svc.Handler().ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusOK)
	if rr.Body.Len() != 0 {
		t.Fatalf("expected empty body when no logs, got %q", rr.Body.String())
	}
}

func TestDecisionLogMultipleIngestBatchesAccumulate(t *testing.T) {
	t.Parallel()

	svc, logFile := newDecisionLogService(t)

	for i, id := range []string{"ev1", "ev2", "ev3"} {
		events := []any{map[string]any{"decision_id": id, "seq": i}}
		body := gzipJSON(t, events)
		req := httptest.NewRequest(http.MethodPost, DefaultDecisionLogIngestPath, bytes.NewReader(body))
		req.Header.Set("Content-Encoding", "gzip")
		rr := httptest.NewRecorder()
		svc.Handler().ServeHTTP(rr, req)
		assertStatus(t, rr, http.StatusOK)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 accumulated NDJSON lines, got %d: %q", len(lines), string(data))
	}
}
