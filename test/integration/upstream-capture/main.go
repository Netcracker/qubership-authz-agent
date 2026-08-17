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
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
)

// CapturedRequest stores the exact request Envoy sent upstream.
type CapturedRequest struct {
	Tag     string            `json:"tag"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

var (
	captures []CapturedRequest
	mu       sync.Mutex
)

func main() {
	port := envOr("CAPTURE_PORT", "9090")
	upstream := envOr("CAPTURE_UPSTREAM", "http://opa:8181")

	target, err := url.Parse(upstream)
	if err != nil {
		log.Fatalf("invalid upstream URL %s: %v", upstream, err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	captures = make([]CapturedRequest, 0, 256)

	mux := http.NewServeMux()
	mux.HandleFunc("/capture/requests", handleGetRequests)
	mux.HandleFunc("/capture/reset", handleReset)
	mux.HandleFunc("/capture/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		captureAndForward(w, r, proxy)
	})

	addr := "0.0.0.0:" + port
	log.Printf("upstream-capture listening on %s, forwarding to %s", addr, upstream)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func captureAndForward(w http.ResponseWriter, r *http.Request, proxy *httputil.ReverseProxy) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body failed", 500)
		return
	}
	_ = r.Body.Close()

	tag := r.Header.Get("X-Request-Id")

	headers := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	captured := CapturedRequest{
		Tag:     tag,
		Method:  r.Method,
		Path:    r.URL.RequestURI(),
		Headers: headers,
		Body:    string(bodyBytes),
	}

	mu.Lock()
	captures = append(captures, captured)
	mu.Unlock()

	// Reconstruct body for the proxy.
	r.Body = io.NopCloser(newBytesReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))

	proxy.ServeHTTP(w, r)
}

func handleGetRequests(w http.ResponseWriter, r *http.Request) {
	tag := r.URL.Query().Get("tag")

	mu.Lock()
	var result []CapturedRequest
	for _, c := range captures {
		if tag == "" || c.Tag == tag {
			result = append(result, c)
		}
	}
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func handleReset(w http.ResponseWriter, _ *http.Request) {
	mu.Lock()
	captures = make([]CapturedRequest, 0, 256)
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprint(w, `{"status":"reset"}`)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type bytesReader struct {
	data []byte
	pos  int
}

func newBytesReader(data []byte) *bytesReader {
	return &bytesReader{data: data}
}

func (br *bytesReader) Read(p []byte) (int, error) {
	if br.pos >= len(br.data) {
		return 0, io.EOF
	}
	n := copy(p, br.data[br.pos:])
	br.pos += n
	return n, nil
}
