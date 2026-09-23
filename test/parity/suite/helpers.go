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

package paritysuite

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultHTTPClient is the shared client every wire helper funnels through.
// 30s timeout matches the tests/integration/testify default and is deliberately
// generous — the legacy stack is running inside Docker on localhost, so a long
// tail is almost always a bug, not latency.
var defaultHTTPClient = &http.Client{Timeout: 30 * time.Second}

// prohibitedHeaders are the headers the legacy thin client refuses to pass
// through from a caller. Per D-V item 5 the Go helper strips these
// case-insensitively from any caller-supplied headers map before setting them
// on the outgoing request.
var prohibitedHeaders = map[string]struct{}{
	"authorization": {},
	"tenant":        {},
}

// PerCallOptions carries the optional query/header parameters a wire helper
// supports. userID maps to D-V item 7 (the on-behalf-of userId query param);
// customHeaders maps to the thin client's filterHeaders pathway.
type PerCallOptions struct {
	UserID        string
	CustomHeaders map[string]string

	// TenantID replaces Config.TenantID in the tenant_id query parameter when
	// non-nil. A pointer to "" sends tenant_id with an empty value, which is
	// what the thin client sends when it has no tenant.
	TenantID *string
	// OmitTenantID sends no tenant_id parameter at all, which the thin client
	// never does; it takes precedence over TenantID.
	OmitTenantID bool
	// TenantHeader, when non-empty, is sent as the Tenant header. The thin
	// client strips that header from CustomHeaders, so it has its own field.
	TenantHeader string
}

// buildQuery constructs the canonical parity query string for v1 and v2
// helpers. tenant_id (D-V item 6) is present unless opts.OmitTenantID is set,
// userId (D-V item 7) is optional, and extra is appended in insertion order for
// per-endpoint params like resourceType, operation, and obligations (D-V items
// 9, 14).
func buildQuery(cfg Config, opts PerCallOptions, extra url.Values) string {
	v := url.Values{}
	switch {
	case opts.OmitTenantID:
	case opts.TenantID != nil:
		v.Set("tenant_id", *opts.TenantID)
	default:
		v.Set("tenant_id", cfg.TenantID)
	}
	if opts.UserID != "" {
		v.Set("userId", opts.UserID)
	}
	for key, values := range extra {
		for _, value := range values {
			v.Add(key, value)
		}
	}
	return v.Encode()
}

// filterCustomHeaders drops the prohibited entries from a caller-supplied
// header map, as the legacy thin client does.
func filterCustomHeaders(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if _, banned := prohibitedHeaders[strings.ToLower(strings.TrimSpace(k))]; banned {
			continue
		}
		out[k] = v
	}
	return out
}

// applyAuthHeaders sets Authorization, Incoming-Token, and Authorization-Type
// according to D-V items 2–4.
func applyAuthHeaders(req *http.Request, tokens TokenBundle) {
	if tokens.M2M != "" {
		req.Header.Set("Authorization", "Bearer "+tokens.M2M)
	}
	if tokens.Anonymous {
		req.Header.Set("Authorization-Type", "anonymous")
		req.Header.Del("Incoming-Token")
		return
	}
	if tokens.EndUser != "" {
		req.Header.Set("Incoming-Token", "Bearer "+tokens.EndUser)
	}
}

// buildRequest constructs an http.Request for the given method / url / body
// shape, applies auth headers, adds Content-Type when a body is present, and
// merges any custom headers after filterCustomHeaders.
func buildRequest(ctx context.Context, method, fullURL string, body any, tokens TokenBundle, opts PerCallOptions) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode body: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, reader)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	applyAuthHeaders(req, tokens)

	for k, v := range filterCustomHeaders(opts.CustomHeaders) {
		req.Header.Set(k, v)
	}
	if opts.TenantHeader != "" {
		req.Header.Set("Tenant", opts.TenantHeader)
	}
	return req, nil
}

// doRequest executes an http.Request and returns the status code + raw body.
// Decoding into a typed DTO is the caller's responsibility because parity
// assertions run against the decoded Go struct, not against raw bytes.
func doRequest(req *http.Request) (int, []byte, error) {
	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("read body: %w", err)
	}
	return resp.StatusCode, body, nil
}

// decodeJSON unmarshals the given body into target when body is non-empty.
// Empty/whitespace bodies are a no-op and target is left as its zero value —
// this matches the RemoteACCommon v1 contract where an empty body maps to
// null, which the client then coerces to false.
func decodeJSON(body []byte, target any) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	return json.Unmarshal(body, target)
}
