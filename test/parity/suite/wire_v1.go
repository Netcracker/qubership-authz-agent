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
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"authz-agent/test/parity/suite/model"
)

// v1 path templates — hard-coded against the thin client's
// AbstractRemoteACCommon (v1):13-24.
const (
	v1PathAPIVersion                  = "/api-version"
	v1PathCheckResource               = "/access/v1/check/resource"
	v1PathCheckResourceBulk           = "/access/v1/check/resource/bulk"
	v1PathCheckResourceBulkOperations = "/access/v1/check/resource/bulk/operations"
	v1PathCheckFilter                 = "/access/v1/check/filter"
	v1PathPreviewBulkOperations       = "/preview/v1/check/resource/bulk/operations"
)

// HelperApiVersion drives parity-contract row 1 (GET /api-version). The thin
// client issues this call with no auth headers — the probe is unauthenticated
// because the interceptor selection itself depends on the /api-version answer
// (RelayRestTemplateConfiguration:57-90).
func HelperApiVersion(ctx context.Context, cfg Config) (int, model.ApiVersionResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cfg.ACBaseURL, "/")+v1PathAPIVersion, nil)
	if err != nil {
		return 0, model.ApiVersionResponse{}, err
	}
	status, body, err := doRequest(req)
	if err != nil {
		return status, model.ApiVersionResponse{}, err
	}
	var decoded model.ApiVersionResponse
	if err := decodeJSON(body, &decoded); err != nil {
		return status, decoded, err
	}
	return status, decoded, nil
}

// HelperCheckResourceV1 drives parity-contract row 2
// (POST /access/v1/check/resource). Returns the decoded boolean decision
// plus the raw status and body so validation rows (row 11) can assert on
// error responses.
func HelperCheckResourceV1(ctx context.Context, cfg Config, body model.CheckAccessRequest, tokens TokenBundle, opts PerCallOptions) (int, bool, []byte, error) {
	target := buildURL(cfg.ACBaseURL, v1PathCheckResource, buildQuery(cfg, opts.UserID, nil))
	req, err := buildRequest(ctx, http.MethodPost, target, body, tokens, opts)
	if err != nil {
		return 0, false, nil, err
	}
	status, raw, err := doRequest(req)
	if err != nil {
		return status, false, raw, err
	}
	decision := decodeBoolean(raw)
	return status, decision, raw, nil
}

// HelperCheckResourcesV1 drives row 3 (POST /access/v1/check/resource/bulk).
// The decoded set of allowed ids is returned as a []string; callers use
// cmpopts.SortSlices at compare time per D-M.
func HelperCheckResourcesV1(ctx context.Context, cfg Config, body []model.CheckAccessRequestWithID, tokens TokenBundle, opts PerCallOptions) (int, []string, []byte, error) {
	target := buildURL(cfg.ACBaseURL, v1PathCheckResourceBulk, buildQuery(cfg, opts.UserID, nil))
	req, err := buildRequest(ctx, http.MethodPost, target, body, tokens, opts)
	if err != nil {
		return 0, nil, nil, err
	}
	status, raw, err := doRequest(req)
	if err != nil {
		return status, nil, raw, err
	}
	var decoded []string
	if err := decodeJSON(raw, &decoded); err != nil {
		return status, nil, raw, err
	}
	return status, decoded, raw, nil
}

// HelperCheckResourcesByOperationsV1 drives row 4
// (POST /access/v1/check/resource/bulk/operations).
func HelperCheckResourcesByOperationsV1(ctx context.Context, cfg Config, body []model.CheckAccessBulkOperationsRequest, tokens TokenBundle, opts PerCallOptions) (int, map[string][]string, []byte, error) {
	target := buildURL(cfg.ACBaseURL, v1PathCheckResourceBulkOperations, buildQuery(cfg, opts.UserID, nil))
	req, err := buildRequest(ctx, http.MethodPost, target, body, tokens, opts)
	if err != nil {
		return 0, nil, nil, err
	}
	status, raw, err := doRequest(req)
	if err != nil {
		return status, nil, raw, err
	}
	var decoded map[string][]string
	if err := decodeJSON(raw, &decoded); err != nil {
		return status, nil, raw, err
	}
	return status, decoded, raw, nil
}

// HelperPreviewCheckResourcesByOperationsV1 drives row 5
// (POST /preview/v1/check/resource/bulk/operations). Same wire shape as
// row 4; differs only in the path prefix (thin client passes
// Flags.withPreview() which rewrites the path template).
func HelperPreviewCheckResourcesByOperationsV1(ctx context.Context, cfg Config, body []model.CheckAccessBulkOperationsRequest, tokens TokenBundle, opts PerCallOptions) (int, map[string][]string, []byte, error) {
	target := buildURL(cfg.ACBaseURL, v1PathPreviewBulkOperations, buildQuery(cfg, opts.UserID, nil))
	req, err := buildRequest(ctx, http.MethodPost, target, body, tokens, opts)
	if err != nil {
		return 0, nil, nil, err
	}
	status, raw, err := doRequest(req)
	if err != nil {
		return status, nil, raw, err
	}
	var decoded map[string][]string
	if err := decodeJSON(raw, &decoded); err != nil {
		return status, nil, raw, err
	}
	return status, decoded, raw, nil
}

// HelperFilterV1 drives row 6 (POST /access/v1/check/filter). Body is empty —
// the query string carries resourceType, operation, and userId. An empty
// resourceType reaches the server and triggers the @NotNull validation
// (row 29 relies on this for 400 assertions).
func HelperFilterV1(ctx context.Context, cfg Config, resourceType, operation string, tokens TokenBundle, opts PerCallOptions) (int, model.OldFilterEvaluationResult, []byte, error) {
	extra := url.Values{}
	if resourceType != "" {
		extra.Set("resourceType", resourceType)
	}
	if operation != "" {
		extra.Set("operation", operation)
	}
	target := buildURL(cfg.ACBaseURL, v1PathCheckFilter, buildQuery(cfg, opts.UserID, extra))
	req, err := buildRequest(ctx, http.MethodPost, target, nil, tokens, opts)
	if err != nil {
		return 0, model.OldFilterEvaluationResult{}, nil, err
	}
	status, raw, err := doRequest(req)
	if err != nil {
		return status, model.OldFilterEvaluationResult{}, raw, err
	}
	var decoded model.OldFilterEvaluationResult
	if err := decodeJSON(raw, &decoded); err != nil {
		return status, decoded, raw, err
	}
	return status, decoded, raw, nil
}

// buildURL composes base + path + ?query defensively against trailing slashes.
func buildURL(base, path, query string) string {
	full := strings.TrimRight(base, "/") + path
	if query != "" {
		full += "?" + query
	}
	return full
}

// decodeBoolean mirrors the thin client's BOOLEAN_RESPONSE_TYPE handling —
// empty/whitespace body → null → false.
func decodeBoolean(body []byte) bool {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" || trimmed == "null" {
		return false
	}
	var decoded bool
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		return false
	}
	return decoded
}
