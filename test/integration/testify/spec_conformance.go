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

//go:build integration

package runtimetest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

// Spec path is resolved relative to the testify directory (the cwd when
// `go test` runs). The runtime suite must execute from this directory; the
// canonical entry point `bash test/scripts/test-envoy-runtime.sh` cd's
// here before invoking `go test`.
const specPathRelative = "../../../api/openapi.yaml"

var (
	specOnce   sync.Once
	specDoc    *openapi3.T
	specRouter routers.Router
	specErr    error
)

// init registers a pass-through body decoder for `application/x-ndjson`.
// The spec declares this content type for GET /internal/v1/decision-logs
// (the per-line shape is OPA-defined and intentionally not part of the
// contract), but kin-openapi ships no built-in decoder for it, which
// would otherwise surface as a false-positive drift signal.
func init() {
	openapi3filter.RegisterBodyDecoder("application/x-ndjson", ndjsonPassthroughDecoder)
}

// ndjsonPassthroughDecoder treats the entire NDJSON stream as an opaque
// string for schema validation purposes. The spec's schema for this body
// is `type: string`, so returning the raw bytes as a string lets the
// validator accept it without trying to JSON-parse each line.
func ndjsonPassthroughDecoder(body io.Reader, header http.Header, schema *openapi3.SchemaRef, encFn openapi3filter.EncodingFn) (interface{}, error) {
	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	return string(raw), nil
}

// LoadSpec lazy-loads the OpenAPI document and the gorillamux router once
// per test process. Both the structural lint (TestOpenAPISpecLints) and
// the conformance hook share this loader.
func LoadSpec() (*openapi3.T, routers.Router, error) {
	specOnce.Do(func() {
		abs, err := filepath.Abs(specPathRelative)
		if err != nil {
			specErr = fmt.Errorf("resolve spec path: %w", err)
			return
		}
		loader := openapi3.NewLoader()
		loader.IsExternalRefsAllowed = false
		doc, err := loader.LoadFromFile(abs)
		if err != nil {
			specErr = fmt.Errorf("load spec %s: %w", abs, err)
			return
		}
		if err := doc.Validate(loader.Context); err != nil {
			specErr = fmt.Errorf("structural validate spec: %w", err)
			return
		}
		r, err := gorillamux.NewRouter(doc)
		if err != nil {
			specErr = fmt.Errorf("build gorillamux router: %w", err)
			return
		}
		specDoc = doc
		specRouter = r
	})
	return specDoc, specRouter, specErr
}

// specValidationOptions is the shared option set for ValidateRequest /
// ValidateResponse calls. NoopAuthenticationFunc accepts the
// `bearerAuth` requirement so security-required operations do not fail
// when the integration tests legitimately omit a token (e.g. anonymous
// flows, `/health`). IncludeResponseStatus is on so undeclared status
// codes count as drift. MultiError surfaces all violations in one error.
var specValidationOptions = &openapi3filter.Options{
	AuthenticationFunc:    openapi3filter.NoopAuthenticationFunc,
	IncludeResponseStatus: true,
	MultiError:            true,
}

// responseTriple identifies one (method, spec path template, status) response
// declared in the OpenAPI document. It is the key shared by the conformance
// hook's exercised-set and the ADR-0064 response-reachability lint
// (TestZZZResponseReachabilityCoverage).
type responseTriple struct {
	Method string
	Path   string
	Status int
}

var (
	exercisedResponsesMu sync.Mutex
	exercisedResponses   = map[responseTriple]bool{}
)

// recordExercisedResponse marks one (method, spec path, status) response as
// having been validated against the spec at least once during this test
// process. The conformance hook calls it on every successful ValidateResponse;
// the terminal reachability lint reads the accumulated set (ADR-0064).
func recordExercisedResponse(method, path string, status int) {
	exercisedResponsesMu.Lock()
	exercisedResponses[responseTriple{Method: method, Path: path, Status: status}] = true
	exercisedResponsesMu.Unlock()
}

// exercisedResponseSet returns a snapshot copy of the exercised-set so the
// lint can read it without holding the lock across its enumeration.
func exercisedResponseSet() map[responseTriple]bool {
	exercisedResponsesMu.Lock()
	defer exercisedResponsesMu.Unlock()
	out := make(map[responseTriple]bool, len(exercisedResponses))
	for k := range exercisedResponses {
		out[k] = true
	}
	return out
}

// assertConformsToSpec validates one request/response exchange against
// the loaded OpenAPI document. Skips silently when:
//   - The URL host is not the public Envoy listener (e.g. pip-stub,
//     Keycloak). The spec covers only the agent's
//     surface; off-target probes belong to harness plumbing.
//   - The router cannot match the path (e.g. intentional 404 probes in
//     route_security_test.go).
//
// Any other failure becomes a t.Fatal so the offending step shows up in
// the standard suite output.
func assertConformsToSpec(t *testing.T, method, rawURL string, reqHeaders map[string]string, reqBody []byte, statusCode int, respHeaders http.Header, respBody []byte) {
	assertConformsToSpecOpts(t, method, rawURL, reqHeaders, reqBody, statusCode, respHeaders, respBody, true)
}

// assertConformsToSpecResponseOnly validates only the response side of an
// exchange. Use this for tests that deliberately send a malformed request body
// to exercise the runtime's 400 reject path — the kin-openapi request-side
// validator would otherwise reject the body client-side and the test would
// never reach the agent. The response 400 body is still validated against
// LegacyErrorResponse.
func assertConformsToSpecResponseOnly(t *testing.T, method, rawURL string, reqHeaders map[string]string, reqBody []byte, statusCode int, respHeaders http.Header, respBody []byte) {
	assertConformsToSpecOpts(t, method, rawURL, reqHeaders, reqBody, statusCode, respHeaders, respBody, false)
}

func assertConformsToSpecOpts(t *testing.T, method, rawURL string, reqHeaders map[string]string, reqBody []byte, statusCode int, respHeaders http.Header, respBody []byte, validateRequest bool) {
	t.Helper()

	cfg := LoadConfig()
	if !isAgentURL(rawURL, cfg) {
		return
	}

	doc, router, err := LoadSpec()
	if err != nil {
		t.Fatalf("openapi spec load failed: %v", err)
	}

	// Normalize the request URL onto the spec's first server prefix so
	// the gorillamux router (which matches scheme+host from spec
	// `servers`) finds the route regardless of which listener the
	// runtime config sent the call to (BaseURL vs degraded ports).
	specURL := rawURL
	if len(doc.Servers) > 0 {
		if path, query := splitPathAndQuery(rawURL); path != "" {
			specURL = doc.Servers[0].URL + path
			if query != "" {
				specURL = specURL + "?" + query
			}
		}
	}

	parsed, err := url.Parse(specURL)
	if err != nil {
		t.Fatalf("parse url %q: %v", specURL, err)
	}

	httpReq, err := http.NewRequest(method, specURL, bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("rebuild request for spec validation: %v", err)
	}
	for k, v := range reqHeaders {
		httpReq.Header.Set(k, v)
	}
	if len(reqBody) > 0 && httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	httpReq.URL = parsed

	route, pathParams, err := router.FindRoute(httpReq)
	if err != nil {
		// No operation matches this URL. Tests that exercise the
		// catch-all 404 (route_security_test.go) take this branch.
		return
	}

	reqInput := &openapi3filter.RequestValidationInput{
		Request:    httpReq,
		PathParams: pathParams,
		Route:      route,
		Options:    specValidationOptions,
	}
	if validateRequest {
		if err := openapi3filter.ValidateRequest(context.Background(), reqInput); err != nil {
			t.Fatalf("spec request validation failed for %s %s: %v", method, parsed.Path, err)
		}
	}

	respInput := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: reqInput,
		Status:                 statusCode,
		Header:                 cloneOrDefaultHeader(respHeaders, respBody),
		Options:                specValidationOptions,
	}
	respInput.SetBodyBytes(respBody)
	if err := openapi3filter.ValidateResponse(context.Background(), respInput); err != nil {
		t.Fatalf("spec response validation failed for %s %s (status %d): %v\nbody: %s", method, parsed.Path, statusCode, err, truncate(respBody, 512))
	}

	// ADR-0064 response-reachability: record the spec route+method+status just
	// validated so the terminal coverage lint can prove every declared response
	// is reachable. route.Path is the spec path template, matching the keys the
	// lint enumerates from doc.Paths.
	recordExercisedResponse(method, route.Path, statusCode)
}

// cloneOrDefaultHeader returns a copy of the captured response headers.
// When the captured map is empty (older DoHTTP callers), we infer a
// reasonable default Content-Type from the body so the validator can
// pick the right schema branch.
func cloneOrDefaultHeader(h http.Header, body []byte) http.Header {
	out := http.Header{}
	for k, vs := range h {
		out[k] = append([]string(nil), vs...)
	}
	if out.Get("Content-Type") == "" {
		out.Set("Content-Type", guessContentType(body))
	}
	return out
}

func guessContentType(body []byte) string {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return "application/json"
	}
	switch trimmed[0] {
	case '{', '[', '"', 't', 'f', 'n':
		return "application/json"
	}
	if isProbablyJSONNumber(trimmed) {
		return "application/json"
	}
	return "application/json"
}

func isProbablyJSONNumber(b []byte) bool {
	var v json.Number
	return json.Unmarshal(b, &v) == nil
}

// isAgentURL filters URLs that are part of the agent's HTTP surface,
// versus harness-only endpoints (pip-stub, Keycloak).
func isAgentURL(rawURL string, cfg RuntimeConfig) bool {
	if rawURL == "" {
		return false
	}
	return cfg.BaseURL != "" && strings.HasPrefix(rawURL, cfg.BaseURL)
}

// splitPathAndQuery returns the path and query of rawURL without the
// scheme/host. Returns the empty path if parsing fails.
func splitPathAndQuery(rawURL string) (string, string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", ""
	}
	return u.Path, u.RawQuery
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
