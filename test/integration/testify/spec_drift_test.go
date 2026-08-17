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

package runtimetest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

// driftFixture is the on-disk shape of a captured request/response pair
// used by the drift auto-test. The fixture must be a request the
// authoritative spec accepts, and a response the authoritative spec
// accepts for that request.
type driftFixture struct {
	Method          string            `json:"method"`
	Path            string            `json:"path"`
	Query           string            `json:"query"`
	RequestHeaders  map[string]string `json:"requestHeaders"`
	RequestBody     json.RawMessage   `json:"requestBody"`
	StatusCode      int               `json:"statusCode"`
	ResponseHeaders map[string]string `json:"responseHeaders"`
	ResponseBody    json.RawMessage   `json:"responseBody"`
}

func loadDriftFixture(t *testing.T, name string) driftFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "spec-drift", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var f driftFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
	return f
}

// loadFreshSpec returns a fresh copy of the spec each call so a test
// case can mutate its in-memory copy without affecting other cases.
func loadFreshSpec(t *testing.T) *openapi3.T {
	t.Helper()
	abs, err := filepath.Abs("../../../api/openapi.yaml")
	if err != nil {
		t.Fatalf("resolve spec path: %v", err)
	}
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = false
	doc, err := loader.LoadFromFile(abs)
	if err != nil {
		t.Fatalf("load spec %s: %v", abs, err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("structural validate spec: %v", err)
	}
	return doc
}

// validateFixture runs request + response validation for the given
// fixture against the supplied spec. Returns the first validation error,
// or nil if both directions pass.
func validateFixture(t *testing.T, doc *openapi3.T, f driftFixture) error {
	t.Helper()
	router, err := gorillamux.NewRouter(doc)
	if err != nil {
		t.Fatalf("build router: %v", err)
	}

	// gorillamux router matches host/scheme from spec `servers`, so the
	// fixture URL must be absolute under the first server entry.
	if len(doc.Servers) == 0 {
		t.Fatalf("spec has no servers; cannot resolve fixture URL")
	}
	rawURL := doc.Servers[0].URL + f.Path
	if f.Query != "" {
		rawURL = rawURL + "?" + f.Query
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse fixture URL %q: %v", rawURL, err)
	}

	httpReq, err := http.NewRequest(f.Method, rawURL, bytes.NewReader(f.RequestBody))
	if err != nil {
		t.Fatalf("build fixture request: %v", err)
	}
	for k, v := range f.RequestHeaders {
		httpReq.Header.Set(k, v)
	}
	httpReq.URL = parsed

	route, pathParams, err := router.FindRoute(httpReq)
	if err != nil {
		t.Fatalf("router.FindRoute on fixture URL %q: %v", rawURL, err)
	}

	opts := &openapi3filter.Options{
		AuthenticationFunc:    openapi3filter.NoopAuthenticationFunc,
		IncludeResponseStatus: true,
		MultiError:            true,
	}

	reqInput := &openapi3filter.RequestValidationInput{
		Request:    httpReq,
		PathParams: pathParams,
		Route:      route,
		Options:    opts,
	}
	if err := openapi3filter.ValidateRequest(context.Background(), reqInput); err != nil {
		return err
	}

	respHeader := http.Header{}
	for k, v := range f.ResponseHeaders {
		respHeader.Set(k, v)
	}
	if respHeader.Get("Content-Type") == "" {
		respHeader.Set("Content-Type", "application/json")
	}

	respInput := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: reqInput,
		Status:                 f.StatusCode,
		Header:                 respHeader,
		Options:                opts,
	}
	respInput.SetBodyBytes(f.ResponseBody)
	return openapi3filter.ValidateResponse(context.Background(), respInput)
}

// TestSpecDriftDetection is a table-driven auto-test that proves the
// kin-openapi validator wired into the suite actually catches spec drift.
// Each row mutates a fresh in-memory copy of openapi.yaml and replays the
// captured fixture against the mutated spec; the test passes iff the
// validator rejects the mutated case (the unmodified spec must accept
// the fixture as a sanity precondition).
//
// Coverage required by Decision D7:
//   - ≥1 request-direction mutation (here: tighten required[] to include
//     a field the captured request does not carry).
//   - ≥1 response-direction mutation (here: swap the only declared
//     response status so the captured 200 becomes undeclared).
func TestSpecDriftDetection(t *testing.T) {
	const fixtureName = "check_resource.json"

	// Sanity check — the captured fixture must pass against the
	// unmodified spec, otherwise the drift cases below cannot prove
	// anything.
	t.Run("sanity_fixture_accepted_by_authoritative_spec", func(t *testing.T) {
		doc := loadFreshSpec(t)
		f := loadDriftFixture(t, fixtureName)
		if err := validateFixture(t, doc, f); err != nil {
			t.Fatalf("captured fixture must pass against unmodified spec; got: %v", err)
		}
	})

	cases := []struct {
		name      string
		direction string
		mutate    func(t *testing.T, doc *openapi3.T)
	}{
		{
			name:      "request_direction_add_required_field",
			direction: "request",
			mutate: func(t *testing.T, doc *openapi3.T) {
				schemaRef, ok := doc.Components.Schemas["CheckResourceRequest"]
				if !ok || schemaRef == nil || schemaRef.Value == nil {
					t.Fatalf("CheckResourceRequest schema missing from spec — fixture may be wired against a different operation")
				}
				schemaRef.Value.Required = append(schemaRef.Value.Required, "syntheticMandatoryField")
			},
		},
		{
			name:      "response_direction_swap_200_to_299",
			direction: "response",
			mutate: func(t *testing.T, doc *openapi3.T) {
				op := doc.Paths.Find("/access/v1/check/resource").Post
				if op == nil || op.Responses == nil {
					t.Fatalf("operation /access/v1/check/resource POST has no responses block")
				}
				existing := op.Responses.Value("200")
				if existing == nil {
					t.Fatalf("operation does not declare a 200 response in the unmodified spec")
				}
				op.Responses.Delete("200")
				op.Responses.Set("299", existing)
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			doc := loadFreshSpec(t)
			tc.mutate(t, doc)
			f := loadDriftFixture(t, fixtureName)
			if err := validateFixture(t, doc, f); err == nil {
				t.Fatalf("validator did not reject the mutated spec (%s-direction mutation %q) — drift detection is broken", tc.direction, tc.name)
			}
		})
	}
}
