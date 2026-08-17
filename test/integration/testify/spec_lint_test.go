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
	"context"
	"path/filepath"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// loadSpecForLint loads and structurally validates
// api/openapi.yaml for the lint tests. Example values are
// validated against their media-type schemas — kin-openapi validates
// examples by default, and EnableExamplesValidation pins that behaviour so a
// future library default flip cannot silently drop the guard. The same
// LoadFromFile + Validate call is used at runtime in spec_conformance.go, so
// these tests catch a malformed spec (or a drifted example) before Docker
// Compose boots. Neither test carries a build tag — both run under
// `go test ./...` in this directory without the integration tag.
func loadSpecForLint(t *testing.T) *openapi3.T {
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
	if err := doc.Validate(context.Background(), openapi3.EnableExamplesValidation()); err != nil {
		t.Fatalf("spec structural validation (examples enabled) failed: %v", err)
	}
	return doc
}

// TestOpenAPISpecLints runs the structural lint (with example-vs-schema
// validation) on the OpenAPI document.
func TestOpenAPISpecLints(t *testing.T) {
	loadSpecForLint(t)
}

// TestOpenAPIExamplesCoverage asserts that every request body and every
// declared JSON / string response media type ships at least one `examples:`
// entry. Combined with the default example-vs-schema validation pinned in
// loadSpecForLint, this makes the published wire-shape examples a
// non-rotting contract (authz-agent task R17): an endpoint or status added
// without an example, or an example whose value drifts from its schema,
// fails this package's tests before the runtime harness boots.
//
// kin-openapi v0.124.0 exposes no map iterator over response status codes,
// so the declared statuses are probed from a fixed set that is a superset of
// every status the spec declares (200/400/401/503). 404/405 are runtime-only
// catch-alls with no response object in the spec and are skipped when absent.
func TestOpenAPIExamplesCoverage(t *testing.T) {
	doc := loadSpecForLint(t)
	probeStatuses := []int{200, 400, 401, 404, 405, 503}
	for _, path := range doc.Paths.InMatchingOrder() {
		item := doc.Paths.Find(path)
		for method, op := range item.Operations() {
			if rb := op.RequestBody; rb != nil && rb.Value != nil {
				for mt, media := range rb.Value.Content {
					if len(media.Examples) == 0 {
						t.Errorf("%s %s requestBody [%s]: no examples declared", method, path, mt)
					}
				}
			}
			for _, code := range probeStatuses {
				rr := op.Responses.Status(code)
				if rr == nil || rr.Value == nil {
					continue
				}
				for mt, media := range rr.Value.Content {
					if len(media.Examples) == 0 {
						t.Errorf("%s %s response %d [%s]: no examples declared", method, path, code, mt)
					}
				}
			}
		}
	}
}
