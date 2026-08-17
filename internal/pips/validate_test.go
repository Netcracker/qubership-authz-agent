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

package pips

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRejectFilteredPIP(t *testing.T) {
	t.Parallel()
	items := []SimplifiedPIP{{Name: "subject.foo", PipType: "FILTERED", URL: "http://x"}}
	err := Validate(items)
	requireError(t, err, "unsupported pipType FILTERED")
}

func TestRejectPermissionScopePIP(t *testing.T) {
	t.Parallel()
	items := []SimplifiedPIP{{Name: "subject.foo", PipType: "PERMISSION_SCOPE", URL: "http://x"}}
	err := Validate(items)
	requireError(t, err, "unsupported pipType PERMISSION_SCOPE")
}

func TestRejectMappingPIP(t *testing.T) {
	t.Parallel()
	items := []SimplifiedPIP{{Name: "subject.foo", PipType: "MAPPING"}}
	err := Validate(items)
	requireError(t, err, "unsupported pipType MAPPING")
}

func TestRejectGeneralWithBeanName(t *testing.T) {
	t.Parallel()
	items := []SimplifiedPIP{{Name: "subject.foo", PipType: "GENERAL", BeanName: "myBean", URL: "http://x"}}
	err := Validate(items)
	requireError(t, err, "unsupported GENERAL pip with beanName")
}

func TestRejectMissingName(t *testing.T) {
	t.Parallel()
	items := []SimplifiedPIP{{Name: "", URL: "http://x"}}
	err := Validate(items)
	requireError(t, err, "name is required")
}

func TestRejectNameWithoutSubjectPrefix(t *testing.T) {
	t.Parallel()
	items := []SimplifiedPIP{{Name: "resource.foo", URL: "http://x"}}
	err := Validate(items)
	requireError(t, err, "must start with 'subject.'")
}

func TestRejectDuplicateName(t *testing.T) {
	t.Parallel()
	items := []SimplifiedPIP{
		{Name: "subject.foo", URL: "http://x"},
		{Name: "subject.foo", URL: "http://y"},
	}
	err := Validate(items)
	requireError(t, err, "duplicate name")
}

func TestRejectTokenWithoutClaim(t *testing.T) {
	t.Parallel()
	items := []SimplifiedPIP{{Name: "subject.foo", PipType: "TOKEN"}}
	err := Validate(items)
	requireError(t, err, "TOKEN pip requires 'claim'")
}

func TestRejectHeaderWithoutHeader(t *testing.T) {
	t.Parallel()
	items := []SimplifiedPIP{{Name: "subject.foo", PipType: "HEADER"}}
	err := Validate(items)
	requireError(t, err, "HEADER pip requires 'header'")
}

func TestRejectGeneralWithoutURL(t *testing.T) {
	t.Parallel()
	items := []SimplifiedPIP{{Name: "subject.foo", PipType: "GENERAL"}}
	err := Validate(items)
	requireError(t, err, "GENERAL pip requires 'url'")
}

func TestRejectInvalidHTTPMethod(t *testing.T) {
	t.Parallel()
	items := []SimplifiedPIP{{Name: "subject.foo", URL: "http://x", HTTPMethod: "DELETE"}}
	err := Validate(items)
	requireError(t, err, "httpMethod must be GET or POST")
}

// ADR-0052 (owner revision `2026-04-19`): the Parse layer silently accepts
// simplified-PIP payloads that carry `cacheable` / `cachePeriod` — the
// SimplifiedPIP struct does not declare these fields, so Go's default
// json.Unmarshal drops them on decode. Upload succeeds; the fields are
// absent from the parsed `SimplifiedPIP` list; the runtime normalized
// config therefore cannot depend on caching metadata. This behavior is
// required so the parity test fixtures can carry `cacheable: false` (to
// disable legacy's per-session PIP cache during golden recording)
// without maintaining two fixture variants.
func TestParseAcceptsAndDropsCacheableField(t *testing.T) {
	t.Parallel()
	items, err := Parse([]byte(`[{"name":"subject.foo","url":"http://x","pipType":"GENERAL","cacheable":false}]`))
	if err != nil {
		t.Fatalf("unexpected error for cacheable field: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 PIP, got %d", len(items))
	}
	if items[0].Name != "subject.foo" {
		t.Fatalf("expected name subject.foo, got %q", items[0].Name)
	}
	marshalled, err := json.Marshal(items[0])
	if err != nil {
		t.Fatalf("round-trip marshal: %v", err)
	}
	if strings.Contains(string(marshalled), "cacheable") {
		t.Fatalf("cacheable field must not survive round-trip: %s", marshalled)
	}
}

func TestParseAcceptsAndDropsCachePeriodField(t *testing.T) {
	t.Parallel()
	items, err := Parse([]byte(`[{"name":"subject.foo","url":"http://x","pipType":"GENERAL","cachePeriod":300}]`))
	if err != nil {
		t.Fatalf("unexpected error for cachePeriod field: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 PIP, got %d", len(items))
	}
	marshalled, err := json.Marshal(items[0])
	if err != nil {
		t.Fatalf("round-trip marshal: %v", err)
	}
	if strings.Contains(string(marshalled), "cachePeriod") {
		t.Fatalf("cachePeriod field must not survive round-trip: %s", marshalled)
	}
}

func TestAcceptValidTokenPIP(t *testing.T) {
	t.Parallel()
	items := []SimplifiedPIP{{Name: "subject.customerId", PipType: "TOKEN", Claim: "customer-id"}}
	if err := Validate(items); err != nil {
		t.Fatalf("valid TOKEN PIP should not error: %v", err)
	}
}

func TestAcceptValidHeaderPIP(t *testing.T) {
	t.Parallel()
	items := []SimplifiedPIP{{Name: "subject.tenantId", PipType: "HEADER", Header: "X-Tenant-Id"}}
	if err := Validate(items); err != nil {
		t.Fatalf("valid HEADER PIP should not error: %v", err)
	}
}

func TestAcceptValidGeneralPIP(t *testing.T) {
	t.Parallel()
	items := []SimplifiedPIP{{
		Name: "subject.allowed",
		URL:  "http://pip-service:8080/api/v1/pip/allowed",
		RequestAttributes: map[string]string{
			"resourceType": "Customer",
		},
	}}
	if err := Validate(items); err != nil {
		t.Fatalf("valid GENERAL PIP should not error: %v", err)
	}
}

func TestAcceptGeneralPIPWithJSONType(t *testing.T) {
	t.Parallel()
	items := []SimplifiedPIP{{
		Name:     "subject.parityMetaDepartment",
		PipType:  "GENERAL",
		Type:     "JSON",
		JsonPath: "$.department",
		URL:      "http://pip-mock:8090/api/v1/pip/meta",
	}}
	if err := Validate(items); err != nil {
		t.Fatalf("GENERAL PIP with type=JSON+jsonPath should be accepted: %v", err)
	}
}

func TestAcceptGeneralPIPWithTextType(t *testing.T) {
	t.Parallel()
	items := []SimplifiedPIP{{
		Name:    "subject.raw",
		PipType: "GENERAL",
		Type:    "TEXT",
		URL:     "http://pip-mock:8090/api/v1/pip/raw",
	}}
	if err := Validate(items); err != nil {
		t.Fatalf("GENERAL PIP with type=TEXT should be accepted: %v", err)
	}
}

func TestRejectGeneralPIPWithUnknownType(t *testing.T) {
	t.Parallel()
	items := []SimplifiedPIP{{
		Name:    "subject.binary",
		PipType: "GENERAL",
		Type:    "BINARY",
		URL:     "http://pip-mock:8090/api/v1/pip/binary",
	}}
	err := Validate(items)
	requireError(t, err, "type must be JSON or TEXT")
}

func TestRejectJsonPathWithTextType(t *testing.T) {
	t.Parallel()
	items := []SimplifiedPIP{{
		Name:     "subject.bad",
		PipType:  "GENERAL",
		Type:     "TEXT",
		JsonPath: "$.value",
		URL:      "http://pip-mock:8090/api/v1/pip/bad",
	}}
	err := Validate(items)
	requireError(t, err, "jsonPath requires type=JSON")
}

func TestRejectJsonPathWithAbsentType(t *testing.T) {
	t.Parallel()
	items := []SimplifiedPIP{{
		Name:     "subject.bad2",
		PipType:  "GENERAL",
		JsonPath: "$.value",
		URL:      "http://pip-mock:8090/api/v1/pip/bad2",
	}}
	err := Validate(items)
	requireError(t, err, "jsonPath requires type=JSON")
}

func TestResolvePipTypeFromClaimField(t *testing.T) {
	t.Parallel()
	pip := SimplifiedPIP{Name: "subject.x", Claim: "my-claim"}
	if got := resolvePipType(pip); got != PipTypeToken {
		t.Fatalf("expected TOKEN, got %s", got)
	}
}

func TestResolvePipTypeFromHeaderField(t *testing.T) {
	t.Parallel()
	pip := SimplifiedPIP{Name: "subject.x", Header: "X-Custom"}
	if got := resolvePipType(pip); got != PipTypeHeader {
		t.Fatalf("expected HEADER, got %s", got)
	}
}

func TestResolvePipTypeDefaultsToGeneral(t *testing.T) {
	t.Parallel()
	pip := SimplifiedPIP{Name: "subject.x", URL: "http://x"}
	if got := resolvePipType(pip); got != PipTypeGeneral {
		t.Fatalf("expected GENERAL, got %s", got)
	}
}

func TestResolvePipTypeFromLegacyTypeField(t *testing.T) {
	t.Parallel()
	pip := SimplifiedPIP{Name: "subject.x", Type: "TOKEN", Claim: "c"}
	if got := resolvePipType(pip); got != PipTypeToken {
		t.Fatalf("expected TOKEN, got %s", got)
	}
}

func requireError(t *testing.T, err error, needle string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", needle)
	}
	if !strings.Contains(err.Error(), needle) {
		t.Fatalf("expected error containing %q, got: %v", needle, err)
	}
}
