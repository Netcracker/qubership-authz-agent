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

func TestNormalizeMixedPIPs(t *testing.T) {
	t.Parallel()
	input := `[
		{"name":"subject.customerId","pipType":"TOKEN","claim":"customer-id"},
		{"name":"subject.tenantId","pipType":"HEADER","header":"X-Tenant-Id"},
		{"name":"subject.allowed","url":"http://pip:8080/allowed","requestAttributes":{"resourceType":"Customer"}}
	]`

	doc, summary, err := Normalize([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.Total != 3 {
		t.Fatalf("expected 3 total, got %d", summary.Total)
	}
	if summary.Token != 1 {
		t.Fatalf("expected 1 token, got %d", summary.Token)
	}
	if summary.Header != 1 {
		t.Fatalf("expected 1 header, got %d", summary.Header)
	}
	if summary.General != 1 {
		t.Fatalf("expected 1 general, got %d", summary.General)
	}

	tk, ok := doc.Normalized.Local.Token["subject.customerId"]
	if !ok {
		t.Fatal("missing token PIP subject.customerId")
	}
	if tk.Claim != "customer-id" || tk.Alias != "customerId" {
		t.Fatalf("unexpected token config: %+v", tk)
	}

	hd, ok := doc.Normalized.Local.Header["subject.tenantId"]
	if !ok {
		t.Fatal("missing header PIP subject.tenantId")
	}
	if hd.Header != "X-Tenant-Id" || hd.Alias != "tenantId" {
		t.Fatalf("unexpected header config: %+v", hd)
	}

	gn, ok := doc.Normalized.Remote.General["subject.allowed"]
	if !ok {
		t.Fatal("missing general PIP subject.allowed")
	}
	if gn.URL != "http://pip:8080/allowed" || gn.HTTPMethod != "POST" || gn.Alias != "allowed" {
		t.Fatalf("unexpected general config: %+v", gn)
	}

	if len(doc.Normalized.ByName) != 3 {
		t.Fatalf("expected 3 entries in byName, got %d", len(doc.Normalized.ByName))
	}
	if !doc.Normalized.AliasSet["customerId"] || !doc.Normalized.AliasSet["tenantId"] || !doc.Normalized.AliasSet["allowed"] {
		t.Fatalf("expected aliasSet to contain all aliases, got %+v", doc.Normalized.AliasSet)
	}

	if len(doc.Raw.Items) != 3 {
		t.Fatalf("expected 3 raw items, got %d", len(doc.Raw.Items))
	}
}

func TestNormalizeRejectsUnsupported(t *testing.T) {
	t.Parallel()
	input := `[{"name":"subject.foo","pipType":"FILTERED","url":"http://x"}]`
	_, _, err := Normalize([]byte(input))
	if err == nil {
		t.Fatal("expected error for FILTERED pip")
	}
}

// TestNormalize_DefaultMethod_POST — an omitted httpMethod normalizes to POST
// (parity with access-control, ADR-0066), not GET (Test-plan §A).
func TestNormalize_DefaultMethod_POST(t *testing.T) {
	t.Parallel()
	input := `[{"name":"subject.foo","url":"http://pip:8080/foo"}]`
	doc, _, err := Normalize([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gn := doc.Normalized.Remote.General["subject.foo"]
	if gn.HTTPMethod != "POST" {
		t.Fatalf("expected default POST, got %s", gn.HTTPMethod)
	}
}

func TestNormalizeGeneralPOSTMethod(t *testing.T) {
	t.Parallel()
	input := `[{"name":"subject.foo","url":"http://pip:8080/foo","httpMethod":"post"}]`
	doc, _, err := Normalize([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gn := doc.Normalized.Remote.General["subject.foo"]
	if gn.HTTPMethod != "POST" {
		t.Fatalf("expected POST, got %s", gn.HTTPMethod)
	}
}

// Legacy `type:JSON` + `jsonPath` lower into the nested response block
// (ADR-0066/0068): jsonPath → response.extract (string form); legacy `type` is
// dropped (accepted at upload, ignored at runtime — body always JSON).
func TestNormalizeGeneralPropagatesJSONTypeAndJsonPath(t *testing.T) {
	t.Parallel()
	input := `[{"name":"subject.parityMetaDepartment","pipType":"GENERAL","type":"JSON","jsonPath":"$.department","url":"http://pip-mock:8090/api/v1/pip/meta"}]`
	doc, _, err := Normalize([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gn := doc.Normalized.Remote.General["subject.parityMetaDepartment"]
	if gn.Response == nil {
		t.Fatalf("expected response block for legacy jsonPath, got nil")
	}
	if string(gn.Response.Extract) != `"$.department"` {
		t.Fatalf("expected response.extract=\"$.department\", got %s", gn.Response.Extract)
	}
}

func TestNormalizeGeneralDropsLegacyTypeAliasWhenPipTypeAbsent(t *testing.T) {
	t.Parallel()
	// Legacy form: `type` is a pipType alias, not a payload type. With no
	// jsonPath there is no response post-processing, so Response stays nil.
	input := `[{"name":"subject.legacy","type":"GENERAL","url":"http://pip-mock:8090/legacy"}]`
	doc, _, err := Normalize([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gn := doc.Normalized.Remote.General["subject.legacy"]
	if gn.Response != nil {
		t.Fatalf("expected nil response when pipType absent + no jsonPath, got %+v", gn.Response)
	}
}

func TestMarshalDocumentRoundTrip(t *testing.T) {
	t.Parallel()
	input := `[{"name":"subject.customerId","pipType":"TOKEN","claim":"customer-id"}]`
	doc, _, err := Normalize([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	content, err := MarshalDocument(doc)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var roundTrip PIPDocument
	if err := json.Unmarshal(content, &roundTrip); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if roundTrip.Raw.Version != 1 {
		t.Fatalf("expected version 1, got %d", roundTrip.Raw.Version)
	}
}

func TestParseWrappedFormat(t *testing.T) {
	t.Parallel()
	input := `{"pips":[{"name":"subject.foo","url":"http://x"}]}`
	items, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
}

func TestParseBadJSON(t *testing.T) {
	t.Parallel()
	_, err := Parse([]byte(`{broken`))
	if err == nil {
		t.Fatal("expected error for bad json")
	}
}

// ADR-0052 (owner revision `2026-04-19`): cacheable / cachePeriod fields
// are silently accepted and dropped on normalize — the SimplifiedPIP
// struct does not declare them, so Go's default json.Unmarshal ignores
// them. The normalized runtime config therefore cannot depend on caching
// metadata, but upload clients can send them without error (required so
// parity fixtures can carry `cacheable: false` to disable legacy's
// per-session PIP cache during golden recording without splitting
// fixture copies between stacks).
func TestNormalizeAcceptsAndDropsCacheableField(t *testing.T) {
	t.Parallel()
	input := `[{"name":"subject.foo","url":"http://pip:8080/foo","pipType":"GENERAL","cacheable":false}]`
	doc, _, err := Normalize([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error for cacheable field: %v", err)
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal normalized doc: %v", err)
	}
	if strings.Contains(string(encoded), "cacheable") {
		t.Fatalf("cacheable field must not survive normalize: %s", encoded)
	}
}

func TestNormalizeAcceptsAndDropsCachePeriodField(t *testing.T) {
	t.Parallel()
	input := `[{"name":"subject.foo","url":"http://pip:8080/foo","pipType":"GENERAL","cachePeriod":300}]`
	doc, _, err := Normalize([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error for cachePeriod field: %v", err)
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal normalized doc: %v", err)
	}
	if strings.Contains(string(encoded), "cachePeriod") {
		t.Fatalf("cachePeriod field must not survive normalize: %s", encoded)
	}
}
