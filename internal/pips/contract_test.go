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
	"reflect"
	"testing"
)

// Test-plan §A — parse / normalize / validate for the extended GENERAL PIP
// contract (authz-agent-ADR-0066/0067/0068).

func generalConfig(t *testing.T, input string, name string) GeneralPIPConfig {
	t.Helper()
	doc, _, err := Normalize([]byte(input))
	if err != nil {
		t.Fatalf("unexpected normalize error: %v", err)
	}
	gn, ok := doc.Normalized.Remote.General[name]
	if !ok {
		t.Fatalf("missing general PIP %q", name)
	}
	return gn
}

func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

// TestNormalize_LegacyFlat_Maps — a legacy flat GENERAL PIP lowers into the
// wrapper body + response.extract; ${...} placeholders are left untouched.
func TestNormalize_LegacyFlat_Maps(t *testing.T) {
	t.Parallel()
	input := `[{
		"name":"subject.parityMetaIds","pipType":"GENERAL",
		"url":"http://pip-mock:8090/api/v1/pip/meta","httpMethod":"POST",
		"type":"JSON","jsonPath":"$.ids",
		"requestAttributes":{"resourceType":"PARITY_SUITE_META"}
	}]`
	gn := generalConfig(t, input, "subject.parityMetaIds")

	if gn.HTTPMethod != "POST" {
		t.Fatalf("expected POST, got %s", gn.HTTPMethod)
	}
	// Body is the verified legacy wrapper with the literal ${subject.id} template.
	var body map[string]any
	if err := json.Unmarshal(gn.Body, &body); err != nil {
		t.Fatalf("body not valid JSON: %v (%s)", err, gn.Body)
	}
	if body["id"] != "${subject.id}" {
		t.Fatalf("expected id=${subject.id}, got %v", body["id"])
	}
	if v, ok := body["filters"]; !ok || v != nil {
		t.Fatalf("expected filters:null emitted, got %v (present=%v)", v, ok)
	}
	ra, ok := body["requestAttributes"].(map[string]any)
	if !ok || ra["resourceType"] != "PARITY_SUITE_META" {
		t.Fatalf("expected requestAttributes.resourceType=PARITY_SUITE_META, got %v", body["requestAttributes"])
	}
	// jsonPath → response.extract (string form); no substitution in Go.
	if gn.Response == nil || string(gn.Response.Extract) != `"$.ids"` {
		t.Fatalf("expected response.extract=\"$.ids\", got %+v", gn.Response)
	}
}

// TestNormalize_EmptyRequestAttributes_NullWrapper — a POST GENERAL PIP with no
// requestAttributes still gets the wrapper with requestAttributes:null (nulls
// emitted, byte-parity invariant NEW-4).
func TestNormalize_EmptyRequestAttributes_NullWrapper(t *testing.T) {
	t.Parallel()
	input := `[{"name":"subject.noAttrs","pipType":"GENERAL","url":"http://pip/x","httpMethod":"POST"}]`
	gn := generalConfig(t, input, "subject.noAttrs")
	if string(gn.Body) != `{"id":"${subject.id}","filters":null,"requestAttributes":null}` {
		t.Fatalf("expected wrapper with nulls emitted, got %s", gn.Body)
	}
}

// TestNormalize_GetHasNoBody — a GET GENERAL PIP carries no body (legacy parity).
func TestNormalize_GetHasNoBody(t *testing.T) {
	t.Parallel()
	input := `[{"name":"subject.g","pipType":"GENERAL","url":"http://pip/x","httpMethod":"GET"}]`
	gn := generalConfig(t, input, "subject.g")
	if len(gn.Body) != 0 {
		t.Fatalf("expected no body on GET, got %s", gn.Body)
	}
}

// TestNormalize_Extended_Passthrough — the new request/response fields copy into
// the internal shape verbatim; placeholders are untouched.
func TestNormalize_Extended_Passthrough(t *testing.T) {
	t.Parallel()
	input := `[{
		"name":"subject.allowedCustomerIds","pipType":"GENERAL",
		"url":"http://pip/api/v1/allowed/${subject.id}","httpMethod":"POST",
		"query":{"tenant":"${subject.tenantId}"},
		"headers":{"X-Trace-Id":"${subject.traceId}","Content-Type":"application/json"},
		"body":{"resourceType":"${resource.type}","subjectId":"${subject.id}"},
		"timeoutSeconds":5,
		"response":{"type":"JSON","extract":"$.data.ids[*].id","coerce":"string[]","onMissing":"defaultValue"},
		"defaultValue":[]
	}]`
	gn := generalConfig(t, input, "subject.allowedCustomerIds")

	if gn.URL != "http://pip/api/v1/allowed/${subject.id}" {
		t.Fatalf("url not preserved: %s", gn.URL)
	}
	if !reflect.DeepEqual(gn.Query, map[string]string{"tenant": "${subject.tenantId}"}) {
		t.Fatalf("query not preserved: %+v", gn.Query)
	}
	if !reflect.DeepEqual(gn.SetHeaders, map[string]string{"X-Trace-Id": "${subject.traceId}", "Content-Type": "application/json"}) {
		t.Fatalf("setHeaders not preserved: %+v", gn.SetHeaders)
	}
	if len(gn.ForwardHeaders) != 0 {
		t.Fatalf("expected no forward headers, got %+v", gn.ForwardHeaders)
	}
	var body map[string]any
	if err := json.Unmarshal(gn.Body, &body); err != nil || body["resourceType"] != "${resource.type}" {
		t.Fatalf("body placeholders should be untouched, got %s", gn.Body)
	}
	if gn.TimeoutSeconds != 5 {
		t.Fatalf("expected timeout 5, got %d", gn.TimeoutSeconds)
	}
	if gn.Response == nil || string(gn.Response.Extract) != `"$.data.ids[*].id"` ||
		gn.Response.Coerce != "string[]" || gn.Response.OnMissing != "defaultValue" {
		t.Fatalf("response not preserved: %+v", gn.Response)
	}
}

// TestNormalize_General_DefaultValue_Carried — a GENERAL PIP's soft-default
// `defaultValue` must survive normalization so pip.rego's soft_default can apply
// it on an http error / timeout / extract-miss (ADR-0068). Regression guard: the
// field was previously dropped from GeneralPIPConfig, so no GENERAL PIP could
// resolve to its default.
func TestNormalize_General_DefaultValue_Carried(t *testing.T) {
	t.Parallel()
	input := `[{
		"name":"subject.slowIds","pipType":"GENERAL",
		"url":"http://pip/slow","httpMethod":"POST","timeoutSeconds":1,
		"response":{"extract":"$.data.ids[*].id","coerce":"string[]","onMissing":"defaultValue"},
		"defaultValue":["TIMEOUT-DEFAULT"]
	}]`
	gn := generalConfig(t, input, "subject.slowIds")
	if !reflect.DeepEqual(gn.DefaultValue, []any{"TIMEOUT-DEFAULT"}) {
		t.Fatalf("defaultValue not carried into GeneralPIPConfig: %#v", gn.DefaultValue)
	}
}

// TestValidate_OnMissingDefaultValue_RequiresDefault — onMissing:defaultValue with
// no (or null) defaultValue silently fails closed at runtime (soft_default needs a
// non-null default); reject it at upload so the misconfig is explicit.
func TestValidate_OnMissingDefaultValue_RequiresDefault(t *testing.T) {
	t.Parallel()
	input := `[{
		"name":"subject.needsDefault","pipType":"GENERAL",
		"url":"http://pip/x","httpMethod":"POST",
		"response":{"extract":"$.v","onMissing":"defaultValue"}
	}]`
	doc, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(doc); err == nil {
		t.Fatal("expected validation error for onMissing:defaultValue without a defaultValue, got nil")
	}
}

// TestNormalize_LegacyAndExtended_Equal — the legacy-flat form and the explicit
// extended form of the same PIP normalize to the same internal config.
func TestNormalize_LegacyAndExtended_Equal(t *testing.T) {
	t.Parallel()
	legacy := `[{
		"name":"subject.parityMetaIds","pipType":"GENERAL",
		"url":"http://pip-mock:8090/api/v1/pip/meta","httpMethod":"POST",
		"type":"JSON","jsonPath":"$.ids",
		"requestAttributes":{"resourceType":"PARITY_SUITE_META"}
	}]`
	extended := `[{
		"name":"subject.parityMetaIds","pipType":"GENERAL",
		"url":"http://pip-mock:8090/api/v1/pip/meta","httpMethod":"POST",
		"body":{"id":"${subject.id}","filters":null,"requestAttributes":{"resourceType":"PARITY_SUITE_META"}},
		"response":{"type":"JSON","extract":"$.ids"}
	}]`
	a := generalConfig(t, legacy, "subject.parityMetaIds")
	b := generalConfig(t, extended, "subject.parityMetaIds")
	if !reflect.DeepEqual(asMap(t, a), asMap(t, b)) {
		t.Fatalf("legacy and extended did not normalize equal:\n legacy=%s\n extended=%s",
			mustJSON(t, a), mustJSON(t, b))
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

// TestNormalize_ResponseWinsOverLegacy — response block wins over legacy
// type/jsonPath when both present (no 400); response-absent falls back to legacy.
func TestNormalize_ResponseWinsOverLegacy(t *testing.T) {
	t.Parallel()
	both := `[{
		"name":"subject.x","pipType":"GENERAL","url":"http://pip/x","httpMethod":"POST",
		"type":"JSON","jsonPath":"$.legacyPath",
		"response":{"extract":"$.newPath"}
	}]`
	gn := generalConfig(t, both, "subject.x")
	if gn.Response == nil || string(gn.Response.Extract) != `"$.newPath"` {
		t.Fatalf("expected response to win with $.newPath, got %+v", gn.Response)
	}

	legacyOnly := `[{"name":"subject.y","pipType":"GENERAL","url":"http://pip/y","httpMethod":"POST","type":"JSON","jsonPath":"$.legacyPath"}]`
	gy := generalConfig(t, legacyOnly, "subject.y")
	if gy.Response == nil || string(gy.Response.Extract) != `"$.legacyPath"` {
		t.Fatalf("expected legacy fallback $.legacyPath, got %+v", gy.Response)
	}
}

func TestValidate_MalformedPlaceholder_Rejected(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"unterminated": `[{"name":"subject.a","pipType":"GENERAL","url":"http://x/${subject."}]`,
		"empty":        `[{"name":"subject.a","pipType":"GENERAL","url":"http://x/${}"}]`,
		"unknownScope": `[{"name":"subject.a","pipType":"GENERAL","url":"http://x/${bogus.x}"}]`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Normalize([]byte(in)); err == nil {
				t.Fatalf("%s: expected rejection", name)
			}
		})
	}
}

func TestValidate_UnknownScope_Rejected(t *testing.T) {
	t.Parallel()
	// v1 has no ${request.*} scope; only subject.* / resource.* are valid.
	in := `[{"name":"subject.a","pipType":"GENERAL","url":"http://x/${request.requestId}"}]`
	if _, _, err := Normalize([]byte(in)); err == nil {
		t.Fatal("expected ${request.*} scope to be rejected")
	}
}

func TestValidate_BadMethod_Rejected(t *testing.T) {
	t.Parallel()
	in := `[{"name":"subject.a","pipType":"GENERAL","url":"http://x","httpMethod":"FETCH"}]`
	err := Validate(mustParse(t, in))
	requireError(t, err, "httpMethod must be GET or POST")
}

func TestValidate_HeadersShape(t *testing.T) {
	t.Parallel()
	// legacy []string (forward inbound names)
	list := `[{"name":"subject.a","pipType":"GENERAL","url":"http://x","httpMethod":"POST","headers":["X-A","X-B"]}]`
	ga := generalConfig(t, list, "subject.a")
	if !reflect.DeepEqual(ga.ForwardHeaders, []string{"X-A", "X-B"}) {
		t.Fatalf("expected forward headers [X-A X-B], got %+v", ga.ForwardHeaders)
	}
	// extended {name:value} map
	m := `[{"name":"subject.b","pipType":"GENERAL","url":"http://x","httpMethod":"POST","headers":{"X-A":"1"}}]`
	gb := generalConfig(t, m, "subject.b")
	if !reflect.DeepEqual(gb.SetHeaders, map[string]string{"X-A": "1"}) {
		t.Fatalf("expected set headers {X-A:1}, got %+v", gb.SetHeaders)
	}
	// neither → rejected
	bad := `[{"name":"subject.c","pipType":"GENERAL","url":"http://x","httpMethod":"POST","headers":42}]`
	if _, _, err := Normalize([]byte(bad)); err == nil {
		t.Fatal("expected non-list/non-map headers to be rejected")
	}
}

func TestValidate_JsonPath_Subset(t *testing.T) {
	t.Parallel()
	good := []string{"$", "$.a", "$.data.ids[0].id", "$.data.ids[*].id", "$.nested.a[*].b[*].c", "$.empty[*]"}
	for _, jp := range good {
		in := `[{"name":"subject.g","pipType":"GENERAL","url":"http://x","httpMethod":"POST","response":{"extract":` + mustQuote(jp) + `}}]`
		if _, _, err := Normalize([]byte(in)); err != nil {
			t.Fatalf("expected %q accepted, got %v", jp, err)
		}
	}
	bad := []string{"$.data.ids[", "$..ids", "$.data.ids[?(@.id=='C1')]"}
	for _, jp := range bad {
		in := `[{"name":"subject.b","pipType":"GENERAL","url":"http://x","httpMethod":"POST","response":{"extract":` + mustQuote(jp) + `}}]`
		if _, _, err := Normalize([]byte(in)); err == nil {
			t.Fatalf("expected %q rejected", jp)
		}
	}
	// legacy jsonPath field is also subset-checked
	legacyBad := `[{"name":"subject.lb","pipType":"GENERAL","url":"http://x","httpMethod":"POST","type":"JSON","jsonPath":"$..ids"}]`
	if _, _, err := Normalize([]byte(legacyBad)); err == nil {
		t.Fatal("expected legacy jsonPath recursive-descent rejected")
	}
}

func TestValidate_TimeoutClamp(t *testing.T) {
	t.Parallel()
	above := `[{"name":"subject.a","pipType":"GENERAL","url":"http://x","httpMethod":"POST","timeoutSeconds":100}]`
	if gn := generalConfig(t, above, "subject.a"); gn.TimeoutSeconds != 30 {
		t.Fatalf("expected clamp to 30, got %d", gn.TimeoutSeconds)
	}
	below := `[{"name":"subject.b","pipType":"GENERAL","url":"http://x","httpMethod":"POST","timeoutSeconds":0}]`
	if gn := generalConfig(t, below, "subject.b"); gn.TimeoutSeconds != 1 {
		t.Fatalf("expected clamp to 1, got %d", gn.TimeoutSeconds)
	}
	omitted := `[{"name":"subject.c","pipType":"GENERAL","url":"http://x","httpMethod":"POST"}]`
	if gn := generalConfig(t, omitted, "subject.c"); gn.TimeoutSeconds != 5 {
		t.Fatalf("expected default 5, got %d", gn.TimeoutSeconds)
	}
}

func TestValidate_QueryConflict_Rejected(t *testing.T) {
	t.Parallel()
	in := `[{"name":"subject.a","pipType":"GENERAL","url":"http://x?a=1","httpMethod":"POST","query":{"b":"2"}}]`
	err := Validate(mustParse(t, in))
	requireError(t, err, "query")
}

func TestValidate_GetWithBody_Rejected(t *testing.T) {
	t.Parallel()
	in := `[{"name":"subject.a","pipType":"GENERAL","url":"http://x","httpMethod":"GET","body":{"k":"v"}}]`
	err := Validate(mustParse(t, in))
	requireError(t, err, "GET with a 'body'")
}

// Edge cases hardened after the Step 2.1 code review.

func TestValidate_HeadersNullAndEmpty_TreatedAsAbsent(t *testing.T) {
	t.Parallel()
	for _, hdr := range []string{`null`, `[]`, `{}`} {
		in := `[{"name":"subject.a","pipType":"GENERAL","url":"http://x","httpMethod":"POST","headers":` + hdr + `}]`
		gn := generalConfig(t, in, "subject.a")
		if len(gn.ForwardHeaders) != 0 || len(gn.SetHeaders) != 0 {
			t.Fatalf("headers %s should be absent, got forward=%+v set=%+v", hdr, gn.ForwardHeaders, gn.SetHeaders)
		}
	}
	// a scalar is rejected with a clear message
	bad := `[{"name":"subject.b","pipType":"GENERAL","url":"http://x","httpMethod":"POST","headers":"X-A"}]`
	if _, _, err := Normalize([]byte(bad)); err == nil {
		t.Fatal("expected scalar headers to be rejected")
	}
}

func TestValidate_ExtractNull_TreatedAsAbsent(t *testing.T) {
	t.Parallel()
	in := `[{"name":"subject.a","pipType":"GENERAL","url":"http://x","httpMethod":"POST","response":{"extract":null,"coerce":"string"}}]`
	gn := generalConfig(t, in, "subject.a")
	if gn.Response == nil || len(gn.Response.Extract) != 0 {
		t.Fatalf("expected null extract dropped, got %+v", gn.Response)
	}
	if gn.Response.Coerce != "string" {
		t.Fatalf("expected coerce preserved, got %+v", gn.Response)
	}
}

func TestValidate_ExtractEmptyMap_Rejected(t *testing.T) {
	t.Parallel()
	in := `[{"name":"subject.a","pipType":"GENERAL","url":"http://x","httpMethod":"POST","response":{"extract":{}}}]`
	if _, _, err := Normalize([]byte(in)); err == nil {
		t.Fatal("expected empty extract map to be rejected")
	}
}

func TestValidate_ExtractMapEntry_UnknownKey_Rejected(t *testing.T) {
	t.Parallel()
	in := `[{"name":"subject.a","pipType":"GENERAL","url":"http://x","httpMethod":"POST","response":{"extract":{"ids":{"path":"$.a","coerceType":"string"}}}}]`
	if _, _, err := Normalize([]byte(in)); err == nil {
		t.Fatal("expected unknown key in extract entry to be rejected")
	}
}

func TestValidate_ExtractMapEntry_Valid(t *testing.T) {
	t.Parallel()
	in := `[{"name":"subject.a","pipType":"GENERAL","url":"http://x","httpMethod":"POST","response":{"extract":{"ids":"$.data.ids[*].id","count":{"path":"$.data.total","coerce":"number","onMissing":"empty"}}}}]`
	gn := generalConfig(t, in, "subject.a")
	if gn.Response == nil {
		t.Fatal("expected response block")
	}
	var m map[string]any
	if err := json.Unmarshal(gn.Response.Extract, &m); err != nil {
		t.Fatalf("extract map should round-trip: %v", err)
	}
	if _, ok := m["ids"]; !ok {
		t.Fatalf("expected ids entry, got %v", m)
	}
}

func mustParse(t *testing.T, in string) []SimplifiedPIP {
	t.Helper()
	items, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return items
}

func mustQuote(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}
