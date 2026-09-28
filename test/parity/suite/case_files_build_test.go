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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"authz-agent/test/parity/suite/model"

	"github.com/google/go-cmp/cmp"
)

// The expected ids in these tests are the derivation derivedID documents,
// computed outside Go, and the expected wire forms follow the rules the README
// states under "Cases kept as data"; neither is output of the code under test.

func stringOf(v string) *string { return &v }

func boolOf(v bool) *bool { return &v }

func TestDerivedID_IsTheFirst16BytesOfTheSHA256OfThePath(t *testing.T) {
	if got, want := derivedID("c1", "set/outer"), "d82b5a69-4822-465d-d804-1c9317bcfe92"; got != want {
		t.Errorf(`derivedID("c1", "set/outer") = %s, want %s`, got, want)
	}
}

func TestCustomEntry_RenamesTheUploadMembersAndSendsTheRestAsWritten(t *testing.T) {
	entry := map[string]any{
		"key":       "outer",
		"algorithm": "DENY_OVERRIDES",
		"iterate":   map[string]any{"foreach": "subject.permissionScope", "algorithm": "PERMIT_OVERRIDES"},
		"target":    "resourceType == '{{resourceType}}'",
		"policies": []any{map[string]any{"key": "p", "rules": []any{map[string]any{
			"key": "r", "predicates": map[string]any{"rsqlPredicate": "a==b"}, "status": "INACTIVE",
		}}}},
		"sets": "x",
	}
	want := map[string]any{
		"policySetId":        "d82b5a69-4822-465d-d804-1c9317bcfe92",
		"combiningAlgorithm": "DENY_OVERRIDES",
		"iterate":            map[string]any{"foreach": "subject.permissionScope", "combiningAlgorithm": "PERMIT_OVERRIDES"},
		"target":             "resourceType == 'RT'",
		"policies": []any{map[string]any{"policyId": "e7852720-9add-579c-e70a-d2e16a6b9cbe", "rules": []any{map[string]any{
			"ruleId": "bdda613b-c5b4-68b9-be02-a936accd128e", "rsqlPredicate": "a==b", "status": "INACTIVE",
		}}}},
		"policySets": "x",
	}
	if diff := cmp.Diff(want, customEntry("c1", "c0", "set", entry, "RT")); diff != "" {
		t.Errorf(`customEntry("c1", ruleIDsOf "c0") mismatch (-want +got):\n%s`, diff)
	}
}

func TestCustomEntry_DerivesRuleIDsFromTheCaseWithoutRuleIDsOf(t *testing.T) {
	got := customEntry("c1", "", "rule", map[string]any{"key": "r"}, "RT")
	want := map[string]any{"ruleId": "15d6b792-eff3-7653-87a2-fa96a7209fb5"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf(`customEntry("c1", rule r) mismatch (-want +got):\n%s`, diff)
	}
}

func TestCustomEntry_SendsAnEntryThatIsNotAnObjectAsWritten(t *testing.T) {
	if got := customEntry("c1", "", "set", json.Number("5"), "RT"); got != json.Number("5") {
		t.Errorf(`customEntry("c1", 5) = %v, want 5`, got)
	}
}

// The cleanup deletes each level and set once, at a step's own level when it
// is PROJECT or CUSTOMER and at both otherwise, and skips an entry that is not
// an object, since it names no set.
func TestCustomizationCleanup_DeletesEachSetAndPIPOnceAtTheLevelsOfItsSteps(t *testing.T) {
	steps := []customizeStep{
		{Name: "own-level", Level: stringOf("PROJECT"), Sets: []any{map[string]any{"key": "outer"}, json.Number("5")}},
		{Name: "other-level", Level: stringOf("PARITY_OTHER"), Sets: []any{map[string]any{"key": "outer"}},
			PIPs: []any{map[string]any{"name": "subject.{{resourceType}}"}}},
		{Name: "no-level", Level: stringOf("PROJECT"), OmitLevel: true, Sets: []any{map[string]any{"key": "outer"}}},
	}
	set := "/access/v1/config/customization/policySet/d82b5a69-4822-465d-d804-1c9317bcfe92"
	pip := "/access/v1/pip/customization/pip/subject.RT"
	want := []papCall{
		{method: http.MethodDelete, path: set, query: url.Values{"level": {"PROJECT"}, "recursive": {"true"}}},
		{method: http.MethodDelete, path: set, query: url.Values{"level": {"CUSTOMER"}, "recursive": {"true"}}},
		{method: http.MethodDelete, path: pip, query: url.Values{"level": {"PROJECT"}}},
		{method: http.MethodDelete, path: pip, query: url.Values{"level": {"CUSTOMER"}}},
	}
	if diff := cmp.Diff(want, customizationCleanup("c1", steps, "RT"), cmp.AllowUnexported(papCall{})); diff != "" {
		t.Errorf("customizationCleanup mismatch (-want +got):\n%s", diff)
	}
}

func TestCustomizeStepCall(t *testing.T) {
	set := "/access/v1/config/customization/policySet/d82b5a69-4822-465d-d804-1c9317bcfe92"
	cases := []struct {
		name       string
		step       customizeStep
		want       papCall
		wantGolden ParityEndpointID
	}{
		{"an import sends the entries Sets builds",
			customizeStep{Level: stringOf("CUSTOMER"), Sets: []any{map[string]any{"key": "outer"}}},
			papCall{method: http.MethodPost, path: "/access/v1/config/customization/import", query: url.Values{"level": {"CUSTOMER"}},
				body: []any{map[string]any{"policySetId": "d82b5a69-4822-465d-d804-1c9317bcfe92"}}},
			PSUITE_IMPORT_CUSTOMIZATION},
		{"body replaces the entries Sets builds",
			customizeStep{Level: stringOf("CUSTOMER"), Sets: []any{map[string]any{"key": "outer"}}, Body: json.RawMessage(`{}`)},
			papCall{method: http.MethodPost, path: "/access/v1/config/customization/import", query: url.Values{"level": {"CUSTOMER"}},
				body: json.RawMessage(`{}`)},
			PSUITE_IMPORT_CUSTOMIZATION},
		{"omitLevel sends no level",
			customizeStep{Level: stringOf("CUSTOMER"), OmitLevel: true},
			papCall{method: http.MethodPost, path: "/access/v1/config/customization/import", query: url.Values{}, body: []any{}},
			PSUITE_IMPORT_CUSTOMIZATION},
		{"a PIP import sends the entries with the placeholders replaced",
			customizeStep{Level: stringOf("PROJECT"), PIPs: []any{map[string]any{"name": "subject.{{resourceType}}"}}},
			papCall{method: http.MethodPost, path: "/access/v1/pip/customization/import", query: url.Values{"level": {"PROJECT"}},
				body: []any{map[string]any{"name": "subject.RT"}}},
			PSUITE_IMPORT_PIP_CUSTOMIZATION},
		{"a delete without recursive sends no recursive",
			customizeStep{Level: stringOf("CUSTOMER"), Delete: &customizeDelete{Key: "outer"}},
			papCall{method: http.MethodDelete, path: set, query: url.Values{"level": {"CUSTOMER"}}},
			PSUITE_DELETE_CUSTOMIZATION},
		{"a delete with recursive false sends it",
			customizeStep{Level: stringOf("CUSTOMER"), Delete: &customizeDelete{Key: "outer", Recursive: boolOf(false)}},
			papCall{method: http.MethodDelete, path: set, query: url.Values{"level": {"CUSTOMER"}, "recursive": {"false"}}},
			PSUITE_DELETE_CUSTOMIZATION},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, golden := customizeStepCall("c1", "", tc.step, "RT")
			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(papCall{})); diff != "" {
				t.Errorf("customizeStepCall mismatch (-want +got):\n%s", diff)
			}
			if golden != tc.wantGolden {
				t.Errorf("customizeStepCall golden = %s, want %s", Meta(golden).GoldenDir, Meta(tc.wantGolden).GoldenDir)
			}
		})
	}
}

// An item keeps a type it names, null included, and takes the case's
// resource type only where it names none.
func TestBulkItems_DefaultsOnlyAnAbsentType(t *testing.T) {
	items := []any{
		map[string]any{"id": "a", "resource": map[string]any{"id": "{{resourceType}}"}},
		map[string]any{"id": "b", "type": "OTHER"},
		map[string]any{"id": "c", "type": nil},
	}
	want := []any{
		map[string]any{"id": "a", "type": "RT", "resource": map[string]any{"id": "RT"}},
		map[string]any{"id": "b", "type": "OTHER"},
		map[string]any{"id": "c", "type": nil},
	}
	if diff := cmp.Diff(want, bulkItems(items, "RT")); diff != "" {
		t.Errorf("bulkItems mismatch (-want +got):\n%s", diff)
	}
}

func TestMergeFields_ReplacesAddsAndNullsMembers(t *testing.T) {
	object := map[string]any{"status": "ACTIVE", "target": "true"}
	mergeFields(object, map[string]any{"status": nil, "target": "resourceType == '{{resourceTypeLowerCase}}'", "extra": true}, "RT")
	want := map[string]any{"status": nil, "target": "resourceType == 'rt'", "extra": true}
	if diff := cmp.Diff(want, object); diff != "" {
		t.Errorf("mergeFields mismatch (-want +got):\n%s", diff)
	}
}

// Only the first call on the route counts, and a header value is replaced by
// a label wherever it would put a token or the tenant into a golden.
func TestForwardedHeaders(t *testing.T) {
	sent := map[string]string{"authorization": "Bearer m2m-token", "incoming-token": "Bearer user-token"}
	calls := []PipStubCall{
		{Path: "/other", Headers: map[string]string{"x-a": "from another route"}},
		{Path: "/pip", Headers: map[string]string{
			"x-a":            "va",
			"authorization":  "Bearer m2m-token",
			"incoming-token": "bearer user-token",
			"x-copy":         "m2m-token",
			"x-auth-other":   "Bearer elsewhere",
			"tenant":         "default",
		}},
		{Path: "/pip", Headers: map[string]string{"x-b": "from the second call"}},
	}
	got := forwardedHeaders(calls, "/pip", []string{"X-A", "x-b", "authorization", "incoming-token", "x-copy", "tenant"}, sent, "default")
	want := map[string]any{
		"x-a":            "va",
		"x-b":            nil,
		"authorization":  "<m2m token>",
		"incoming-token": "<user token>",
		"x-copy":         "<m2m token>",
		"tenant":         "<tenant_id>",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("forwardedHeaders mismatch (-want +got):\n%s", diff)
	}
}

func TestForwardedHeaders_LabelsAnotherTokenAndAnotherTenant(t *testing.T) {
	calls := []PipStubCall{{Path: "/pip", Headers: map[string]string{"authorization": "Bearer elsewhere", "tenant": "tenant-b"}}}
	got := forwardedHeaders(calls, "/pip", []string{"authorization", "tenant"}, map[string]string{"authorization": "Bearer m2m-token"}, "default")
	want := map[string]any{"authorization": "<other token>", "tenant": "<other>"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("forwardedHeaders mismatch (-want +got):\n%s", diff)
	}
}

// wellFormedCaseFile returns a file caseFileProblems accepts: a case without
// sets and a case with sets and one customize step, each with one request.
func wellFormedCaseFile() caseFile {
	return caseFile{
		Pins: map[string]PipStubResponse{"/pip": {StatusCode: http.StatusOK}},
		Cases: []caseSpec{
			{ID: "iso", Requests: []requestSpec{{Name: "read"}}},
			{ID: "reg", Sets: []setSpec{{Key: "outer"}}, Requests: []requestSpec{{Name: "read"}},
				Customize: []customizeStep{{Name: "step", Level: stringOf("CUSTOMER"),
					Sets: []any{map[string]any{"key": "outer"}}, Requests: []requestSpec{{Name: "after"}}}}},
		},
	}
}

// An entry that is not an object names no PIP, so the cleanup deletes only the
// PIPs the other entries name.
func TestCustomizationCleanup_SkipsAPIPEntryThatIsNotAnObject(t *testing.T) {
	steps := []customizeStep{{Name: "import", Level: stringOf("CUSTOMER"),
		PIPs: []any{"not an object", map[string]any{"name": "subject.a"}}}}
	want := []papCall{{method: http.MethodDelete, path: "/access/v1/pip/customization/pip/subject.a",
		query: url.Values{"level": {"CUSTOMER"}}}}
	if diff := cmp.Diff(want, customizationCleanup("c1", steps, "RT"), cmp.AllowUnexported(papCall{})); diff != "" {
		t.Errorf("customizationCleanup mismatch (-want +got):\n%s", diff)
	}
}

func TestCaseFileProblems(t *testing.T) {
	cases := []struct {
		name   string
		change func(f *caseFile)
		want   string
	}{
		{"a well-formed file", func(*caseFile) {}, ""},
		{"policy on a case with sets", func(f *caseFile) { f.Cases[1].Policy = map[string]any{} },
			"case reg sets roles, domain, policyOmit, policy, or policiesQuery"},
		{"customize on a case without sets", func(f *caseFile) { f.Cases[0].Customize = []customizeStep{} },
			"case iso sets customize"},
		{"status beside omitStatus", func(f *caseFile) { f.Cases[1].Sets[0].Status = "INACTIVE"; f.Cases[1].Sets[0].OmitStatus = true },
			"case reg set outer sets both status and omitStatus"},
		{"a step request named as a case request", func(f *caseFile) { f.Cases[1].Customize[0].Requests[0].Name = "read" },
			"case reg has two requests named read"},
		{"two steps with one name", func(f *caseFile) {
			f.Cases[1].Customize = append(f.Cases[1].Customize, customizeStep{Name: "step", OmitLevel: true})
		},
			`case reg has a customize step named "step"`},
		{"a step with no level", func(f *caseFile) { f.Cases[1].Customize[0].Level = nil },
			"case reg step step names no level"},
		{"a step with sets and pips", func(f *caseFile) { f.Cases[1].Customize[0].PIPs = []any{map[string]any{"name": "subject.a"}} },
			"case reg step step sets more than one of delete, pips, and sets or body"},
		{"a PIP customization with no name", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = nil
			f.Cases[1].Customize[0].PIPs = []any{map[string]any{"status": "INACTIVE"}}
		}, "imports a PIP customization map[status:INACTIVE] with no name"},
		{"a PIP customization entry that is not an object", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = nil
			f.Cases[1].Customize[0].PIPs = []any{"not an object", map[string]any{"name": "subject.a"}}
		}, ""},
		{"omitFields in a customization entry", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = []any{map[string]any{"key": "outer", "omitFields": []any{"target"}}}
		}, "case reg step step has a set entry with omitFields, which only an upload reads"},
		{"a nested entry with no key", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = []any{map[string]any{"key": "outer", "policies": []any{map[string]any{}}}}
		}, "case reg step step has a policy entry with no key"},
		{"an iterate with no algorithm", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = []any{map[string]any{"key": "outer", "iterate": map[string]any{"foreach": "x"}}}
		}, "has a set entry whose iterate is not an object with foreach and algorithm"},
		{"pipHeaders without pipCalls", func(f *caseFile) { f.Cases[0].Requests[0].PIPHeaders = []string{"tenant"} },
			"case iso request read sets pipHeaders without pipCalls"},
		{"emptyOperation beside operation", func(f *caseFile) {
			f.Cases[0].Requests[0].EmptyOperation = true
			f.Cases[0].Requests[0].Operation = "READ"
		}, "case iso request read sets both operation and emptyOperation"},
		{"a negative pause", func(f *caseFile) { f.Cases[0].Requests[0].PauseMs = -1 }, "case iso request read pauses for -1 ms"},
		{"bulk beside bulkOperations", func(f *caseFile) {
			f.Cases[0].Requests[0].Bulk = []any{}
			f.Cases[0].Requests[0].BulkOperations = []any{}
		}, "case iso request read sets both bulk and bulkOperations"},
		{"bulk beside a resource", func(f *caseFile) {
			f.Cases[0].Requests[0].Bulk = []any{map[string]any{"id": "a"}}
			f.Cases[0].Requests[0].Resource = map[string]any{}
		}, "sets filter, resource, operation, type, emptyOperation, or classifyBy beside a bulk request"},
		{"a bulk item that is not an object", func(f *caseFile) { f.Cases[0].Requests[0].Bulk = []any{"a"} },
			"case iso request read has the bulk item a, which is not an object"},
		{"policyOmit on a case with sets", func(f *caseFile) { f.Cases[1].PolicyOmit = []string{"roles"} },
			"case reg sets roles, domain, policyOmit, policy, or policiesQuery"},
		{"policiesQuery on a case with sets", func(f *caseFile) { f.Cases[1].PoliciesQuery = "a=b" },
			"case reg sets roles, domain, policyOmit, policy, or policiesQuery"},
		{"a delete without a key", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = nil
			f.Cases[1].Customize[0].Delete = &customizeDelete{}
		}, "case reg step step deletes the customization of a set with no key"},
		{"a step with no name", func(f *caseFile) { f.Cases[1].Customize[0].Name = "" },
			`case reg has a customize step named ""`},
		{"a bulkOperations item that is not an object", func(f *caseFile) { f.Cases[0].Requests[0].BulkOperations = []any{"a"} },
			"case iso request read has the bulk item a, which is not an object"},
		{"emptyOperation beside bulk", func(f *caseFile) {
			f.Cases[0].Requests[0].Bulk = []any{}
			f.Cases[0].Requests[0].EmptyOperation = true
		}, "beside a bulk request"},
		{"predicates that are not an object", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = []any{map[string]any{"key": "outer", "predicates": "a==b"}}
		}, "has a set entry whose predicates is not an object"},
		{"algorithm beside combiningAlgorithm", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = []any{map[string]any{"key": "outer", "algorithm": "A", "combiningAlgorithm": "B"}}
		}, "has a set entry whose members algorithm and combiningAlgorithm write the same member combiningAlgorithm"},
		{"a predicate beside a member of the same name", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = []any{map[string]any{"key": "outer",
				"policies": []any{map[string]any{"key": "p", "rules": []any{map[string]any{
					"key": "r", "status": "ACTIVE", "predicates": map[string]any{"status": "INACTIVE"}}}}}}}
		}, "has a rule entry whose members predicates.status and status write the same member status"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := wellFormedCaseFile()
			tc.change(&f)
			problems := caseFileProblems(f)
			if tc.want == "" {
				if len(problems) != 0 {
					t.Errorf("caseFileProblems = %q, want none", problems)
				}
				return
			}
			if len(problems) != 1 || !strings.Contains(problems[0], tc.want) {
				t.Errorf("caseFileProblems = %q, want one problem containing %q", problems, tc.want)
			}
		})
	}
}

// A header the case sets replaces the token header of the same name, so a
// forwarded value is labeled by the header the request carried, not by the
// token the suite minted.
func TestForwardedHeaders_LabelsByTheHeadersTheRequestSent(t *testing.T) {
	sent := sentHeaders(TokenBundle{M2M: "m2m-token", EndUser: "user-token"},
		PerCallOptions{CustomHeaders: map[string]string{"incoming-token": "Bearer case-token", "Authorization": "dropped"}})
	wantSent := map[string]string{"authorization": "Bearer m2m-token", "incoming-token": "Bearer case-token"}
	if diff := cmp.Diff(wantSent, sent); diff != "" {
		t.Errorf("sentHeaders mismatch (-want +got):\n%s", diff)
	}
	calls := []PipStubCall{{Path: "/pip", Headers: map[string]string{"x-fwd": "case-token", "x-minted": "user-token"}}}
	got := forwardedHeaders(calls, "/pip", []string{"x-fwd", "x-minted"}, sent, "default")
	want := map[string]any{"x-fwd": "<user token>", "x-minted": "user-token"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("forwardedHeaders mismatch (-want +got):\n%s", diff)
	}
}

// A rule's fields are merged after its predicates, so a field replaces a
// predicate of the same name.
func TestBuildSet_RuleFieldsReplaceAPredicate(t *testing.T) {
	set := setSpec{Key: "outer", Policies: []policySpec{{Key: "p", Rules: []ruleSpec{{
		Key: "r", Effect: "ALLOW",
		Predicates: map[string]any{"rsqlPredicate": "a==b"},
		Fields:     map[string]any{"rsqlPredicate": "c=={{resourceType}}", "status": nil},
	}}}}}
	rule := map[string]any{
		"ruleId": "15d6b792-eff3-7653-87a2-fa96a7209fb5", "name": "c1 r", "target": "", "condition": "", "effect": "ALLOW",
		"rsqlPredicate": "c==RT", "status": nil,
	}
	want := map[string]any{
		"policySetId": "d82b5a69-4822-465d-d804-1c9317bcfe92", "name": "c1 outer", "status": "ACTIVE", "target": "",
		"policies": []any{map[string]any{
			"policyId": "e7852720-9add-579c-e70a-d2e16a6b9cbe", "name": "c1 p", "target": "", "rules": []any{rule},
		}},
		"policySets": []any{},
	}
	b := regularBuilder{caseID: "c1"}
	if diff := cmp.Diff(want, buildSet(b, b, set, "RT")); diff != "" {
		t.Errorf("buildSet mismatch (-want +got):\n%s", diff)
	}
}

// omitFields removes members after fields is merged, from a rule, a policy,
// and a set alike, so a member fields sets and omitFields names is not sent.
func TestBuildSet_OmitFieldsRemovesMembersAfterFields(t *testing.T) {
	set := setSpec{Key: "outer", OmitFields: []string{"target"}, Policies: []policySpec{{
		Key: "p", OmitFields: []string{"policyId"}, Rules: []ruleSpec{{
			Key: "r", Effect: "ALLOW", Fields: map[string]any{"effect": "DENY"}, OmitFields: []string{"effect", "ruleId"},
		}},
	}}}
	want := map[string]any{
		"policySetId": "d82b5a69-4822-465d-d804-1c9317bcfe92", "name": "c1 outer", "status": "ACTIVE",
		"policies": []any{map[string]any{
			"name": "c1 p", "target": "",
			"rules": []any{map[string]any{"name": "c1 r", "target": "", "condition": ""}},
		}},
		"policySets": []any{},
	}
	b := regularBuilder{caseID: "c1"}
	if diff := cmp.Diff(want, buildSet(b, b, set, "RT")); diff != "" {
		t.Errorf("buildSet mismatch (-want +got):\n%s", diff)
	}
}

// omitStatus removes the status the set would carry, and a status in fields,
// merged after it, puts one back.
func TestBuildSet_OmitStatus(t *testing.T) {
	cases := []struct {
		name       string
		fields     map[string]any
		wantStatus any
		wantSet    bool
	}{
		{"without fields the set has no status", nil, nil, false},
		{"a status in fields is sent", map[string]any{"status": "INACTIVE"}, "INACTIVE", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := regularBuilder{caseID: "c1"}
			got := buildSet(b, b, setSpec{Key: "outer", Status: "", OmitStatus: true, Fields: tc.fields}, "RT")
			status, set := got["status"]
			if set != tc.wantSet || status != tc.wantStatus {
				t.Errorf("buildSet(omitStatus, fields %v) status = %v (present %t), want %v (present %t)",
					tc.fields, status, set, tc.wantStatus, tc.wantSet)
			}
		})
	}
}

// recordedRequest is what testServer received in one request.
type recordedRequest struct {
	method, path, query, body string
}

// testServer answers every request with 200 and an empty JSON object, and
// records each request it received.
func testServer(t *testing.T) (*httptest.Server, *[]recordedRequest) {
	t.Helper()
	var mu sync.Mutex
	var got []recordedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, recordedRequest{r.Method, r.URL.Path, r.URL.RawQuery, string(body)})
		mu.Unlock()
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestUploadIsolatedPoliciesWithQuery_ExtendsOnlyTheUploadOfThePolicies(t *testing.T) {
	srv, got := testServer(t)
	cfg := Config{ACBaseURL: srv.URL, TenantID: "t", Profile: "legacy"}
	tokens := &TokenFactory{cache: map[string]tokenEntry{"m2m": {accessToken: "m2m-token", expiresAt: time.Now().Add(time.Hour)}}}
	if _, err := UploadIsolatedPoliciesWithQuery(context.Background(), cfg, tokens, "D", nil, []any{}, "applicableForFrontend=true"); err != nil {
		t.Fatal(err)
	}
	var queries []string
	for _, r := range *got {
		queries = append(queries, r.method+" "+r.path+"?"+r.query)
	}
	want := []string{
		"PUT /access/v1/simplifiedPolicies/domainPolicies/D?tenant_id=t",
		"PUT /access/v1/simplifiedPolicies/domainPIPs/D?tenant_id=t",
		"PUT /access/v1/simplifiedPolicies/domainPolicies/D?tenant_id=t&applicableForFrontend=true",
	}
	if diff := cmp.Diff(want, queries); diff != "" {
		t.Errorf("UploadIsolatedPoliciesWithQuery requests mismatch (-want +got):\n%s", diff)
	}
}

func TestEmptyOperation_WireForms(t *testing.T) {
	srv, got := testServer(t)
	cfg := Config{ACBaseURL: srv.URL, TenantID: "t"}
	ctx := context.Background()
	if _, _, _, err := HelperFilterV1Query(ctx, cfg, filterV1Query("RT", "LIST", true), TokenBundle{}, PerCallOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := HelperFilterV1Query(ctx, cfg, filterV1Query("RT", "LIST", false), TokenBundle{}, PerCallOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := HelperCheckResourceV1(ctx, cfg, model.CheckAccessRequest{Operation: checkOperation("UPDATE", true), Type: "RT"}, TokenBundle{}, PerCallOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := HelperCheckResourceV1(ctx, cfg, model.CheckAccessRequest{Operation: checkOperation("", false), Type: "RT"}, TokenBundle{}, PerCallOptions{}); err != nil {
		t.Fatal(err)
	}
	want := []recordedRequest{
		{"POST", "/access/v1/check/filter", "operation=&resourceType=RT&tenant_id=t", ""},
		{"POST", "/access/v1/check/filter", "operation=LIST&resourceType=RT&tenant_id=t", ""},
		{"POST", "/access/v1/check/resource", "tenant_id=t", `{"operation":"","type":"RT"}`},
		{"POST", "/access/v1/check/resource", "tenant_id=t", `{"operation":"READ","type":"RT"}`},
	}
	if diff := cmp.Diff(want, *got, cmp.AllowUnexported(recordedRequest{})); diff != "" {
		t.Errorf("requests mismatch (-want +got):\n%s", diff)
	}
}
