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
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"authz-agent/test/parity/suite/model"

	"github.com/google/go-cmp/cmp"
)

// The expected calls follow the binding table testdata/pap-operations.json and
// the rules stepSpec states; they are written out, not computed by the code
// under test.

func TestStepCall(t *testing.T) {
	cases := []struct {
		name       string
		step       stepSpec
		want       *papCall
		wantGolden ParityEndpointID
	}{
		{"a write fills the path parameter and sends the body with the placeholders replaced",
			stepSpec{Op: "write-domain-policies", Args: map[string]any{"domain": "PARITY_{{resourceType}}"},
				Body: json.RawMessage(`[{"resourceType": "{{resourceType}}"}]`)},
			&papCall{method: http.MethodPut, path: "/access/v1/simplifiedPolicies/domainPolicies/PARITY_RT", query: url.Values{},
				body: []any{map[string]any{"resourceType": "RT"}}},
			PSUITE_LOAD_SIMPLIFIED_POLICIES},
		{"a variant binding sends its own method, and its status goes under pap-status-v1",
			stepSpec{Op: "write-domain-pips", Binding: "patch", Args: map[string]any{"domain": "D"}, Body: json.RawMessage(`[]`)},
			&papCall{method: http.MethodPatch, path: "/access/v1/simplifiedPolicies/domainPIPs/D", query: url.Values{}, body: []any{}},
			PSUITE_PAP_STATUS},
		{"a query argument is sent as a parameter, a boolean as true or false",
			stepSpec{Op: "delete-set-customization", Args: map[string]any{"id": "s/1", "level": "PROJECT", "recursive": false}},
			&papCall{method: http.MethodDelete, path: "/access/v1/config/customization/policySet/s%2F1",
				query: url.Values{"level": {"PROJECT"}, "recursive": {"false"}}},
			PSUITE_DELETE_CUSTOMIZATION},
		{"a step without a body sends none",
			stepSpec{Op: "change-set-status", Args: map[string]any{"id": "s", "transition": "archive"}},
			&papCall{method: http.MethodPost, path: "/access/v1/policySets/s/archive", query: url.Values{}},
			PSUITE_PAP_STATUS},
		{"a JSON null body is sent as null, not as no body",
			stepSpec{Op: "import-sets", Body: json.RawMessage(`null`)},
			&papCall{method: http.MethodPost, path: "/access/v1/config/import", query: url.Values{}, body: json.RawMessage("null")},
			PSUITE_PAP_STATUS},
		{"a read step sends no call of its own",
			stepSpec{Op: "read-config-sets"}, nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, golden, err := stepCall(tc.step, "RT")
			if err != nil {
				t.Fatalf("stepCall(%s): %v", tc.step.Op, err)
			}
			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(papCall{})); diff != "" {
				t.Errorf("stepCall(%s) mismatch (-want +got):\n%s", tc.step.Op, diff)
			}
			if golden != tc.wantGolden {
				t.Errorf("stepCall(%s) golden = %s, want %s", tc.step.Op, Meta(golden).GoldenDir, Meta(tc.wantGolden).GoldenDir)
			}
		})
	}
}

// Every callable binding of the table records its status under a golden kind
// the catalog knows, so a step of any operation can run; the table comes from
// another repository and could name a kind this suite has no endpoint for.
func TestPAPOperations_EveryCallableWriteHasAGoldenEndpoint(t *testing.T) {
	for op, o := range papOperations() {
		for name, b := range o.Bindings {
			if o.Kind == "read" || strings.Contains(b.Path, "*") {
				continue
			}
			if _, ok := goldenEndpoint(b.Golden); !ok {
				t.Errorf("%s/%s files its status under %q, which no endpoint of the catalog has", op, name, b.Golden)
			}
		}
	}
}

func TestReadCall_SendsTheReadOperationsGETWithTheStepsArguments(t *testing.T) {
	got, err := readCall("read-domain-pips", map[string]any{"domain": "D", "other": "x"}, "RT")
	if err != nil {
		t.Fatal(err)
	}
	want := papCall{method: http.MethodGet, path: "/access/v1/simplifiedPolicies/domainPIPs/D", query: url.Values{}}
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(papCall{})); diff != "" {
		t.Errorf("readCall(read-domain-pips) mismatch (-want +got):\n%s", diff)
	}
}

// Each case breaks one rule of stepSpec, and caseStepProblems names it; the
// valid step beside them reports nothing, so a problem comes from the broken
// rule and not from the rest of the step.
func TestCaseStepProblems(t *testing.T) {
	write := func(edit func(*stepSpec)) stepSpec {
		st := stepSpec{Name: "s", Op: "write-domain-policies", Args: map[string]any{"domain": "D"},
			Body: json.RawMessage(`[]`), Observe: []string{"status", "decide:here"}, Requests: []requestSpec{{Name: "here"}}}
		edit(&st)
		return st
	}
	cases := []struct {
		name string
		step stepSpec
		want string // a part of the one problem reported; empty for none
	}{
		{"a valid write", write(func(*stepSpec) {}), ""},
		{"an unknown operation", write(func(st *stepSpec) { st.Op = "write-nothing" }), `operation "write-nothing"`},
		{"an unknown binding", write(func(st *stepSpec) { st.Binding = "post-twice" }), `binding "post-twice"`},
		{"a decision as a step", stepSpec{Name: "s", Op: "decide-resource"}, "a request of decide: observes"},
		{"an argument the binding does not take", write(func(st *stepSpec) { st.Args["level"] = "PROJECT" }), "argument level"},
		{"a value outside the argument's values",
			stepSpec{Name: "s", Op: "change-set-status", Args: map[string]any{"id": "x", "transition": "retire"}}, "none of activate"},
		{"a missing path argument", write(func(st *stepSpec) { delete(st.Args, "domain") }), "path parameter domain"},
		{"a write that does not observe status first", write(func(st *stepSpec) { st.Observe = []string{"decide:here", "status"} }), "observes decide:here first"},
		{"a decision with no such request", write(func(st *stepSpec) { st.Observe = []string{"status", "decide:there", "decide:here"} }), "decide:there"},
		{"a request no observation sends", write(func(st *stepSpec) { st.Observe = []string{"status"} }), "request here"},
		{"two reads, one golden", write(func(st *stepSpec) {
			st.Observe = []string{"status", "read:read-domain-pips", "read:read-config-pips", "decide:here"}
		}), "read twice"},
		{"an unknown observation", write(func(st *stepSpec) { st.Observe = []string{"status", "decide:here", "log"} }), `"log"`},
		{"status on a read", stepSpec{Name: "s", Op: "read-config-sets", Observe: []string{"status"}}, "status on the read"},
		{"a body on a read", stepSpec{Name: "s", Op: "read-config-sets", Body: json.RawMessage(`[]`)}, "body, onRefusal, or binding"},
		{"a binding on a read", stepSpec{Name: "s", Op: "read-config-sets", Binding: "get"}, "body, onRefusal, or binding"},
		{"error-class after another observation", write(func(st *stepSpec) {
			st.Observe = []string{"status", "decide:here", "error-class"}
		}), `observes "error-class" at 3`},
		{"error-class with an argument", write(func(st *stepSpec) {
			st.Observe = []string{"status", "error-class:x", "decide:here"}
		}), `observes "error-class:x" at 2`},
		{"error-class right after status", write(func(st *stepSpec) {
			st.Observe = []string{"status", "error-class", "decide:here"}
		}), ""},
		{"an unknown onRefusal", write(func(st *stepSpec) { st.OnRefusal = "retry" }), `onRefusal "retry"`},
		{"a read through a write", write(func(st *stepSpec) {
			st.Observe = []string{"status", "read:write-domain-pips", "decide:here"}
		}), "no read operation"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := caseStepProblems(caseSpec{ID: "c"}, tc.step)
			switch {
			case tc.want == "" && len(got) > 0:
				t.Errorf("caseStepProblems = %q, want none", got)
			case tc.want != "" && (len(got) != 1 || !strings.Contains(got[0], tc.want)):
				t.Errorf("caseStepProblems = %q, want one problem containing %q", got, tc.want)
			}
		})
	}
}

// A tenant is read only on a case with steps and no sets, and such a case
// reads nothing but its steps, pins, and tenant.
func TestCaseFileProblems_SequenceCasesAndTenants(t *testing.T) {
	step := []stepSpec{{Name: "read", Op: "read-config-sets"}}
	sets := []setSpec{{Key: "s"}}
	cases := []struct {
		name string
		file caseFile
		want string
	}{
		{"a sequence case in a tenant of its own",
			caseFile{Cases: []caseSpec{{ID: "c", Tenant: stringOf("t"), Steps: step}}}, ""},
		{"a file tenant over sequence cases",
			caseFile{Tenant: stringOf("t"), Cases: []caseSpec{{ID: "c", Steps: step}}}, ""},
		{"a tenant on a case with sets",
			caseFile{Cases: []caseSpec{{ID: "c", Tenant: stringOf("t"), Sets: sets}}}, "runs in a tenant"},
		{"a file tenant beside a case without steps",
			caseFile{Tenant: stringOf("t"), Cases: []caseSpec{{ID: "c", Condition: "true"}}}, "runs in a tenant"},
		{"a sequence case with a condition",
			caseFile{Cases: []caseSpec{{ID: "c", Condition: "true", Steps: step}}}, "does not read"},
		{"a sequence case with no step",
			caseFile{Cases: []caseSpec{{ID: "c", Steps: []stepSpec{}}}}, "empty list"},
		{"steps beside customize",
			caseFile{Cases: []caseSpec{{ID: "c", Sets: sets, Steps: step, Customize: []customizeStep{{Name: "x", OmitLevel: true}}}}},
			"both steps and customize"},
		{"two steps with one name",
			caseFile{Cases: []caseSpec{{ID: "c", Steps: append(step, step...)}}}, "names another step"},
		{"an empty tenant",
			caseFile{Cases: []caseSpec{{ID: "c", Tenant: stringOf(""), Steps: step}}}, "is no tenant"},
		{"a step named as the case's upload",
			caseFile{Cases: []caseSpec{{ID: "c", Sets: sets, Steps: []stepSpec{{Name: "upload-1", Op: "read-config-sets"}}}}},
			"records a golden under too"},
		{"a sequence step named as an upload of a case with sets",
			caseFile{Cases: []caseSpec{{ID: "c", Steps: []stepSpec{{Name: "declare-the-domain", Op: "read-config-sets"}}}}}, ""},
		{"a step named as a request of the case",
			caseFile{Cases: []caseSpec{{ID: "c", Sets: sets, Requests: []requestSpec{{Name: "read"}}, Steps: step}}},
			"records a golden under too"},
		{"a pip-call on a route nothing pins",
			caseFile{Cases: []caseSpec{{ID: "c", Steps: []stepSpec{{Name: "r", Op: "read-config-sets",
				Observe: []string{"read:read-config-sets", "pip-call:/api/v1/pip/x"}}}}}}, "nothing pins"},
		{"a pip-call beside the case's own pipCalls",
			caseFile{Pins: map[string]PipStubResponse{"/api/v1/pip/x": {}}, Cases: []caseSpec{{ID: "c", Sets: sets, PIPCalls: "/api/v1/pip/x",
				Steps: []stepSpec{{Name: "r", Op: "read-config-sets", Observe: []string{"read:read-config-sets", "pip-call:/api/v1/pip/x"}}}}}},
			"counts the calls of the whole case"},
		{"a pip-call beside a request that clears the log",
			caseFile{Pins: map[string]PipStubResponse{"/api/v1/pip/x": {}}, Cases: []caseSpec{{ID: "c", Steps: []stepSpec{{Name: "r",
				Op: "read-config-sets", Observe: []string{"read:read-config-sets", "pip-call:/api/v1/pip/x", "decide:d"},
				Requests: []requestSpec{{Name: "d", PIPCalls: "/api/v1/pip/x"}}}}}}},
			"clears the call log"},
		{"a request pinned by a request decided before it",
			caseFile{Cases: []caseSpec{{ID: "c", Steps: []stepSpec{{Name: "r", Op: "read-config-sets",
				Observe: []string{"read:read-config-sets", "decide:pins", "decide:reads"},
				Requests: []requestSpec{{Name: "reads", ClassifyBy: "/api/v1/pip/x"},
					{Name: "pins", Pins: map[string]PipStubResponse{"/api/v1/pip/x": {}}}}}}}}}, ""},
		{"a pip-call on a route a request decided before it pins",
			caseFile{Cases: []caseSpec{{ID: "c", Steps: []stepSpec{{Name: "r", Op: "read-config-sets",
				Observe:  []string{"read:read-config-sets", "decide:pins", "pip-call:/api/v1/pip/x"},
				Requests: []requestSpec{{Name: "pins", Pins: map[string]PipStubResponse{"/api/v1/pip/x": {}}}}}}}}}, ""},
		{"two requests of a step with one name",
			caseFile{Cases: []caseSpec{{ID: "c", Steps: []stepSpec{{Name: "r", Op: "read-config-sets",
				Observe:  []string{"read:read-config-sets", "decide:d"},
				Requests: []requestSpec{{Name: "d"}, {Name: "d", Subject: "m2m"}}}}}}}, "two requests named d"},
		{"a request decided before the request that pins its route",
			caseFile{Cases: []caseSpec{{ID: "c", Steps: []stepSpec{{Name: "r", Op: "read-config-sets",
				Observe: []string{"read:read-config-sets", "decide:reads", "decide:pins"},
				Requests: []requestSpec{{Name: "pins", Pins: map[string]PipStubResponse{"/api/v1/pip/x": {}}},
					{Name: "reads", ClassifyBy: "/api/v1/pip/x"}}}}}}}, "nothing pins"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := caseFileProblems(tc.file)
			switch {
			case tc.want == "" && len(got) > 0:
				t.Errorf("caseFileProblems = %q, want none", got)
			case tc.want != "" && (len(got) != 1 || !strings.Contains(got[0], tc.want)):
				t.Errorf("caseFileProblems = %q, want one problem containing %q", got, tc.want)
			}
		})
	}
}

func TestNarrowStepRead_DropsTheEnvelopeStampsAndListsEveryTenant(t *testing.T) {
	body := `{"hash": "h", "lastModificationTimestamp": 1, "policySets": [
		{"name": "c1 s", "tenantId": "t1", "createdWhen": 5},
		{"name": "other", "tenantId": "default"}]}`
	got := narrowStepRead(http.StatusOK, []byte(body), []string{"c1"})
	want := &model.PapReadOutcome{Status: http.StatusOK,
		Body:    map[string]any{"policySets": []any{map[string]any{"name": "c1 s", "tenantId": "t1"}}},
		Tenants: []string{"default", "t1"}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("narrowStepRead mismatch (-want +got):\n%s", diff)
	}
}

func TestErrorOutcome(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   *model.PapErrorOutcome
	}{
		{"an accepted call records no body", http.StatusOK, `{"x": 1}`, &model.PapErrorOutcome{Status: http.StatusOK}},
		{"a JSON error body without its timestamp", http.StatusBadRequest, `{"timestamp": "now", "message": "bad"}`,
			&model.PapErrorOutcome{Status: http.StatusBadRequest, Body: map[string]any{"message": "bad"}}},
		{"a text error body as text", http.StatusConflict, `exists`, &model.PapErrorOutcome{Status: http.StatusConflict, Body: "exists"}},
		{"a text error body without its reference chain", http.StatusBadRequest, `bad: a == (through reference chain: x.Y["condition"])`,
			&model.PapErrorOutcome{Status: http.StatusBadRequest, Body: "bad: a =="}},
		{"a JSON error body without the reference chain of its message", http.StatusBadRequest,
			`{"message": "bad (through reference chain: x.Y[\"condition\"])", "status": 400}`,
			&model.PapErrorOutcome{Status: http.StatusBadRequest, Body: map[string]any{"message": "bad", "status": float64(400)}}},
		{"a text error body without the server's class names", http.StatusBadRequest,
			"value of type `com.example.web.ParityWidgetDto` refused",
			&model.PapErrorOutcome{Status: http.StatusBadRequest, Body: "value of type `<class>` refused"}},
		{"a JSON array body without class names", http.StatusBadRequest, `["see ParityWidgetEntity", 5]`,
			&model.PapErrorOutcome{Status: http.StatusBadRequest, Body: []any{"see <class>", float64(5)}}},
		{"a JSON error body without class names at any depth", http.StatusConflict,
			`{"errors": [{"detail": "net.example.Store refused"}], "message": "see ParityWidgetEntity"}`,
			&model.PapErrorOutcome{Status: http.StatusConflict,
				Body: map[string]any{"errors": []any{map[string]any{"detail": "<class> refused"}}, "message": "see <class>"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, errorOutcome(tc.status, []byte(tc.body))); diff != "" {
				t.Errorf("errorOutcome(%d, %s) mismatch (-want +got):\n%s", tc.status, tc.body, diff)
			}
		})
	}
}

// A case file of round 44 or later records the body of a 400 or 409 answer;
// an earlier one, and a file outside a round directory, record the status
// alone, so that its goldens stay as they were.
func TestRecordsErrorBodies(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"round44/spell-data.json", true},
		{"round45/tenant-fresh.json", true},
		{"round100/x.json", true},
		{"round43/open-m2m-level.json", false},
		{"round9/x.json", false},
		{"early/x.json", false},
		{"round44.json", false},
	}
	for _, tc := range cases {
		if got := recordsErrorBodies(tc.name); got != tc.want {
			t.Errorf("recordsErrorBodies(%q) = %t, want %t", tc.name, got, tc.want)
		}
	}
}

// Only a 400 or 409 answer of a file that records bodies gets a message, shaped
// as errorOutcome shapes the body of an error-class observation.
func TestRefusalMessage(t *testing.T) {
	cases := []struct {
		name   string
		record bool
		status int
		body   string
		want   any
	}{
		{"a 400 text body", true, http.StatusBadRequest, `bad: a ==`, "bad: a =="},
		{"a 409 JSON body without its timestamp", true, http.StatusConflict, `{"timestamp": "now", "message": "exists"}`,
			map[string]any{"message": "exists"}},
		{"a 400 empty body", true, http.StatusBadRequest, ``, ""},
		{"a 404 body", true, http.StatusNotFound, `missing`, nil},
		{"a 500 body", true, http.StatusInternalServerError, `boom`, nil},
		{"an accepted call", true, http.StatusOK, `true`, nil},
		{"a 400 body of a file that records none", false, http.StatusBadRequest, `bad`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, refusalMessage(tc.record, tc.status, []byte(tc.body))); diff != "" {
				t.Errorf("refusalMessage(%t, %d, %s) mismatch (-want +got):\n%s", tc.record, tc.status, tc.body, diff)
			}
		})
	}
}

// A recorded error body keeps the PAP's reason for a refusal and loses the
// names of the server's classes, packages, stack frames, and exceptions, which
// must not reach the published goldens. A qualified JDK name stays; a bare
// exception name is replaced, JDK or not. The inputs follow the shape of
// Spring and Jackson errors; the names in them are made up.
func TestWithoutServerNames(t *testing.T) {
	cases := []struct {
		name, message, want string
	}{
		{"a Spring validation message",
			"Validation failed for argument [0] in public org.example.http.Response<java.lang.Void> " +
				"com.example.pap.web.ParityWidgetController.upload(java.util.List<com.example.pap.dto.ParityWidgetDto>): " +
				"[Field error in object 'parityWidgetDto' on field 'name': rejected value [null]; " +
				"codes [NotNull.parityWidgetDto.name,NotNull.name]; default message [must not be null]]",
			"Validation failed for argument [0] in public <class><java.lang.Void> " +
				"<class>(java.util.List<<class>>): " +
				"[Field error in object 'parityWidgetDto' on field 'name': rejected value [null]; " +
				"codes [NotNull.parityWidgetDto.name,NotNull.name]; default message [must not be null]]"},
		{"a Jackson MismatchedInputException",
			"Cannot deserialize value of type `java.util.ArrayList<com.example.pap.dto.ParityWidgetDto>` " +
				"from Object value (token `JsonToken.START_OBJECT`)",
			"Cannot deserialize value of type `java.util.ArrayList<<class>>` " +
				"from Object value (token `JsonToken.START_OBJECT`)"},
		{"a Jackson InvalidFormatException with its path",
			"JSON parse error: Cannot deserialize value of type `com.example.pap.model.EffectKind` from String \"PERMITX\": " +
				"not one of the values accepted for Enum class: [ALLOW, DENY] (through reference chain: " +
				"java.util.ArrayList[0]->com.example.pap.dto.ParityRuleDto[\"effect\"])",
			"JSON parse error: Cannot deserialize value of type `<class>` from String \"PERMITX\": " +
				"not one of the values accepted for Enum class: [ALLOW, DENY]"},
		{"a bare class name in backticks and quotes",
			"Cannot construct instance of `ParityWidgetEntity` (no Creators, like default constructor, exist); " +
				"'ParityWidgetMapper' failed",
			"Cannot construct instance of `<class>` (no Creators, like default constructor, exist); '<class>' failed"},
		{"a wrapped cause with stack frames",
			"Request processing failed: com.example.pap.ParityWidgetException: Expression [resource.a ==]: " +
				"Invalid expression; nested exception is java.lang.IllegalStateException: parser stopped\n" +
				"\tat com.example.pap.Parser.parse(Parser.java:42)\n\tat com.example.pap.Parser$Visitor.visit(Unknown Source)",
			"Request processing failed: <class>: Expression [resource.a ==]: " +
				"Invalid expression; nested exception is java.lang.IllegalStateException: parser stopped\n" +
				"\tat <class>\n\tat <class>"},
		{"a source position and a nested class alone", "thrown at Parser.java:42 by Parser$Visitor",
			"thrown at <class> by <class>"},
		{"a bare exception name", "ParityWidgetException after NullPointerException",
			"<class> after <class>"},
		{"a package without a class", "no bean in com.example.pap", "no bean in <class>"},
		{"a package under io", "scanned io.example.pap.web", "scanned <class>"},
		{"a class under another root", "dto.ParityThing and acme.pap.ParityWidget failed", "<class> and <class> failed"},
		{"a java segment inside a server name", "com.example.java.ParityWidgetDto and org.acme.javax.dto.ParityThing refused",
			"<class> and <class> refused"},
		{"a JDK name under javax", "javax.validation.ConstraintViolationException: name", "javax.validation.ConstraintViolationException: name"},
		{"a cause line and frames of every form",
			"Caused by: com.example.pap.ParityWidgetException: bad\n\tat com.example.Bar.<init>(Bar.java:10)\n" +
				"\tat com.example.Baz.run(Baz.kt:7)\n\tat com.example.Qux.call(Native Method)\n\tat com.example.Gen.go(<generated>)",
			"Caused by: <class>: bad\n\tat <class>\n\tat <class>\n\tat <class>\n\tat <class>"},
		{"a proxy class and a Kotlin position", "ParityWidget$$EnhancerByProxy$$1a2b failed at Bar.kt:12",
			"<class> failed at <class>"},
		{"an attribute without the resource prefix", "owner.Id == subject.id", "<class> == subject.id"},
		{"plain words", "Bad Request: Error in the policy, the Service is busy",
			"Bad Request: Error in the policy, the Service is busy"},
		{"a JSON path", "no value at $.items[0].a, $['k'].OwnerService, $.store.Book, or $.items[*].owner.Id",
			"no value at $.items[0].a, $['k'].OwnerService, $.store.Book, or $.items[*].owner.Id"},
		{"attribute names and operator words",
			"resource.a == 'y' OR subject.parityAllowed IS NULL AND resource.o.Id NOT IN ('v') OR resource.o.OwnerService IS NULL",
			"resource.a == 'y' OR subject.parityAllowed IS NULL AND resource.o.Id NOT IN ('v') OR resource.o.OwnerService IS NULL"},
		{"a placeholder, a version, and a header name", "${subject.id} on 6.1.6 in X-Parity-Request",
			"${subject.id} on 6.1.6 in X-Parity-Request"},
		{"PARITY names", "the domain PARITY_ISOLATED_B has no PIP for PARITY_PAYMENT",
			"the domain PARITY_ISOLATED_B has no PIP for PARITY_PAYMENT"},
		{"a URL of the stub", "call to http://pip-mock:8090/api/v1/pip/s44-sent failed",
			"call to http://pip-mock:8090/api/v1/pip/s44-sent failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := withoutServerNames(tc.message); got != tc.want {
				t.Errorf("withoutServerNames(%q)\n got %q\nwant %q", tc.message, got, tc.want)
			}
		})
	}
}
