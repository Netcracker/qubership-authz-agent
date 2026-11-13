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

package regogen

import (
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/tester"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regobuiltins/regotest"
)

// pipCase is one Rego test of the function of the PIP subject.g: the
// response a mock of nc.http.send gives, the request the mock answers, if
// any, and the state the record of the PIP must have.
type pipCase struct {
	name string
	// want is the request the mock answers, as Rego, without its cache_key;
	// "" answers any request. Another request gets status 500, whose record
	// is ERROR.
	want     string
	response string
	state    string
	// allow, when set, is whether the rule subject.g == 'acc-7' allows:
	// "true" or "false".
	allow string
}

// runPIPCases generates the module of a rule over subject.g, declared by
// decl, projects req, and runs each case as a test of OPA's runner that
// replaces nc.http.send with its mock. It returns the outcome of each case
// by name: "pass", "fail", or the error.
func runPIPCases(t *testing.T, decl string, req Request, cases []pipCase) map[string]string {
	t.Helper()
	tree := tenantWithSetAndPIPs(t, "DENY_UNLESS_PERMIT", "ALLOW", "subject.g == 'acc-7'", decl)
	m, err := Generate(tree, table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var fn string
	for _, r := range m.Refs {
		if r.pip != nil {
			fn = "pip_" + r.Var
		}
	}
	if fn == "" {
		t.Fatalf("the module has no function of a PIP:\n%s", m.Text)
	}
	// the record comes from the mock; the projection still wants a value
	if req.Values == nil {
		req.Values = map[string]Resolved{}
	}
	req.Values[`["subj","g"]`] = resolved(t, "VALUE", `"acc-7"`)
	req.Body = Body{Operation: "read", ResourceType: "doc", Resource: req.Body.Resource, HasResource: req.Body.HasResource}
	in, err := Project(m, req)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "package pip_test\n\nimport data.%s\n\ndoc := %v\n\n", DefaultOptions().Package, in.Value())
	for i, c := range cases {
		cond := ""
		if c.want != "" {
			cond = ` if object.remove(q, {"cache_key"}) == ` + c.want
			fmt.Fprintf(&b, "mock_%d(q) := {\"status_code\": 500, \"raw_body\": \"\"} if object.remove(q, {\"cache_key\"}) != %s\n\n", i, c.want)
		}
		fmt.Fprintf(&b, "mock_%d(q) := %s%s\n\n", i, c.response, cond)
		fmt.Fprintf(&b, "got_%d := s if s := %s.%s.state with input as doc with nc.http.send as mock_%d\n\n",
			i, DefaultOptions().Package, fn, i)
		fmt.Fprintf(&b, "allow_%d if %s.allow with input as doc with nc.http.send as mock_%d\n\n",
			i, DefaultOptions().Package, i)
		switch c.allow {
		case "true":
			fmt.Fprintf(&b, "test_%d if {\n\tgot_%d == %q\n\tallow_%d\n}\n\n", i, i, c.state, i)
		case "false":
			fmt.Fprintf(&b, "test_%d if {\n\tgot_%d == %q\n\tnot allow_%d\n}\n\n", i, i, c.state, i)
		default:
			fmt.Fprintf(&b, "test_%d if got_%d == %q\n\n", i, i, c.state)
		}
	}
	mods := map[string]*ast.Module{}
	for name, text := range map[string]string{"gen.rego": m.Text, "pip_test.rego": b.String()} {
		mod, err := ast.ParseModule(name, text)
		if err != nil {
			t.Fatalf("ParseModule(%s): %v\n%s", name, err, text)
		}
		mods[name] = mod
	}
	extra := []*tester.Builtin{{Decl: PIPRecordDecl, Func: pipRecordFunction()},
		{Decl: JSONPathDecl, Func: jsonPathFunction()}}
	// a test that reaches the network fails: the token is refused
	h := &regobuiltins.HTTP{Token: func() (string, error) { return "", fmt.Errorf("the test sends no request") }}
	ctx := in.Context(regobuiltins.WithCalls(h.Context(context.Background())))
	ch, err := tester.NewRunner().AddCustomBuiltins(append(regotest.Builtins(), extra...)).SetModules(mods).
		RunTests(ctx, nil)
	if err != nil {
		t.Fatalf("RunTests: %v", err)
	}
	got := map[string]string{}
	for r := range ch {
		var i int
		if _, err := fmt.Sscanf(r.Name, "test_%d", &i); err != nil {
			t.Fatalf("test %s: %v", r.Name, err)
		}
		switch {
		case r.Error != nil:
			got[cases[i].name] = "error: " + r.Error.Error()
		case r.Fail:
			got[cases[i].name] = "fail"
			// the state the record has, and the request the mock got
			rs, err := rego.New(append(Builtins(), rego.Query(fmt.Sprintf("[data.pip_test.got_%d, object.get(data.pip_test, \"allow_%d\", false), data.pip_test.doc.pq]", i, i)),
				rego.ParsedModule(mods["gen.rego"]), rego.ParsedModule(mods["pip_test.rego"]))...).Eval(ctx)
			if err == nil && len(rs) == 1 {
				got[cases[i].name] += fmt.Sprintf(": [state, allow, requests] is %v", rs[0].Expressions[0].Value)
			}
		default:
			got[cases[i].name] = "pass"
		}
	}
	return got
}

// checkPIPCases runs the cases and fails the test for each that does not
// pass, with the module of the tests.
func checkPIPCases(t *testing.T, decl string, req Request, cases []pipCase) {
	t.Helper()
	got := runPIPCases(t, decl, req, cases)
	for _, c := range cases {
		if got[c.name] != "pass" {
			t.Errorf("%s: %s, want the record of subject.g in state %s and allow %q for the response %s", c.name,
				got[c.name], c.state, c.allow, c.response)
		}
	}
}

// subjectValues gives the subject's attribute id the value u1, which the
// requests below put into the url and the body.
func subjectValues(t *testing.T, id string) map[string]Resolved {
	return map[string]Resolved{`["subj","id"]`: resolved(t, "VALUE", id)}
}

// TestPIPFunction_ReadsTheResponse: the function of a GENERAL PIP reads the
// response of its call as the agent profile does: a failed call and a
// status other than 200 and 204 are ERROR, a body that is no list is PIP_NULL, a scalar
// or a list of one value other than a string is odd, and a list of strings
// is the value, its duplicates dropped.
func TestPIPFunction_ReadsTheResponse(t *testing.T) {
	ok := func(raw string) string {
		r := fmt.Sprintf(`{"status_code": 200, "raw_body": %q`, raw)
		if json, err := jsonvalue.Decode([]byte(raw)); err == nil {
			r += fmt.Sprintf(`, "body": %s`, jsonText(json))
		}
		return r + "}"
	}
	checkPIPCases(t, `{"name": "subject.g", "pipType": "GENERAL", "url": "http://g"}`,
		Request{Values: map[string]Resolved{}}, []pipCase{
			{name: "a list of one string", response: ok(`["acc-7"]`), state: "VALUE", allow: "true"},
			{name: "a list of one string twice", response: ok(`["acc-7", "acc-7"]`), state: "VALUE", allow: "true"},
			{name: "a list of two strings", response: ok(`["acc-7", "acc-8"]`), state: "VALUE", allow: "false"},
			{name: "an empty list", response: ok(`[]`), state: "PIP_EMPTY"},
			{name: "a null body", response: ok(`null`), state: "PIP_NULL"},
			{name: "an object", response: ok(`{"id": "acc-7"}`), state: "PIP_NULL"},
			{name: "a string", response: ok(`"acc-7"`), state: "PIP_NULL"},
			{name: "a body that is not JSON", response: ok(`acc-7`), state: "PIP_NULL"},
			{name: "a boolean", response: ok(`true`), state: "SCALAR_ODD"},
			{name: "a number", response: ok(`7`), state: "SCALAR_ODD"},
			{name: "a list of one null", response: ok(`[null]`), state: "SINGLE_ODD"},
			{name: "a list of one number", response: ok(`[7]`), state: "SINGLE_ODD"},
			{name: "a list of one object", response: ok(`[{"id": "acc-7"}]`), state: "SINGLE_ODD"},
			{name: "status 503", response: `{"status_code": 503, "raw_body": "[\"acc-7\"]", "body": ["acc-7"]}`,
				state: "ERROR"},
			{name: "status 404", response: `{"status_code": 404, "raw_body": ""}`, state: "ERROR"},
			{name: "status 204 without a body", response: `{"status_code": 204, "raw_body": ""}`, state: "PIP_NULL"},
			{name: "status 201", response: `{"status_code": 201, "raw_body": "[\"acc-7\"]", "body": ["acc-7"]}`,
				state: "ERROR"},
			{name: "status 302", response: `{"status_code": 302, "raw_body": "[\"acc-7\"]", "body": ["acc-7"]}`,
				state: "ERROR"},
			{name: "a timeout", response: `{"status_code": 0, "error": {"code": "timeout", "message": "m"}}`,
				state: "ERROR"},
			{name: "no token of the agent", response: `{"status_code": 0, "error": {"code": "no_token", "message": "m"}}`,
				state: "ERROR"},
		})
}

// TestPIPFunction_ReadsTheJSONPathOfTheResponse: a PIP of type JSON reads
// the value its jsonPath selects, and a null or nothing selected is PIP_NULL.
func TestPIPFunction_ReadsTheJSONPathOfTheResponse(t *testing.T) {
	resp := func(body string) string {
		return fmt.Sprintf(`{"status_code": 200, "raw_body": %q, "body": %s}`, body, body)
	}
	checkPIPCases(t, `{"name": "subject.g", "pipType": "GENERAL", "url": "http://g", "type": "JSON",
		"jsonPath": "$.a.b"}`, Request{Values: map[string]Resolved{}}, []pipCase{
		{name: "a string selected", response: resp(`{"a": {"b": "acc-7"}}`), state: "VALUE", allow: "true"},
		{name: "a null selected", response: resp(`{"a": {"b": null}}`), state: "PIP_NULL"},
		{name: "nothing selected", response: resp(`{"a": {}}`), state: "PIP_NULL"},
	})
}

// TestPIPFunction_ReadsALeadingBracketAsAMember: a jsonPath that opens with
// ['key'], with or without $, reads the member key of the response.
func TestPIPFunction_ReadsALeadingBracketAsAMember(t *testing.T) {
	resp := func(body string) string {
		return fmt.Sprintf(`{"status_code": 200, "raw_body": %q, "body": %s}`, body, body)
	}
	for _, jp := range []string{`$['a']`, `['a']`, `$['a'].b`} {
		t.Run(jp, func(t *testing.T) {
			body := `{"a": "acc-7"}`
			if strings.HasSuffix(jp, ".b") {
				body = `{"a": {"b": "acc-7"}}`
			}
			checkPIPCases(t, fmt.Sprintf(`{"name": "subject.g", "pipType": "GENERAL", "url": "http://g",
				"type": "JSON", "jsonPath": %q}`, jp), Request{Values: map[string]Resolved{}}, []pipCase{
				{name: "the member selected", response: resp(body), state: "VALUE", allow: "true"},
				{name: "no such member", response: resp(`{"b": "acc-7"}`), state: "PIP_NULL"},
			})
		})
	}
}

// The request a declaration sends. The mock answers ["acc-7"] only to the
// request each case names, so the record is VALUE only for that request.
const answer = `{"status_code": 200, "raw_body": "[\"acc-7\"]", "body": ["acc-7"]}`

// TestPIPFunction_SendsTheRequestOfTheDeclaration covers what a request of
// the declaration carries: the url with the subject's value in place of its
// placeholder, the method, the tenant and the declared headers the request
// has, and requestAttributes with each string that is one placeholder
// replaced by its value, objects included, and every other value as written.
func TestPIPFunction_SendsTheRequestOfTheDeclaration(t *testing.T) {
	req := Request{Values: subjectValues(t, `"u1"`), Tenant: "t1",
		Headers: map[string]string{"x-corr": "c1", "authorization": "Bearer caller", "tenant": "t2"},
		Body:    Body{Resource: mustDecode(t, `{"a": "r1"}`), HasResource: true}}
	tests := []struct {
		name, decl, want string
	}{
		{
			name: "a placeholder in the url and declared headers",
			decl: `{"name": "subject.g", "pipType": "GENERAL", "url": "http://g/u/${subject.id}",
				"headers": " X-Corr , Authorization,tenant,x-absent"}`,
			want: `{"method": "POST", "url": "http://g/u/u1", "headers": {"Tenant": "t1", "x-corr": "c1"},
				"raise_error": false, "pip": "subject.g", "body": {"requestAttributes": null}}`,
		},
		{
			name: "placeholders in requestAttributes",
			decl: `{"name": "subject.g", "pipType": "GENERAL", "url": "http://g", "requestAttributes":
				{"id": "${subject.id}", "n": {"r": "${resource.a}"}, "in_text": "x ${subject.id}",
				 "list": ["${subject.id}"], "rt": "${resourceType}", "other": "${request.id}"}}`,
			want: `{"method": "POST", "url": "http://g", "headers": {"Tenant": "t1"}, "raise_error": false,
				"pip": "subject.g", "body": {"requestAttributes": {"id": "u1", "n": {"r": "r1"},
				"in_text": "x ${subject.id}", "list": ["${subject.id}"], "rt": "${resourceType}",
				"other": "${request.id}"}}}`,
		},
		{
			name: "empty requestAttributes go as written",
			decl: `{"name": "subject.g", "pipType": "GENERAL", "url": "http://g", "requestAttributes": {}}`,
			want: `{"method": "POST", "url": "http://g", "headers": {"Tenant": "t1"}, "raise_error": false,
				"pip": "subject.g", "body": {"requestAttributes": {}}}`,
		},
		{
			// LI-22: the agent puts in what the subject is, where legacy fails the tenant
			name: "subject.isM2M in requestAttributes",
			decl: `{"name": "subject.g", "pipType": "GENERAL", "url": "http://g", "requestAttributes":
				{"m": "${subject.isM2M}"}}`,
			want: `{"method": "POST", "url": "http://g", "headers": {"Tenant": "t1"}, "raise_error": false,
				"pip": "subject.g", "body": {"requestAttributes": {"m": false}}}`,
		},
		{
			name: "GET carries no body",
			decl: `{"name": "subject.g", "pipType": "GENERAL", "url": "http://g", "httpMethod": "get",
				"requestAttributes": {"id": "${subject.id}"}}`,
			want: `{"method": "GET", "url": "http://g", "headers": {"Tenant": "t1"}, "raise_error": false,
				"pip": "subject.g"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkPIPCases(t, tt.decl, req, []pipCase{{name: tt.name, want: tt.want, response: answer, state: "VALUE"}})
		})
	}
	t.Run("subject.isM2M of an M2M subject", func(t *testing.T) {
		checkPIPCases(t, `{"name": "subject.g", "pipType": "GENERAL", "url": "http://g", "requestAttributes":
			{"m": "${subject.isM2M}"}}`, Request{Values: map[string]Resolved{}, M2M: true}, []pipCase{{
			name: "M2M", want: `{"method": "POST", "url": "http://g", "headers": {}, "raise_error": false,
				"pip": "subject.g", "body": {"requestAttributes": {"m": true}}}`, response: answer, state: "VALUE"}})
	})
	t.Run("subject.roles without roles in requestAttributes", func(t *testing.T) {
		req := Request{Values: map[string]Resolved{`["subj","roles"]`: resolved(t, "EMPTY_COLL", "")}}
		checkPIPCases(t, `{"name": "subject.g", "pipType": "GENERAL", "url": "http://g", "requestAttributes":
			{"r": "${subject.roles}"}}`, req, []pipCase{{name: "no roles",
			want: `{"method": "POST", "url": "http://g", "headers": {}, "raise_error": false, "pip": "subject.g",
				"body": {"requestAttributes": {"r": null}}}`, response: answer, state: "VALUE"}})
	})
	t.Run("a HEADER PIP in requestAttributes", func(t *testing.T) {
		const decl = `{"name": "subject.g", "pipType": "GENERAL", "url": "http://g", "requestAttributes":
			{"h": "${subject.hd}", "n": "${subject.hn}"}},
			{"name": "subject.hd", "pipType": "HEADER", "header": "X-H", "defaultValue": "hdef"},
			{"name": "subject.hn", "pipType": "HEADER", "header": "X-N"}`
		body := func(h, n string) string {
			return `{"method": "POST", "url": "http://g", "headers": {}, "raise_error": false, "pip": "subject.g",
				"body": {"requestAttributes": {"h": ` + h + `, "n": ` + n + `}}}`
		}
		checkPIPCases(t, decl, Request{Values: map[string]Resolved{},
			Headers: map[string]string{"x-h": "a, b", "x-n": "c"}}, []pipCase{{name: "the headers as they stand",
			want: body(`"a, b"`, `"c"`), response: answer, state: "VALUE"}})
		checkPIPCases(t, decl, Request{Values: map[string]Resolved{}, Headers: map[string]string{}}, []pipCase{{
			name: "the default, or null without one", want: body(`"hdef"`, `null`), response: answer, state: "VALUE"}})
	})
	t.Run("an empty collection and an absent value in requestAttributes", func(t *testing.T) {
		req := Request{Values: map[string]Resolved{`["subj","id"]`: resolved(t, "EMPTY_COLL", ""),
			`["subj","name"]`: resolved(t, "ABSENT", "")}}
		checkPIPCases(t, `{"name": "subject.g", "pipType": "GENERAL", "url": "http://g", "requestAttributes":
			{"id": "${subject.id}", "name": "${subject.name}"}}`, req, []pipCase{{name: "empty and absent",
			want: `{"method": "POST", "url": "http://g", "headers": {}, "raise_error": false, "pip": "subject.g",
				"body": {"requestAttributes": {"id": [], "name": null}}}`, response: answer, state: "VALUE"}})
	})
}

// TestPIPFunction_ReadsATokenPlaceholderFromTheClaims: a TOKEN PIP that only
// a placeholder reads takes its value from the subject's claims: the claim,
// the default value split at commas, and [] for a claim path that selects no
// element.
func TestPIPFunction_ReadsATokenPlaceholderFromTheClaims(t *testing.T) {
	claims, ok := mustDecode(t, `{"department": "finance", "groups": []}`).(*jsonvalue.Object)
	if !ok {
		t.Fatal("the claims are not an object")
	}
	const decl = `{"name": "subject.g", "pipType": "GENERAL", "url": "http://g", "requestAttributes":
			{"v": "${subject.dept}", "x": "${subject.listed}", "d": "${subject.none}", "e": "${subject.lacking}"}},
		{"name": "subject.dept", "pipType": "TOKEN", "claim": "department"},
		{"name": "subject.listed", "pipType": "TOKEN", "claim": "absent", "defaultValue": "d1,d2"},
		{"name": "subject.none", "pipType": "TOKEN", "claim": "$..x"},
		{"name": "subject.lacking", "pipType": "TOKEN", "claim": "absent"}`
	checkPIPCases(t, decl, Request{Values: map[string]Resolved{}, Claims: claims}, []pipCase{{
		name: "the claims", response: answer, state: "VALUE",
		want: `{"method": "POST", "url": "http://g", "headers": {}, "raise_error": false, "pip": "subject.g",
			"body": {"requestAttributes": {"v": "finance", "x": ["d1", "d2"], "d": [], "e": null}}}`}})
}

// TestPIPFunction_ReadsABracketPlaceholderFromTheMemberResource: a
// placeholder ${resource['x']} reads x of the member resource of the
// resource, as a condition's resource['x'] does.
func TestPIPFunction_ReadsABracketPlaceholderFromTheMemberResource(t *testing.T) {
	const decl = `{"name": "subject.g", "pipType": "GENERAL", "url": "http://g", "requestAttributes":
		{"v": "${resource['x']}"}}`
	for name, tc := range map[string]struct{ resource, want string }{
		"in the member resource": {`{"resource": {"x": "m"}, "x": "top"}`, `"m"`},
		"only at the top":        {`{"x": "top"}`, `null`},
	} {
		t.Run(name, func(t *testing.T) {
			req := Request{Values: map[string]Resolved{},
				Body: Body{Resource: mustDecode(t, tc.resource), HasResource: true}}
			checkPIPCases(t, decl, req, []pipCase{{name: name, response: answer, state: "VALUE",
				want: `{"method": "POST", "url": "http://g", "headers": {}, "raise_error": false, "pip": "subject.g",
					"body": {"requestAttributes": {"v": ` + tc.want + `}}}`}})
		})
	}
}

// TestPIPFunction_ForwardsTheIncomingTokenItNames: the Incoming-Token of
// the request goes to a PIP whose headers name it, and to no other.
func TestPIPFunction_ForwardsTheIncomingTokenItNames(t *testing.T) {
	req := Request{Values: map[string]Resolved{}, Headers: map[string]string{}, IncomingToken: "Bearer user"}
	t.Run("named", func(t *testing.T) {
		checkPIPCases(t, `{"name": "subject.g", "pipType": "GENERAL", "url": "http://g", "headers": "Incoming-Token"}`,
			req, []pipCase{{name: "named", response: answer, state: "VALUE",
				want: `{"method": "POST", "url": "http://g", "headers": {"incoming-token": "Bearer user"},
					"raise_error": false, "pip": "subject.g", "body": {"requestAttributes": null}}`}})
	})
	t.Run("not named", func(t *testing.T) {
		checkPIPCases(t, `{"name": "subject.g", "pipType": "GENERAL", "url": "http://g", "headers": "x-other"}`,
			req, []pipCase{{name: "not named", response: answer, state: "VALUE",
				want: `{"method": "POST", "url": "http://g", "headers": {}, "raise_error": false,
					"pip": "subject.g", "body": {"requestAttributes": null}}`}})
	})
}

// TestPIPCall_ReadsAGzipResponseToTheCallersAcceptEncoding: the caller's
// Accept-Encoding goes to the service, so Go's transport leaves a gzip
// response to the agent to decompress.
func TestPIPCall_ReadsAGzipResponseToTheCallersAcceptEncoding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept-Encoding"); got != "gzip" {
			http.Error(w, "Accept-Encoding is "+got+", want gzip", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		_, _ = zw.Write([]byte(`["acc-7"]`))
		_ = zw.Close()
	}))
	defer srv.Close()
	tree := tenantWithSetAndPIPs(t, "DENY_UNLESS_PERMIT", "ALLOW", "subject.g == 'acc-7'", fmt.Sprintf(
		`{"name": "subject.g", "pipType": "GENERAL", "url": %q, "httpMethod": "GET", "headers": "Accept-Encoding"}`,
		srv.URL))
	m, err := Generate(tree, table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var fn string
	for _, r := range m.Refs {
		if r.pip != nil {
			fn = "pip_" + r.Var
		}
	}
	in, err := Project(m, Request{Body: Body{Operation: "read", ResourceType: "doc"},
		Headers: map[string]string{"accept-encoding": "gzip"},
		// the record comes from the call; the projection still wants a value
		Values: map[string]Resolved{`["subj","g"]`: resolved(t, "VALUE", `"acc-7"`)}})
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	h := &regobuiltins.HTTP{Token: func() (string, error) { return "own", nil }}
	ctx := in.Context(regobuiltins.WithCalls(h.Context(context.Background())))
	query := fmt.Sprintf("[data.%[1]s.%[2]s.state, data.%[1]s.allow]", DefaultOptions().Package, fn)
	rs, err := rego.New(append(Builtins(), rego.Query(query), rego.Module("gen.rego", m.Text),
		rego.ParsedInput(in.Value()))...).Eval(ctx)
	if err != nil || len(rs) != 1 {
		t.Fatalf("Eval(%s) = %v, %v", query, rs, err)
	}
	if got, want := fmt.Sprint(rs[0].Expressions[0].Value), "[VALUE true]"; got != want {
		t.Errorf("[state of subject.g, allow] = %s, want %s for the gzip body [\"acc-7\"]", got, want)
	}
}

// TestPIPFunction_EncodesTheValuesOfTheURL: a value put into the url of a
// PIP is percent-encoded as a path segment before the query and as a query
// component after it, so the value of a subject's operand or of a caller's
// header cannot change the path or the query of a call that carries the
// agent's token.
func TestPIPFunction_EncodesTheValuesOfTheURL(t *testing.T) {
	const decl = `{"name": "subject.g", "pipType": "GENERAL", "url": "http://g/users/${subject.id}/roles?scope=${subject.id}"}`
	tests := []struct{ name, id, url string }{
		{"a plain value", `alice`, `http://g/users/alice/roles?scope=alice`},
		{"a fragment", `x#`, `http://g/users/x%23/roles?scope=x%23`},
		{"a path and a query", `bob/../../admin?x=`, `http://g/users/bob%2F..%2F..%2Fadmin%3Fx=/roles?scope=bob%2F..%2F..%2Fadmin%3Fx%3D`},
		{"a parameter of the query", `a&all=true`, `http://g/users/a&all=true/roles?scope=a%26all%3Dtrue`},
		{"a percent sign", `50%`, `http://g/users/50%25/roles?scope=50%25`},
		{"dots inside a segment", `a..`, `http://g/users/a../roles?scope=a..`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := Request{Values: map[string]Resolved{`["subj","id"]`: {State: "VALUE", Value: tt.id}}}
			checkPIPCases(t, decl, req, []pipCase{{name: tt.name, response: answer, state: "VALUE",
				want: `{"method": "POST", "url": "` + tt.url + `", "headers": {}, "raise_error": false,
					"pip": "subject.g", "body": {"requestAttributes": null}}`}})
		})
	}
	t.Run("a HEADER PIP", func(t *testing.T) {
		const decl = `{"name": "subject.g", "pipType": "GENERAL", "url": "http://g/h/${subject.who}"},
			{"name": "subject.who", "pipType": "HEADER", "header": "X-Who"}`
		req := Request{Values: map[string]Resolved{}, Headers: map[string]string{"x-who": "bob/../admin?all=true#"}}
		checkPIPCases(t, decl, req, []pipCase{{name: "a HEADER PIP", response: answer, state: "VALUE",
			want: `{"method": "POST", "url": "http://g/h/bob%2F..%2Fadmin%3Fall=true%23", "headers": {}, "raise_error": false,
				"pip": "subject.g", "body": {"requestAttributes": null}}`}})
	})
}

// TestPIPFunction_FilteredAndUntypedPIPsAreGeneral: a FILTERED PIP and a
// PIP without pipType send the request of a GENERAL one and read its
// response the same way.
func TestPIPFunction_FilteredAndUntypedPIPsAreGeneral(t *testing.T) {
	const want = `{"method": "POST", "url": "http://g/u/u1", "headers": {}, "raise_error": false,
		"pip": "subject.g", "body": {"requestAttributes": null}}`
	for name, decl := range map[string]string{
		"FILTERED":   `{"name": "subject.g", "pipType": "FILTERED", "url": "http://g/u/${subject.id}"}`,
		"no pipType": `{"name": "subject.g", "url": "http://g/u/${subject.id}"}`,
	} {
		t.Run(name, func(t *testing.T) {
			checkPIPCases(t, decl, Request{Values: subjectValues(t, `"u1"`)}, []pipCase{
				{name: name, want: want, response: answer, state: "VALUE", allow: "true"},
				{name: name + ", an object", want: want, state: "PIP_NULL",
					response: `{"status_code": 200, "raw_body": "{}", "body": {}}`},
			})
		})
	}
}

// TestPIPFunction_MakesNoCall: where the agent does not call the PIP, its
// record has the state of the case whatever the PIP would answer.
func TestPIPFunction_MakesNoCall(t *testing.T) {
	const general = `{"name": "subject.g", "pipType": "GENERAL", "url": "http://g/u/${subject.id}"}`
	tests := []struct {
		name, decl string
		req        Request
		state      string
	}{
		{"an anonymous request", general, Request{Values: subjectValues(t, `"u1"`), Anonymous: true}, "ABSENT"},
		{"a service account", general, Request{Values: subjectValues(t, `"u1"`),
			Claims: mustDecode(t, `{"preferred_username": "service-account-x"}`).(*jsonvalue.Object)}, "ERROR"},
		{"a token of level external", general, Request{Values: subjectValues(t, `"u1"`),
			Claims: mustDecode(t, `{"level": "External"}`).(*jsonvalue.Object)}, "ERROR"},
		{"a token of level m2m", general, Request{Values: subjectValues(t, `"u1"`),
			Claims: mustDecode(t, `{"level": "M2M"}`).(*jsonvalue.Object)}, "ERROR"},
		{"a value java.net.URI refuses in the url", general, Request{Values: subjectValues(t, `"u 1"`)}, "ERROR"},
		{"a placeholder of another source in the url",
			`{"name": "subject.g", "pipType": "GENERAL", "url": "http://g/${tenant}"}`,
			Request{Values: map[string]Resolved{}}, "ERROR"},
		{"a resource placeholder in the url",
			`{"name": "subject.g", "pipType": "GENERAL", "url": "http://g/${resource.a}"}`,
			Request{Values: map[string]Resolved{}}, "ERROR"},
		{"the resource as a placeholder in the url",
			`{"name": "subject.g", "pipType": "GENERAL", "url": "http://g/${resource}"}`,
			Request{Values: map[string]Resolved{}, Body: Body{Resource: "r1", HasResource: true}}, "ERROR"},
		{"a dot segment in the path", general, Request{Values: subjectValues(t, `".."`)}, "ERROR"},
		{"a placeholder in the host of the url",
			`{"name": "subject.g", "pipType": "GENERAL", "url": "http://${subject.id}/u"}`,
			Request{Values: subjectValues(t, `"g"`)}, "ERROR"},
		{"a placeholder that is the whole url",
			`{"name": "subject.g", "pipType": "GENERAL", "url": "${subject.id}"}`,
			Request{Values: subjectValues(t, `"http://g/u"`)}, "ERROR"},
		{"no url", `{"name": "subject.g", "pipType": "GENERAL"}`, Request{Values: map[string]Resolved{}}, "PIP_NULL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkPIPCases(t, tt.decl, tt.req, []pipCase{{name: tt.name, response: answer, state: tt.state}})
		})
	}
}

// TestPIPFunction_CaseThatCannotPass is the negative control of the cases
// above: a mock that answers another request, and a state the response does
// not give, each fail.
func TestPIPFunction_CaseThatCannotPass(t *testing.T) {
	got := runPIPCases(t, `{"name": "subject.g", "pipType": "GENERAL", "url": "http://g"}`,
		Request{Values: map[string]Resolved{}}, []pipCase{
			{name: "another request", want: `{"url": "http://other"}`, response: answer, state: "VALUE"},
			{name: "another state", response: answer, state: "PIP_NULL"},
		})
	for _, name := range []string{"another request", "another state"} {
		if !strings.HasPrefix(got[name], "fail") {
			t.Errorf("%s: %s, want fail", name, got[name])
		}
	}
}

func mustDecode(t *testing.T, text string) jsonvalue.Value {
	t.Helper()
	v, err := jsonvalue.Decode([]byte(text))
	if err != nil {
		t.Fatalf("jsonvalue.Decode(%s): %v", text, err)
	}
	return v
}

// BenchmarkPIPCall measures what one GENERAL PIP costs a decision whose
// call nc.http.send already answered within the decision request, against
// the same decision with nc.http.send replaced by its response, a stub
// without the cache: the difference is the price of the cache.
func BenchmarkPIPCall(b *testing.B) {
	tree := tenantWithSetAndPIPs(b, "DENY_UNLESS_PERMIT", "ALLOW", "subject.g == 'acc-7'",
		`{"name": "subject.g", "pipType": "GENERAL", "url": "http://g/u/${subject.id}",
		  "requestAttributes": {"id": "${subject.id}", "kind": "account"}}`)
	m, err := Generate(tree, table(b), DefaultOptions())
	if err != nil {
		b.Fatal(err)
	}
	g, err := jsonvalue.Decode([]byte(`"acc-7"`))
	if err != nil {
		b.Fatal(err)
	}
	in, err := Project(m, Request{Body: Body{Operation: "read", ResourceType: "doc"}, Tenant: "t1",
		Values: map[string]Resolved{`["subj","id"]`: {State: "VALUE", Value: "u1"}, `["subj","g"]`: {State: "VALUE", Value: g}}})
	if err != nil {
		b.Fatal(err)
	}
	tr, errs := ReplayTransport(in)
	if len(errs) > 0 {
		b.Fatal(errs)
	}
	h := &regobuiltins.HTTP{Client: &http.Client{Transport: tr}, Token: func() (string, error) { return "own", nil }}
	ctx := in.Context(regobuiltins.WithCalls(h.Context(context.Background())))
	for _, bc := range []struct{ name, query string }{
		{"cache hit", "data." + DefaultOptions().Package + ".allow"},
		{"stub", "data." + DefaultOptions().Package + `.allow with nc.http.send as {"status_code": 200,
			"raw_body": "[\"acc-7\"]", "body": ["acc-7"]}`},
	} {
		b.Run(bc.name, func(b *testing.B) {
			pq, err := rego.New(append(Builtins(), rego.Query(bc.query), rego.Module("gen.rego", m.Text))...).
				PrepareForEval(context.Background())
			if err != nil {
				b.Fatal(err)
			}
			v := in.Value()
			// the first evaluation makes the call, the rest find it in the cache
			rs, err := pq.Eval(ctx, rego.EvalParsedInput(v))
			if err != nil || len(rs) != 1 || rs[0].Expressions[0].Value != true {
				b.Fatalf("allow = %v, %v; want true", rs, err)
			}
			for b.Loop() {
				if _, err := pq.Eval(ctx, rego.EvalParsedInput(v)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
