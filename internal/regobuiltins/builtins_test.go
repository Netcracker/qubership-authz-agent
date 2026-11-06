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

package regobuiltins

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"

	"authz-agent/internal/jsonpath"
	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/legacyvalue"
)

// Term refuses a Go value that a jsonvalue.Value does not hold, at the top and
// inside a list or an object, rather than panicking.
func TestDocuments_TermRefusesAValueOutsideJSONValue(t *testing.T) {
	tests := []struct {
		name string
		v    jsonvalue.Value
	}{
		{"a map[string]any", map[string]any{"a": 1.5}},
		{"a float64 inside a list", []jsonvalue.Value{"a", 1.5}},
		{"an int inside an object", objectOf("a", 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := NewDocuments().Term(tt.v); err == nil {
				t.Errorf("Term(%#v) = %v, want an error", tt.v, got)
			}
		})
	}
}

func objectOf(k string, v jsonvalue.Value) *jsonvalue.Object {
	o := jsonvalue.NewObject()
	o.Set(k, v)
	return o
}

// textFunction registers text(v), which returns the Java text of the JSON that
// [JSONOf] reads from v, so that a test sees the member order JSONOf keeps.
func textFunction() func(*rego.Rego) {
	return rego.Function1(&rego.Function{Name: "text", Decl: types.NewFunction(types.Args(types.A), types.S)},
		func(bctx rego.BuiltinContext, v *ast.Term) (*ast.Term, error) {
			j, err := JSONOf(bctx, v)
			if err != nil {
				return nil, err
			}
			return ast.StringTerm(legacyvalue.Text(j)), nil
		})
}

// evalInput evaluates query over input with text registered and returns the
// value of x. With docs set, input is built by [Documents.Term] and the
// query's context carries docs.
func evalInput(t *testing.T, query, input string, docs bool) *ast.Term {
	t.Helper()
	raw, err := jsonvalue.Decode([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var in ast.Value
	if docs {
		d := NewDocuments()
		term, err := d.Term(raw)
		if err != nil {
			t.Fatalf("Term(%s): %v", input, err)
		}
		in = term.Value
		ctx = d.Context(ctx)
	} else {
		in = ast.MustParseTerm(input).Value
	}
	rs, err := rego.New(rego.Query("x := "+query), rego.StrictBuiltinErrors(true), rego.ParsedInput(in),
		textFunction()).Eval(ctx)
	if err != nil {
		t.Fatalf("%s over %s: %v", query, input, err)
	}
	if len(rs) != 1 {
		t.Fatalf("%s over %s: %d results, want 1", query, input, len(rs))
	}
	v, err := ast.InterfaceToValue(rs[0].Bindings["x"])
	if err != nil {
		t.Fatal(err)
	}
	return ast.NewTerm(v)
}

// An object built by Documents keeps the member order of its JSON at every
// depth, also inside a value Rego builds around it; the same object parsed by
// OPA comes in sorted key order.
func TestJSONOf_KeepsTheMemberOrderOfDocuments(t *testing.T) {
	const input = `{"o": {"b": "X", "a": "Y"}}`
	tests := []struct {
		name, query string
		docs        bool
		want        string
	}{
		{"an object Documents built", `text(input.o)`, true, `"{b=X, a=Y}"`},
		{"the same object parsed by OPA", `text(input.o)`, false, `"{a=Y, b=X}"`},
		{"an object inside a list Rego builds", `text([input.o])`, true, `"[{b=X, a=Y}]"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := evalInput(t, tt.query, input, tt.docs); !got.Equal(ast.MustParseTerm(tt.want)) {
				t.Errorf("%s over %s = %v, want %s", tt.query, input, got, tt.want)
			}
		})
	}
}

// Two objects of one query keep their own JSON in the query's built-in cache.
func TestJSONOf_CacheKeepsTwoObjectsApart(t *testing.T) {
	const input = `{"p": {"a": "X"}, "q": {"a": "Y"}}`
	q := `[text(input.p), text(input.q), text(input.p)]`
	want := ast.MustParseTerm(`["{a=X}", "{a=Y}", "{a=X}"]`)
	if got := evalInput(t, q, input, false); !got.Equal(want) {
		t.Errorf("%s over %s = %v, want %v", q, input, got, want)
	}
}

func TestCompilePath_RefusesAPathOutsideTheSubset(t *testing.T) {
	if got, err := CompilePath(".a.*"); err == nil {
		t.Errorf("CompilePath(%q) = %v, want an error", ".a.*", got)
	}
}

// A second call with the same path returns the path the first call compiled,
// and two paths each select their own value.
func TestCompilePath_KeepsEachCompiledPath(t *testing.T) {
	const input = `{"a": "X", "b": "Y"}`
	doc, err := jsonvalue.Decode([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	a, err := CompilePath(".a")
	if err != nil {
		t.Fatalf("CompilePath(%q): %v", ".a", err)
	}
	b, err := CompilePath(".b")
	if err != nil {
		t.Fatalf("CompilePath(%q): %v", ".b", err)
	}
	if got := a.Select(doc); got.Kind != jsonpath.KindOne || got.Value != "X" {
		t.Errorf("CompilePath(%q).Select(%s) = %+v, want one X", ".a", input, got)
	}
	if got := b.Select(doc); got.Kind != jsonpath.KindOne || got.Value != "Y" {
		t.Errorf("CompilePath(%q).Select(%s) = %+v, want one Y", ".b", input, got)
	}
	if again, err := CompilePath(".a"); err != nil || again != a {
		t.Errorf("CompilePath(%q) again = %p, %v, want the first path %p", ".a", again, err, a)
	}
}
