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
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"authz-agent/internal/jsonvalue"
)

// eval evaluates query with the built-in functions registered and strict
// built-in errors, and returns the value of x.
func eval(t *testing.T, query string) (*ast.Term, error) {
	t.Helper()
	opts := append([]func(*rego.Rego){
		rego.Query("x := " + query),
		rego.Capabilities(Capabilities()),
		rego.StrictBuiltinErrors(true),
	}, Options()...)
	rs, err := rego.New(opts...).Eval(context.Background())
	if err != nil {
		return nil, err
	}
	if len(rs) != 1 {
		t.Fatalf("%s: %d results, want 1", query, len(rs))
	}
	v, err := ast.InterfaceToValue(rs[0].Bindings["x"])
	if err != nil {
		t.Fatal(err)
	}
	return ast.NewTerm(v), nil
}

func mustEval(t *testing.T, query string) *ast.Term {
	t.Helper()
	got, err := eval(t, query)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return got
}

func TestDecimalCompare_IsExactWhereRegoIsNot(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want string
	}{
		{"fractions with trailing zeros equal as float64", "0.300000000000000010", "0.30", "1"},
		{"17 significant digits", "0.30000000000000001", "0.3", "1"},
		{"20-digit integers", "12345678901234567890", "12345678901234567891", "-1"},
		{"40-digit fractions", "0.1234567890123456789012345678901234567891", "0.123456789012345678901234567890123456789", "1"},
		{"minus zero", "-0.0", "0", "0"},
		{"exponents past the double range", "1e400", "9.99e399", "1"},
		{"equal numbers written differently", "1.5E+3", "1500.00", "0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := "nc.decimal.compare(" + tt.a + ", " + tt.b + ")"
			if got := mustEval(t, q); !got.Equal(ast.MustParseTerm(tt.want)) {
				t.Errorf("%s = %v, want %s", q, got, tt.want)
			}
		})
	}
}

// The negative control for TestDecimalCompare_IsExactWhereRegoIsNot: Rego's
// own > compares two fractions that both end in zeros as float64, and finds
// two different numbers equal.
func TestRegoGreaterThan_LosesDigitsBeyondFloat64(t *testing.T) {
	if got := mustEval(t, "0.300000000000000010 > 0.30"); !got.Equal(ast.BooleanTerm(false)) {
		t.Errorf("0.300000000000000010 > 0.30 = %v in Rego, want false, the loss nc.decimal.compare avoids", got)
	}
}

// A record with nl carries no n, and nc.decimal.compare reads its number from
// ck exactly, at an exponent where Rego's own comparison panics.
func TestDecimalCompare_ReadsTheNumberOfARecord(t *testing.T) {
	tests := []struct {
		name, a, b, want string
	}{
		{"a string past the exponent Rego compares", `nc.value("1e10000000")`, "5", "1"},
		{"a string next to zero", `nc.value("1e-2147483647")`, "0", "1"},
		{"two records of long numbers", `nc.value("1e-2147483646")`, `nc.value("1e-2147483647")`, "1"},
		{"a record with n", `nc.value("5.0")`, "5", "0"},
		{"a long integer", `nc.value(12345678901234567890)`, "12345678901234567891", "-1"},
		{"a record with n and a record with nl", `nc.value("5")`, `nc.value("1e10000000")`, "-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := "nc.decimal.compare(" + tt.a + ", " + tt.b + ")"
			if got := mustEval(t, q); !got.Equal(ast.MustParseTerm(tt.want)) {
				t.Errorf("%s = %v, want %s", q, got, tt.want)
			}
		})
	}
}

// A long number has no n, so Rego's own operators find nothing to compare
// rather than panicking or rounding it.
func TestValue_LongNumberHasNoN(t *testing.T) {
	for _, arg := range []string{`"1e10000000"`, `"1e-2147483647"`, `12345678901234567890`} {
		q := `object.get(nc.value(` + arg + `), "n", "absent")`
		if got := mustEval(t, q); !got.Equal(ast.StringTerm("absent")) {
			t.Errorf("%s = %v, want \"absent\"", q, got)
		}
	}
}

// A string becomes a number only through its record, so nc.decimal.compare
// refuses one even where BigDecimal reads it, and refuses the record of a
// value that is not a number.
func TestDecimalCompare_RefusesWhatIsNotANumber(t *testing.T) {
	for _, q := range []string{`nc.decimal.compare("5", 1)`, `nc.decimal.compare(1, "1.1e-2147483647")`, `nc.decimal.compare(true, 1)`, `nc.decimal.compare(nc.value("abc"), 1)`, `nc.decimal.compare(nc.value(1e400), 1)`} {
		if got, err := eval(t, q); err == nil {
			t.Errorf("%s = %v, want an error", q, got)
		}
	}
}

// A string whose type the compiler cannot see, as one read from a document,
// is refused when the function runs.
func TestDecimalCompare_RefusesAStringAtRunTime(t *testing.T) {
	q := `nc.decimal.compare(json.unmarshal("\"5\""), 1)`
	got, err := eval(t, q)
	if err == nil || !strings.Contains(err.Error(), `eval_builtin_error: nc.decimal.compare: "5" is neither a number nor the record of one`) {
		t.Errorf("%s = %v, %v, want the error that \"5\" is neither a number nor the record of one", q, got, err)
	}
}

// An object of the request shaped like the record of a number is an object to
// nc.value, whose record has no n, so nc.decimal.compare refuses it.
func TestDecimalCompare_RefusesTheRecordOfAnObjectShapedLikeANumber(t *testing.T) {
	q := `nc.decimal.compare(nc.value(input.x), 5)`
	const input = `{"x": {"n": 0, "ck": "1e9"}}`
	for _, docs := range []bool{false, true} {
		raw, err := jsonvalue.Decode([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		in := ast.MustParseTerm(input).Value
		if docs {
			d := NewDocuments()
			term, err := d.Term(raw)
			if err != nil {
				t.Fatalf("Term(%s): %v", input, err)
			}
			in, ctx = term.Value, d.Context(ctx)
		}
		opts := append([]func(*rego.Rego){
			rego.Query("x := " + q),
			rego.Capabilities(Capabilities()),
			rego.StrictBuiltinErrors(true),
			rego.ParsedInput(in),
		}, Options()...)
		rs, err := rego.New(opts...).Eval(ctx)
		if err == nil || !strings.Contains(err.Error(), "nc.decimal.compare: the object is not the record of a number") {
			t.Errorf("%s over %s with Documents %v = %v, %v, want the error that the object is not the record of a number", q, input, docs, rs, err)
		}
	}
}

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

func TestValue_ReturnsTheRecordOfAValue(t *testing.T) {
	tests := []struct {
		name, arg, want string
	}{
		{"a string", `"Abc"`, `{"s": "VALUE", "t": "s", "j": "string", "k": "abc", "ck": "Abc", "ks": ["abc"]}`},
		{"a long number", `12345678901234567890`,
			`{"s": "VALUE", "t": "n", "j": "number", "k": "12345678901234567890", "ck": "12345678901234567890", "ks": ["12345678901234567890"], "nl": true}`},
		{"null", `null`, `{"s": "NULL"}`},
		{"an object, in sorted key order", `{"b": 1, "a": 2}`,
			`{"s": "VALUE", "t": "x", "j": "object", "k": "{a=2, b=1}", "ck": "{a=2, b=1}", "ks": ["{a=2, b=1}"], "o": "{\"a\":2,\"b\":1}"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := "nc.value(" + tt.arg + ")"
			if got, want := mustEval(t, q), ast.MustParseTerm(tt.want); !got.Equal(want) {
				t.Errorf("%s = %v, want %v", q, got, want)
			}
		})
	}
}

func TestJSONPath_ReturnsTheSelectionAndItsRecord(t *testing.T) {
	tests := []struct {
		name, args, want string
	}{
		{"one value", `{"a": {"b": "X"}}, ".a.b"`,
			`{"sel": "one", "rec": {"s": "VALUE", "t": "s", "j": "string", "k": "x", "ck": "X", "ks": ["x"]}}`},
		{"one null", `{"a": null}, ".a"`, `{"sel": "one", "rec": {"s": "NULL"}}`},
		{"many, none selected", `{"a": []}, ".a[*]"`, `{"sel": "many", "rec": {"s": "EMPTY_COLL"}}`},
		{"an index out of bounds", `{"a": [1]}, ".a[1]"`, `{"sel": "oob"}`},
		{"a number beyond the double range in a filter", `{"a": [{"n": 1e400}, {"n": 5}]}, ".a[?(@.n > 10)].n"`,
			`{"sel": "many", "rec": {"s": "VALUE", "t": "l", "j": "array", "k": "[infinity]", "ck": "[Infinity]", "ks": ["infinity"], "o": "[Infinity]", "e": [{"s": "VALUE", "t": "n", "j": "number", "k": "infinity", "ck": "Infinity", "ks": ["infinity"]}]}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := "nc.jsonpath(" + tt.args + ")"
			if got, want := mustEval(t, q), ast.MustParseTerm(tt.want); !got.Equal(want) {
				t.Errorf("%s = %v, want %v", q, got, want)
			}
		})
	}
}

// A selection that outgrows its document has a record in state ERROR, which
// generated code reads as it reads any operand that failed to resolve.
func TestJSONPath_ASelectionThatOutgrowsTheDocumentIsAnError(t *testing.T) {
	depth := 9000
	doc := strings.Repeat(`{"key":`, depth) + "1" + strings.Repeat("}", depth)
	q := "nc.jsonpath(" + doc + `, "..key")`
	want := ast.MustParseTerm(`{"sel": "toolarge", "rec": {"s": "ERROR"}}`)
	if got := mustEval(t, q); !got.Equal(want) {
		text := got.String()
		if len(text) > 200 {
			text = text[:200] + "..."
		}
		t.Errorf("nc.jsonpath(<objects nested %d deep>, \"..key\") = %s, want %v", depth, text, want)
	}
}

func TestJSONPath_RefusesAPathOutsideTheSubset(t *testing.T) {
	q := `nc.jsonpath({"a": 1}, ".a.*")`
	if got, err := eval(t, q); err == nil {
		t.Errorf("%s = %v, want an error", q, got)
	}
}

// Nothing is registered globally: a query without Capabilities and Options
// does not know the functions.
func TestBuiltins_AreUnknownWithoutTheOptions(t *testing.T) {
	for _, q := range []string{`nc.value(1)`, `nc.decimal.compare(1, 2)`, `nc.jsonpath({}, ".a")`} {
		rs, err := rego.New(rego.Query("x := " + q)).Eval(context.Background())
		if err == nil || !strings.Contains(err.Error(), "undefined function") {
			t.Errorf("%s without the options = %v, %v, want an undefined-function error", q, rs, err)
		}
	}
}

// evalInput evaluates query over input with the built-in functions registered
// and returns the value of x. With docs set, input is built by
// [Documents.Term] and the query's context carries docs.
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
	opts := append([]func(*rego.Rego){
		rego.Query("x := " + query),
		rego.Capabilities(Capabilities()),
		rego.StrictBuiltinErrors(true),
		rego.ParsedInput(in),
	}, Options()...)
	rs, err := rego.New(opts...).Eval(ctx)
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
func TestDocuments_KeepMemberOrder(t *testing.T) {
	const input = `{"o": {"b": "X", "a": "Y"}}`
	tests := []struct {
		name, query string
		docs        bool
		want        string
	}{
		{"nc.value with Documents", `nc.value(input.o).ck`, true, `"{b=X, a=Y}"`},
		{"nc.value without Documents", `nc.value(input.o).ck`, false, `"{a=Y, b=X}"`},
		{"nc.jsonpath with Documents", `nc.jsonpath(input, ".o[*]").rec.ck`, true, `"[X, Y]"`},
		{"nc.jsonpath without Documents", `nc.jsonpath(input, ".o[*]").rec.ck`, false, `"[Y, X]"`},
		{"an object inside a list Rego builds", `nc.value([input.o]).ck`, true, `"[{b=X, a=Y}]"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := evalInput(t, tt.query, input, tt.docs); !got.Equal(ast.MustParseTerm(tt.want)) {
				t.Errorf("%s over %s = %v, want %s", tt.query, input, got, tt.want)
			}
		})
	}
}

// Two documents in one query keep their own values when the same path selects
// from each.
func TestJSONPath_TwoDocumentsInOneQuery(t *testing.T) {
	const input = `{"p": {"a": "X"}, "q": {"a": "Y"}}`
	q := `[nc.jsonpath(input.p, ".a").rec.ck, nc.jsonpath(input.q, ".a").rec.ck, nc.jsonpath(input.p, ".a").rec.ck]`
	want := ast.MustParseTerm(`["X", "Y", "X"]`)
	if got := evalInput(t, q, input, false); !got.Equal(want) {
		t.Errorf("%s over %s = %v, want %v", q, input, got, want)
	}
}

// Without strict built-in errors, a function that refuses its argument leaves
// the rule that calls it undefined, and a rule that negates that rule holds.
// A rule that has to stay false on a refused argument cannot reach the call
// through not.
func TestBuiltinError_LeavesTheRuleUndefinedAndItsNegationTrue(t *testing.T) {
	const module = `package p

gt5 if nc.decimal.compare(nc.value(input.x), 5) > 0

not_gt5 if not gt5
`
	tests := []struct {
		name, rule, input string
		want              bool
	}{
		{"gt5 over a number greater than 5", "gt5", `{"x": 10}`, true},
		{"gt5 over a string BigDecimal refuses", "gt5", `{"x": "abc"}`, false},
		{"not_gt5 over a number greater than 5", "not_gt5", `{"x": 10}`, false},
		{"not_gt5 over a string BigDecimal refuses", "not_gt5", `{"x": "abc"}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := append([]func(*rego.Rego){
				rego.Query("data.p." + tt.rule),
				rego.Module("p.rego", module),
				rego.Capabilities(Capabilities()),
				rego.ParsedInput(ast.MustParseTerm(tt.input).Value),
			}, Options()...)
			rs, err := rego.New(opts...).Eval(context.Background())
			if err != nil {
				t.Fatalf("data.p.%s over %s: %v", tt.rule, tt.input, err)
			}
			if got := len(rs) == 1; got != tt.want {
				t.Errorf("data.p.%s over %s defined = %v, want %v", tt.rule, tt.input, got, tt.want)
			}
		})
	}
}
