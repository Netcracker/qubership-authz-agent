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

// A string becomes a number only through the n of its record, so
// nc.decimal.compare refuses one even where BigDecimal reads it.
func TestDecimalCompare_RefusesWhatIsNotANumber(t *testing.T) {
	for _, q := range []string{`nc.decimal.compare("5", 1)`, `nc.decimal.compare(1, "1.1e-2147483647")`, `nc.decimal.compare(true, 1)`} {
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
	if err == nil || !strings.Contains(err.Error(), `nc.decimal.compare: "5" is not a number`) {
		t.Errorf("%s = %v, %v, want the error that \"5\" is not a number", q, got, err)
	}
}

func TestValue_ReturnsTheRecordOfAValue(t *testing.T) {
	tests := []struct {
		name, arg, want string
	}{
		{"a string", `"Abc"`, `{"s": "VALUE", "t": "s", "j": "string", "k": "abc", "ck": "Abc", "ks": ["abc"]}`},
		{"a long number", `12345678901234567890`,
			`{"s": "VALUE", "t": "n", "j": "number", "k": "12345678901234567890", "ck": "12345678901234567890", "ks": ["12345678901234567890"], "n": 12345678901234567890, "nl": true}`},
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
			`{"sel": "many", "rec": {"s": "VALUE", "t": "l", "j": "array", "k": "[infinity]", "ck": "[Infinity]", "ks": ["infinity"], "e": [{"s": "VALUE", "t": "n", "j": "number", "k": "infinity", "ck": "Infinity", "ks": ["infinity"]}]}}`},
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
