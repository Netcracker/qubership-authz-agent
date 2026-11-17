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

package legacyvalue

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"authz-agent/internal/jsonvalue"
)

func mustDecode(t *testing.T, doc string) jsonvalue.Value {
	t.Helper()
	v, err := jsonvalue.Decode([]byte(doc))
	if err != nil {
		t.Fatalf("Decode(%s): %v", doc, err)
	}
	return v
}

// The keys and the number of a scalar come from its Java text. == compares the
// folded text; <, and == where one side is a number, compare the number
// BigDecimal reads from that text.
func TestOf_ScalarCarriesTheTextsEachOperatorComparesBy(t *testing.T) {
	type want struct {
		class   Class
		typ     Type
		key     string
		caseKey string
		number  string // Decimal.String, or "" for none
	}
	tests := []struct {
		name string
		doc  string
		want want
	}{
		{"a string folds to lower case", `"ABC"`, want{ClassString, TypeString, "abc", "ABC", ""}},
		{"a string whose scale BigDecimal refuses is no number", `"1.1e-2147483647"`, want{ClassString, TypeString, "1.1e-2147483647", "1.1e-2147483647", ""}},
		{"a string at the largest scale BigDecimal accepts is a number", `"1e-2147483647"`, want{ClassString, TypeString, "1e-2147483647", "1e-2147483647", "1e-2147483647"}},
		{"sharp s has no one-character upper case and stays", `"Straße"`, want{ClassString, TypeString, "straße", "Straße", ""}},
		{"dotted capital I folds to i", `"İ"`, want{ClassString, TypeString, "i", "İ", ""}},
		{"long s folds through its upper case to s", `"ſ"`, want{ClassString, TypeString, "s", "ſ", ""}},
		{"final sigma folds through its upper case to sigma", `"ς"`, want{ClassString, TypeString, "σ", "ς", ""}},
		{"a letter outside the BMP folds as one code point", `"𐐀"`, want{ClassString, TypeString, "𐐨", "𐐀", ""}},
		{"a string of digits reads as a number", `"5"`, want{ClassString, TypeString, "5", "5", "5"}},
		{"a string with a plus sign reads as a number", `"+5"`, want{ClassString, TypeString, "+5", "+5", "5"}},
		{"a string with no integer digits reads as a number", `".5"`, want{ClassString, TypeString, ".5", ".5", "0.5"}},
		{"a string with a trailing point reads as a number", `"5."`, want{ClassString, TypeString, "5.", "5.", "5"}},
		{"a string of Arabic-Indic digits reads as a number", `"٣"`, want{ClassString, TypeString, "٣", "٣", "3"}},
		{"a string beyond the double range keeps its exact value", `"1e400"`, want{ClassString, TypeString, "1e400", "1e400", "1e400"}},
		{"a string with a leading space is not a number", `" 5"`, want{ClassString, TypeString, " 5", " 5", ""}},
		{"a string with an underscore is not a number", `"5_0"`, want{ClassString, TypeString, "5_0", "5_0", ""}},
		{"the string NaN is not a number", `"NaN"`, want{ClassString, TypeString, "nan", "NaN", ""}},
		{"the string Infinity is not a number", `"Infinity"`, want{ClassString, TypeString, "infinity", "Infinity", ""}},
		{"an integer prints as its digits", `5`, want{ClassScalar, TypeNumber, "5", "5", "5"}},
		{"minus zero integer prints as 0", `-0`, want{ClassScalar, TypeNumber, "0", "0", "0"}},
		{"a fraction prints as Double.toString", `5.0`, want{ClassScalar, TypeNumber, "5.0", "5.0", "5"}},
		{"minus zero fraction keeps its sign in the text only", `-0.0`, want{ClassScalar, TypeNumber, "-0.0", "-0.0", "0"}},
		{"an exponent prints as a fraction", `1e2`, want{ClassScalar, TypeNumber, "100.0", "100.0", "100"}},
		{"a small magnitude prints with an exponent", `1.5e-4`, want{ClassScalar, TypeNumber, "1.5e-4", "1.5E-4", "0.00015"}},
		{"ten million prints with an exponent", `1e7`, want{ClassScalar, TypeNumber, "1.0e7", "1.0E7", "10000000"}},
		{"just under ten million prints plain", `9999999.0`, want{ClassScalar, TypeNumber, "9999999.0", "9999999.0", "9999999"}},
		{"an underflow reads as the zero of its Double", `1e-400`, want{ClassScalar, TypeNumber, "0.0", "0.0", "0"}},
		{"a negative underflow prints as minus zero and reads as zero", `-1e-400`, want{ClassScalar, TypeNumber, "-0.0", "-0.0", "0"}},
		{"an overflow prints as Infinity and has no number", `1e400`, want{ClassScalar, TypeNumber, "infinity", "Infinity", ""}},
		{"a long integer keeps every digit", `123456789012345678901234567890`, want{ClassScalar, TypeNumber, "123456789012345678901234567890", "123456789012345678901234567890", "1.2345678901234567890123456789e29"}},
		{"a long fraction reads as the nearest double", `12345678901234567.5`, want{ClassScalar, TypeNumber, "1.2345678901234568e16", "1.2345678901234568E16", "12345678901234568"}},
		{"digits beyond a double read as the double", `0.300000000000000010`, want{ClassScalar, TypeNumber, "0.3", "0.3", "0.3"}},
		{"true has a key and no number", `true`, want{ClassScalar, TypeBoolean, "true", "true", ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Of(mustDecode(t, tt.doc))
			var got want
			got.class, got.typ = r.Class, r.Type
			if r.Key != nil {
				got.key, got.caseKey = *r.Key, *r.CaseKey
			}
			if r.Number != nil {
				got.number = r.Number.String()
			}
			if r.State != StateValue {
				t.Errorf("Of(%s).State = %s, want VALUE", tt.doc, r.State)
			}
			if got != tt.want {
				t.Errorf("Of(%s) = %+v, want %+v", tt.doc, got, tt.want)
			}
			if !reflect.DeepEqual(r.Keys, []string{got.key}) {
				t.Errorf("Of(%s).Keys = %q, want [%q]", tt.doc, r.Keys, got.key)
			}
		})
	}
}

func TestOf_StateOfAValueWithoutAKey(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want State
	}{
		{"null", `null`, StateNull},
		{"an empty list", `[]`, StateEmptyColl},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Of(mustDecode(t, tt.doc))
			if !reflect.DeepEqual(got, Record{State: tt.want}) {
				t.Errorf("Of(%s) = %+v, want a record of state %s alone", tt.doc, got, tt.want)
			}
		})
	}
}

// A structure has the key of its Java text, which a string equals it by, and a
// list also has the keys of its elements that are not null.
func TestOf_StructureCarriesItsJavaTextAndTheKeysOfItsElements(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		state   State
		class   Class
		caseKey string
		keys    []string
	}{
		{"a list of scalars", `[1, "A", true]`, StateValue, ClassList, "[1, A, true]", []string{"1", "a", "true"}},
		{"a list that holds null", `[null, "A"]`, StateNullElement, ClassOther, "[null, A]", []string{"a"}},
		{"a list that holds a list", `[[1], "x"]`, StateValue, ClassOther, "[[1], x]", []string{"[1]", "x"}},
		{"a list that holds an empty object", `[{}]`, StateValue, ClassOther, "[{}]", []string{"{}"}},
		{"a list that holds an empty list", `[[], "x"]`, StateValue, ClassOther, "[[], x]", []string{"[]", "x"}},
		{"an object in document order", `{"b": 1, "A": [2, "X"]}`, StateValue, ClassOther, "{b=1, A=[2, X]}", []string{"{b=1, a=[2, x]}"}},
		{"an empty object", `{}`, StateValue, ClassOther, "{}", []string{"{}"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Of(mustDecode(t, tt.doc))
			if r.State != tt.state || r.Class != tt.class {
				t.Errorf("Of(%s) state, class = %s, %s, want %s, %s", tt.doc, r.State, r.Class, tt.state, tt.class)
			}
			if r.CaseKey == nil {
				t.Fatalf("Of(%s) has no case key, want %q", tt.doc, tt.caseKey)
			}
			if *r.CaseKey != tt.caseKey || *r.Key != Fold(tt.caseKey) {
				t.Errorf("Of(%s) keys = %q, %q, want %q and its fold", tt.doc, *r.Key, *r.CaseKey, tt.caseKey)
			}
			if !reflect.DeepEqual(r.Keys, tt.keys) {
				t.Errorf("Of(%s).Keys = %q, want %q", tt.doc, r.Keys, tt.keys)
			}
			if r.Number != nil {
				t.Errorf("Of(%s) has the number %s, want none", tt.doc, r.Number)
			}
		})
	}
}

// Building the record of a list nested 1000 deep allocates a few times the
// size of the document, where joining the text level by level would copy each
// byte once per level.
func TestOf_RecordOfADeepListAllocatesAFewTimesItsSize(t *testing.T) {
	const depth = 1000
	doc := strings.Repeat(`["abc",`, depth) + "1" + strings.Repeat("]", depth)
	v := mustDecode(t, doc)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	Of(v)
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	if limit := uint64(20 * len(doc)); allocated > limit {
		t.Errorf("Of(a list nested %d deep) allocates %d bytes, want at most %d, twenty times the %d-byte document", depth, allocated, limit, len(doc))
	}
}

// recordText returns the fields of r that hold text, for a failure message.
func recordText(r Record) string {
	deref := func(s *string) string {
		if s == nil {
			return "<nil>"
		}
		return *s
	}
	n := "<nil>"
	if r.Number != nil {
		n = r.Number.String()
	}
	return fmt.Sprintf("{s: %s, t: %s, j: %s, k: %q, ck: %q, ks: %q, n: %s}",
		r.State, r.Class, r.Type, deref(r.Key), deref(r.CaseKey), r.Keys, n)
}

// The record OfParts builds with some of the parts of a list is the record of
// Of with the other parts left out, null elements, nested lists, and objects
// included.
func TestOfPartsLeavesOutTheOtherParts(t *testing.T) {
	docs := []string{`["Straße", "x\"y", 1.50, true]`, `[null, "a", [2, null], {"B": []}]`, `[1, 1, "1"]`, `[]`,
		`"a"`, `{"a": [1]}`}
	for _, doc := range docs {
		v := mustDecode(t, doc)
		whole := Of(v)
		for p := Parts(0); p <= AllParts; p++ {
			want := whole
			if _, ok := v.([]jsonvalue.Value); ok {
				if p&PartKey == 0 {
					want.Key, want.CaseKey = nil, nil
				}
				if p&PartKeys == 0 {
					want.Keys = nil
				}
			}
			if got := OfParts(v, p); !reflect.DeepEqual(got, want) {
				t.Errorf("OfParts(%s, %02b) = %s, want %s", doc, p, recordText(got), recordText(want))
			}
		}
	}
}
