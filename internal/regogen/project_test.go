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
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/regogen/spectables"
)

// The text a string compares a structure by prints a scalar member as Java
// text, and a nested member as compact JSON with its numbers as written. A
// number with an exponent that leaves no digits after the point prints as
// Double.toString, any other with its trailing zeros stripped. The expected
// texts are what the specification's agent profile prints.
func TestStructureText(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{`["x", null]`, `[x, null]`},
		{`[1.0, true]`, `[1, true]`},
		{`[1.50e1, -0.0, 100]`, `[15, 0, 100]`},
		{`[1e3, 1E3, -1e3]`, `[1000.0, 1000.0, -1000.0]`},
		{`{"k": 1e7}`, `{k=1.0E7}`},
		{`[5e0, 0e5, -0e0]`, `[5.0, 0.0, -0.0]`},
		{`[1.5e1, 1.50e1, 1.2345678912345679E8]`, `[15.0, 15, 123456789.12345679]`},
		{`[1e-0, 5E-00, -0e-0, 1e+0, 1.0e-0, 10e-1]`, `[1.0, 5.0, -0.0, 1.0, 1, 1]`},
		{`[1e64, 1e65, 1e400]`, `[1.0E64, 1.0E65, Infinity]`},
		{`[1` + strings.Repeat("0", 64) + `, 1` + strings.Repeat("0", 65) + `]`,
			`[1` + strings.Repeat("0", 64) + `, 1` + strings.Repeat("0", 65) + `]`},
		{`[1e-65, 1e-66]`, `[0.` + strings.Repeat("0", 64) + `1, 1e-66]`},
		{`[1e9223372036854775807, 10e9223372036854775807]`, `[Infinity, Infinity]`},
		{`[1e-9223372036854775808, 0.1e-9223372036854775808]`, `[1e-9223372036854775808, 0.1e-9223372036854775808]`},
		{`[1e99999999999999999999]`, `[Infinity]`},
		{`[1e-99999999999999999999]`, `[1e-99999999999999999999]`},
		{`[["a"], "b"]`, `[["a"], b]`},
		{`{"k": {"b": "c"}}`, `{k={"b":"c"}}`},
		{`{"a": [1.0]}`, `{a=[1.0]}`},
		{`[]`, `[]`},
	} {
		v, err := jsonvalue.Decode([]byte(tc.value))
		if err != nil {
			t.Fatalf("jsonvalue.Decode(%s): %v", tc.value, err)
		}
		if got := structureText(v); got != tc.want {
			t.Errorf("structureText(%s) = %q, want %q", tc.value, got, tc.want)
		}
	}
}

// The record of a value carries the folded text a string compares it by
// (TextKey). A list with a number or null is not a list of strings, whose
// text TextKey takes from the folded Java text.
func TestRecordReadsTheTextKey(t *testing.T) {
	for _, tc := range []struct{ value, tk string }{
		{`["Ab", "c"]`, `[ab, c]`},
		{`[]`, `[]`},
		{`["x", ["Y"], "Z"]`, `[x, ["y"], z]`},
		{`[1.0, "A"]`, `[1, a]`},
		{`["05", 5]`, `[05, 5]`},
		{`[null, "A"]`, `[null, a]`},
		{`"Q"`, ``},
	} {
		t.Run(tc.value, func(t *testing.T) {
			v, err := jsonvalue.Decode([]byte(tc.value))
			if err != nil {
				t.Fatalf("jsonvalue.Decode(%s): %v", tc.value, err)
			}
			rec := record(&Ref{}, Resolved{State: spectables.StateValue, Value: v})
			tk := ""
			if rec.TextKey != nil {
				tk = *rec.TextKey
			}
			if tk != tc.tk {
				t.Errorf("record(%s).TextKey = %q, want %q", tc.value, tk, tc.tk)
			}
		})
	}
}

// The shape of a nested list adds a fixed length per level of nesting: a
// list nested 16 deep around the string `"` is 16 times "[" and "]" around
// the quoted leaf t:"\"", 38 bytes in all. Quoting the token of a nested
// list again at each level doubled its backslashes per level, and the same
// value gave a token of 98364 bytes.
func TestAShapeGrowsByAFixedLengthPerLevelOfNesting(t *testing.T) {
	value := `[[[[[[[[[[[[[[[["\""]]]]]]]]]]]]]]]]`
	if shape := deepOf(decode(t, value), inputNumberValue).shape; len(shape) != 38 {
		t.Errorf("deepOf(%s).shape is %d bytes, want 38: %.80q", value, len(shape), shape)
	}
}

// An index stops adding the deeps of a shape once it has more groups than a
// lookup may read, so building it costs the length of the list, not its
// square, when every element of one shape has texts at its own leaves.
func TestAnIndexStopsGrowingAShapeAtTheLimit(t *testing.T) {
	elems := make([]string, 1000)
	for i := range elems {
		leaves := make([]string, 10)
		for j := range leaves {
			leaves[j] = "1"
			if (i+1)>>j&1 == 1 {
				leaves[j] = `"1"`
			}
		}
		elems[i] = "[" + strings.Join(leaves, ",") + "]"
	}
	v, err := jsonvalue.Decode([]byte("[" + strings.Join(elems, ",") + "]"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	ix := elementIndex(v, inputNumberValue, true)
	if !ix.tooBig() {
		t.Errorf("tooBig of 1000 groups of one shape = false, want true")
	}
	for shape, gs := range ix {
		if len(gs) > maxLookup+1 {
			t.Errorf("groups of the shape %s = %d, want at most %d", shape, len(gs), maxLookup+1)
		}
	}
}

// A deep without texts, such as a string that is not a number, adds no group
// of its own to an index: a list of 1024 such strings costs the index its
// map and nothing per element.
func TestADeepWithoutTextsAddsNoGroup(t *testing.T) {
	ds := make([]deep, 1024)
	for i := range ds {
		ds[i] = deepOf(fmt.Sprintf("x%d", i), inputNumberValue)
	}
	allocs := testing.AllocsPerRun(5, func() {
		ix := deepIndex{}
		for _, d := range ds {
			ix.add(d)
		}
	})
	if perDeep := allocs / float64(len(ds)); perDeep > 1 {
		t.Errorf("allocations per deep without texts = %.2f, want at most 1", perDeep)
	}
}

// A shape that holds a deep without texts holds a deep equal to any deep of
// the shape, whether the deep without texts came first or last, and adding a
// deep with texts to one such shape leaves another one as it was.
func TestAShapeWithADeepWithoutTextsHoldsEveryDeepOfIt(t *testing.T) {
	plain := deepOf(mustDecode(t, `[1]`), inputNumberValue)
	spelled := deepOf(mustDecode(t, `["1"]`), inputNumberValue)
	other := deepOf(mustDecode(t, `["01"]`), inputNumberValue)
	if plain.shape != spelled.shape || len(plain.texts) != 0 || len(spelled.texts) == 0 {
		t.Fatalf("deeps of [1] and [\"1\"] = %v and %v, want one shape, texts for the second only", plain, spelled)
	}
	for name, order := range map[string][]deep{"without texts first": {plain, spelled},
		"without texts last": {spelled, plain}} {
		ix := deepIndex{}
		alone := deepOf("x", inputNumberValue)
		ix.add(alone)
		for _, d := range order {
			ix.add(d)
		}
		if !ix.has(other) {
			t.Errorf("%s: has(%v) = false, want true", name, other)
		}
		if gs := ix[alone.shape]; len(gs) != 1 {
			t.Errorf("%s: groups of %s = %d, want 1", name, alone.shape, len(gs))
		}
	}
	// a deep without texts before or after more groups than a lookup may
	// read leaves the shape a hit
	groups := make([]deep, maxLookup+2)
	for i := range groups {
		leaves := make([]string, len(groups))
		for j := range leaves {
			leaves[j] = "1"
			if j == i {
				leaves[j] = `"1"`
			}
		}
		groups[i] = deepOf(mustDecode(t, "["+strings.Join(leaves, ",")+"]"), inputNumberValue)
	}
	none := deepOf(mustDecode(t, "["+strings.Repeat("1,", len(groups)-1)+"1]"), inputNumberValue)
	for name, order := range map[string][]deep{"first": append([]deep{none}, groups...),
		"last": append(slices.Clone(groups), none)} {
		many := deepIndex{}
		for _, d := range order {
			many.add(d)
		}
		if many.tooBig() {
			t.Errorf("tooBig of a shape with %d groups and a deep without texts %s = true, want false",
				len(groups), name)
		}
	}
	ix := deepIndex{}
	ix.add(spelled)
	if ix.has(other) {
		t.Errorf("has(%v) of the index of [\"1\"] alone = true, want false", other)
	}
}

// Two values are equal exactly when the deep of one is in the index of the
// other. A string that holds a quote and a comma, or that spells the shape of
// a list, stays apart from the lists it looks like. The relation is not
// transitive: "5.0" equals 5 and 5 equals "5.00", while "5.0" and "5.00"
// differ.
func TestADeepIsInTheIndexOfAnEqualValueOnly(t *testing.T) {
	for _, tc := range []struct {
		name, a, b string
		want       bool
	}{
		{"a string with a quote and a comma against two strings", `["a\",\"b"]`, `["a", "b"]`, false},
		{"a string that spells a list shape against the list", `["[t:\"a\"]"]`, `[["a"]]`, false},
		{"two lists against one list of both", `[["a"], ["b"]]`, `[["a", "b"]]`, false},
		{"lists in another order", `["a", "b"]`, `["b", "a"]`, false},
		{"strings in another case", `[["A"]]`, `[["a"]]`, true},
		{"numbers of one value in two spellings", `[[1]]`, `[[1.0]]`, true},
		{"a number and a string of its value", `[[1]]`, `[["1.0"]]`, true},
		{"a string of a value and a number", `[["5.0"]]`, `[[5]]`, true},
		{"a number and a string of another value", `[[5]]`, `[["5.00"]]`, true},
		{"two strings of one value", `[["5.0"]]`, `[["5.00"]]`, false},
		{"a boolean and its text", `[true]`, `["TRUE"]`, true},
		{"a boolean and a number", `[true]`, `[1]`, false},
		{"null and null", `[null]`, `[null]`, true},
		{"null and its text", `[null]`, `["null"]`, false},
		{"member names in another case", `{"K": 1}`, `{"k": 1}`, false},
		{"members in another order", `{"a": 1, "b": "x"}`, `{"b": "X", "a": "1"}`, true},
		{"a number beside a text of the same spelling", `[1, "5.0"]`, `["1", "5.0"]`, true},
		{"a number beside a text of another spelling", `[1, "5.0"]`, `["1", "5.00"]`, false},
		{"a number beside three texts of the same spelling", `[1, "2", "3", "5.0"]`, `["1", "2", "3", "5.0"]`, true},
		{"a number beside a text of another spelling of four", `[1, "2", "3", "5.0"]`, `["1", "2", "3", "5.00"]`,
			false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := deepOf(decode(t, tc.a), inputNumberValue), deepOf(decode(t, tc.b), inputNumberValue)
			ix := deepIndex{}
			ix.add(b)
			if got := ix.has(a); got != tc.want {
				t.Errorf("index of %s %+v has %s %+v = %v, want %v", tc.b, b, tc.a, a, got, tc.want)
			}
		})
	}
}

func decode(t *testing.T, value string) jsonvalue.Value {
	t.Helper()
	v, err := jsonvalue.Decode([]byte(value))
	if err != nil {
		t.Fatalf("jsonvalue.Decode(%s): %v", value, err)
	}
	return v
}

// A record holds a field that is costly to build, the keys, the text, or the
// deeps of a list, where the module reads it
// and the record of every field holds it, and nowhere else: CONTAINS reads
// the keys alone, as do the policies of a subject's permissions, and == with
// a string reads the text. The value is a list of strings, an empty list, or
// a one-element GENERAL list of an object, whose record has no text.
func TestARecordHoldsTheFieldsTheModuleReads(t *testing.T) {
	for _, tc := range []struct{ condition, state, value string }{
		{"subject.permissions CONTAINS 'p1'", "VALUE", `["p1", "p2"]`},
		{"subject.permissions == 'p1'", "VALUE", `["p1", "p2"]`},
		{"subject.permissions == resource.b", "VALUE", `["p1", "p2"]`},
		{"subject.permissions CONTAINS ANY resource.b", "VALUE", `["p1", "p2"]`},
		{"subject.permissions IS EMPTY", "VALUE", `["p1", "p2"]`},
		{"subject.permissions == resource.b", "VALUE", `[]`},
		{"subject.permissions CONTAINS ANY resource.b", "VALUE", `[]`},
		{"subject.g CONTAINS 'p1'", "SINGLE_ODD", `[{"a": 1}]`},
		{"subject.g CONTAINS ANY resource.b", "SINGLE_ODD", `[{"a": 1}]`},
		{"subject.g == 'x'", "SINGLE_ODD", `[{"a": 1}]`},
	} {
		t.Run(tc.condition+" "+tc.value, func(t *testing.T) {
			condition := tc.condition
			id, key, pips := "subject.permissions", `["subj","permissions"]`, ""
			if tc.state == "SINGLE_ODD" {
				id, key, pips = "subject.g", `["subj","g"]`, generalPIPs
			}
			values := map[string]Resolved{key: resolved(t, tc.state, tc.value),
				`["res",".b"]`: resolved(t, "VALUE", `["p2"]`)}
			m, err := Generate(tenantWithSetAndPIPs(t, "DENY_UNLESS_PERMIT", "ALLOW", condition, pips), table(t),
				DefaultOptions())
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			in, err := Project(m, Request{Body: Body{Operation: "read", ResourceType: "doc"}, Values: values})
			if err != nil {
				t.Fatalf("Project: %v", err)
			}
			rec, ok := in.Records[id]
			if !ok {
				t.Fatalf("the input holds no record of %s", id)
			}
			whole := record(&Ref{}, values[key])
			i := slices.IndexFunc(m.Refs, func(r *Ref) bool { return r.ID == id })
			if i < 0 {
				t.Fatalf("the module has no reference %s", id)
			}
			// a copy, so that reading the expressions marks no field
			r := *m.Refs[i]
			s := &side{ref: &r}
			for f, has := range map[string][2]bool{fieldElementKeys: {rec.ElementKeys != nil, whole.ElementKeys != nil},
				fieldTextKey: {rec.TextKey != nil, whole.TextKey != nil}, fieldEqAlts: {rec.EqAlts != nil, whole.EqAlts != nil},
				fieldElementAlts: {rec.ElementAlts != nil, whole.ElementAlts != nil}} {
				reads := strings.Contains(m.Text, s.field(f))
				switch f {
				case fieldEqAlts:
					reads = reads || strings.Contains(m.Text, s.field(fieldEqIndex))
				case fieldElementAlts:
					reads = reads || strings.Contains(m.Text, s.field(fieldElementIndex))
				}
				if has[0] != (reads && has[1]) {
					t.Errorf("the module reads %s of %s: %v, the record of every field holds it: %v, "+
						"the record holds it: %v", f, id, reads, has[1], has[0])
				}
			}
		})
	}
}

// The input carries a field of a record where the text of the module reads
// it, and the subject groups read the others from the record in Go: with
// groups, CONTAINS of the subject's permissions moves into a group, and the
// input keeps the keys of the permissions out while the record holds them.
func TestTheInputCarriesTheFieldsTheTextReads(t *testing.T) {
	const id, key = "subject.permissions", `["subj","permissions"]`
	req := Request{Body: Body{Operation: "read", ResourceType: "doc"},
		Values: map[string]Resolved{key: resolved(t, "VALUE", `["p1", "p2"]`)}}
	for _, groups := range []bool{false, true} {
		opt := DefaultOptions()
		opt.Groups = groups
		m, err := Generate(tenantWithSetAndPIPs(t, "DENY_UNLESS_PERMIT", "ALLOW", "subject.permissions CONTAINS 'p1'",
			""), table(t), opt)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		in := mustProject(t, m, req)
		if in.Records[id].ElementKeys == nil {
			t.Errorf("groups %v: the record of %s holds no keys", groups, id)
		}
		ks := in.Value().(ast.Object).Get(ast.StringTerm(fieldElementKeys)).Value.(ast.Object).Get(ast.StringTerm(id))
		reads := strings.Contains(m.Text, "input."+fieldElementKeys+refIndex(id))
		if (ks != nil) != reads {
			t.Errorf("groups %v: the text reads input.element_keys of %s: %v, the input carries it: %v", groups, id, reads,
				ks != nil)
		}
		if reads == groups {
			t.Errorf("groups %v: the text reads input.element_keys of %s: %v", groups, id, reads)
		}
	}
}

// markEmitted sets each field the text reads of the reference it reads it
// of, and no other: every field name, has_null and segment_count among them, after input
// and after p, the record of a pass value, with the index of a name that is
// an identifier and of one that is not. A field read with no index is set
// for every reference.
func TestMarkEmittedSetsTheFieldsTheTextReads(t *testing.T) {
	x, ab := &Ref{ID: "x"}, &Ref{ID: "a.b<"}
	for _, f := range recordFields {
		for _, text := range []string{
			"input." + f + refIndex(x.ID) + " == 1\n  not input.state" + refIndex(ab.ID),
			"some p in input.scope_passes\n  p." + f + refIndex(x.ID) + "[0]\n  p.state" + refIndex(ab.ID),
		} {
			markEmitted([]*Ref{x, ab}, text)
			if want := fieldsKnown | fieldBit(f); x.emit != want {
				t.Errorf("%q: emit of x %b, want %b", text, x.emit, want)
			}
			if want := fieldsKnown | fieldBit(fieldState); ab.emit != want {
				t.Errorf("%q: emit of %s %b, want %b", text, ab.ID, ab.emit, want)
			}
		}
	}
	markEmitted([]*Ref{x, ab}, "count(input.element_keys) > 0")
	if want := fieldsKnown | fieldBit(fieldElementKeys); x.emit != want || ab.emit != want {
		t.Errorf("input.element_keys with no index: emit %b and %b, want %b for both", x.emit, ab.emit, want)
	}
}
