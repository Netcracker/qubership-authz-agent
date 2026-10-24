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
	"slices"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"

	"authz-agent/internal/jsonvalue"
)

// State is the state an operand resolves to.
type State string

// The states. [Of] gives a value one of StateValue, StateNullElement,
// StateNull, and StateEmptyColl; the others depend on how the value was read,
// such as a path that selected nothing, and the caller sets them with
// [WithState].
const (
	StateValue State = "VALUE"
	// StateNullElement is the state of a list that holds null among its
	// elements. Its record is the record of a VALUE list, and the state lets
	// generated code tell it apart with one comparison.
	StateNullElement State = "NULL_ELEMENT"
	StateAbsent      State = "ABSENT"
	StateNull        State = "NULL"
	StatePIPEmpty    State = "PIP_EMPTY"
	StateEmptyColl   State = "EMPTY_COLL"
	StateEmptySel    State = "EMPTY_SEL"
	StateIndexOOB    State = "INDEX_OOB"
	StatePIPNull     State = "PIP_NULL"
	StateError       State = "ERROR"
)

// Class is the class of a value in state VALUE or NULL_ELEMENT, which decides
// how a comparison treats it.
type Class string

// The classes.
const (
	// ClassString is a string.
	ClassString Class = "s"
	// ClassScalar is a number or a boolean.
	ClassScalar Class = "n"
	// ClassList is a list whose elements are strings, numbers, or booleans.
	ClassList Class = "l"
	// ClassOther is any other value: an object, and a list that holds null, a
	// list, or an object.
	ClassOther Class = "x"
)

// Type is the JSON type of a value in state VALUE or NULL_ELEMENT.
type Type string

// The types.
const (
	TypeString  Type = "string"
	TypeNumber  Type = "number"
	TypeBoolean Type = "boolean"
	TypeArray   Type = "array"
	TypeObject  Type = "object"
)

// Record is what generated Rego reads of an operand instead of its raw JSON.
// Every field but State is set only where the value has it; a record in any
// state other than VALUE and NULL_ELEMENT carries State alone.
//
// [Record.Term] writes the record as a Rego object; each field comment starts
// with the key it has there.
type Record struct {
	// s: the state.
	State State
	// t: the class.
	Class Class
	// j: the JSON type.
	Type Type
	// k: the key two values are equal by under equalsIgnoreCase. For a
	// scalar it is [Fold] of the text the legacy service compares the value
	// by, so the number 5 and the string "5" share a key, and so do true and
	// "TRUE". For a list or an object it is Fold of its Java [Text], which a
	// string equals it by. Generated code compares a number with a number or
	// a string by n instead, and the two are unequal unless both have n; two
	// numbers that both lack n, such as 1e400, compare by k (ADR-0083).
	Key *string
	// ck: the key with case, the same text before [Fold].
	CaseKey *string
	// ks: the keys of the elements that are not null, for a list; the record's
	// own Key for any other value, which a collection operator reads as a list
	// of one. A number element compares with a number or a string by the n of
	// its record in e instead.
	Keys []string
	// o: for an object, the key two objects are equal by: members in key
	// order, keys and strings with their case, and each value typed, so
	// {"a": 1} and {"a": "1"} have two keys. A number is keyed by its n, or by
	// its [NumberText] where it has none, so {"a": 1}, {"a": 1.0}, and
	// {"a": 1e0} share one (ADR-0083). A list compares by its elements, whose
	// records carry their own.
	Structure *string
	// n: the number new BigDecimal(ck) reads, set for a number and for a
	// string that BigDecimal reads; <, <=, >, and >= compare n, and so does ==
	// between a number and a number or a string. A fraction or an exponent has
	// the value of its Double, so 1e-400 is 0, and 1e400, whose ck is
	// Infinity, has none. n is normalized, so two equal numbers have the same
	// n.
	Number *jsonvalue.Decimal
	// e: the records of the elements of a list, null elements included.
	Elements []Record
}

// WithState returns the record of an operand in state s, which carries no
// value. s must not be StateValue or StateNullElement; [Of] builds those.
func WithState(s State) Record {
	return Record{State: s}
}

// Of returns the record of v as the operand's value: state NULL for nil,
// EMPTY_COLL for an empty list, NULL_ELEMENT for a list that holds nil, and
// VALUE otherwise. Of panics if v is not a [jsonvalue.Value].
func Of(v jsonvalue.Value) Record {
	switch x := v.(type) {
	case nil:
		return Record{State: StateNull}
	case string:
		return scalar(TypeString, ClassString, x)
	case jsonvalue.Number:
		return scalar(TypeNumber, ClassScalar, NumberText(x))
	case bool:
		return scalar(TypeBoolean, ClassScalar, Text(x))
	case []jsonvalue.Value:
		return listRecord(x)
	case *jsonvalue.Object:
		ck := Text(x)
		k := Fold(ck)
		sk := structureKey(x)
		return Record{State: StateValue, Class: ClassOther, Type: TypeObject, Key: &k, CaseKey: &ck,
			Keys: []string{k}, Structure: &sk}
	}
	panic("legacyvalue: not a Value")
}

func scalar(t Type, c Class, text string) Record {
	k := Fold(text)
	r := Record{State: StateValue, Class: c, Type: t, Key: &k, CaseKey: &text, Keys: []string{k}}
	if d, ok := jsonvalue.ParseBigDecimal(text); ok {
		r.Number = &d
	}
	return r
}

func listRecord(list []jsonvalue.Value) Record {
	if len(list) == 0 {
		return Record{State: StateEmptyColl}
	}
	ck := Text(list)
	k := Fold(ck)
	r := Record{State: StateValue, Class: ClassList, Type: TypeArray, Key: &k, CaseKey: &ck,
		Keys: []string{}, Elements: make([]Record, len(list))}
	for i, e := range list {
		er := Of(e)
		r.Elements[i] = er
		switch e.(type) {
		case nil:
			r.State = StateNullElement
			r.Class = ClassOther
			continue
		case string, jsonvalue.Number, bool:
		default:
			r.Class = ClassOther
		}
		r.Keys = append(r.Keys, Fold(Text(e)))
	}
	return r
}

// Term returns the record as a Rego object with the keys s, t, j, k, ck, ks, o,
// n, nl, and e, leaving out every field the record does not set. n is a
// Rego number with the text of [jsonvalue.Decimal.String], and nl, set beside it, is true
// when the number is not [jsonvalue.Decimal.Short]: generated code then compares it with
// nc.decimal.compare rather than with Rego's own operators.
func (r Record) Term() *ast.Term {
	obj := ast.NewObject(ast.Item(ast.InternedTerm("s"), ast.StringTerm(string(r.State))))
	put := func(key string, v *ast.Term) {
		obj.Insert(ast.InternedTerm(key), v)
	}
	if r.Class != "" {
		put("t", ast.StringTerm(string(r.Class)))
		put("j", ast.StringTerm(string(r.Type)))
	}
	if r.Key != nil {
		put("k", ast.StringTerm(*r.Key))
		put("ck", ast.StringTerm(*r.CaseKey))
	}
	if r.Keys != nil {
		keys := make([]*ast.Term, len(r.Keys))
		for i, k := range r.Keys {
			keys[i] = ast.StringTerm(k)
		}
		put("ks", ast.ArrayTerm(keys...))
	}
	if r.Structure != nil {
		put("o", ast.StringTerm(*r.Structure))
	}
	if r.Number != nil {
		put("n", ast.NewTerm(ast.Number(r.Number.String())))
		put("nl", ast.BooleanTerm(!r.Number.Short()))
	}
	if r.Elements != nil {
		elems := make([]*ast.Term, len(r.Elements))
		for i, e := range r.Elements {
			elems[i] = e.Term()
		}
		put("e", ast.ArrayTerm(elems...))
	}
	return ast.NewTerm(obj)
}

// structureKey returns a text of v in which every object lists its members in
// key order, a string is quoted with its case, and a number is unquoted as its
// n prints it, or as [NumberText] where it has none, so a number and a string
// of the same digits differ.
func structureKey(v jsonvalue.Value) string {
	var b strings.Builder
	writeStructureKey(&b, v)
	return b.String()
}

func writeStructureKey(b *strings.Builder, v jsonvalue.Value) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case jsonvalue.Number:
		if d, ok := jsonvalue.ParseBigDecimal(NumberText(x)); ok {
			b.WriteString(d.String())
		} else {
			b.WriteString(NumberText(x))
		}
	case string:
		b.WriteString(strconv.Quote(x))
	case []jsonvalue.Value:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeStructureKey(b, e)
		}
		b.WriteByte(']')
	case *jsonvalue.Object:
		keys := slices.Sorted(slices.Values(x.Keys()))
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(strconv.Quote(k))
			b.WriteByte(':')
			e, _ := x.Get(k)
			writeStructureKey(b, e)
		}
		b.WriteByte('}')
	}
}
