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

import "authz-agent/internal/jsonvalue"

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
// Each field comment starts with a short name for the field, by which other
// comments and ADR-0083 refer to it.
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
	// a string by Number instead, and the two are unequal unless both have
	// one; two numbers that both lack one, such as 1e400, compare by ck
	// (ADR-0083).
	Key *string
	// ck: the key with case, the same text before [Fold].
	CaseKey *string
	// ks: the keys of the elements that are not null, for a list; the record's
	// own Key for any other value, which a collection operator reads as a list
	// of one. A number element compares with a number or a string by its value
	// instead.
	Keys []string
	// n: the number new BigDecimal(ck) reads, set for a number and for
	// a string that BigDecimal reads; <, <=, >, and >= compare it, and so does
	// == between a number and a number or a string. A fraction or an exponent
	// has the value of its Double, so 1e-400 is 0, and 1e400, whose ck is
	// Infinity, has none. It is normalized, so two equal numbers have the same
	// Number.
	Number *jsonvalue.Decimal
}

// WithState returns the record of an operand in state s, which carries no
// value. s must not be StateValue or StateNullElement; [Of] builds those.
func WithState(s State) Record {
	return Record{State: s}
}

// Parts names the fields of the record of a list that [OfParts] builds.
type Parts uint8

// The parts of the record of a list.
const (
	// PartKey is k and ck.
	PartKey Parts = 1 << iota
	// PartKeys is ks.
	PartKeys
	// AllParts is every part, the record [Of] returns.
	AllParts = PartKey | PartKeys
)

// Of returns the record of v as the operand's value: state NULL for nil,
// EMPTY_COLL for an empty list, NULL_ELEMENT for a list that holds nil, and
// VALUE otherwise. Of panics if v is not a [jsonvalue.Value].
func Of(v jsonvalue.Value) Record {
	return OfParts(v, AllParts)
}

// OfParts returns the record [Of] returns, with only the parts p of a
// non-empty list; the state and the class of a list, and the record of any
// other value, are whole.
func OfParts(v jsonvalue.Value, p Parts) Record {
	if l, ok := v.([]jsonvalue.Value); ok && len(l) > 0 {
		return listRecord(l, p)
	}
	return of(v)
}

func of(v jsonvalue.Value) Record {
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
		if len(x) == 0 {
			return Record{State: StateEmptyColl}
		}
		return listRecord(x, AllParts)
	case *jsonvalue.Object:
		ck := Text(x)
		k := Fold(ck)
		return Record{State: StateValue, Class: ClassOther, Type: TypeObject, Key: &k, CaseKey: &ck,
			Keys: []string{k}}
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

// listRecord returns the record of a non-empty list with the parts p. It
// writes the Java text of the list once and that of each element once, so
// its cost is linear in the size of the list however deep its lists nest.
func listRecord(list []jsonvalue.Value, p Parts) Record {
	r := Record{State: StateValue, Class: ClassList, Type: TypeArray}
	if p&PartKey != 0 {
		ck := Text(list)
		k := Fold(ck)
		r.CaseKey, r.Key = &ck, &k
	}
	if p&PartKeys != 0 {
		r.Keys = []string{}
	}
	for _, e := range list {
		if !classify(&r, e) && r.Keys != nil {
			r.Keys = append(r.Keys, Fold(Text(e)))
		}
	}
	return r
}

// classify updates the state and the class of the list record r for its
// element e, and reports whether e is null, which has no key in ks.
func classify(r *Record, e jsonvalue.Value) bool {
	switch e.(type) {
	case nil:
		r.State = StateNullElement
		r.Class = ClassOther
		return true
	case string, jsonvalue.Number, bool:
	default:
		r.Class = ClassOther
	}
	return false
}
