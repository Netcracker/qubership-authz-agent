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
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"authz-agent/internal/policyir"
	"authz-agent/internal/regogen/spectables"
)

// tpl is the template of a value-dependent cell: the true and the false rows
// of the comparison of two values, and the record fields the true rows read of
// each side.
type tpl struct {
	t, f   dnf
	fields map[*side]map[string]bool
	// undefined is set when a value leaves the comparison on neither rail.
	undefined bool
	// rules are the value rules the template implements; a cell that names
	// another rule is not this template's.
	rules map[spectables.ValueRule]bool
}

// fieldClasses lists the classes of the domain of s whose record carries
// every field the true rows read of s, as [record] writes them.
func (t tpl) fieldClasses(s *side) []spectables.Class {
	var out []spectables.Class
	for _, cl := range s.ref.domain.Classes {
		ok := true
		for f := range t.fields[s] {
			if !fieldOf(f, cl) {
				ok = false
			}
		}
		if ok {
			out = append(out, cl)
		}
	}
	return out
}

// fieldOf reports whether [record] writes field f, which the module reads,
// for a value of class cl: key, match_key, and number for s and n; value_key
// for s; element_keys and element_own_keys for every class but z; text and
// the segments for s; text_key, eq_alts, and eq_index for the lists and the
// object.
// Any other field, such as has_null, keeps the check of the class.
func fieldOf(f string, cl spectables.Class) bool {
	switch f {
	case fieldKey, fieldNumber, fieldMatchKey:
		return cl == spectables.ClassString || cl == spectables.ClassScalar
	case fieldValueKey:
		return cl == spectables.ClassString
	case fieldElementKeys, fieldElementOwnKeys:
		return cl != spectables.ClassNull
	case fieldText, fieldSegments:
		return cl == spectables.ClassString
	case fieldTextKey, fieldEqAlts, fieldEqIndex:
		return cl == spectables.ClassList || cl == spectables.ClassPIPList || isStructure(cl)
	}
	return false
}

// isStructureOrList reports whether cl is a list or an object.
func isStructureOrList(cl spectables.Class) bool {
	return isListClass(cl) || cl == spectables.ClassObject
}

// isListClass reports whether cl is a list.
func isListClass(cl spectables.Class) bool {
	return cl == spectables.ClassList || cl == spectables.ClassPIPList || cl == spectables.ClassNullElement ||
		cl == spectables.ClassNested
}

// isStructure reports whether cl is a list with a null, a list or object
// element, or an object.
func isStructure(cl spectables.Class) bool {
	return cl == spectables.ClassNullElement || cl == spectables.ClassNested || cl == spectables.ClassObject
}

func lit(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func setLit(keys []string) string {
	if len(keys) == 0 {
		return "set()"
	}
	sorted := slices.Clone(keys)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	parts := make([]string, len(sorted))
	for i, k := range sorted {
		parts[i] = lit(k)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

type tb struct {
	fields map[*side]map[string]bool
}

func (b *tb) use(s *side, f string) {
	if s.ref == nil {
		return
	}
	s.ref.read |= fieldBit(f)
	if b.fields[s] == nil {
		b.fields[s] = map[string]bool{}
	}
	b.fields[s][f] = true
}

// key is the key of a scalar side, as a literal or a field.
func (b *tb) key(s *side) string {
	if s.ref == nil {
		return lit(s.lit.key)
	}
	b.use(s, fieldKey)
	return s.field(fieldKey)
}

// elementKeys is the set of element keys of a list side, as a literal or a
// field.
func (b *tb) elementKeys(s *side) string {
	if s.ref == nil {
		return setLit(s.lit.keys)
	}
	b.use(s, fieldElementKeys)
	return s.field(fieldElementKeys)
}

func vfact(s *side) fact {
	if s.ref == nil {
		return fact{}
	}
	return fact{ref: s.ref.ID, field: factValue}
}

func isScalar(c spectables.Class) bool {
	return c == spectables.ClassString || c == spectables.ClassScalar
}

func isRes(k spectables.Kind) bool {
	return k == spectables.KindResource || k == spectables.KindResPath || k == spectables.KindResNested ||
		k == spectables.KindResJSONPath
}

// negated maps an operator to the one it negates within the value-by-value
// case.
var negated = map[spectables.Operator]spectables.Operator{
	spectables.OpNE: spectables.OpEQ, spectables.OpNotIn: spectables.OpIn,
	spectables.OpNotContains: spectables.OpContains, spectables.OpNotContainsAny: spectables.OpContainsAny,
	spectables.OpNotMatch: spectables.OpMatch, spectables.OpIsNotSubset: spectables.OpIsSubset,
}

// template returns the rows of a comparison between a value of class cl on the
// left and one of class cr on the right, and false when no template covers the
// pair. The cells say where a template applies, and the templates say how
// the values decide.
func template(op spectables.Operator, L, R *side, cl, cr spectables.Class) (tpl, bool) {
	if _, ok := negated[op]; ok {
		return valueTemplate(op, L, R, cl, cr)
	}
	// A list with a null element (class list_with_null, or a SINGLE_ODD list
	// read as one) ends the rule on one side of a collection operator: the
	// right of IN, the left of CONTAINS, and the left of CONTAINS ANY when the
	// right has none.
	// The agent reads the end as undefined, so both rails require that side to
	// hold no null element; elsewhere the null element has no key and the
	// list compares as any other.
	var ends *side
	switch op {
	case spectables.OpIn:
		if cr == spectables.ClassNullElement {
			ends = R
		}
	case spectables.OpContains:
		if cl == spectables.ClassNullElement {
			ends = L
		}
	case spectables.OpContainsAny:
		if cl == spectables.ClassNullElement && cr != spectables.ClassNullElement {
			// with a null on both sides the values are compared, and a null
			// equals nothing, so the keys without it decide
			ends = L
		}
	}
	t, ok := valueTemplate(op, L, R, cl, cr)
	if !ok || ends == nil || ends.ref == nil {
		return t, ok
	}
	g := conj(ends.bind(), clause{{cls: ends.cls(clsCheck), text: "not " + ends.field(fieldHasNull), fact: vfact(ends),
		test: refTest(ends, &test{kind: "non0"})}})
	t.t = prod(dnf{g}, t.t, true)
	t.f = prod(dnf{g}, t.f, true)
	if t.fields[ends] == nil {
		t.fields[ends] = map[string]bool{}
	}
	t.fields[ends][fieldHasNull] = true
	t.undefined = true
	t.rules[spectables.RuleNullElementEnds] = true
	return t, true
}

func valueTemplate(op spectables.Operator, L, R *side, cl, cr spectables.Class) (tpl, bool) {
	if pos, ok := negated[op]; ok {
		t, ok := template(pos, L, R, cl, cr)
		if !ok {
			return tpl{}, false
		}
		// the true rows of the negation are the false rows of the operator,
		// which carry their own checks; the fields its true rows read are
		// the fields those checks read
		fields := map[*side]map[string]bool{}
		for _, s := range []*side{L, R} {
			if s != nil && s.ref != nil {
				fields[s] = map[string]bool{"guard": true}
			}
		}
		return tpl{t: t.f, f: t.t, fields: fields, undefined: t.undefined, rules: t.rules}, true
	}
	if (op == spectables.OpIsEmpty || op == spectables.OpIsNotEmpty) && L.ref != nil && isListClass(cl) {
		// a list in state VALUE is empty by its length: the whole resource
		// [], or a subject list (rule empty)
		empty := conj(L.bind(), clause{{cls: L.cls(clsCheck), text: L.field(fieldLength) + " == 0", fact: vfact(L)}})
		full := conj(L.bind(), clause{{cls: L.cls(clsCheck), text: L.field(fieldLength) + " > 0", fact: vfact(L)}})
		if op == spectables.OpIsNotEmpty {
			empty, full = full, empty
		}
		return tpl{t: dnf{empty}, f: dnf{full}, fields: map[*side]map[string]bool{L: {fieldLength: true}},
			rules: map[spectables.ValueRule]bool{spectables.RuleEmpty: true}}, true
	}
	if R == nil {
		return tpl{}, false
	}
	b := &tb{fields: map[*side]map[string]bool{}}
	out := func(rule spectables.ValueRule, t, f dnf) (tpl, bool) {
		return tpl{t: t, f: f, fields: b.fields, rules: map[spectables.ValueRule]bool{rule: true}}, true
	}
	lref, rref := L.ref != nil, R.ref != nil
	net := lref && L.ref.Network || rref && R.ref.Network
	if op == spectables.OpEQ && (isStructureOrList(cl) && cr == spectables.ClassString && lref ||
		cl == spectables.ClassString && isStructureOrList(cr) && rref) {
		// a list or an object equals a string by its Java text under
		// equalsIgnoreCase: value_op reaches it for a list on the left
		// (structure_text_left), eq for every other order (eq)
		structure, text := L, R
		if !isStructureOrList(cl) {
			structure, text = R, L
		}
		b.use(structure, fieldTextKey)
		bind := conj(L.bind(), R.bind())
		c := clsCheck
		if net {
			c = clsAfterBuilt
		}
		t := conj(bind, clause{{cls: c, text: structure.field(fieldTextKey) + " == " + b.key(text), fact: vfact(structure)}})
		f := conj(bind, clause{{cls: c, text: structure.field(fieldTextKey) + " != " + b.key(text), fact: vfact(structure)}})
		tp, _ := out(spectables.RuleEq, dnf{t}, dnf{f})
		tp.rules[spectables.RuleStructureTextLeft] = true
		return tp, true
	}
	if op == spectables.OpContains && cl == spectables.ClassObject && cr == spectables.ClassString && lref {
		// an object on the left of CONTAINS equals a string by its Java text
		b.use(L, fieldTextKey)
		bind := conj(L.bind(), R.bind())
		c := L.cls(clsCheck)
		if net {
			c = clsAfterBuilt
		}
		t := conj(bind, clause{{cls: c, text: L.field(fieldTextKey) + " == " + b.key(R), fact: vfact(L)}})
		f := conj(bind, clause{{cls: c, text: L.field(fieldTextKey) + " != " + b.key(R), fact: vfact(L)}})
		return out(spectables.RuleStructureTextLeft, dnf{t}, dnf{f})
	}
	if op == spectables.OpContains && cl == spectables.ClassObject && isListClass(cr) && lref && rref &&
		!isRes(R.kind) {
		// an object on the left of CONTAINS contains a string by its text or
		// an equal object, never a list
		return out(spectables.RuleObjectEq, dnfFalse, dnf{conj(L.bind(), R.bind())})
	}
	if op == spectables.OpIn && lref && !rref && (isListClass(cl) || cl == spectables.ClassObject) {
		// a list or an object on the left of IN is in a literal list holding
		// its Java text
		b.use(L, fieldTextKey)
		keys := R.lit.keys
		t := conj(L.bind(), clause{{cls: L.cls(clsCheck), text: L.field(fieldTextKey) + " in " + setLit(keys), fact: vfact(L)}})
		f := conj(L.bind(), clause{{cls: L.cls(clsCheck), text: "not " + L.field(fieldTextKey) + " in " + setLit(keys),
			fact: vfact(L)}})
		return out(spectables.RuleStructureTextLeft, dnf{t}, dnf{f})
	}
	if (op == spectables.OpIn || op == spectables.OpContains || op == spectables.OpEQ) &&
		cl == spectables.ClassObject && cr == spectables.ClassObject && lref && rref {
		// two objects are equal by their members: the same names, each value
		// equal, a list inside in order (ADR-0083 R6)
		t, f := b.eqStructures(L, R, net)
		// IN and CONTAINS reach the comparison through object_eq, == through
		// eq
		tp, _ := out(spectables.RuleObjectEq, t, f)
		tp.rules[spectables.RuleEq] = true
		return tp, true
	}
	switch op {
	case spectables.OpIsSubset:
		return subsetTemplate(L, R, b)
	case spectables.OpLT, spectables.OpLE, spectables.OpGT, spectables.OpGE:
		if !isScalar(cl) || !isScalar(cr) {
			return tpl{}, false
		}
		return relTemplate(op, L, R, b)
	case spectables.OpMatch:
		if cl != spectables.ClassString || !R.isPattern() || !lref {
			return tpl{}, false
		}
		rx, err := matchRegex(R.pattern)
		if err != nil {
			return tpl{}, false
		}
		b.use(L, fieldText)
		call := expr{cls: L.cls(clsCheck), text: fmt.Sprintf("regex.match(%s, %s)", lit(rx), L.field(fieldText)),
			fact: vfact(L)}
		t := conj(L.bind(), clause{call})
		if !L.ref.Network {
			if guards := segmentGuards(R.pattern, L.ref.ID); len(guards) > 0 {
				L.ref.Segments = true
				t = conj(guards, t)
			}
		}
		f := conj(L.bind(), clause{{cls: L.cls(clsCheck),
			text: fmt.Sprintf("not regex.match(%s, %s)", lit(rx), L.field(fieldText)), fact: vfact(L)}})
		return out(spectables.RuleMatch, dnf{t}, dnf{f})
	case spectables.OpEQ:
		// a null element is an element of the set too
		listOrNested := func(c spectables.Class) bool {
			return c == spectables.ClassList || c == spectables.ClassNested || c == spectables.ClassNullElement
		}
		if listOrNested(cl) && listOrNested(cr) && lref && rref {
			// two lists are equal as sets of elements, each compared by
			// value (ADR-0083 R6)
			t, f := b.eqStructures(L, R, net)
			return out(spectables.RuleListEq, t, f)
		}
		if (cl == spectables.ClassScalar || cl == spectables.ClassObject || cl == spectables.ClassNull) &&
			isListClass(cr) && rref {
			// a number, a boolean, an object, or a null equals no list: only a
			// string is compared with a list's Java text
			return out(spectables.RuleEq, dnfFalse, dnf{conj(L.bind(), R.bind())})
		}
		if !isScalar(cl) || !isScalar(cr) || !lref && !rref {
			return tpl{}, false
		}
		if lref && rref {
			c := clsCheck
			if net {
				c = clsAfterBuilt
			}
			t, f := b.eqRefs(L, R, cl, cr, c)
			return out(spectables.RuleEq, t, dnf{f})
		}
		ref, lits, rc := L, R, cl
		if !lref {
			ref, lits, rc = R, L, cr
		}
		t, f := b.eqLiteral(ref, lits.lit.keys, rc)
		return out(spectables.RuleEq, t, dnf{f})
	case spectables.OpIn:
		if cl == spectables.ClassNull && lref {
			// a null on the left is in no list; a null element on the right
			// ends the rule before the values are compared
			return out(spectables.RuleInAny, dnfFalse, dnf{conj(L.bind(), R.bind())})
		}
		if (cl == spectables.ClassList || isStructure(cl)) && lref && rref {
			// a list or an object on the left is in the right when a string
			// there equals its Java text
			b.use(L, fieldTextKey)
			c := clsCheck
			if net {
				c = clsAfterBuilt
			}
			bind := conj(L.bind(), R.bind())
			t := conj(bind, clause{{cls: c, text: L.field(fieldTextKey) + " in " + b.elementKeys(R), fact: vfact(L)}})
			f := conj(bind, clause{{cls: c, text: "not " + L.field(fieldTextKey) + " in " + b.elementKeys(R), fact: vfact(L)}})
			return out(spectables.RuleStructureTextLeft, dnf{t}, dnf{f})
		}
		rightOK := isScalar(cr) || cr == spectables.ClassList || cr == spectables.ClassPIPList ||
			isStructure(cr) && rref
		if !isScalar(cl) || !rightOK {
			return tpl{}, false
		}
		if !lref {
			if !rref {
				return tpl{}, false
			}
			// each own token of the literal is a clause of its own, which
			// the OPA rule index files under the token
			var t dnf
			var f clause
			eks := b.elementKeys(R)
			for _, k := range L.lit.own {
				t = append(t, conj(R.bind(), clause{{cls: R.cls(clsIndexIn), text: lit(k) + " in " + eks, fact: vfact(R),
					test: refTest(R, &test{kind: "has", val: k})}}))
				f = append(f, expr{cls: R.cls(clsCheck), text: "not " + lit(k) + " in " + eks,
					fact: vfact(R), test: refTest(R, &test{kind: "nothas", val: k})})
			}
			return out(spectables.RuleInAny, t, dnf{conj(R.bind(), f)})
		}
		if !rref {
			t, f := b.eqLiteral(L, R.lit.keys, cl)
			return out(spectables.RuleInAny, t, dnf{f})
		}
		c := clsCheck
		if net {
			c = clsAfterBuilt
		}
		bind := conj(L.bind(), R.bind())
		var t dnf
		var f clause
		for _, lf := range ownFields(cl) {
			b.use(L, lf)
			inref := func(kind string) *test {
				if t := pairTest(kind, L, R); t != nil {
					t.field = scalarField(lf)
					return t
				}
				return nil
			}
			t = append(t, conj(bind, clause{{cls: c, text: L.field(lf) + " in " + b.elementKeys(R), fact: vfact(L),
				test: inref("inref")}}))
			f = append(f, expr{cls: c, text: "not " + L.field(lf) + " in " + b.elementKeys(R), fact: vfact(L),
				test: inref("notinref")})
		}
		return out(spectables.RuleInAny, t, dnf{conj(bind, f)})
	case spectables.OpContains, spectables.OpContainsAny:
		listy := func(c spectables.Class) bool {
			return isScalar(c) || c == spectables.ClassList || c == spectables.ClassPIPList || isStructure(c)
		}
		if op == spectables.OpContains && rref && isRes(R.kind) && isListClass(cr) {
			// a resource attribute on the right is one value, and no element
			// equals a list (right_attribute_one_value,
			// contains_right_attribute_list_false)
			b.use(L, fieldElementKeys)
			return out(spectables.RuleContainsRightAttributeList, dnfFalse, dnf{conj(L.bind(), R.bind())})
		}
		subjectList := cr == spectables.ClassList || cr == spectables.ClassNullElement ||
			cr == spectables.ClassNested
		if op == spectables.OpContains && rref && !isScalar(cr) && cr != spectables.ClassObject &&
			(!subjectList || isRes(R.kind)) {
			// a list on the right of CONTAINS is one value, unless it is a
			// list of class list, list_with_null, or nested_list of the
			// subject or a PIP, whose cells
			// add right_list_scalar_ops: the template then sees a list of at
			// most one value
			return tpl{}, false
		}
		if !listy(cl) || !listy(cr) {
			return tpl{}, false
		}
		structured := func(c spectables.Class) bool {
			return c == spectables.ClassNested || c == spectables.ClassNullElement || c == spectables.ClassObject
		}
		if structured(cl) || structured(cr) {
			// a list or an object takes part, so elements are equal as eq
			// says, which their deeps give (Record.ElementAlts)
			c := clsCheck
			if net {
				c = clsAfterBuilt
			}
			if !lref || !rref {
				// a literal is a scalar or a list of scalars, equal to an
				// element exactly where one of its deeps is in that
				// element's index
				lits, other := L, R
				if lref {
					lits, other = R, L
				}
				b.use(other, fieldElementIndex)
				ix := other.field(fieldElementIndex)
				anyText, noneText := literalDeepAny(lits.lit.alts, ix)
				test := func(kind string) *test { return refTest(other, &test{kind: kind, alts: lits.lit.alts}) }
				t := conj(other.bind(), clause{{cls: other.cls(c), text: anyText, fact: vfact(other),
					test: rightTest(test("deepany"))}})
				f := conj(other.bind(), clause{{cls: other.cls(c), text: noneText, fact: vfact(other),
					test: rightTest(test("deepnone"))}})
				return out(spectables.RuleContainsAny, dnf{t}, dnf{f})
			}
			b.use(L, fieldElementAlts)
			b.use(R, fieldElementIndex)
			bind := conj(L.bind(), R.bind())
			alts, ix := L.field(fieldElementAlts), R.field(fieldElementIndex)
			t := conj(bind, clause{{cls: c, text: regoDeepAny(alts, ix), fact: vfact(L), test: pairTest("deepany", L, R)}})
			f := conj(bind, clause{{cls: c, text: regoDeepNone(alts, ix), fact: vfact(L), test: pairTest("deepnone", L, R)}})
			return out(spectables.RuleContainsAny, dnf{t}, dnf{f})
		}
		rks := ""
		if rref {
			rks = b.elementKeys(R)
		}
		// With literals on one side, each literal gets a clause of its own,
		// "k" in element_keys, because the OPA rule index files such a clause
		// under k and skips it for a request whose element_keys lacks k. One
		// clause for all literals, some x in element_keys; x in {...}, is a loop the index cannot file,
		// so every request evaluates it. On the PROD corpus with subject groups
		// it saved under 0.2 % of the clauses and made Eval p50 and p99 3 to 7 %
		// slower on the bundles it changed. Without groups it cut the largest
		// module from 82239 to 24254 clauses at equal Eval, so a form without
		// groups may want it.
		if !lref {
			if !rref {
				return tpl{}, false
			}
			var ts dnf
			for _, k := range L.lit.own {
				ts = append(ts, conj(R.bind(), clause{{cls: R.cls(clsIndexIn), text: lit(k) + " in " + rks,
					fact: vfact(R), test: refTest(R, &test{kind: "has", val: k})}}))
			}
			f := conj(R.bind(), clause{{cls: R.cls(clsCheck), fact: vfact(R),
				test: refTest(R, &test{kind: "none", set: L.lit.own}),
				text: fmt.Sprintf("every x in %s { not x in %s }", rks, setLit(L.lit.own))}})
			return out(spectables.RuleContainsAny, union(ts), dnf{f})
		}
		if !rref {
			var ts dnf
			for _, k := range R.lit.own {
				ts = append(ts, conj(L.bind(), clause{{cls: L.cls(clsIndexIn), text: lit(k) + " in " + b.elementKeys(L),
					fact: vfact(L), test: refTest(L, &test{kind: "has", val: k})}}))
			}
			f := conj(L.bind(), clause{{cls: L.cls(clsCheck), fact: vfact(L),
				test: refTest(L, &test{kind: "none", set: R.lit.own}),
				text: fmt.Sprintf("every x in %s { not x in %s }", b.elementKeys(L), setLit(R.lit.own))}})
			return out(spectables.RuleContainsAny, union(ts), dnf{f})
		}
		c := clsCheck
		if net {
			c = clsAfterBuilt
		}
		v := "x_" + L.ref.Var + "_" + R.ref.Var
		bind := conj(L.bind(), R.bind())
		b.use(L, fieldElementOwnKeys)
		own := L.field(fieldElementOwnKeys)
		pair := func(kind string) *test {
			if t := pairTest(kind, L, R); t != nil {
				t.field = fieldElementOwnKeys
				return t
			}
			return nil
		}
		t := conj(bind, clause{{cls: c, text: fmt.Sprintf("some %s in %s", v, own), fact: vfact(L),
			test: pair("overlap")},
			{cls: c, text: fmt.Sprintf("%s in %s", v, rks), fact: vfact(R), test: pairTest("noop", L, R)}})
		f := conj(bind, clause{{cls: c, fact: vfact(L), test: pair("disjoint"),
			text: fmt.Sprintf("every %s in %s { not %s in %s }", v, own, v, rks)}})
		return out(spectables.RuleContainsAny, dnf{t}, dnf{f})
	}
	return tpl{}, false
}

// matchRegex is the [policyir.Pattern.Anchored] of a MATCH pattern.
func matchRegex(pattern string) (string, error) {
	return policyir.Pattern{Text: pattern}.Anchored()
}

// segmentGuards are equalities a value must satisfy to match the pattern: its
// literal path segments, counted from the start up to the first segment that
// can span a slash and from the end after the last one, and the number of
// segments when no segment can. The index of OPA uses each of them.
func segmentGuards(pattern, ref string) clause {
	const most = 3
	isMeta := func(s string) bool { return strings.ContainsAny(s, `*?().[]{}+^$|\`) }
	breaks := func(s string) bool { return strings.Contains(s, "**") || strings.Contains(s, ".") }
	if strings.ContainsAny(pattern, `[]{}+^$|\`) {
		return nil
	}
	segs := strings.Split(pattern, "/")
	first, last := -1, -1
	for i, s := range segs {
		if breaks(s) {
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	var out clause
	if first < 0 {
		out = append(out, expr{cls: clsIndexEq, text: fmt.Sprintf("input.%s%s == %d", fieldSegmentCount, refIndex(ref), len(segs))})
	}
	head := segs
	if first >= 0 {
		head = segs[:first]
	}
	n := 0
	for i := len(head) - 1; i >= 0 && n < most; i-- {
		if head[i] != "" && !isMeta(head[i]) {
			out = append(out, expr{cls: clsIndexEq, text: fmt.Sprintf("input.%s%s[%d] == %s", fieldSegments, refIndex(ref), i, lit(head[i]))})
			n++
		}
	}
	if last >= 0 {
		tail := segs[last+1:]
		for j := 0; j < len(tail) && len(out) < most+1; j++ {
			x := tail[len(tail)-1-j]
			if x != "" && !isMeta(x) {
				out = append(out, expr{cls: clsIndexEq, text: fmt.Sprintf("input.%s%s[%d] == %s", fieldSegmentsFromEnd, refIndex(ref), j, lit(x))})
			}
		}
	}
	return out
}

// refTest returns t for the reference of s, or nil when the group evaluator
// cannot read s: a literal or a network PIP.
func refTest(s *side, t *test) *test {
	if s.ref == nil || s.ref.Network {
		return nil
	}
	t.ref = s.ref.ID
	return t
}

// eqLiteral returns the rows where the scalar reference s of class cl equals
// a literal whose match tokens are match, and the clause where it does not:
// where the own tokens of s, its key and value_key, meet match.
func (b *tb) eqLiteral(s *side, match []string, cl spectables.Class) (dnf, clause) {
	keys, values := splitTokens(match, cl == spectables.ClassString)
	var t dnf
	var f clause
	for _, g := range []struct {
		field  string
		tokens []string
	}{{fieldKey, keys}, {fieldValueKey, values}} {
		if len(g.tokens) == 0 {
			continue
		}
		b.use(s, g.field)
		x, tf := s.field(g.field), scalarField(g.field)
		if len(g.tokens) == 1 {
			t = append(t, conj(s.bind(), clause{{cls: s.cls(clsIndexEq), text: x + " == " + lit(g.tokens[0]), fact: vfact(s),
				test: refTest(s, &test{kind: "eq", val: g.tokens[0], field: tf})}}))
			f = append(f, expr{cls: s.cls(clsCheck), text: x + " != " + lit(g.tokens[0]), fact: vfact(s),
				test: refTest(s, &test{kind: "ne", val: g.tokens[0], field: tf})})
			continue
		}
		t = append(t, conj(s.bind(), clause{{cls: s.cls(clsIndexIn), text: x + " in " + setLit(g.tokens), fact: vfact(s),
			test: refTest(s, &test{kind: "in", set: g.tokens, field: tf})}}))
		f = append(f, expr{cls: s.cls(clsCheck), text: "not " + x + " in " + setLit(g.tokens), fact: vfact(s),
			test: refTest(s, &test{kind: "notin", set: g.tokens, field: tf})})
	}
	return t, conj(s.bind(), f)
}

// eqRefs returns the rows where the scalar references L, of class cl, and R,
// of class cr, are equal, and the clause where they are not: where the own
// tokens of L meet the match tokens of R. Two values of one class compare by
// key alone: the N token a number owns never meets the S token another number
// matches, nor does the S token a string owns meet the N token another string
// matches.
func (b *tb) eqRefs(L, R *side, cl, cr spectables.Class, c int) (dnf, clause) {
	bind := conj(L.bind(), R.bind())
	b.use(L, fieldKey)
	b.use(R, fieldKey)
	t := dnf{conj(bind, clause{{cls: c, text: L.field(fieldKey) + " == " + R.field(fieldKey), fact: vfact(L),
		test: pairTest("eqref", L, R)}})}
	f := clause{{cls: c, text: L.field(fieldKey) + " != " + R.field(fieldKey), fact: vfact(L), test: pairTest("neref", L, R)}}
	if cl != cr {
		lf := fieldKey
		if cl == spectables.ClassString {
			lf = fieldValueKey
		}
		b.use(L, lf)
		b.use(R, fieldMatchKey)
		pair := func(kind string) *test {
			if t := pairTest(kind, L, R); t != nil {
				t.field, t.rightField = scalarField(lf), fieldMatchKey
				return t
			}
			return nil
		}
		x := L.field(lf) + " == " + R.field(fieldMatchKey)
		t = append(t, conj(bind, clause{{cls: c, text: x, fact: vfact(L), test: pair("eqref")}}))
		f = append(f, expr{cls: c, text: "not " + x, fact: vfact(L), test: pair("noteqref")})
	}
	return t, conj(bind, f)
}

// ownFields are the fields of the own tokens of a scalar of class cl: key,
// and value_key for a string.
func ownFields(cl spectables.Class) []string {
	if cl == spectables.ClassString {
		return []string{fieldKey, fieldValueKey}
	}
	return []string{fieldKey}
}

// scalarField is the field a test names for a scalar field f of a record:
// empty for key, which a test reads by default.
func scalarField(f string) string {
	if f == fieldKey {
		return ""
	}
	return f
}

// eqStructures returns the rows where two references are equal as == compares
// two lists or two objects, each element of one equal to some element of the
// other, and the rows where they are not; net marks a side from the network.
func (b *tb) eqStructures(L, R *side, net bool) (dnf, dnf) {
	for _, s := range []*side{L, R} {
		b.use(s, fieldEqAlts)
		b.use(s, fieldEqIndex)
	}
	c := clsCheck
	if net {
		c = clsAfterBuilt
	}
	bind := conj(L.bind(), R.bind())
	la, li, ra, ri := L.field(fieldEqAlts), L.field(fieldEqIndex), R.field(fieldEqAlts), R.field(fieldEqIndex)
	t := conj(bind, clause{{cls: c, text: regoEqAll(la, ri), fact: vfact(L)}, {cls: c, text: regoEqAll(ra, li), fact: vfact(R)}})
	return dnf{t}, dnf{
		conj(bind, clause{{cls: c, text: regoEqNotAll(la, ri), fact: vfact(L)}}),
		conj(bind, clause{{cls: c, text: regoEqNotAll(ra, li), fact: vfact(R)}}),
	}
}

// rightTest moves the reference of a test of refTest to the right: a test
// of deepany or deepnone reads the alternatives of a literal and the index of
// the reference.
func rightTest(t *test) *test {
	if t != nil {
		t.rightRef, t.ref = t.ref, ""
	}
	return t
}

// pairTest is a test over two references.
func pairTest(kind string, L, R *side) *test {
	if L.ref == nil || R.ref == nil || L.ref.Network || R.ref.Network {
		return nil
	}
	return &test{kind: kind, ref: L.ref.ID, rightRef: R.ref.ID}
}
