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
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/legacyvalue"
)

// Two lists or two objects are equal when their members are equal pairwise,
// and two scalars by the rule of eqtokens.go, at any depth (ADR-0083 R5, R6).
// That rule is not transitive, so no key of a whole value gives it. A value
// is written instead as a deep: its shape and its texts.
//
//	shape  the value with a number and a string that BigDecimal reads as #
//	       and its value, any other string and a boolean as t: and the
//	       folded text quoted, null as null, a list in order, and an object
//	       by its member names with case, in name order
//	texts  the folded text of each string that BigDecimal reads, by the
//	       ordinal of its leaf in the shape
//
// Two deeps are equal when their shapes are equal and, at each leaf that is a
// string in both, their texts are equal: "5.0" and 5 share the shape #5, and
// "5.0" and "5.00" differ in their texts. A number beyond the range of a
// double has the value Infinity, and the string "Infinity", which BigDecimal
// does not read, has the shape t:"infinity".
type deep struct {
	shape string
	texts map[string]string
}

// deepOf returns the deep of v; num gives the value of a number.
func deepOf(v jsonvalue.Value, num numberValue) deep {
	var b strings.Builder
	d := deep{}
	leaf := 0
	writeDeep(&b, v, num, &d, &leaf)
	d.shape = b.String()
	return d
}

func writeDeep(b *strings.Builder, v jsonvalue.Value, num numberValue, d *deep, leaf *int) {
	switch x := v.(type) {
	case []jsonvalue.Value:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeDeep(b, e, num, d, leaf)
		}
		b.WriteByte(']')
		return
	case *jsonvalue.Object:
		b.WriteByte('{')
		for i, k := range slices.Sorted(slices.Values(x.Keys())) {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(strconv.Quote(k))
			b.WriteByte(':')
			e, _ := x.Get(k)
			writeDeep(b, e, num, d, leaf)
		}
		b.WriteByte('}')
		return
	}
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(textShape(strconv.FormatBool(x)))
	case jsonvalue.Number:
		b.WriteString("#" + num(x))
	case string:
		if n, ok := jsonvalue.ParseBigDecimal(x); ok {
			b.WriteString("#" + n.String())
			if d.texts == nil {
				d.texts = map[string]string{}
			}
			d.texts[strconv.Itoa(*leaf)] = legacyvalue.Fold(x)
		} else {
			b.WriteString(textShape(x))
		}
	default:
		panic(fmt.Sprintf("regogen: %T is not a Value", x))
	}
	*leaf++
}

// textShape is the shape of a text that BigDecimal does not read.
func textShape(s string) string { return "t:" + strconv.Quote(legacyvalue.Fold(s)) }

// structureAlias is the deep a list or an object e has as its Java text,
// which a string equals it by (ADR-0083 R8), on the left of a comparison;
// stringAlias is the deep a string s on the right offers it. The two share
// the prefix x:, which no shape has, so the texts of two structures never
// meet.
func structureAlias(e jsonvalue.Value) deep {
	return deep{shape: "x:" + strconv.Quote(legacyvalue.Fold(structureText(e)))}
}

func stringAlias(s string) deep { return deep{shape: "x:" + strconv.Quote(legacyvalue.Fold(s))} }

// deepIndex holds the deeps of a value's elements by their shape, and the
// deeps of one shape in groups by the leaves that have texts.
//
// A deep a equals a deep m of its shape when they agree on the texts of the
// leaves both have texts at, the leaves of m's group where a has a text. A
// group of at most maxSubsetLeaves leaves holds the texts of its deeps at
// every subset of its leaves, so a lookup is one probe per group. A larger
// group holds them at all its leaves only, and a lookup where a lacks a text
// at one of them scans the group. Matching texts where either side may lack
// one has no lookup that is linear in general, so what one lookup in a shape
// reads, its groups and the deeps it may scan, is bounded
// ([deepIndex.tooBig]).
type deepIndex map[string][]*textGroup

// textGroup holds the deeps that have texts at the same leaves. by maps the
// join of a subset of the leaves to the texts of the deeps at that subset, by
// their join: every subset for a group of at most maxSubsetLeaves leaves, the
// whole set for a larger one.
type textGroup struct {
	leaves []string
	by     map[string]map[string][]string
}

// The bounds of a deep index of a request's value: the leaves of a group whose
// subsets it holds, and the groups and scanned deeps one lookup in a shape
// reads.
const (
	maxSubsetLeaves = 3
	maxLookup       = 16
)

func (ix deepIndex) add(d deep) {
	if len(d.texts) == 0 {
		// a deep without texts equals any deep of its shape, so the shape
		// needs no other group, in whatever order the deeps come; most
		// elements, a string that is not a number among them, are such
		// deeps, and their shapes share one list
		ix[d.shape] = noTextsShape
		return
	}
	gs := ix[d.shape]
	if len(gs) > maxLookup || len(gs) == 1 && gs[0] == noTextsGroup {
		// tooBig already holds, and the index is never read, or any deep
		// of the shape is a hit; looking the group up would cost the
		// number of groups per deep
		return
	}
	leaves := slices.Sorted(maps.Keys(d.texts))
	i := slices.IndexFunc(gs, func(g *textGroup) bool { return slices.Equal(g.leaves, leaves) })
	if i < 0 {
		gs = append(gs, &textGroup{leaves: leaves, by: map[string]map[string][]string{}})
		ix[d.shape] = gs
		i = len(gs) - 1
	}
	g := gs[i]
	if len(leaves) > maxSubsetLeaves {
		g.put(leaves, d)
		return
	}
	for mask := range 1 << len(leaves) {
		var sub []string
		for j, l := range leaves {
			if mask>>j&1 == 1 {
				sub = append(sub, l)
			}
		}
		g.put(sub, d)
	}
}

// noTextsGroup is the group of the deeps without texts, and noTextsShape the
// groups of a shape that holds one. Every such shape shares them, and add
// never changes them.
var (
	noTextsGroup = &textGroup{by: map[string]map[string][]string{"": {"": nil}}}
	noTextsShape = []*textGroup{noTextsGroup}
)

// put adds the texts of d at the leaves sub to g.
func (g *textGroup) put(sub []string, d deep) {
	texts := make([]string, len(sub))
	for j, l := range sub {
		texts[j] = d.texts[l]
	}
	k := textsKey(sub)
	if g.by[k] == nil {
		g.by[k] = map[string][]string{}
	}
	g.by[k][textsKey(texts)] = texts
}

// textsKey joins texts, or leaves, with a separator that no text BigDecimal
// reads holds.
func textsKey(texts []string) string { return strings.Join(texts, "\x00\x01") }

// has reports whether ix holds a deep equal to d.
func (ix deepIndex) has(d deep) bool {
	return slices.ContainsFunc(ix[d.shape], func(g *textGroup) bool {
		var sub, texts []string
		for _, l := range g.leaves {
			if x, ok := d.texts[l]; ok {
				sub, texts = append(sub, l), append(texts, x)
			}
		}
		if at, ok := g.by[textsKey(sub)]; ok {
			_, hit := at[textsKey(texts)]
			return hit
		}
		return g.scan(d)
	})
}

// scan reports whether a deep of the large group g agrees with d at the
// leaves both have texts at.
func (g *textGroup) scan(d deep) bool {
	for _, texts := range g.by[textsKey(g.leaves)] {
		agree := true
		for j, l := range g.leaves {
			if x, ok := d.texts[l]; ok && x != texts[j] {
				agree = false
				break
			}
		}
		if agree {
			return true
		}
	}
	return false
}

// tooBig reports whether a lookup in ix may read more than maxLookup groups
// and scanned deeps of one shape, which a value of a request that holds ix
// fails on. A lookup reads every group of the shape, and scans the deeps of a
// group of more than maxSubsetLeaves leaves. A list whose elements of one
// shape spell their numbers alike has one group per shape.
func (ix deepIndex) tooBig() bool {
	for _, gs := range ix {
		read := len(gs)
		for _, g := range gs {
			if len(g.leaves) > maxSubsetLeaves {
				read += len(g.by[textsKey(g.leaves)])
			}
		}
		if read > maxLookup {
			return true
		}
	}
	return false
}

// deepAny reports whether a deep of some element of alts is in ix; deepAll
// whether one of each element is.
func deepAny(alts [][]deep, ix deepIndex) bool {
	return slices.ContainsFunc(alts, func(ds []deep) bool { return slices.ContainsFunc(ds, ix.has) })
}

func deepAll(alts [][]deep, ix deepIndex) bool {
	return !slices.ContainsFunc(alts, func(ds []deep) bool { return !slices.ContainsFunc(ds, ix.has) })
}

// elementAlts returns the deeps each element of v, read as a list, can equal
// another element by under IN, CONTAINS, CONTAINS ANY, and IS SUBSET: a scalar
// its deep, a list or an object also its Java text (structureAlias), and null
// none, since null equals nothing there.
func elementAlts(v jsonvalue.Value, num numberValue) [][]deep {
	out := [][]deep{}
	for _, e := range asList(v) {
		switch e.(type) {
		case nil:
			out = append(out, []deep{})
		case []jsonvalue.Value, *jsonvalue.Object:
			out = append(out, []deep{deepOf(e, num), structureAlias(e)})
		default:
			out = append(out, []deep{deepOf(e, num)})
		}
	}
	return out
}

// elementIndex returns the index the elements of v, read as a list, offer to
// the elementAlts of the other side: each element's deep, a string's
// stringAlias, and the Java text of a list or an object as the shape of a
// string. Null equals nothing and is left out, and so is an object unless
// objects is set.
func elementIndex(v jsonvalue.Value, num numberValue, objects bool) deepIndex {
	ix := deepIndex{}
	for _, e := range asList(v) {
		switch e := e.(type) {
		case nil:
		case *jsonvalue.Object:
			if objects {
				ix.add(deepOf(e, num))
				ix.add(deep{shape: textShape(structureText(e))})
			}
		case []jsonvalue.Value:
			ix.add(deepOf(e, num))
			ix.add(deep{shape: textShape(structureText(e))})
		case string:
			ix.add(deepOf(e, num))
			ix.add(stringAlias(e))
		default:
			ix.add(deepOf(e, num))
		}
	}
	return ix
}

// eqElements returns the deeps of the elements of a list, null included, or
// of an object as the one element, and their index: == compares two lists as
// sets of elements and two objects as one element each (ADR-0083 R6).
func eqElements(v jsonvalue.Value, num numberValue) ([]deep, deepIndex) {
	ds := []deep{}
	ix := deepIndex{}
	for _, e := range asList(v) {
		d := deepOf(e, num)
		ds = append(ds, d)
		ix.add(d)
	}
	return ds, ix
}

func asList(v jsonvalue.Value) []jsonvalue.Value {
	if l, ok := v.([]jsonvalue.Value); ok {
		return l
	}
	return []jsonvalue.Value{v}
}

// A deep is the pair [shape, texts] in a module, an array rather than an
// object because a request holds one per element of a list and an array costs
// a quarter of the bytes. Most deeps have no texts, and they share one empty
// object.
var noTexts = ast.NewTerm(ast.NewObject())

func (d deep) term() *ast.Term { return ast.ArrayTerm(ast.StringTerm(d.shape), textsTerm(d.texts)) }

func textsTerm(texts map[string]string) *ast.Term {
	if len(texts) == 0 {
		return noTexts
	}
	o := ast.NewObject()
	for _, i := range slices.Sorted(maps.Keys(texts)) {
		o.Insert(ast.StringTerm(i), ast.StringTerm(texts[i]))
	}
	return ast.NewTerm(o)
}

func deepsTerm(ds []deep) *ast.Term {
	ts := make([]*ast.Term, len(ds))
	for i, d := range ds {
		ts[i] = d.term()
	}
	return ast.ArrayTerm(ts...)
}

func altsTerm(alts [][]deep) *ast.Term {
	ts := make([]*ast.Term, len(alts))
	for i, ds := range alts {
		ts[i] = deepsTerm(ds)
	}
	return ast.ArrayTerm(ts...)
}

// term writes each shape as a list of its groups, a group as the pair of its
// leaves and the object from a subset of them, a list, to the set of the
// texts there. A shape a deep without texts has needs only that deep's group,
// since such a deep equals any deep of its shape, and all such shapes share
// one term.
func (ix deepIndex) term() *ast.Term {
	o := ast.NewObject()
	for _, shape := range slices.Sorted(maps.Keys(ix)) {
		gs := ix[shape]
		if slices.ContainsFunc(gs, func(g *textGroup) bool { return len(g.leaves) == 0 }) {
			o.Insert(ast.StringTerm(shape), noTextsGroups)
			continue
		}
		ts := make([]*ast.Term, len(gs))
		for i, g := range gs {
			by := ast.NewObject()
			for _, k := range slices.Sorted(maps.Keys(g.by)) {
				set := ast.NewSet()
				for _, tk := range slices.Sorted(maps.Keys(g.by[k])) {
					set.Add(strsTerm(g.by[k][tk]))
				}
				var sub []string
				if k != "" {
					sub = strings.Split(k, "\x00\x01")
				}
				by.Insert(strsTerm(sub), ast.NewTerm(set))
			}
			ts[i] = ast.ArrayTerm(strsTerm(g.leaves), ast.NewTerm(by))
		}
		o.Insert(ast.StringTerm(shape), ast.ArrayTerm(ts...))
	}
	return ast.NewTerm(o)
}

var noTextsGroups = ast.ArrayTerm(ast.ArrayTerm(ast.ArrayTerm(),
	ast.ObjectTerm([2]*ast.Term{ast.ArrayTerm(), ast.SetTerm(ast.ArrayTerm())})))

// deepHit is the Rego text that holds where the index ix has a deep equal to
// the deep a, as deepIndex.has decides; deepMiss its negation. Both call
// deepFunctions.
func deepHit(a, ix string) string { return fmt.Sprintf("%s(%s, %s)", deepHitName, a, ix) }

func deepMiss(a, ix string) string { return "not " + deepHit(a, ix) }

const deepHitName = "deep_hit"

// deepFunctions is the Rego text of the functions deepHit calls, which a
// module holds where it calls them. The first clause of deep_group_hit probes
// the texts at the leaves where the deep has texts, the second scans a large
// group, as deepIndex.has does.
const deepFunctions = `
deep_hit(a, ix) if {
	some g in object.get(ix, a[0], [])
	deep_group_hit(a[1], g)
}

deep_group_hit(t, g) if {
	s := [i | some i in g[0]; t[i]]
	g[1][s][[t[i] | some i in s]]
}

deep_group_hit(t, g) if {
	not g[1][[i | some i in g[0]; t[i]]]
	some k in g[1][g[0]]
	every j, l in g[0] { object.get(t, l, k[j]) == k[j] }
}
`

// The Rego texts of deepAny, its negation, deepAll, and its negation over
// alternatives alts and an index ix.
func regoDeepAny(alts, ix string) string {
	return fmt.Sprintf("count([a | some d in %s; some a in d; %s]) > 0", alts, deepHit("a", ix))
}

func regoDeepNone(alts, ix string) string {
	return fmt.Sprintf("every d in %s { every a in d { %s } }", alts, deepMiss("a", ix))
}

func regoDeepAll(alts, ix string) string {
	return fmt.Sprintf("every d in %s { some a in d; %s }", alts, deepHit("a", ix))
}

func regoDeepNotAll(alts, ix string) string {
	return fmt.Sprintf("count([d | some d in %s; every a in d { %s }]) > 0", alts, deepMiss("a", ix))
}

// literalDeepAny returns the Rego texts of deepAny over the alternatives of
// literals and an index ix, and of its negation. A literal whose deeps have no
// texts equals an element exactly where ix holds its shape, so a lookup of
// the shape takes the place of a pass over the texts.
func literalDeepAny(alts [][]deep, ix string) (anyText, noneText string) {
	var shapes []*ast.Term
	for _, ds := range alts {
		for _, d := range ds {
			if len(d.texts) > 0 {
				a := altsTerm(alts).String()
				return regoDeepAny(a, ix), regoDeepNone(a, ix)
			}
			shapes = append(shapes, ast.StringTerm(d.shape))
		}
	}
	if len(shapes) == 1 {
		return fmt.Sprintf("%s[%s]", ix, shapes[0]), fmt.Sprintf("not %s[%s]", ix, shapes[0])
	}
	set := ast.SetTerm(shapes...).String()
	// the comprehension keeps s local, so two such rows share a clause
	return fmt.Sprintf("count([s | some s in %s; %s[s]]) > 0", set, ix), fmt.Sprintf("every s in %s { not %s[s] }", set, ix)
}

// regoEqAll is the Rego text that holds where each of the deeps ds has an
// equal deep in ix; regoEqNotAll its negation.
func regoEqAll(ds, ix string) string {
	return fmt.Sprintf("every a in %s { %s }", ds, deepHit("a", ix))
}

func regoEqNotAll(ds, ix string) string {
	return fmt.Sprintf("count([a | some a in %s; %s]) > 0", ds, deepMiss("a", ix))
}
