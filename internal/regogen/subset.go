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

	"authz-agent/internal/regogen/spectables"
)

// IS SUBSET holds when the left value, read as a list, has at least one
// element and each of its elements equals an element of the right value, read
// as a list, as the collection operators compare elements (ADR-0083 R7): the
// left elements by their deeps (Record.ElementAlts), the right ones by their
// index without objects, since an object on the right equals nothing
// (Record.SubsetIndex). A resource attribute or a PIP on the right offers its
// elements as a literal list does.

// subsetTemplate is the template of IS SUBSET over any two values.
func subsetTemplate(L, R *side, b *tb) (tpl, bool) {
	var la, rb string
	if L.ref != nil {
		b.use(L, fieldElementAlts)
		la = L.field(fieldElementAlts)
	} else {
		la = altsTerm(L.lit.alts).String()
	}
	if R.ref != nil {
		b.use(R, fieldSubsetIndex)
		rb = R.field(fieldSubsetIndex)
	} else {
		rb = R.lit.subsetIndex.term().String()
	}
	c := clsCheck
	if L.ref != nil && L.ref.Network || R.ref != nil && R.ref.Network {
		c = clsAfterBuilt
	}
	ref := L
	if L.ref == nil {
		ref = R
	}
	bind := conj(L.bind(), R.bind())
	row := func(kind, text string) clause {
		return conj(bind, clause{{cls: c, text: text, fact: vfact(ref), test: subsetTest(L, R, kind)}})
	}
	// every element of the left has a deep in the index of the right; a
	// comprehension keeps the element variable local, so two such rows can
	// share a clause
	t := row("subset", regoDeepAll(la, rb))
	f := dnf{row("unmatched", regoDeepNotAll(la, rb))}
	if L.ref != nil {
		// an empty list on the left is a subset of nothing
		t = conj(row("nonempty", fmt.Sprintf("count(%s) > 0", la)), t)
		f = append(f, row("emptyleft", fmt.Sprintf("count(%s) == 0", la)))
	}
	return tpl{t: dnf{t}, f: f, fields: b.fields, rules: map[spectables.ValueRule]bool{spectables.RuleSubset: true}},
		true
}

// subsetTest is the group test of a row of IS SUBSET: subset and unmatched
// (some left element equals no right one) over both sides, nonempty and
// emptyleft over the left one; nil when a side is a network PIP.
func subsetTest(L, R *side, kind string) *test {
	for _, s := range []*side{L, R} {
		if s.ref != nil && s.ref.Network {
			return nil
		}
	}
	t := &test{kind: kind}
	if L.ref != nil {
		t.ref = L.ref.ID
	} else {
		t.alts = L.lit.alts
	}
	if R.ref != nil {
		t.rightRef = R.ref.ID
	} else {
		t.index = R.lit.subsetIndex
	}
	return t
}

// subsetHolds answers a test of subsetTest as its Rego row does: a missing
// field fails it.
func (t *test) subsetHolds(e *groupEval) bool {
	la := t.alts
	if t.ref != "" {
		r, ok := e.rec(t.refIndex)
		if !ok {
			return false
		}
		la = r.ElementAlts
	}
	if la == nil {
		return false
	}
	switch t.kind {
	case "nonempty":
		return len(la) > 0
	case "emptyleft":
		return len(la) == 0
	}
	rb := t.index
	if t.rightRef != "" {
		r, ok := e.rec(t.rightRefIndex)
		if !ok {
			return false
		}
		rb = r.SubsetIndex
	}
	if rb == nil {
		return false
	}
	return deepAll(la, rb) == (t.kind == "subset")
}
