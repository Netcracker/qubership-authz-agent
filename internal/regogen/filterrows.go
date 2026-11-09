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
	"regexp"
	"strings"

	"authz-agent/internal/policyir"
)

// A condition the filter reads without the resource has a value per row. A
// leaf over the resource is true on the rows it matches; a leaf a failed
// source leaves unknown is unknown on every row; any other leaf is true or
// false on every row. Kleene's AND and OR over these give the rows where the
// condition is true and the rows where it is unknown. The check denies a
// resource whole where the condition of an applicable rule is unknown, so the
// filter denies exactly those rows, whatever the rule's effect and whatever
// its neighbors allow.

// rowsF is a set of rows as a formula of the leaves over the resource: true
// (every row), false (none), a leaf, or a NOT, AND, or OR of formulas.
type rowsF struct {
	kind  string // "true", "false", "atom", "not", "and", "or"
	atom  *rowAtom
	parts []rowsF
}

var (
	rowsTrue  = rowsF{kind: "true"}
	rowsFalse = rowsF{kind: "false"}
)

// rowAtom is a leaf over the resource. It has text where it compares a path
// of keys with a string or number literal by == or !=, which rsql, sql, and
// mongodb can write.
type rowAtom struct {
	key  string // the path without its leading dot
	eq   bool
	text bool
	// q is the literal as rsql and mongodb write it, sq as sql does
	q, sq string
}

var rowPathRE = regexp.MustCompile(`^(?:\.[A-Za-z_][A-Za-z0-9_]*)+$`)

// rowAtomOf is the leaf over the resource of comparison c.
func rowAtomOf(c policyir.Compare) *rowAtom {
	a := &rowAtom{eq: c.Op == policyir.OpEQ}
	if c.Op != policyir.OpEQ && c.Op != policyir.OpNE {
		return a
	}
	res, lit := c.Left, c.Right
	if _, ok := res.(policyir.Resource); !ok {
		res, lit = lit, res
	}
	r, ok := res.(policyir.Resource)
	if !ok || r.TrailingDot || !rowPathRE.MatchString(r.Path) {
		return a
	}
	switch v := lit.(type) {
	case policyir.Number:
		a.q, a.sq = v.Text, v.Text
	case policyir.String:
		if strings.ContainsFunc(v.Value, func(r rune) bool { return r < 0x20 || strings.ContainsRune(`"'\`, r) }) {
			return a
		}
		a.q, a.sq = `"`+v.Value+`"`, "'"+v.Value+"'"
	default:
		return a
	}
	a.key, a.text = r.Path[1:], true
	return a
}

func fAnd(a, b rowsF) rowsF {
	switch {
	case a.kind == "false" || b.kind == "false":
		return rowsFalse
	case a.kind == "true":
		return b
	case b.kind == "true":
		return a
	}
	return rowsF{kind: "and", parts: []rowsF{a, b}}
}

func fOr(a, b rowsF) rowsF {
	switch {
	case a.kind == "true" || b.kind == "true":
		return rowsTrue
	case a.kind == "false":
		return b
	case b.kind == "false":
		return a
	}
	return rowsF{kind: "or", parts: []rowsF{a, b}}
}

func fNot(a rowsF) rowsF {
	switch a.kind {
	case "true":
		return rowsFalse
	case "false":
		return rowsTrue
	}
	return rowsF{kind: "not", parts: []rowsF{a}}
}

// rowsVal is a condition on the rows: where it is true and where unknown.
type rowsVal struct{ t, u rowsF }

// kleeneAnd is unknown where neither operand is false and one is unknown.
func kleeneAnd(x, y rowsVal) rowsVal {
	return rowsVal{t: fAnd(x.t, y.t), u: fAnd(fAnd(fOr(x.t, x.u), fOr(y.t, y.u)), fOr(x.u, y.u))}
}

// kleeneOr is unknown where neither operand is true and one is unknown.
func kleeneOr(x, y rowsVal) rowsVal {
	return rowsVal{t: fOr(x.t, y.t), u: fAnd(fAnd(fNot(x.t), fNot(y.t)), fOr(x.u, y.u))}
}

// rowsExpr is the predicate expression of the rows f, or of the others where
// neg, with each NOT taken down to a leaf; nil where a leaf has no text.
func rowsExpr(f rowsF, neg bool) *fexpr {
	switch f.kind {
	case "not":
		return rowsExpr(f.parts[0], !neg)
	case "atom":
		if !f.atom.text {
			return nil
		}
		return &fexpr{kind: "leaf", term: f.atom.term(neg)}
	case "and", "or":
		kind := f.kind
		if neg {
			kind = map[string]string{"and": "or", "or": "and"}[kind]
		}
		parts := make([]*fexpr, len(f.parts))
		for i, p := range f.parts {
			if parts[i] = rowsExpr(p, neg); parts[i] == nil {
				return nil
			}
		}
		return &fexpr{kind: kind, parts: parts}
	}
	return nil
}

// term is the predicate of the rows of a, or of the others where neg. The
// text compares as the database does, which is stricter than == in the check:
// a value that differs in case or type, a missing member, and a list that
// holds the value are rows where the two may disagree. A rule's own
// predicate, negated, has the same gap.
func (a *rowAtom) term(neg bool) *fterm {
	text := map[policyir.Dialect]string{policyir.DialectRSQL: a.key + "!=" + a.q,
		policyir.DialectSQL: a.key + " <> " + a.sq, policyir.DialectMongoDB: `"` + a.key + `": { "$ne": ` + a.q + " }"}
	if a.eq != neg {
		text = map[policyir.Dialect]string{policyir.DialectRSQL: a.key + "==" + a.q,
			policyir.DialectSQL: a.key + " = " + a.sq, policyir.DialectMongoDB: `"` + a.key + `": ` + a.q}
	}
	tmpl := map[policyir.Dialect]string{}
	subst := map[policyir.Dialect]map[string]string{}
	for d, t := range text {
		tmpl[d], subst[d] = t, map[string]string{}
	}
	return &fterm{key: "row:" + a.key, text: text, template: tmpl, subst: subst}
}
