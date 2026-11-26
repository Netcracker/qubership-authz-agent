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
	"context"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"authz-agent/internal/policyir"
)

// textMeaningKnown lists the dialects and the operands whose text does not
// mean its expression today. A key names the dialect and the smallest
// expression whose text selects other rows than its operands' texts
// compose to: the negation of a template, or an AND or an OR with one
// operand that a plain comparison beside it already breaks. A listed key is
// logged; a listed key that no expression shows fails the test until its
// entry is removed, and an unlisted one fails it.
var textMeaningKnown = map[string]string{
	"sql/AND with operand or-template":                  f18,
	"sql/AND with operand escape-beside-placeholder-or": f18,
	"sql/AND with operand and-under-or":                 f18,
}

const (
	f18 = "F18: an AND writes an author's SQL template that is an OR without parentheses, so the AND " +
		"binds only to the template's operand next to it"
)

// textTemplate is a predicate an author writes for a rule, in every dialect.
type textTemplate struct {
	name                       string
	rsql, sql, mongo, querydsl string
}

// textTemplates are the predicates the expressions are built from: an
// answer holds no text but its authors' templates, so no expression holds a
// comparison derived from a condition. They compare strings only, and no
// RSQL value holds a *, which compileRSQLAtom refuses.
var textTemplates = []textTemplate{
	{"equality", `a=="y"`, `a = 'y'`, `"a": {"$eq": "y"}`, `a.eq("y")`},
	{"or-template", `a=="y",b=="y"`, `a = 'y' OR b = 'y'`, `{"$or": [{"a": "y"}, {"b": "y"}]}`,
		`a.eq("y").or(b.eq("y"))`},
	{"inequality", `b!="y"`, `b <> 'y'`, `"b": {"$ne": "y"}`, `b.ne("y")`},
	{"literal-list", `c=in=("x","n")`, `c IN ('x', 'n')`, `{"c": {"$in": ["x", "n"]}}`, `c.in("x", "n")`},
	{"placeholder", `a==${subject.id}`, `a = '${subject.id}'`, `"a": "${subject.id}"`, `a.eq("${subject.id}")`},
	{"escaped-placeholder", `a=="$${subject.id}"`, `a = '$${subject.id}'`, `"a": "$${subject.id}"`,
		`a.eq("$${subject.id}")`},
	{"escape-beside-placeholder-or", `a=="$${subject.id}",b==${subject.id}`,
		`a = '$${subject.id}' OR b = '${subject.id}'`,
		`{"$or": [{"a": "$${subject.id}"}, {"b": "${subject.id}"}]}`,
		`a.eq("$${subject.id}").or(b.eq("${subject.id}"))`},
	{"and-under-or", `(a=="y";b=="y"),c=="x"`, `a = 'y' AND b = 'y' OR c = 'x'`,
		`{"$or": [{"a": "y", "b": "y"}, {"c": "x"}]}`, `a.eq("y").and(b.eq("y")).or(c.eq("x"))`},
	{"list-placeholder", `c=in=(${subject.roles})`, `c IN (${subject.roles})`, `{"c": {"$in": ${subject.roles}}}`,
		`c.in(${subject.roles})`},
}

// textRows are the rows every text is evaluated on. Column a holds the
// value subject.id substitutes, the literal ${subject.id} an escaped
// placeholder stands for, and the text $q the escape becomes where it is
// substituted anyway.
func textRows() []textRow {
	var rows []textRow
	for _, a := range []any{"y", "n", "q", "${subject.id}", "$q", nil} {
		for _, b := range []any{"y", "q", nil} {
			for _, c := range []any{"x", "n", "q", nil} {
				rows = append(rows, textRow{"a": a, "b": b, "c": c})
			}
		}
	}
	return rows
}

// exprTree is an expression over textTemplates, as a rule tree combines
// predicates: a template (op "leaf"), its negation, or an AND or an OR.
type exprTree struct {
	op    string
	leaf  int
	parts []*exprTree
}

func (e *exprTree) String() string {
	switch e.op {
	case "leaf":
		return textTemplates[e.leaf].name
	case "not":
		return "NOT " + e.parts[0].String()
	}
	parts := make([]string, len(e.parts))
	for i, p := range e.parts {
		parts[i] = p.String()
	}
	return strings.ToUpper(e.op) + "(" + strings.Join(parts, ", ") + ")"
}

// build is the expression of e as the filter writes it, by andOf, orOf, and
// negate.
func (e *exprTree) build(leaves []*fexpr) *fexpr {
	switch e.op {
	case "leaf":
		return leaves[e.leaf]
	case "not":
		return negate(e.parts[0].build(leaves))
	}
	parts := make([]*fexpr, len(e.parts))
	for i, p := range e.parts {
		parts[i] = p.build(leaves)
	}
	if e.op == "and" {
		return andOf(parts)
	}
	return orOf(parts)
}

func randomExprTree(rnd *rand.Rand, depth int) *exprTree {
	if depth == 0 || rnd.IntN(3) == 0 {
		leaf := &exprTree{op: "leaf", leaf: rnd.IntN(len(textTemplates))}
		if rnd.IntN(3) == 0 {
			return &exprTree{op: "not", parts: []*exprTree{leaf}}
		}
		return leaf
	}
	e := &exprTree{op: []string{"and", "or"}[rnd.IntN(2)]}
	for i := rnd.IntN(2) + 2; i > 0; i-- {
		e.parts = append(e.parts, randomExprTree(rnd, depth-1))
	}
	if rnd.IntN(4) == 0 {
		return &exprTree{op: "not", parts: []*exprTree{e}}
	}
	return e
}

// meaningCheck compares the text of an expression with the composition of
// its templates' own texts, in one dialect.
type meaningCheck struct {
	d      policyir.Dialect
	rows   []textRow
	leaves []*fexpr
	names  map[*fterm]string
	// own is the compiled text of each template alone
	own map[*fterm]rowPredicate
}

// composed is the truth of x on r composed from its templates' own texts:
// three-valued, where the negation of a template is the not of its text.
func (c *meaningCheck) composed(x *fexpr, r textRow) truth {
	switch x.kind {
	case "leaf":
		return c.own[x.term](r)
	case "not":
		return c.composed(x.parts[0], r).not()
	}
	acc := isTrue
	if x.kind == "or" {
		acc = isFalse
	}
	for _, p := range x.parts {
		if x.kind == "and" {
			acc = acc.and(c.composed(p, r))
		} else {
			acc = acc.or(c.composed(p, r))
		}
	}
	return acc
}

func (c *meaningCheck) treeTruth(e *exprTree, r textRow) truth {
	switch e.op {
	case "leaf":
		return c.own[c.leaves[e.leaf].term](r)
	case "not":
		return c.treeTruth(e.parts[0], r).not()
	}
	acc := isTrue
	if e.op == "or" {
		acc = isFalse
	}
	for _, p := range e.parts {
		if e.op == "and" {
			acc = acc.and(c.treeTruth(p, r))
		} else {
			acc = acc.or(c.treeTruth(p, r))
		}
	}
	return acc
}

// textMismatch is a row on which a text selects otherwise than its
// expression means; err is set where the text has none or does not parse.
type textMismatch struct {
	text      string
	row       textRow
	got, want truth
	err       error
}

func (m *textMismatch) String() string {
	if m.err != nil {
		return fmt.Sprintf("text %q: %v", m.text, m.err)
	}
	return fmt.Sprintf("text %s is %v on %v, its operands compose to %v", m.text, m.got, m.row, m.want)
}

// mismatch returns the first row on which the text of x selects otherwise
// than want, nil where there is none. A row is selected where it is true.
func (c *meaningCheck) mismatch(x *fexpr, want func(textRow) truth) *textMismatch {
	text, ok := render(x, c.d)
	if !ok {
		return &textMismatch{err: fmt.Errorf("render wrote no %s text", c.d)}
	}
	sel, err := compileText(c.d, text)
	if err != nil {
		return &textMismatch{text: text, err: err}
	}
	for _, r := range c.rows {
		got, w := sel(r), want(r)
		if (got == isTrue) != (w == isTrue) {
			return &textMismatch{text: text, row: r, got: got, want: w}
		}
	}
	return nil
}

// ownMismatch is the mismatch of the text of x with the composition of its
// own templates' texts, nil where there is none.
func (c *meaningCheck) ownMismatch(x *fexpr) *textMismatch {
	return c.mismatch(x, func(r textRow) truth { return c.composed(x, r) })
}

// culprit is the smallest part of x whose own text does not mean it,
// where x does not.
func (c *meaningCheck) culprit(x *fexpr) *fexpr {
	for _, p := range x.parts {
		if c.ownMismatch(p) != nil {
			return c.culprit(p)
		}
	}
	return x
}

// blame names the cause of a mismatch at x, the smallest expression that
// shows it: the negation of a template, or each operand of an AND or an OR
// that breaks it beside the plain comparison equality, before or after it.
func (c *meaningCheck) blame(x *fexpr) []string {
	prefix := string(c.d) + "/"
	switch x.kind {
	case "not":
		return []string{prefix + "NOT " + c.names[x.parts[0].term]}
	case "and", "or":
	default:
		return []string{prefix + x.kind}
	}
	var plain *fexpr
	for _, l := range c.leaves {
		if c.names[l.term] == "equality" {
			plain = l
		}
	}
	var keys []string
	for _, p := range x.parts {
		left := &fexpr{kind: x.kind, parts: []*fexpr{plain, p}}
		right := &fexpr{kind: x.kind, parts: []*fexpr{p, plain}}
		if c.ownMismatch(left) != nil || c.ownMismatch(right) != nil {
			keys = append(keys, prefix+strings.ToUpper(x.kind)+" with operand "+c.describe(p))
		}
	}
	if len(keys) == 0 {
		var parts []string
		for _, p := range x.parts {
			parts = append(parts, c.describe(p))
		}
		keys = append(keys, prefix+strings.ToUpper(x.kind)+" of "+strings.Join(parts, ", "))
	}
	return keys
}

func (c *meaningCheck) describe(x *fexpr) string {
	switch x.kind {
	case "leaf":
		return c.names[x.term]
	case "not":
		return "NOT " + c.describe(x.parts[0])
	}
	return "an " + strings.ToUpper(x.kind)
}

// templateLeaves substitutes every template once, with subject.id the
// value q and subject.roles the list q, x.
func templateLeaves(t *testing.T) []*fexpr {
	t.Helper()
	sub := &substituter{m: &Module{}, ctx: context.Background(), req: &Request{Values: map[string]Resolved{
		specKey("subj", "id"):    resolved(t, "VALUE", `"q"`),
		specKey("subj", "roles"): resolved(t, "VALUE", `["x", "q"]`),
	}}}
	leaves := make([]*fexpr, len(textTemplates))
	for i, tp := range textTemplates {
		x, err := sub.term(policyir.Predicates{Text: map[policyir.Dialect]string{
			policyir.DialectRSQL: tp.rsql, policyir.DialectSQL: tp.sql, policyir.DialectMongoDB: tp.mongo,
			policyir.DialectQueryDSL: tp.querydsl}}, tp.name, -1)
		if err != nil {
			t.Fatalf("term(%s): %v", tp.name, err)
		}
		leaves[i] = x
	}
	return leaves
}

func newMeaningCheck(t *testing.T, d policyir.Dialect, leaves []*fexpr) *meaningCheck {
	t.Helper()
	c := &meaningCheck{d: d, rows: textRows(), leaves: leaves, names: map[*fterm]string{},
		own: map[*fterm]rowPredicate{}}
	for i, x := range leaves {
		text, ok := render(x, d)
		if !ok {
			t.Fatalf("render(%s, %s) wrote no text", textTemplates[i].name, d)
		}
		sel, err := compileText(d, text)
		if err != nil {
			t.Fatalf("the text of %s does not compile: %v", textTemplates[i].name, err)
		}
		c.names[x.term] = textTemplates[i].name
		c.own[x.term] = sel
	}
	return c
}

// The expressions are every template, its negation, the AND and the OR of
// every ordered pair of those, and random deeper trees under a fixed seed.
// The text of each must select, in every dialect, the rows the composition
// of its templates' own texts selects; andOf, orOf, and negate rewrite the
// expression, and the composition is taken over the tree as written, so a
// rewrite that changes its meaning fails as well.
func TestTheTextOfAFilterExpressionMeansTheExpression(t *testing.T) {
	leaves := templateLeaves(t)
	var trees []*exprTree
	var operands []*exprTree
	for i := range textTemplates {
		leaf := &exprTree{op: "leaf", leaf: i}
		operands = append(operands, leaf, &exprTree{op: "not", parts: []*exprTree{leaf}})
	}
	trees = append(trees, operands...)
	for _, op := range []string{"and", "or"} {
		for _, a := range operands {
			for _, b := range operands {
				trees = append(trees, &exprTree{op: op, parts: []*exprTree{a, b}})
			}
		}
	}
	rnd := rand.New(rand.NewPCG(13, 14))
	for range 300 {
		trees = append(trees, randomExprTree(rnd, 3))
	}
	found := map[string]string{}
	for _, d := range filterDialects {
		c := newMeaningCheck(t, d, leaves)
		for _, e := range trees {
			x := e.build(leaves)
			m := c.mismatch(x, func(r textRow) truth { return c.treeTruth(e, r) })
			if m == nil {
				continue
			}
			keys := []string{string(d) + "/rewrite of " + e.String()}
			if m.err != nil {
				keys = []string{string(d) + "/unreadable text of " + e.String()}
			} else if c.ownMismatch(x) != nil {
				keys = c.blame(c.culprit(x))
			}
			for _, k := range keys {
				if _, ok := found[k]; !ok {
					found[k] = fmt.Sprintf("%s: %v", e, m)
				}
			}
		}
	}
	for _, k := range slices.Sorted(func(yield func(string) bool) {
		for k := range found {
			if !yield(k) {
				return
			}
		}
	}) {
		if why, ok := textMeaningKnown[k]; ok {
			t.Logf("known: %s (%s), first seen in %s", k, why, found[k])
			continue
		}
		t.Errorf("the text of %s does not mean the expression, first seen in %s", k, found[k])
	}
	for _, k := range slices.Sorted(func(yield func(string) bool) {
		for k := range textMeaningKnown {
			if !yield(k) {
				return
			}
		}
	}) {
		if _, ok := found[k]; !ok {
			t.Errorf("no expression shows %s any longer; remove its entry from textMeaningKnown", k)
		}
	}
}

// The comparison of a text with its composed meaning tells an OR template
// under an AND in parentheses from the same text without them.
func TestATextIsComparedWithTheCompositionOfItsOperands(t *testing.T) {
	or, err := compileText(policyir.DialectSQL, `a = 'y' OR b = 'y'`)
	if err != nil {
		t.Fatal(err)
	}
	c3, err := compileText(policyir.DialectSQL, `c = 'x'`)
	if err != nil {
		t.Fatal(err)
	}
	want := func(r textRow) truth { return or(r).and(c3(r)) }
	for _, tc := range []struct {
		text    string
		matches bool
	}{
		{`(a = 'y' OR b = 'y') AND c = 'x'`, true},
		{`a = 'y' OR b = 'y' AND c = 'x'`, false},
	} {
		sel, err := compileText(policyir.DialectSQL, tc.text)
		if err != nil {
			t.Fatalf("compileText(%q): %v", tc.text, err)
		}
		var first textRow
		for _, r := range textRows() {
			if (sel(r) == isTrue) != (want(r) == isTrue) {
				first = r
				break
			}
		}
		if got := first == nil; got != tc.matches {
			t.Errorf("%q selects the rows of (a = 'y' OR b = 'y') AND c = 'x': %v, want %v; first differing row %v",
				tc.text, got, tc.matches, first)
		}
	}
}
