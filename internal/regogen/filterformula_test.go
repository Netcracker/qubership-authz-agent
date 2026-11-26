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
	"sort"
	"strings"
	"testing"
	"unicode"

	"authz-agent/internal/policyir"
)

// formula is the boolean structure of a filter text: AND, OR, and NOT over
// atoms, each atom the text of one comparison. Two formulas with the same
// truth table select the same rows where every atom is true or false, so a
// test can compare two filter answers without a database: reordered,
// regrouped, or repeated operands do not change the truth table. An SQL
// comparison on a NULL column is neither true nor false, and there a shared
// truth table is not enough (a OR NOT a against true); reordering,
// regrouping, and repetition still keep its result.
type formula struct {
	op    string // "atom", "and", "or", "not", "true", "false"
	atom  string
	parts []*formula
}

func (f *formula) eval(v map[string]bool) bool {
	switch f.op {
	case "atom":
		return v[f.atom]
	case "true":
		return true
	case "false":
		return false
	case "not":
		return !f.parts[0].eval(v)
	case "and":
		for _, p := range f.parts {
			if !p.eval(v) {
				return false
			}
		}
		return true
	}
	for _, p := range f.parts {
		if p.eval(v) {
			return true
		}
	}
	return false
}

func (f *formula) atoms(into map[string]bool) {
	if f.op == "atom" {
		into[f.atom] = true
	}
	for _, p := range f.parts {
		p.atoms(into)
	}
}

// maxFormulaAtoms bounds the truth table at 2^16 rows.
const maxFormulaAtoms = 16

// sameFormula reports whether a and b have the same truth table over the
// atoms of both. Past [maxFormulaAtoms] atoms it compares their normal forms
// up to the order and repetition of operands, which may report a difference
// where the tables agree.
func sameFormula(a, b *formula) bool {
	set := map[string]bool{}
	a.atoms(set)
	b.atoms(set)
	if len(set) > maxFormulaAtoms {
		return a.canonical() == b.canonical()
	}
	names := slices.Sorted(func(yield func(string) bool) {
		for k := range set {
			if !yield(k) {
				return
			}
		}
	})
	v := map[string]bool{}
	for bits := 0; bits < 1<<len(names); bits++ {
		for i, n := range names {
			v[n] = bits&(1<<i) != 0
		}
		if a.eval(v) != b.eval(v) {
			return false
		}
	}
	return true
}

// canonical writes f with the operands of each AND and OR sorted and
// repeated ones dropped.
func (f *formula) canonical() string {
	switch f.op {
	case "atom":
		return "[" + f.atom + "]"
	case "true", "false":
		return f.op
	}
	var ps []string
	for _, p := range f.parts {
		ps = append(ps, p.canonical())
	}
	sort.Strings(ps)
	ps = slices.Compact(ps)
	return f.op + "(" + strings.Join(ps, " ") + ")"
}

// answerFormula is the formula of the rows the answer selects in dialect d:
// true for ALLOW, false for DENY. A condition without text in d has no
// formula, and ok is false.
func answerFormula(fa FilterAnswer, d policyir.Dialect) (f *formula, ok bool, err error) {
	switch fa.Result {
	case FilterAllow:
		return &formula{op: "true"}, true, nil
	case FilterDeny:
		return &formula{op: "false"}, true, nil
	}
	text, ok := fa.Text[d]
	if !ok {
		return nil, false, nil
	}
	f, err = parseFilterText(d, text)
	return f, true, err
}

// parseFilterText reads the boolean structure of a text in dialect d. A
// dialect it has no reader for is one atom.
func parseFilterText(d policyir.Dialect, text string) (*formula, error) {
	switch d {
	case policyir.DialectRSQL:
		p := &infixReader{s: text, and: []string{";"}, or: []string{","}}
		return p.read()
	case policyir.DialectSQL:
		p := &infixReader{s: text, and: []string{"AND"}, or: []string{"OR"}, not: "NOT", words: true}
		return p.read()
	case policyir.DialectMongoDB:
		return readMongoFormula(text)
	case policyir.DialectQueryDSL:
		p := &queryDSLReader{s: text}
		return p.read()
	}
	return &formula{op: "atom", atom: strings.TrimSpace(text)}, nil
}

// queryDSLReader reads a QueryDSL text: a chain of calls on a parenthesized
// text or a name, where .and(x) and .or(x) combine, .not() negates, and any
// other call makes the text read so far one atom, as in a.eq("y").
type queryDSLReader struct {
	s  string
	at int
}

func (p *queryDSLReader) read() (*formula, error) {
	f, err := p.chain()
	if err != nil {
		return nil, err
	}
	if p.at != len(p.s) {
		return nil, fmt.Errorf("unexpected %q at %d in %q", p.s[p.at:], p.at, p.s)
	}
	return f, nil
}

func (p *queryDSLReader) expect(c byte) error {
	for p.at < len(p.s) && p.s[p.at] == ' ' {
		p.at++
	}
	if p.at == len(p.s) || p.s[p.at] != c {
		return fmt.Errorf("want %q at %d in %q", c, p.at, p.s)
	}
	p.at++
	return nil
}

func (p *queryDSLReader) name() string {
	start := p.at
	for p.at < len(p.s) && (p.s[p.at] == '_' || unicode.IsLetter(rune(p.s[p.at])) ||
		unicode.IsDigit(rune(p.s[p.at]))) {
		p.at++
	}
	return p.s[start:p.at]
}

func (p *queryDSLReader) chain() (*formula, error) {
	for p.at < len(p.s) && p.s[p.at] == ' ' {
		p.at++
	}
	start := p.at
	var f *formula
	if p.at < len(p.s) && p.s[p.at] == '(' {
		p.at++
		inner, err := p.chain()
		if err != nil {
			return nil, err
		}
		if err := p.expect(')'); err != nil {
			return nil, err
		}
		f = inner
	} else if n := p.name(); n != "" {
		f = &formula{op: "atom", atom: n}
	} else {
		return nil, fmt.Errorf("want a name or ( at %d in %q", p.at, p.s)
	}
	for p.at < len(p.s) && p.s[p.at] == '.' {
		p.at++
		call := p.name()
		if err := p.expect('('); err != nil {
			return nil, err
		}
		switch call {
		case "and", "or":
			arg, err := p.chain()
			if err != nil {
				return nil, err
			}
			if err := p.expect(')'); err != nil {
				return nil, err
			}
			f = &formula{op: call, parts: []*formula{f, arg}}
		case "not":
			if err := p.expect(')'); err != nil {
				return nil, err
			}
			f = &formula{op: "not", parts: []*formula{f}}
		default:
			if err := p.skipArguments(); err != nil {
				return nil, err
			}
			f = &formula{op: "atom", atom: p.s[start:p.at]}
		}
	}
	return f, nil
}

// skipArguments moves past the arguments of a call and its closing
// parenthesis, skipping parentheses inside quoted strings.
func (p *queryDSLReader) skipArguments() error {
	depth := 1
	for ; p.at < len(p.s); p.at++ {
		switch p.s[p.at] {
		case '"':
			for p.at++; p.at < len(p.s) && p.s[p.at] != '"'; p.at++ {
				if p.s[p.at] == '\\' {
					p.at++
				}
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				p.at++
				return nil
			}
		}
	}
	return fmt.Errorf("unbalanced parentheses in %q", p.s)
}

// infixReader reads an infix text with parentheses: RSQL, where ; binds
// tighter than ,, and SQL, where AND binds tighter than OR and NOT tighter
// than both. An atom runs to the next operator or unmatched closing
// parenthesis outside quotes, and keeps the parentheses it opens, as in
// c=in=("x","q") or c IN ('x', 'q').
type infixReader struct {
	s       string
	at      int
	and, or []string
	not     string
	words   bool // operators are words, matched without case
}

func (p *infixReader) read() (*formula, error) {
	f, err := p.disjunction()
	if err != nil {
		return nil, err
	}
	p.space()
	if p.at != len(p.s) {
		return nil, fmt.Errorf("unexpected %q at %d in %q", p.s[p.at:], p.at, p.s)
	}
	return f, nil
}

func (p *infixReader) space() {
	for p.at < len(p.s) && p.s[p.at] == ' ' {
		p.at++
	}
}

// operator reports whether one of ops starts at the reader's position, and
// consumes it.
func (p *infixReader) operator(ops []string) bool {
	p.space()
	for _, op := range ops {
		end := p.at + len(op)
		if end > len(p.s) {
			continue
		}
		if p.words {
			if !strings.EqualFold(p.s[p.at:end], op) || end < len(p.s) && isWordByte(p.s[end]) ||
				p.at > 0 && isWordByte(p.s[p.at-1]) {
				continue
			}
		} else if p.s[p.at:end] != op {
			continue
		}
		p.at = end
		return true
	}
	return false
}

func isWordByte(b byte) bool {
	return b == '_' || unicode.IsLetter(rune(b)) || unicode.IsDigit(rune(b))
}

func (p *infixReader) disjunction() (*formula, error) {
	return p.chain("or", p.or, p.conjunction)
}

func (p *infixReader) conjunction() (*formula, error) {
	return p.chain("and", p.and, p.negation)
}

func (p *infixReader) chain(op string, ops []string, next func() (*formula, error)) (*formula, error) {
	first, err := next()
	if err != nil {
		return nil, err
	}
	parts := []*formula{first}
	for p.operator(ops) {
		f, err := next()
		if err != nil {
			return nil, err
		}
		parts = append(parts, f)
	}
	if len(parts) == 1 {
		return first, nil
	}
	return &formula{op: op, parts: parts}, nil
}

func (p *infixReader) negation() (*formula, error) {
	if p.not != "" && p.operator([]string{p.not}) {
		f, err := p.negation()
		if err != nil {
			return nil, err
		}
		return &formula{op: "not", parts: []*formula{f}}, nil
	}
	p.space()
	if p.at < len(p.s) && p.s[p.at] == '(' {
		p.at++
		f, err := p.disjunction()
		if err != nil {
			return nil, err
		}
		p.space()
		if p.at >= len(p.s) || p.s[p.at] != ')' {
			return nil, fmt.Errorf("unclosed parenthesis in %q", p.s)
		}
		p.at++
		return f, nil
	}
	return p.atom()
}

func (p *infixReader) atom() (*formula, error) {
	start, depth := p.at, 0
	var quote byte
	for p.at < len(p.s) {
		c := p.s[p.at]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			if depth == 0 {
				return p.atomFrom(start)
			}
			depth--
		case depth == 0 && p.atOperator():
			return p.atomFrom(start)
		}
		p.at++
	}
	if quote != 0 || depth != 0 {
		return nil, fmt.Errorf("unbalanced atom %q", p.s[start:])
	}
	return p.atomFrom(start)
}

// atOperator reports whether an AND or OR starts at the reader's position,
// without consuming it.
func (p *infixReader) atOperator() bool {
	at := p.at
	if p.words && p.s[at] != ' ' {
		return false
	}
	found := p.operator(p.and) || p.operator(p.or)
	p.at = at
	return found
}

func (p *infixReader) atomFrom(start int) (*formula, error) {
	text := strings.TrimSpace(p.s[start:p.at])
	if text == "" {
		return nil, fmt.Errorf("empty operand at %d in %q", start, p.s)
	}
	return &formula{op: "atom", atom: text}, nil
}

// readMongoFormula reads a MongoDB filter: $and and $or over their items, $nor
// as the negation of its OR, and each other member, or several members of one
// object, as the AND of their atoms. It accepts an author's object inside the
// extra braces the answer wraps it in, {{"a": 1}}.
func readMongoFormula(text string) (*formula, error) {
	r := &mongoReader{s: text}
	v, err := r.value()
	if err != nil {
		return nil, fmt.Errorf("%w in %q", err, text)
	}
	r.space()
	if r.at != len(r.s) {
		return nil, fmt.Errorf("unexpected %q in %q", r.s[r.at:], text)
	}
	return mongoFormula(v)
}

// mongoMember is one member of an object, in the order of the text.
type mongoMember struct {
	key string
	val any
}

func mongoFormula(v any) (*formula, error) {
	members, ok := v.([]mongoMember)
	if !ok {
		return nil, fmt.Errorf("a filter is an object, got %v", v)
	}
	var parts []*formula
	for _, m := range members {
		switch m.key {
		case "$and", "$or", "$nor":
			items, ok := m.val.([]any)
			if !ok {
				return nil, fmt.Errorf("%s takes an array, got %v", m.key, m.val)
			}
			var fs []*formula
			for _, it := range items {
				f, err := mongoFormula(it)
				if err != nil {
					return nil, err
				}
				fs = append(fs, f)
			}
			switch m.key {
			case "$and":
				parts = append(parts, &formula{op: "and", parts: fs})
			case "$or":
				parts = append(parts, &formula{op: "or", parts: fs})
			default:
				parts = append(parts, &formula{op: "not", parts: []*formula{{op: "or", parts: fs}}})
			}
		default:
			parts = append(parts, &formula{op: "atom", atom: mongoCanonical([]mongoMember{m})})
		}
	}
	if len(parts) == 1 {
		return parts[0], nil
	}
	return &formula{op: "and", parts: parts}, nil
}

// mongoCanonical writes v as JSON with no spaces; members keep their order,
// which MongoDB gives a meaning to in an embedded document.
func mongoCanonical(v any) string {
	switch x := v.(type) {
	case []mongoMember:
		var ms []string
		for _, m := range x {
			ms = append(ms, genJSON(m.key)+":"+mongoCanonical(m.val))
		}
		return "{" + strings.Join(ms, ",") + "}"
	case []any:
		var is []string
		for _, it := range x {
			is = append(is, mongoCanonical(it))
		}
		return "[" + strings.Join(is, ",") + "]"
	}
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// mongoReader reads JSON, keeping the order of members, and reads an object
// that holds one object and no members, {{...}}, as the inner object.
type mongoReader struct {
	s  string
	at int
}

func (r *mongoReader) space() {
	for r.at < len(r.s) && strings.ContainsRune(" \t\r\n", rune(r.s[r.at])) {
		r.at++
	}
}

func (r *mongoReader) expect(c byte) error {
	r.space()
	if r.at >= len(r.s) || r.s[r.at] != c {
		return fmt.Errorf("want %q at %d", c, r.at)
	}
	r.at++
	return nil
}

func (r *mongoReader) value() (any, error) {
	r.space()
	if r.at >= len(r.s) {
		return nil, fmt.Errorf("unexpected end")
	}
	switch r.s[r.at] {
	case '{':
		r.at++
		r.space()
		if r.at < len(r.s) && r.s[r.at] == '{' {
			inner, err := r.value()
			if err != nil {
				return nil, err
			}
			return inner, r.expect('}')
		}
		var ms []mongoMember
		r.space()
		if r.at < len(r.s) && r.s[r.at] == '}' {
			r.at++
			return ms, nil
		}
		for {
			k, err := r.value()
			if err != nil {
				return nil, err
			}
			key, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("a key is a string, got %v", k)
			}
			if err := r.expect(':'); err != nil {
				return nil, err
			}
			v, err := r.value()
			if err != nil {
				return nil, err
			}
			ms = append(ms, mongoMember{key, v})
			r.space()
			if r.at < len(r.s) && r.s[r.at] == ',' {
				r.at++
				continue
			}
			return ms, r.expect('}')
		}
	case '[':
		r.at++
		items := []any{}
		r.space()
		if r.at < len(r.s) && r.s[r.at] == ']' {
			r.at++
			return items, nil
		}
		for {
			v, err := r.value()
			if err != nil {
				return nil, err
			}
			items = append(items, v)
			r.space()
			if r.at < len(r.s) && r.s[r.at] == ',' {
				r.at++
				continue
			}
			return items, r.expect(']')
		}
	}
	dec := json.NewDecoder(strings.NewReader(r.s[r.at:]))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	r.at += int(dec.InputOffset())
	return v, nil
}

func TestTheFormulaOfAFilterTextIgnoresTheOrderAndRepetitionOfOperands(t *testing.T) {
	for _, tc := range []struct {
		name string
		d    policyir.Dialect
		a, b string
		same bool
	}{
		{"rsql operands swapped", policyir.DialectRSQL, `a=="y";(d!="y",b!="y")`, `(b!="y",d!="y");a=="y"`, true},
		{"rsql operand repeated", policyir.DialectRSQL, `d!="y",d!="y"`, `d!="y"`, true},
		{"rsql AND read as OR", policyir.DialectRSQL, `a=="y";d!="y"`, `a=="y",d!="y"`, false},
		{"rsql list kept in its atom", policyir.DialectRSQL, `c=in=("x","q");d=="y"`, `d=="y";c=in=("x","q")`, true},
		{"rsql precedence of ; over ,", policyir.DialectRSQL, `a==1;b==1,c==1`, `(a==1;b==1),c==1`, true},
		{"sql precedence of AND over OR", policyir.DialectSQL, `a = 'y' OR b = 'y' AND d <> 'y'`,
			`(a = 'y' OR b = 'y') AND d <> 'y'`, false},
		{"sql groups joined by lowercase or", policyir.DialectSQL, `(a = 'y') or (b = 'y')`, `b = 'y' OR a = 'y'`, true},
		{"sql NOT of a list", policyir.DialectSQL, `NOT (c IN ('x', 'q')) AND d = 'y'`,
			`d = 'y' AND NOT (c IN ('x', 'q'))`, true},
		{"sql a word inside a value is no operator", policyir.DialectSQL, `a = 'x AND y'`, `a = 'x AND y'`, true},
		{"mongodb $and items swapped", policyir.DialectMongoDB, `{ "$and": [ {"a": {"$eq": "y"}}, {"d": "y"} ] }`,
			`{"$and": [{"d": "y"}, {"a": {"$eq": "y"}}]}`, true},
		{"mongodb doubled braces", policyir.DialectMongoDB, `{{"c": {"$in": ["x", "q"]}}}`, `{"c": {"$in": ["x","q"]}}`, true},
		{"querydsl operands swapped", policyir.DialectQueryDSL, `(a.eq("y")).and((b.ne("y")).or(d.eq("y")))`,
			`((d.eq("y")).or(b.ne("y"))).and(a.eq("y"))`, true},
		{"querydsl AND read as OR", policyir.DialectQueryDSL, `(a.eq("y")).and(b.ne("y"))`,
			`(a.eq("y")).or(b.ne("y"))`, false},
		{"querydsl a predicate that is an OR", policyir.DialectQueryDSL, `a.eq("y").or(b.eq("y"))`,
			`(b.eq("y")).or(a.eq("y"))`, true},
		{"querydsl negation", policyir.DialectQueryDSL, `(a.eq("y")).not()`, `a.eq("y")`, false},
		{"querydsl a parenthesis inside a value", policyir.DialectQueryDSL, `(a.eq(").or(")).and(d.eq("y"))`,
			`(d.eq("y")).and(a.eq(").or("))`, true},
		{"rsql 17 atoms reordered", policyir.DialectRSQL, manyAtoms(17, ";", false), manyAtoms(17, ";", true), true},
		{"rsql 17 atoms with AND read as OR", policyir.DialectRSQL, manyAtoms(17, ";", false),
			manyAtoms(17, ",", false), false},
		{"mongodb $nor against $or", policyir.DialectMongoDB, `{ "$nor": [ {"d": "y"} ] }`, `{ "$or": [ {"d": "y"} ] }`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fa, err := parseFilterText(tc.d, tc.a)
			if err != nil {
				t.Fatalf("parseFilterText(%s, %q): %v", tc.d, tc.a, err)
			}
			fb, err := parseFilterText(tc.d, tc.b)
			if err != nil {
				t.Fatalf("parseFilterText(%s, %q): %v", tc.d, tc.b, err)
			}
			if got := sameFormula(fa, fb); got != tc.same {
				t.Errorf("sameFormula(%s, %s) = %v, want %v", fa.canonical(), fb.canonical(), got, tc.same)
			}
		})
	}
}

// manyAtoms joins the comparisons a0=="y" to a(n-1)=="y" by sep, in reverse
// order where reversed is true; past maxFormulaAtoms atoms they are compared
// by their normal forms.
func manyAtoms(n int, sep string, reversed bool) string {
	var parts []string
	for i := range n {
		parts = append(parts, fmt.Sprintf(`a%d=="y"`, i))
	}
	if reversed {
		slices.Reverse(parts)
	}
	return strings.Join(parts, sep)
}
