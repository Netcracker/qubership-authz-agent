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
	"regexp"
	"strings"
	"testing"

	"authz-agent/internal/policyir"
)

// truth is a value of three-valued logic: SQL, and an RSQL or QueryDSL
// filter translated to SQL, find a comparison with NULL neither true nor
// false. A row is selected only where the filter is true.
type truth int8

const (
	isFalse truth = iota
	isUnknown
	isTrue
)

func (a truth) and(b truth) truth { return min(a, b) }
func (a truth) or(b truth) truth  { return max(a, b) }
func (a truth) not() truth        { return isTrue - a }

func (a truth) String() string {
	return [...]string{"false", "unknown", "true"}[a]
}

// textRow is a row a filter text is evaluated on: each column holds a
// string or nil for null, and a column the row does not hold is null.
type textRow map[string]any

// rowPredicate is a compiled filter text: its truth on a row.
type rowPredicate func(textRow) truth

// compileText compiles the filter text of dialect d into its truth on a
// row. It reads the boolean structure with [parseFilterText] and each
// comparison with the evaluator of the dialect, and returns an error for a
// comparison that evaluator does not know.
func compileText(d policyir.Dialect, text string) (rowPredicate, error) {
	f, err := parseFilterText(d, text)
	if err != nil {
		return nil, err
	}
	return compileFormula(f, func(atom string) (rowPredicate, error) { return compileAtom(d, atom) })
}

func compileFormula(f *formula, atom func(string) (rowPredicate, error)) (rowPredicate, error) {
	switch f.op {
	case "atom":
		return atom(f.atom)
	case "true":
		return func(textRow) truth { return isTrue }, nil
	case "false":
		return func(textRow) truth { return isFalse }, nil
	}
	parts := make([]rowPredicate, len(f.parts))
	for i, p := range f.parts {
		c, err := compileFormula(p, atom)
		if err != nil {
			return nil, err
		}
		parts[i] = c
	}
	switch f.op {
	case "not":
		return func(r textRow) truth { return parts[0](r).not() }, nil
	case "and":
		return func(r textRow) truth {
			acc := isTrue
			for _, p := range parts {
				acc = acc.and(p(r))
			}
			return acc
		}, nil
	}
	return func(r textRow) truth {
		acc := isFalse
		for _, p := range parts {
			acc = acc.or(p(r))
		}
		return acc
	}, nil
}

func compileAtom(d policyir.Dialect, atom string) (rowPredicate, error) {
	switch d {
	case policyir.DialectRSQL:
		return compileRSQLAtom(atom)
	case policyir.DialectSQL:
		return compileSQLAtom(atom)
	case policyir.DialectMongoDB:
		return compileMongoAtom(atom)
	case policyir.DialectQueryDSL:
		return compileQueryDSLAtom(atom)
	}
	return nil, fmt.Errorf("no evaluator for dialect %s", d)
}

// inList is the truth of col IN (values) in SQL: unknown on a null column,
// true where a value equals the column, unknown where none does and one of
// values is NULL (nil), and false otherwise.
func inList(r textRow, col string, values []*string) truth {
	v, _ := r[col].(string)
	if r[col] == nil {
		return isUnknown
	}
	out := isFalse
	for _, x := range values {
		switch {
		case x == nil:
			out = out.or(isUnknown)
		case *x == v:
			return isTrue
		}
	}
	return out
}

var rsqlAtomRE = regexp.MustCompile(`^([A-Za-z_][\w.]*)(==|!=|=in=|=out=)(.*)$`)

// compileRSQLAtom compiles an RSQL comparison: ==, !=, =in=, or =out= with
// a value or a parenthesized list of values, each quoted with " or ' or bare.
// A null column makes every comparison unknown, as the usual translation of
// != and =out= to SQL <> and NOT IN reads it.
//
// A * in a value is refused: a consumer may read it in == as a wildcard or
// as the character itself, and the two readings select different rows. The
// test that uses this evaluator writes no value with a *.
func compileRSQLAtom(atom string) (rowPredicate, error) {
	m := rsqlAtomRE.FindStringSubmatch(strings.TrimSpace(atom))
	if m == nil {
		return nil, fmt.Errorf("rsql: no comparison in %q", atom)
	}
	col, op, rest := m[1], m[2], strings.TrimSpace(m[3])
	var values []string
	if strings.HasPrefix(rest, "(") {
		if !strings.HasSuffix(rest, ")") {
			return nil, fmt.Errorf("rsql: unclosed list in %q", atom)
		}
		vs, err := readValues(rest[1:len(rest)-1], `\`)
		if err != nil {
			return nil, fmt.Errorf("rsql: %w in %q", err, atom)
		}
		values = vs
	} else {
		vs, err := readValues(rest, `\`)
		if err != nil || len(vs) != 1 {
			return nil, fmt.Errorf("rsql: want one value in %q", atom)
		}
		values = vs
	}
	lits := make([]*string, len(values))
	for i, v := range values {
		if strings.Contains(v, "*") {
			return nil, fmt.Errorf("rsql: %q holds a *, which a consumer may read as a wildcard", atom)
		}
		lits[i] = &values[i]
	}
	if op == "==" || op == "!=" {
		if len(lits) != 1 {
			return nil, fmt.Errorf("rsql: %s takes one value in %q", op, atom)
		}
	}
	negated := op == "!=" || op == "=out="
	return func(r textRow) truth {
		v := inList(r, col, lits)
		if negated {
			return v.not()
		}
		return v
	}, nil
}

// readValues reads a comma-separated list of values, each quoted with " or
// ' (where escape, when not empty, escapes the next character) or bare up to
// the next comma.
func readValues(s, escape string) ([]string, error) {
	var out []string
	i := 0
	skip := func() {
		for i < len(s) && s[i] == ' ' {
			i++
		}
	}
	for skip(); i < len(s); skip() {
		var b strings.Builder
		if q := s[i]; q == '"' || q == '\'' {
			i++
			for ; i < len(s) && s[i] != q; i++ {
				if escape != "" && s[i] == escape[0] && i+1 < len(s) {
					i++
				}
				b.WriteByte(s[i])
			}
			if i == len(s) {
				return nil, fmt.Errorf("unterminated string")
			}
			i++
		} else {
			for ; i < len(s) && s[i] != ',' && s[i] != ' '; i++ {
				if strings.ContainsRune(`"'()`, rune(s[i])) {
					return nil, fmt.Errorf("unexpected %q in a bare value", s[i])
				}
				b.WriteByte(s[i])
			}
			if b.Len() == 0 {
				return nil, fmt.Errorf("empty value")
			}
		}
		out = append(out, b.String())
		skip()
		if i < len(s) {
			if s[i] != ',' {
				return nil, fmt.Errorf("want , at %d", i)
			}
			i++
		}
	}
	return out, nil
}

var (
	sqlCompareRE = regexp.MustCompile(`^([A-Za-z_][\w.]*)\s*(=|<>|!=)\s*(.+)$`)
	sqlInRE      = regexp.MustCompile(`(?i)^([A-Za-z_][\w.]*)\s+(NOT\s+)?IN\s*\((.*)\)$`)
	sqlIsNullRE  = regexp.MustCompile(`(?i)^([A-Za-z_][\w.]*)\s+IS\s+(NOT\s+)?NULL$`)
)

// compileSQLAtom compiles an SQL comparison of a column with a literal: =,
// <>, or !=; [NOT] IN with a list of literals; or IS [NOT] NULL. A literal
// is a string in single quotes, with a doubled single quote for a quote, or NULL.
func compileSQLAtom(atom string) (rowPredicate, error) {
	atom = strings.TrimSpace(atom)
	if m := sqlIsNullRE.FindStringSubmatch(atom); m != nil {
		col, negated := m[1], m[2] != ""
		return func(r textRow) truth {
			if (r[col] == nil) != negated {
				return isTrue
			}
			return isFalse
		}, nil
	}
	if m := sqlInRE.FindStringSubmatch(atom); m != nil {
		lits, err := sqlLiterals(m[3])
		if err != nil {
			return nil, fmt.Errorf("sql: %w in %q", err, atom)
		}
		col, negated := m[1], m[2] != ""
		return func(r textRow) truth {
			v := inList(r, col, lits)
			if negated {
				return v.not()
			}
			return v
		}, nil
	}
	if m := sqlCompareRE.FindStringSubmatch(atom); m != nil {
		lits, err := sqlLiterals(m[3])
		if err != nil || len(lits) != 1 {
			return nil, fmt.Errorf("sql: want one literal in %q", atom)
		}
		col, negated := m[1], m[2] != "="
		return func(r textRow) truth {
			v := inList(r, col, lits)
			if negated {
				return v.not()
			}
			return v
		}, nil
	}
	return nil, fmt.Errorf("sql: no comparison in %q", atom)
}

// sqlLiterals reads a comma-separated list of SQL literals; NULL is nil.
func sqlLiterals(s string) ([]*string, error) {
	var out []*string
	i := 0
	skip := func() {
		for i < len(s) && s[i] == ' ' {
			i++
		}
	}
	for skip(); i < len(s); skip() {
		switch {
		case s[i] == '\'':
			var b strings.Builder
			for i++; ; i++ {
				if i == len(s) {
					return nil, fmt.Errorf("unterminated string")
				}
				if s[i] == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						i++
					} else {
						break
					}
				}
				b.WriteByte(s[i])
			}
			i++
			v := b.String()
			out = append(out, &v)
		case len(s)-i >= 4 && strings.EqualFold(s[i:i+4], "NULL"):
			i += 4
			out = append(out, nil)
		default:
			return nil, fmt.Errorf("want a literal at %d", i)
		}
		skip()
		if i < len(s) {
			if s[i] != ',' {
				return nil, fmt.Errorf("want , at %d", i)
			}
			i++
		}
	}
	return out, nil
}

var queryDSLAtomRE = regexp.MustCompile(`^([A-Za-z_]\w*)\.(eq|ne|in|notIn)\((.*)\)$`)

// compileQueryDSLAtom compiles a QueryDSL comparison of a path with string
// constants: eq and ne with one, in and notIn with several. QueryDSL writes
// SQL, so a comparison on a null column is unknown.
func compileQueryDSLAtom(atom string) (rowPredicate, error) {
	m := queryDSLAtomRE.FindStringSubmatch(strings.TrimSpace(atom))
	if m == nil {
		return nil, fmt.Errorf("querydsl: no comparison in %q", atom)
	}
	values, err := readValues(m[3], `\`)
	if err != nil {
		return nil, fmt.Errorf("querydsl: %w in %q", err, atom)
	}
	if strings.Contains(m[3], "'") || !strings.HasPrefix(strings.TrimSpace(m[3]), `"`) {
		return nil, fmt.Errorf("querydsl: want string constants in %q", atom)
	}
	if (m[2] == "eq" || m[2] == "ne") && len(values) != 1 {
		return nil, fmt.Errorf("querydsl: %s takes one value in %q", m[2], atom)
	}
	lits := make([]*string, len(values))
	for i := range values {
		lits[i] = &values[i]
	}
	col, negated := m[1], m[2] == "ne" || m[2] == "notIn"
	return func(r textRow) truth {
		v := inList(r, col, lits)
		if negated {
			return v.not()
		}
		return v
	}, nil
}

// compileMongoAtom compiles one member of a MongoDB filter, as
// [readMongoFormula] writes it: a field with a string or null, which it
// equals, or with an object of $eq, $ne, $in, and $nin. MongoDB is
// two-valued: null equals a missing field and only null, and $ne and $nin
// select a row whose field is null.
func compileMongoAtom(atom string) (rowPredicate, error) {
	r := &mongoReader{s: atom}
	v, err := r.value()
	if err != nil {
		return nil, fmt.Errorf("mongodb: %w in %q", err, atom)
	}
	ms, ok := v.([]mongoMember)
	if !ok || len(ms) != 1 || strings.HasPrefix(ms[0].key, "$") {
		return nil, fmt.Errorf("mongodb: want one field in %q", atom)
	}
	col := ms[0].key
	ops, isOps := ms[0].val.([]mongoMember)
	if !isOps {
		lit, err := mongoLiteral(ms[0].val)
		if err != nil {
			return nil, fmt.Errorf("mongodb: %w in %q", err, atom)
		}
		return func(r textRow) truth { return mongoIn(r, col, []*string{lit}, false) }, nil
	}
	var checks []rowPredicate
	for _, op := range ops {
		var lits []*string
		switch op.key {
		case "$eq", "$ne":
			lit, err := mongoLiteral(op.val)
			if err != nil {
				return nil, fmt.Errorf("mongodb: %w in %q", err, atom)
			}
			lits = []*string{lit}
		case "$in", "$nin":
			items, ok := op.val.([]any)
			if !ok {
				return nil, fmt.Errorf("mongodb: %s takes an array in %q", op.key, atom)
			}
			for _, it := range items {
				lit, err := mongoLiteral(it)
				if err != nil {
					return nil, fmt.Errorf("mongodb: %w in %q", err, atom)
				}
				lits = append(lits, lit)
			}
		default:
			return nil, fmt.Errorf("mongodb: no evaluator for %s in %q", op.key, atom)
		}
		negated := op.key == "$ne" || op.key == "$nin"
		checks = append(checks, func(r textRow) truth { return mongoIn(r, col, lits, negated) })
	}
	return func(r textRow) truth {
		acc := isTrue
		for _, c := range checks {
			acc = acc.and(c(r))
		}
		return acc
	}, nil
}

// mongoLiteral is a string or null of a MongoDB filter; nil is null.
func mongoLiteral(v any) (*string, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case string:
		return &x, nil
	}
	b, _ := json.Marshal(v)
	return nil, fmt.Errorf("no evaluator for the value %s", b)
}

// mongoIn reports whether the field col equals one of lits, negated where
// negated is true.
func mongoIn(r textRow, col string, lits []*string, negated bool) truth {
	v, isString := r[col].(string)
	found := false
	for _, l := range lits {
		if l == nil && r[col] == nil || l != nil && isString && *l == v {
			found = true
		}
	}
	if found != negated {
		return isTrue
	}
	return isFalse
}

func TestTheDialectEvaluatorsReadKnownTexts(t *testing.T) {
	y, n, q := "y", "n", "q"
	for _, tc := range []struct {
		name string
		d    policyir.Dialect
		text string
		row  textRow
		want truth
	}{
		{"rsql equality", policyir.DialectRSQL, `a=="y"`, textRow{"a": y}, isTrue},
		{"rsql equality with another value", policyir.DialectRSQL, `a=="y"`, textRow{"a": q}, isFalse},
		{"rsql equality on a null column", policyir.DialectRSQL, `a=="y"`, textRow{"a": nil}, isUnknown},
		{"rsql inequality on a null column", policyir.DialectRSQL, `a!="y"`, textRow{}, isUnknown},
		{"rsql bare value", policyir.DialectRSQL, `a==q`, textRow{"a": q}, isTrue},
		{"rsql dollar sign kept", policyir.DialectRSQL, `a=="${subject.id}"`, textRow{"a": "${subject.id}"}, isTrue},
		{"rsql list", policyir.DialectRSQL, `c=in=("x", "n")`, textRow{"c": "n"}, isTrue},
		{"rsql list negated", policyir.DialectRSQL, `c=out=("x","n")`, textRow{"c": q}, isTrue},
		{"rsql ; binds tighter than ,", policyir.DialectRSQL, `a=="y",b=="y";c=="x"`,
			textRow{"a": y, "b": n, "c": n}, isTrue},
		{"rsql parentheses group", policyir.DialectRSQL, `(a=="y",b=="y");c=="x"`,
			textRow{"a": y, "b": n, "c": n}, isFalse},
		{"sql equality", policyir.DialectSQL, `a = 'y'`, textRow{"a": y}, isTrue},
		{"sql inequality on a null column", policyir.DialectSQL, `a <> 'y'`, textRow{"a": nil}, isUnknown},
		{"sql doubled quote", policyir.DialectSQL, `a = 'it''s'`, textRow{"a": "it's"}, isTrue},
		{"sql list without a match but with NULL", policyir.DialectSQL, `c IN ('x', NULL)`, textRow{"c": q}, isUnknown},
		{"sql list with a match and NULL", policyir.DialectSQL, `c IN ('x', NULL)`, textRow{"c": "x"}, isTrue},
		{"sql NOT IN", policyir.DialectSQL, `c NOT IN ('x')`, textRow{"c": q}, isTrue},
		{"sql IS NULL", policyir.DialectSQL, `a IS NULL`, textRow{}, isTrue},
		{"sql NOT of unknown", policyir.DialectSQL, `NOT (a = 'y')`, textRow{"a": nil}, isUnknown},
		{"sql AND binds tighter than OR", policyir.DialectSQL, `a = 'y' OR b = 'y' AND c = 'x'`,
			textRow{"a": y, "b": n, "c": n}, isTrue},
		{"sql parentheses group", policyir.DialectSQL, `(a = 'y' OR b = 'y') AND c = 'x'`,
			textRow{"a": y, "b": n, "c": n}, isFalse},
		{"mongodb equality", policyir.DialectMongoDB, `{"a": "y"}`, textRow{"a": y}, isTrue},
		{"mongodb $ne selects a null field", policyir.DialectMongoDB, `{"a": {"$ne": "y"}}`, textRow{"a": nil}, isTrue},
		{"mongodb null equals a missing field", policyir.DialectMongoDB, `{"a": null}`, textRow{}, isTrue},
		{"mongodb $in", policyir.DialectMongoDB, `{"c": {"$in": ["x", "n"]}}`, textRow{"c": n}, isTrue},
		{"mongodb $nin selects a null field", policyir.DialectMongoDB, `{"c": {"$nin": ["x"]}}`, textRow{}, isTrue},
		{"mongodb $nor", policyir.DialectMongoDB, `{ "$nor": [ {"a": "y"} ] }`, textRow{"a": y}, isFalse},
		{"mongodb $or", policyir.DialectMongoDB, `{"$or": [{"a": "y"}, {"b": "y"}]}`, textRow{"b": y}, isTrue},
		{"mongodb doubled braces", policyir.DialectMongoDB, `{ {"a": "$q"} }`, textRow{"a": "$q"}, isTrue},
		{"querydsl equality", policyir.DialectQueryDSL, `a.eq("y")`, textRow{"a": y}, isTrue},
		{"querydsl inequality on a null column", policyir.DialectQueryDSL, `a.ne("y")`, textRow{}, isUnknown},
		{"querydsl list", policyir.DialectQueryDSL, `c.in("x", "n")`, textRow{"c": n}, isTrue},
		{"querydsl not of unknown", policyir.DialectQueryDSL, `(a.eq("y")).not()`, textRow{}, isUnknown},
		{"querydsl or", policyir.DialectQueryDSL, `(a.eq("y")).or(b.eq("y"))`, textRow{"a": n, "b": y}, isTrue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sel, err := compileText(tc.d, tc.text)
			if err != nil {
				t.Fatalf("compileText(%s, %q): %v", tc.d, tc.text, err)
			}
			if got := sel(tc.row); got != tc.want {
				t.Errorf("%s %q on %v = %v, want %v", tc.d, tc.text, tc.row, got, tc.want)
			}
		})
	}
}

// Whether a consumer reads * in an RSQL == as a wildcard is open, so the
// RSQL evaluator takes neither side.
func TestTheRSQLEvaluatorRefusesAWildcardCharacter(t *testing.T) {
	for _, text := range []string{`a=="x*"`, `c=in=("x","q*")`} {
		if _, err := compileText(policyir.DialectRSQL, text); err == nil {
			t.Errorf("compileText(rsql, %q) succeeded, want an error", text)
		}
	}
}
