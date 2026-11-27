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
	"strings"
	"testing"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/policyir"
)

func TestRSQLMayBeOr(t *testing.T) {
	for _, tc := range []struct {
		text string
		want bool
	}{
		{"a==1", false},
		{"a==1;b==2", false},
		{"a==1,b==2", true},
		{"a==1 or b==2", true},
		{"(a==1,b==2)", false},
		{"(a==1,b==2);c==3", false},
		{"a=in=(1,2)", false},
		{"a=='x,y'", false},
		{`a=="x\",y"`, false},
		{"(a==1", true},
		{"a==1)", true},
		{"a=='x", true},
	} {
		if got := rsqlMayBeOr(tc.text); got != tc.want {
			t.Errorf("rsqlMayBeOr(%q) = %v, want %v", tc.text, got, tc.want)
		}
	}
}

func TestSQLMayBeOr(t *testing.T) {
	for _, tc := range []struct {
		text string
		want bool
	}{
		{"a = 1", false},
		{"a = 1 AND b = 2", false},
		{"a = 1 OR b = 2", true},
		{"a = 1 or b = 2", true},
		{"a = 1\tOr\nb = 2", true},
		{"(a = 1 OR b = 2)", false},
		{"(a = 1 OR b = 2) AND c = 3", false},
		{"a IN (1, 2)", false},
		{"color = 'red' AND origin = 'x'", false},
		{"a = 'x OR y'", false},
		{"a = 'it''s' OR b = 1", true},
		{`"or" = 1`, false},
		{"a <> 1.5 AND b::text >= 'x'", false},
		{"a = 1OR b = 2", true},
		{"a = 1 XOR b = 2", true},
		{"a = 1 # note", true},
		{"a | b = 1", true},
		{"a = ?", true},
		{"[it's] = 1 OR b = [x']", true},
		{"a = 1 AND b = 2\u00a0OR c = 3", true},
		{"a || b = 'xy'", true},
		{"a = 'x\\' OR b = 1", true},
		{"a = $$x$$", true},
		{"a = 1 -- note", true},
		{"a = 1 /* note */", true},
		{"(a = 1", true},
		{"a = 1)", true},
		{"a = 'x", true},
	} {
		if got := sqlMayBeOr(tc.text); got != tc.want {
			t.Errorf("sqlMayBeOr(%q) = %v, want %v", tc.text, got, tc.want)
		}
	}
}

// The text holds the values of placeholders, which the caller and the PIPs
// give, so rsqlMayBeOr scans it rather than building a tree of its groups.
// Parsing a value nested 4000 groups deep allocated tens of megabytes.
func TestRSQLMayBeOrDoesNotBuildTheGroups(t *testing.T) {
	const n = 4000
	s := "a==x;" + strings.Repeat("(a==x;", n) + "a==1" + strings.Repeat(")", n)
	if allocs := testing.AllocsPerRun(1, func() { rsqlMayBeOr(s) }); allocs > 100 {
		t.Errorf("rsqlMayBeOr over %d nested groups made %v allocations, want at most 100", n, allocs)
	}
}

// A MongoDB text nested deeper than a JSON document may be is negated whole,
// as text whose brackets do not pair, rather than by a walk as deep as the
// text. At the limit the walk reaches the innermost object, and a scalar in
// it does not count as a level.
func TestAMongoDBTextNestedTooDeeplyIsWrappedInNorWhole(t *testing.T) {
	for _, tc := range []struct {
		name, inner string
		depth       int
		want        func(s string) string
	}{
		{"at the limit", "", jsonvalue.MaxDepth, func(s string) string {
			d := jsonvalue.MaxDepth
			return strings.Repeat("{", d-1) + `{ "$nor": [ {} ] }` + strings.Repeat("}", d-1)
		}},
		{"a scalar at the limit", `"a": 1`, jsonvalue.MaxDepth, func(s string) string {
			d := jsonvalue.MaxDepth
			return strings.Repeat("{", d-1) + `{ "$nor": [ {"a": 1} ] }` + strings.Repeat("}", d-1)
		}},
		{"past the limit", "", jsonvalue.MaxDepth + 1, func(s string) string { return `{ "$nor": [ ` + s + " ] }" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := strings.Repeat("{", tc.depth) + tc.inner + strings.Repeat("}", tc.depth)
			if got, want := negateMongoText(s), tc.want(s); got != want {
				t.Errorf("negateMongoText(%d nested objects) has $nor at %d of %d bytes, want at %d of %d",
					tc.depth, strings.Index(got, "$nor"), len(got), strings.Index(want, "$nor"), len(want))
			}
		})
	}
}

func sqlLeaf(text string) *fexpr {
	return &fexpr{kind: "leaf", term: &fterm{key: text, text: map[policyir.Dialect]string{policyir.DialectSQL: text}}}
}

// An SQL line comment, -- or the # of MySQL, runs to the end of its line, so
// a text whose last line holds an opener is followed by a line feed before the
// syntax the filter writes after it, a quoted -- included.
func TestTheSQLSyntaxAfterALineCommentStaysOutOfIt(t *testing.T) {
	plain := sqlLeaf("b = 2")
	for _, tc := range []struct {
		name string
		x    *fexpr
		want string
	}{
		{"the negation of a text ending in --", negate(sqlLeaf("a = 1 -- note")), "NOT (a = 1 -- note\n)"},
		{"the negation of a text ending in #", negate(sqlLeaf("a = 1 # note")), "NOT (a = 1 # note\n)"},
		{"an AND after a text ending in --", &fexpr{kind: "and", parts: []*fexpr{sqlLeaf("a = 1 -- it's"), plain}},
			"(a = 1 -- it's\n) AND b = 2"},
		{"an OR after a text ending in --", &fexpr{kind: "or", parts: []*fexpr{sqlLeaf("a = 1 -- note"), plain}},
			"a = 1 -- note\n OR b = 2"},
		{"groups after a text ending in --", &fexpr{kind: "grp", parts: []*fexpr{sqlLeaf("a = 1 -- note"), plain}},
			"(a = 1 -- note\n) or (b = 2)"},
		{"a text that ends in -- last", &fexpr{kind: "or", parts: []*fexpr{plain, sqlLeaf("a = 1 -- note")}},
			"b = 2 OR a = 1 -- note"},
		{"the negation of a text ending in -- and a carriage return", negate(sqlLeaf("a = 1 -- note\r")),
			"NOT (a = 1 -- note\r\n)"},
		{"the negation of a dollar-quoted string with a quote, then --", negate(sqlLeaf("a = $$x'$$ -- note")),
			"NOT (a = $$x'$$ -- note\n)"},
		{"the negation of a dollar-quoted string with a quote, then -- with a quote",
			negate(sqlLeaf("a = $$'$$ -- it's")), "NOT (a = $$'$$ -- it's\n)"},
		{"a -- inside a quoted string", negate(sqlLeaf("a = '--'")), "NOT (a = '--'\n)"},
		{"a block comment", negate(sqlLeaf("a = 1 /* note */")), "NOT (a = 1 /* note */)"},
		{"a comment ended by a line break", negate(sqlLeaf("a = 1 -- note\nAND b = 2")),
			"NOT (a = 1 -- note\nAND b = 2)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := render(tc.x, policyir.DialectSQL); got != tc.want {
				t.Errorf("render(%s) = %q, want %q", tc.x.key(), got, tc.want)
			}
		})
	}
}
