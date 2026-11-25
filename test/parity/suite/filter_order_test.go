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

package paritysuite

import (
	"encoding/json"
	"testing"

	"authz-agent/test/parity/suite/model"
	"github.com/google/go-cmp/cmp"
)

func sqlCanon(s string) string     { return canonicalInfix(s, sqlDialect) }
func rsqlCanon(s string) string    { return canonicalInfix(s, rsqlDialect) }
func mongodbCanon(s string) string { return canonicalInfix(s, mongodbDialect) }
func customCanon(s string) string  { return string(canonicalJSON(json.RawMessage(s))) }

// A filterOrderCase is two texts of one filter dialect and the canonicalizer of
// that dialect.
type filterOrderCase struct {
	name         string
	canonicalize func(string) string
	left, right  string
}

// The operands of a logical operator and the elements of a list that stands
// for a set compare without regard to their order, in every dialect, whatever
// the letter case of the keyword and the white space before the bracket. Most
// texts are recorded answers with their terms permuted.
func TestCanonicalFilter_UnorderedListsCompareEqual(t *testing.T) {
	t.Parallel()
	cases := []filterOrderCase{
		{name: "sql operands of AND under NOT and of a bracketed OR", canonicalize: sqlCanon,
			left:  "(a=1 OR b=2) AND NOT (c=3) AND NOT (d=4)",
			right: "NOT (d=4) AND (b=2 OR a=1) AND NOT (c=3)"},
		{name: "sql operands of a lower-case or", canonicalize: sqlCanon,
			left:  "(f14a='v0') or (NOT (f5a IN ('R') OR f5b='v1'))",
			right: "(NOT (f5b='v1' OR f5a IN ('R'))) OR (f14a='v0')"},
		{name: "sql IN list elements", canonicalize: sqlCanon,
			left:  "perms IN ('parity_other_permission', 'parity_permission') AND a=1",
			right: "a=1 AND perms IN ('parity_permission', 'parity_other_permission')"},
		{name: "sql lower-case in with a space before the bracket", canonicalize: sqlCanon,
			left:  "k in ('x', 'y')",
			right: "k in ('y', 'x')"},
		{name: "sql NOT IN list elements", canonicalize: sqlCanon,
			left:  "k NOT IN ('x', 'y')",
			right: "k NOT IN ('y','x')"},
		{name: "sql operands of AND beside a BETWEEN, whose AND joins nothing", canonicalize: sqlCanon,
			left:  "a BETWEEN 1 AND 2 AND b=3",
			right: "b=3 and a BETWEEN 1 AND 2"},
		{name: "sql operands of a lower-case and beside a lower-case between", canonicalize: sqlCanon,
			left:  "a between 1 and 2 and b=3",
			right: "b=3 and a between 1 and 2"},
		{name: "sql operands of AND beside a bracketed BETWEEN", canonicalize: sqlCanon,
			left:  "(a BETWEEN 1 AND 2 AND c=4) AND b=3",
			right: "b=3 AND (c=4 AND a BETWEEN 1 AND 2)"},
		{name: "sql OR right after a closing quote", canonicalize: sqlCanon,
			left:  "a='v'OR b=1",
			right: "b=1 OR a='v'"},
		{name: "sql backslash before a closing quote", canonicalize: sqlCanon,
			left:  `a='x\' OR b=1`,
			right: `b=1 OR a='x\'`},
		{name: "rsql operands of AND and of a bracketed OR", canonicalize: rsqlCanon,
			left:  "(b==2,a==1);c!=3;d!=4",
			right: "d!=4;(a==1,b==2);c!=3"},
		{name: "rsql bracketed groups of four sources", canonicalize: rsqlCanon,
			left:  "(allowed==1),((region=in=(\"r1\")),(region=in=(\"r2\")))",
			right: "((region=in=(\"r2\")),(region=in=(\"r1\"))),(allowed==1)"},
		{name: "rsql =in= elements", canonicalize: rsqlCanon,
			left:  `id=in=("row10-dict-1", "row10-dict-2");amount=le="1000"`,
			right: `amount=le="1000";id=in=("row10-dict-2", "row10-dict-1")`},
		{name: "rsql =out= elements with a space before the bracket", canonicalize: rsqlCanon,
			left:  `f1a=out= ("p1", "p2")`,
			right: `f1a=out= ("p2", "p1")`},
		{name: "rsql escaped quote inside a string", canonicalize: rsqlCanon,
			left:  `q=='a\',b';r!=1`,
			right: `r!=1;q=='a\',b'`},
		{name: "rsql escaped backslash before a closing quote", canonicalize: rsqlCanon,
			left:  `q=='a\\';r!=1`,
			right: `r!=1;q=='a\\'`},
		{name: "mongodb elements of $and and of a nested $or", canonicalize: mongodbCanon,
			left:  `{ "$and": [ { "$or": [ {{ "b": 2 }}, {{ "a": 1 }} ] }, {{ "c": 3 }}, {{ "d": 4 }} ] }`,
			right: `{ "$and": [ {{ "d": 4 }}, { "$or": [ {{ "a": 1 }}, {{ "b": 2 }} ] }, {{ "c": 3 }} ] }`},
		{name: "mongodb values of $in and of $nin", canonicalize: mongodbCanon,
			left:  `{ "$or": [ { "a": { "$in": [ { "$uuid": "h1" }, { "$uuid": "h2" } ] } }, { "b": { "$nin": [ "x", "y" ] } } ] }`,
			right: `{ "$or": [ { "b": { "$nin": [ "y", "x" ] } }, { "a": { "$in": [ { "$uuid": "h2" }, { "$uuid": "h1" } ] } } ] }`},
		{name: "mongodb elements of $nor", canonicalize: mongodbCanon,
			left:  `{ "$nor": [ {{ "b": 2 }}, {{ "a": 1 }} ] }`,
			right: `{ "$nor": [ {{ "a": 1 }}, {{ "b": 2 }} ] }`},
		{name: "mongodb $in with white space before the colon", canonicalize: mongodbCanon,
			left:  `{ "a": { "$in" : [ "x", "y" ] } }`,
			right: `{ "a": { "$in" : [ "y", "x" ] } }`},
		{name: "custom apply of an OR node and of a lower-case and node", canonicalize: customCanon,
			left:  `{"logic":{"op":"OR","apply":[{"path":"p2"},{"op":"and","apply":[{"path":"p3"},{"path":"p1"}]}]}}`,
			right: `{"logic":{"apply":[{"apply":[{"path":"p1"},{"path":"p3"}],"op":"and"},{"path":"p2"}],"op":"OR"}}`},
		{name: "custom apply of an OR node under a NOT node", canonicalize: customCanon,
			left:  `{"logic":{"op":"NOT","apply":[{"op":"OR","apply":[{"path":"p2"},{"path":"p1"}]}]}}`,
			right: `{"logic":{"op":"NOT","apply":[{"op":"OR","apply":[{"path":"p1"},{"path":"p2"}]}]}}`},
		{name: "method chain or call with a space after the dot", canonicalize: canonicalMethodChain,
			left:  "(T.a.eq(1)). or (T.b.eq(2))",
			right: "(T.b.eq(2)).or(T.a.eq(1))"},
		{name: "method chain escaped quote inside an argument", canonicalize: canonicalMethodChain,
			left:  `(T.a.eq("x\").or(")).or(T.b.eq(2))`,
			right: `(T.b.eq(2)).or(T.a.eq("x\").or("))`},
		{name: "method chain operands of and and of a nested or", canonicalize: canonicalMethodChain,
			left:  "((T.b.eq(2)).or(T.a.eq(1))).and((T.c.eq(3)).not()).and((T.d.eq(4)).not())",
			right: "((T.d.eq(4)).not()).and((T.a.eq(1)).or(T.b.eq(2))).and((T.c.eq(3)).not())"},
		{name: "method chain in and notIn arguments", canonicalize: canonicalMethodChain,
			left:  `(T.id.in("b", "a")).and(T.x.notIn("d", "c"))`,
			right: `(T.x.notIn("c", "d")).and(T.id.in("a", "b"))`},
		{name: "method chain or call in another case and with a space", canonicalize: canonicalMethodChain,
			left:  "(T.a.eq(1)).OR (T.b.eq(2))",
			right: "(T.b.eq(2)).or(T.a.eq(1))"},
		{name: "method chain mixing or and and groups the leading run", canonicalize: canonicalMethodChain,
			left:  "T.b.eq(2).or(T.a.eq(1)).and(T.c.eq(3))",
			right: "T.c.eq(3).and(T.a.eq(1).or(T.b.eq(2)))"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got, want := tc.canonicalize(tc.right), tc.canonicalize(tc.left); got != want {
				t.Errorf("canonical(%q) = %q, want canonical(%q) = %q", tc.right, got, tc.left, want)
			}
		})
	}
}

// Every list that is neither the operands of a logical operator nor a set of
// values keeps its order, as does the grouping of the operands: the arguments
// of a function or a comparison, a literal array, the members of a MongoDB
// object, and every array of a customFilterCondition other than the apply array
// of an OR or an AND. The letter case of a function name and white space before
// its bracket do not make its arguments a set.
func TestCanonicalFilter_OrderedListsStayApart(t *testing.T) {
	t.Parallel()
	cases := []filterOrderCase{
		{name: "sql arguments of COALESCE", canonicalize: sqlCanon,
			left:  "COALESCE(owner, delegate) = 'u' AND a=1",
			right: "a=1 AND COALESCE(delegate, owner) = 'u'"},
		{name: "sql arguments of SUBSTRING", canonicalize: sqlCanon,
			left:  "SUBSTRING(name, 1, 3) = 'abc'",
			right: "SUBSTRING(name, 3, 1) = 'abc'"},
		{name: "sql arguments of SUBSTRING with a space before the bracket", canonicalize: sqlCanon,
			left:  "SUBSTRING (name, 1, 3) = 'abc'",
			right: "SUBSTRING (name, 3, 1) = 'abc'"},
		{name: "sql arguments of a lower-case function with a space before the bracket", canonicalize: sqlCanon,
			left:  "substring (name, 1, 3) = 'abc' OR a=1",
			right: "a=1 OR substring (name, 3, 1) = 'abc'"},
		{name: "sql operands of a comparison", canonicalize: sqlCanon,
			left:  "a < b",
			right: "b < a"},
		{name: "sql values after a comparison", canonicalize: sqlCanon,
			left:  "a='a', 'b'",
			right: "a='b', 'a'"},
		{name: "sql OR inside the AND against AND inside the OR", canonicalize: sqlCanon,
			left:  "(a=1 OR b=2) AND c=3",
			right: "a=1 OR (b=2 AND c=3)"},
		{name: "sql OR inside a quoted string", canonicalize: sqlCanon,
			left:  "a='x OR y' AND b=1",
			right: "b=1 AND a='y OR x'"},
		{name: "sql bounds of two BETWEEN ranges", canonicalize: sqlCanon,
			left:  "x BETWEEN 1 AND 5 AND y BETWEEN 2 AND 3",
			right: "x BETWEEN 1 AND 3 AND y BETWEEN 2 AND 5"},
		{name: "rsql bounds of between", canonicalize: rsqlCanon,
			left:  "age=between=(18,65);a==1",
			right: "a==1;age=between=(65,18)"},
		{name: "rsql bounds of an upper-case between with a space before the bracket", canonicalize: rsqlCanon,
			left:  "age=BETWEEN= (18,65)",
			right: "age=BETWEEN= (65,18)"},
		{name: "rsql OR inside the AND against AND inside the OR", canonicalize: rsqlCanon,
			left:  "(a==1,b==2);c==3",
			right: "a==1,(b==2;c==3)"},
		{name: "rsql quoted separator is not a term boundary", canonicalize: rsqlCanon,
			left:  `name=="b,a";x==1`,
			right: `name=="a,b";x==1`},
		{name: "mongodb literal array", canonicalize: mongodbCanon,
			left:  `{"tags":["a","b"]}`,
			right: `{"tags":["b","a"]}`},
		{name: "mongodb array of values substituted for a field", canonicalize: mongodbCanon,
			left:  `{ { "a": [ { "$uuid": "b" }, { "$uuid": "a" } ] } }`,
			right: `{ { "a": [ { "$uuid": "a" }, { "$uuid": "b" } ] } }`},
		{name: "mongodb arguments of $substr", canonicalize: mongodbCanon,
			left:  `{ "$expr": { "$eq": [ { "$substr": [ "$name", 1, 3 ] }, "abc" ] } }`,
			right: `{ "$expr": { "$eq": [ { "$substr": [ "$name", 3, 1 ] }, "abc" ] } }`},
		{name: "mongodb operands of $eq", canonicalize: mongodbCanon,
			left:  `{ "$expr": { "$eq": [ "$a", "$b" ] } }`,
			right: `{ "$expr": { "$eq": [ "$b", "$a" ] } }`},
		{name: "mongodb arguments of an aggregation $in", canonicalize: mongodbCanon,
			left:  `{ "$expr": { "$in": [ "$a", "$b" ] } }`,
			right: `{ "$expr": { "$in": [ "$b", "$a" ] } }`},
		{name: "mongodb members of an object", canonicalize: mongodbCanon,
			left:  `{ "a": 1, "b": 2 }`,
			right: `{ "b": 2, "a": 1 }`},
		{name: "custom positional array", canonicalize: customCanon,
			left:  `{"substr":["name",1,3]}`,
			right: `{"substr":["name",3,1]}`},
		{name: "custom params list", canonicalize: customCanon,
			left:  `{"data":{"p1":{"predicate":"region:${p}","params":{"p":["r2","r1"]}}}}`,
			right: `{"data":{"p1":{"predicate":"region:${p}","params":{"p":["r1","r2"]}}}}`},
		{name: "custom apply of an OR node outside the logic tree", canonicalize: customCanon,
			left:  `{"logic":{"path":"p1"},"data":{"p1":{"op":"OR","apply":["r1","r2"]}}}`,
			right: `{"logic":{"path":"p1"},"data":{"p1":{"op":"OR","apply":["r2","r1"]}}}`},
		{name: "custom apply of a node other than OR and AND", canonicalize: customCanon,
			left:  `{"logic":{"op":"SUB","apply":[{"path":"p1"},{"path":"p2"}]}}`,
			right: `{"logic":{"op":"SUB","apply":[{"path":"p2"},{"path":"p1"}]}}`},
		{name: "method chain arguments of eq", canonicalize: canonicalMethodChain,
			left:  `(T.a.eq("b", "a")).or(T.x.eq(1))`,
			right: `(T.x.eq(1)).or(T.a.eq("a", "b"))`},
		{name: "method chain and of an or against or of an and", canonicalize: canonicalMethodChain,
			left:  "(T.a.eq(1).or(T.b.eq(2))).and(T.c.eq(3))",
			right: "(T.a.eq(1).and(T.b.eq(2))).or(T.c.eq(3))"},
		{name: "method chain mixing and with or groups by the order of the calls", canonicalize: canonicalMethodChain,
			left:  "T.b.eq(2).or(T.a.eq(1)).and(T.c.eq(3))",
			right: "T.a.eq(1).and(T.c.eq(3)).or(T.b.eq(2))"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.canonicalize(tc.left); got == tc.canonicalize(tc.right) {
				t.Errorf("canonical(%q) = canonical(%q) = %q, want them apart", tc.left, tc.right, got)
			}
		})
	}
}

// Two integers that a float64 cannot tell apart stay apart in a
// customFilterCondition, while the operands of an OR node are still sorted.
func TestCanonicalJSON_KeepsTheDigitsOfANumber(t *testing.T) {
	t.Parallel()
	left := `{"logic":{"op":"OR","apply":[{"path":"p1"},{"path":"p2"}]},"params":{"p":["a","b"],"n":9007199254740992}}`
	right := `{"logic":{"op":"OR","apply":[{"path":"p2"},{"path":"p1"}]},"params":{"p":["a","b"],"n":9007199254740993}}`
	control := `{"logic":{"op":"OR","apply":[{"path":"p2"},{"path":"p1"}]},"params":{"p":["a","b"],"n":9007199254740992}}`
	if got := canonicalJSON(json.RawMessage(left)); string(got) == string(canonicalJSON(json.RawMessage(right))) {
		t.Errorf("canonicalJSON(%s) = canonicalJSON(%s) = %s, want them apart", left, right, got)
	}
	if got, want := string(canonicalJSON(json.RawMessage(control))), string(canonicalJSON(json.RawMessage(left))); got != want {
		t.Errorf("canonicalJSON(%s) = %s, want canonicalJSON(%s) = %s", control, got, left, want)
	}
}

// A customFilterCondition recorded with indentation compares equal to the compact
// one the stand answers, with the operands of a logic node in either order. A
// null value stays null.
func TestCanonicalJSON_IndentationAndApplyOrderDoNotReachTheComparison(t *testing.T) {
	t.Parallel()
	recorded := json.RawMessage(`{
  "logic": {
    "op": "OR",
    "apply": [
      {
        "path": "p1"
      },
      {
        "path": "p2"
      }
    ]
  },
  "data": {
    "p1": {"predicate": "a:1"},
    "p2": {"predicate": "b:2"}
  }
}`)
	answered := json.RawMessage(`{"data":{"p2":{"predicate":"b:2"},"p1":{"predicate":"a:1"}},"logic":{"apply":[{"path":"p2"},{"path":"p1"}],"op":"OR"}}`)

	if got, want := string(canonicalJSON(answered)), string(canonicalJSON(recorded)); got != want {
		t.Errorf("canonicalJSON(answered) = %s, want canonicalJSON(recorded) = %s", got, want)
	}
	if got := canonicalJSON(json.RawMessage("null")); string(got) != "null" {
		t.Errorf("canonicalJSON(null) = %s, want null", got)
	}
}

// The comparator applies the rewrite to a check/filter outcome as a whole, so a
// golden and an answer that differ in term order alone in every dialect and in
// the customFilterCondition diff empty.
func TestNormalizeComparable_FilterOutcomeWithPermutedTermsDiffsEmpty(t *testing.T) {
	t.Parallel()
	recorded := &model.FilterOutcome{Status: 200, Result: model.OldFilterEvaluationResult{
		CalculationResult:      "USE_FILTER_CONDITION",
		FilterCondition:        model.FilterTextOf("(T.b.eq(2)).or(T.a.eq(1))"),
		MongodbFilterCondition: model.FilterTextOf(`{ "$or": [ {{ "b": 2 }}, {{ "a": 1 }} ] }`),
		RsqlFilterCondition:    model.FilterTextOf("b==2,a==1"),
		SqlFilterCondition:     model.FilterTextOf("b=2 OR a=1"),
		CustomFilterCondition:  json.RawMessage("{\n  \"logic\": {\n    \"op\": \"OR\",\n    \"apply\": [{\"path\": \"b\"}, {\"path\": \"a\"}]\n  }\n}"),
	}}
	answered := &model.FilterOutcome{Status: 200, Result: model.OldFilterEvaluationResult{
		CalculationResult:      "USE_FILTER_CONDITION",
		FilterCondition:        model.FilterTextOf("(T.a.eq(1)).or(T.b.eq(2))"),
		MongodbFilterCondition: model.FilterTextOf(`{ "$or": [ {{ "a": 1 }}, {{ "b": 2 }} ] }`),
		RsqlFilterCondition:    model.FilterTextOf("a==1,b==2"),
		SqlFilterCondition:     model.FilterTextOf("a=1 OR b=2"),
		CustomFilterCondition:  json.RawMessage(`{"logic":{"op":"OR","apply":[{"path":"a"},{"path":"b"}]}}`),
	}}

	want := normalizeComparable(PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, "regular/x/filter", recorded)
	got := normalizeComparable(PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, "regular/x/filter", answered)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("normalizeComparable() of two term orders differs (-recorded +answered):\n%s", diff)
	}
}

// filterOutcomeWithRsql decodes a v1 filter outcome whose rsqlFilterCondition
// member is the JSON text member, or absent when member is empty, the way the
// comparator decodes a golden.
func filterOutcomeWithRsql(t *testing.T, member string) *model.FilterOutcome {
	t.Helper()
	body := `{"status": 200, "result": {"calculationResult": "ALLOW"`
	if member != "" {
		body += `, "rsqlFilterCondition": ` + member
	}
	body += `}}`
	var out model.FilterOutcome
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("json.Unmarshal(%s): %v", body, err)
	}
	return &out
}

// A filter text recorded as "", as null, and with no member are three answers:
// the comparator reports a difference between any two of them, and a golden
// written back from the decoded answer keeps the form it was read in.
func TestNormalizeComparable_FilterTextKeepsEmptyNullAndAbsentApart(t *testing.T) {
	t.Parallel()
	forms := []struct{ name, member, written string }{
		{"empty string", `""`, `{"calculationResult":"ALLOW","rsqlFilterCondition":""}`},
		{"null", `null`, `{"calculationResult":"ALLOW","rsqlFilterCondition":null}`},
		{"absent", ``, `{"calculationResult":"ALLOW"}`},
	}
	for _, recorded := range forms {
		for _, answered := range forms {
			t.Run(recorded.name+" against "+answered.name, func(t *testing.T) {
				want := normalizeComparable(PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, "regular/x/filter", filterOutcomeWithRsql(t, recorded.member))
				got := normalizeComparable(PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, "regular/x/filter", filterOutcomeWithRsql(t, answered.member))
				diff := cmp.Diff(want, got)
				if same := recorded.name == answered.name; same != (diff == "") {
					t.Errorf("cmp.Diff(%s, %s) = %q, want an empty diff exactly when the forms are the same", recorded.name, answered.name, diff)
				}
			})
		}
		t.Run(recorded.name+" written back", func(t *testing.T) {
			b, err := json.Marshal(filterOutcomeWithRsql(t, recorded.member).Result)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			if string(b) != recorded.written {
				t.Errorf("json.Marshal(result with %s) = %s, want %s", recorded.name, b, recorded.written)
			}
		})
	}
}

// A text member that is neither a string nor null fails the decoding of the
// whole answer instead of being recorded as some string.
func TestFilterText_ANumberIsRefused(t *testing.T) {
	t.Parallel()
	var out model.OldFilterEvaluationResult
	if err := json.Unmarshal([]byte(`{"calculationResult": "ALLOW", "rsqlFilterCondition": 5}`), &out); err == nil {
		t.Errorf("json.Unmarshal(rsqlFilterCondition 5) = nil error, result %+v, want an error", out)
	}
}
