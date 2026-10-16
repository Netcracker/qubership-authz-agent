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

// Two answers of one policy set that list the terms of an operator in another
// order, at any depth, canonicalize to one text. The texts are the recorded
// deny-predicates-under-deny-overrides and filter-four-groups-on-one-type
// answers with their terms permuted at every level.
func TestCanonicalFilterDialects_TermOrderDoesNotReachTheComparison(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		canonicalize func(string) string
		recorded     string
		permuted     string
	}{
		{
			name:         "rsql terms of an AND and of a bracketed OR",
			canonicalize: func(s string) string { return canonicalInfix(s, rsqlSeparators) },
			recorded:     "(b==2,a==1);c!=3;d!=4",
			permuted:     "d!=4;(a==1,b==2);c!=3",
		},
		{
			name:         "rsql bracketed groups of four sources",
			canonicalize: func(s string) string { return canonicalInfix(s, rsqlSeparators) },
			recorded:     "(regular1==1),(simplified1==1,simplified2==2),(regular2==2)",
			permuted:     "(simplified2==2,simplified1==1),(regular2==2),(regular1==1)",
		},
		{
			name:         "sql terms under NOT and in a bracketed OR",
			canonicalize: func(s string) string { return canonicalInfix(s, sqlSeparators) },
			recorded:     "(b=2 OR a=1) AND NOT (c=3) AND NOT (d=4)",
			permuted:     "NOT (d=4) AND (a=1 OR b=2) AND NOT (c=3)",
		},
		{
			name:         "mongodb elements of $and and of a nested $or",
			canonicalize: func(s string) string { return canonicalInfix(s, mongodbSeparators) },
			recorded:     `{ "$and": [ { "$or": [ {{ "b": 2 }}, {{ "a": 1 }} ] }, {{ "c": 3 }}, {{ "d": 4 }} ] }`,
			permuted:     `{ "$and": [ {{ "d": 4 }}, { "$or": [ {{ "a": 1 }}, {{ "b": 2 }} ] }, {{ "c": 3 }} ] }`,
		},
		{
			name:         "method chain operands of and and of a nested or",
			canonicalize: canonicalMethodChain,
			recorded:     "((T.b.eq(2)).or(T.a.eq(1))).and((T.c.eq(3)).not()).and((T.d.eq(4)).not())",
			permuted:     "((T.d.eq(4)).not()).and((T.a.eq(1)).or(T.b.eq(2))).and((T.c.eq(3)).not())",
		},
		{
			name:         "sql IN list elements",
			canonicalize: func(s string) string { return canonicalInfix(s, sqlSeparators) },
			recorded:     "perms IN ('parity_other_permission', 'parity_permission') AND a=1",
			permuted:     "a=1 AND perms IN ('parity_permission', 'parity_other_permission')",
		},
		{
			name:         "method chain in-call arguments",
			canonicalize: canonicalMethodChain,
			recorded:     `(T.id.in("b", "a")).and(T.x.eq(1))`,
			permuted:     `(T.x.eq(1)).and(T.id.in("a", "b"))`,
		},
		{
			name:         "rsql in-clause elements",
			canonicalize: func(s string) string { return canonicalInfix(s, rsqlSeparators) },
			recorded:     `id=in=("row10-dict-1", "row10-dict-2");amount=le="1000"`,
			permuted:     `amount=le="1000";id=in=("row10-dict-2", "row10-dict-1")`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got, want := tc.canonicalize(tc.permuted), tc.canonicalize(tc.recorded); got != want {
				t.Errorf("canonical(%q) = %q, want canonical(%q) = %q", tc.permuted, got, tc.recorded, want)
			}
		})
	}
}

// Sorting the terms of an operator keeps the brackets that bind them, so two
// expressions that group the same terms differently stay apart.
func TestCanonicalFilterDialects_GroupingStaysApart(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		canonicalize func(string) string
		left, right  string
	}{
		{
			name:         "rsql OR inside the AND against AND inside the OR",
			canonicalize: func(s string) string { return canonicalInfix(s, rsqlSeparators) },
			left:         "(a==1,b==2);c==3",
			right:        "a==1,(b==2;c==3)",
		},
		{
			name:         "method chain and of an or against or of an and",
			canonicalize: canonicalMethodChain,
			left:         "(T.a.eq(1).or(T.b.eq(2))).and(T.c.eq(3))",
			right:        "(T.a.eq(1).and(T.b.eq(2))).or(T.c.eq(3))",
		},
		{
			name:         "method chain mixing and with or keeps its order",
			canonicalize: canonicalMethodChain,
			left:         "T.b.eq(2).or(T.a.eq(1)).and(T.c.eq(3))",
			right:        "T.a.eq(1).and(T.c.eq(3)).or(T.b.eq(2))",
		},
		{
			name:         "rsql quoted separator is not a term boundary",
			canonicalize: func(s string) string { return canonicalInfix(s, rsqlSeparators) },
			left:         `name=="b,a";x==1`,
			right:        `name=="a,b";x==1`,
		},
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
		FilterCondition:        "(T.b.eq(2)).or(T.a.eq(1))",
		MongodbFilterCondition: `{ "$or": [ {{ "b": 2 }}, {{ "a": 1 }} ] }`,
		RsqlFilterCondition:    "b==2,a==1",
		SqlFilterCondition:     "b=2 OR a=1",
		CustomFilterCondition:  json.RawMessage("{\n  \"logic\": {\n    \"op\": \"OR\",\n    \"apply\": [{\"path\": \"b\"}, {\"path\": \"a\"}]\n  }\n}"),
	}}
	answered := &model.FilterOutcome{Status: 200, Result: model.OldFilterEvaluationResult{
		CalculationResult:      "USE_FILTER_CONDITION",
		FilterCondition:        "(T.a.eq(1)).or(T.b.eq(2))",
		MongodbFilterCondition: `{ "$or": [ {{ "a": 1 }}, {{ "b": 2 }} ] }`,
		RsqlFilterCondition:    "a==1,b==2",
		SqlFilterCondition:     "a=1 OR b=2",
		CustomFilterCondition:  json.RawMessage(`{"logic":{"op":"OR","apply":[{"path":"a"},{"path":"b"}]}}`),
	}}

	want := normalizeComparable(PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, "regular/x/filter", recorded)
	got := normalizeComparable(PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, "regular/x/filter", answered)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("normalizeComparable() of two term orders differs (-recorded +answered):\n%s", diff)
	}
}
