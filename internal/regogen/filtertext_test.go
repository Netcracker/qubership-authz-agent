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

// The negation of a MongoDB $or of n elements makes an edit per element, and
// allocates in proportion to the text rather than to n times the text.
func TestTheNegationOfAMongoDBOrGrowsLinearly(t *testing.T) {
	checkGrowth(t, 8192, 3, requestBudget, false, func(n int) func() {
		s := `{"$or": [` + strings.Repeat(`{"a": 5}, `, n) + `{"b": {"$lt": 1}}]}`
		return func() { negateMongoText(s) }
	})
}
