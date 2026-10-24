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

package policyir

import (
	"errors"
	"testing"
)

// The expected lines are FormatCondition of the tree the specification's
// parser builds for the same text.
func TestParseCondition(t *testing.T) {
	t.Parallel()

	cases := []struct {
		text string
		want string
	}{
		{"resource.a == 'y'", `resource.a EQ "y"`},
		{"a = 'y'", `resource.a EQ "y"`},
		{"resourceX == 1", `resource.resourceX EQ 1`},
		{"resource IS EMPTY", `resource IS_EMPTY`},
		{"resource.a.b. == 1", `resource.a.b EQ 1`},
		{"resource[ 0 ] == 1", `resource[0] EQ 1`},
		{"subject.l[0] IS NULL", `resource.subject.l[0] IS_NULL`},
		{"resource.a GREATER THAN OR EQUAL TO 5", `resource.a GE 5`},
		{"resource.a IS NOT NULL", `resource.a IS_NOT_NULL`},
		{"resource.a == null", `resource.a EQ null`},
		{"resource.a == TRUE", `resource.a EQ true`},
		{"resource.x == ５", `resource.x EQ ５`},
		{"operation IN 'READ', 'EDIT'", `operation IN ["READ", "EDIT"] raw="'READ', 'EDIT'"`},
		{"resource.n IN 1,2", `resource.n IN [1, 2] raw="1,2"`},
		{"subject.roles CONTAINS ANY 'A'", `subject.roles CONTAINS_ANY ["A"]`},
		{"resource.p MATCH /api/*", `resource.p MATCH pattern("/api/*")`},
		{"resource.p MATCH resource.q", `resource.p MATCH resource.q`},
		{"resource.p NOT MATCH subject.name", `resource.p NOT_MATCH subject.name`},
		{"resource.v MATCH resource.*", `resource.v MATCH resource.*`},
		{"resource.v NOT MATCH resource.*", `resource.v NOT_MATCH resource.*`},
		{"resource.v MATCH subject.l[:]", `resource.v MATCH resource.subject.l[:]`},
		{"subject allowed 'EDIT' on resource OR subject.isM2M", `subject allowed "EDIT" on resource OR subject.isM2M`},
		{"TRUE AND resource.a == 1", `TRUE AND resource.a EQ 1`},
		{"subject.region.code == 'x'", `pip("subject.region.code") EQ "x"`},
		{"subject.permissionScope == 'x'", `subject.permissionScope EQ "x"`},
		{"subject.permissionScope.a.b == 'x'", `subject.permissionScope["a.b"] EQ "x"`},
		{"resource.x IN subject.owners FILTERED 'READ'", `resource.x IN pip("subject.owners.filtered") FILTERED "READ"`},
		{"subject.entitledResources.of('order').as('id','owner') CONTAINS resource.id",
			`subject.entitledResources.of("order").as["id", "owner"] CONTAINS resource.id`},
		{"resource.items[?(@.k == 'v')].length() == 1", `resource.items[?(@.k == 'v')].length() EQ 1`},
		{"resource.a == 'y'\n", `resource.a EQ "y"`},
		{"", `TRUE`},
		{"False", `FALSE`},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			t.Parallel()
			c, err := ParseCondition(tc.text, PlaceRuleCondition, "")
			if err != nil {
				t.Fatalf("ParseCondition(%q): %v", tc.text, err)
			}
			if got := FormatCondition(c); got != tc.want {
				t.Errorf("ParseCondition(%q) = %s, want %s", tc.text, got, tc.want)
			}
		})
	}
}

// The raw token of a list runs from its first item to its last as written,
// whatever the kind of the items and whatever literal precedes the list. A
// list of booleans used to get a raw token that started where the previous
// string or number literal would have ended: ",false" for IN true,false. A
// list of strings after a number is the control: its raw token was right.
func TestParseConditionKeepsTheListTokenAsWritten(t *testing.T) {
	t.Parallel()

	cases := []struct {
		text string
		want string
	}{
		{"resource.x IN true,false", `resource.x IN [true, false] raw="true,false"`},
		{"resource.a == 'xy' AND resource.x IN FALSE, true",
			`resource.a EQ "xy" AND resource.x IN [false, true] raw="FALSE, true"`},
		{"resource.a == 10 AND resource.x IN 'p','q'", `resource.a EQ 10 AND resource.x IN ["p", "q"] raw="'p','q'"`},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			t.Parallel()
			c, err := ParseCondition(tc.text, PlaceRuleCondition, "")
			if err != nil {
				t.Fatalf("ParseCondition(%q): %v", tc.text, err)
			}
			if got := FormatCondition(c); got != tc.want {
				t.Errorf("ParseCondition(%q) = %s, want %s", tc.text, got, tc.want)
			}
		})
	}
}

func TestParseConditionRefuses(t *testing.T) {
	t.Parallel()

	cases := []struct{ name, text string }{
		{"two spaces between tokens", "resource.a  == 'y'"},
		{"no spaces around a comparison", "resource.a=='y'"},
		{"a double-quoted string", `resource.a == "y"`},
		{"a lower-case connective", "resource.a == 'y' or resource.b == 'z'"},
		{"no space before a connective", "resource.a == 'y'AND resource.b == 'z'"},
		{"a standalone NOT", "NOT resource.a == 1"},
		{"a number with a leading zero after the minus", "resource.a == -05"},
		{"a list of strings and numbers", "resource.a IN 'a', 1"},
		{"a quoted MATCH pattern", "resource.a MATCH 'x'"},
		{"spaces only", "   "},
		{"a tab between tokens", "resource.a ==\t'y'"},
		{"a step after subject.id", "subject.id.x == 1"},
		{"a misspelled word operator", "resource.a LESS THAN OR EQUALS 5"},
		{"a lower-case operator", "resource.a is null"},
		{"a connective with nothing after it", "resource.a == 'x' OR"},
		{"a bare subject", "subject == 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := ParseCondition(tc.text, PlaceRuleCondition, "")
			var se *SyntaxError
			if !errors.As(err, &se) {
				t.Errorf("ParseCondition(%q) = %v, %v, want a *SyntaxError", tc.text, c, err)
			}
		})
	}
}

// Inside an iterate, subject.permissionScope reads the pass; outside it reads
// the subject attribute.
func TestParseConditionReadsThePassInsideAnIterate(t *testing.T) {
	t.Parallel()

	c, err := ParseCondition("subject.permissionScope.region CONTAINS resource.region", PlaceRuleCondition, "iterate1")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := FormatCondition(c), `pass("iterate1")["region"] CONTAINS resource.region`; got != want {
		t.Errorf("FormatCondition = %s, want %s", got, want)
	}
}

func TestParseConditionMarksAPathOutsideTheJSONPathSubset(t *testing.T) {
	t.Parallel()

	cases := []struct {
		text string
		want string
	}{
		{"resource.a[*] == 1", `resource.a[*] EQ 1`},
		{"resource.x/y == 1", `unsupported(jsonpath "resource.x/y") EQ 1`},
		{"resource.x/y[ 0 ]. == 1", `unsupported(jsonpath "resource.x/y[ 0 ].") EQ 1`},
		{"resource.a['b','c'] == 1", `unsupported(jsonpath "resource.a['b','c']") EQ 1`},
		{"resource.a[?(@.k ~ 'v')] == 1", `unsupported(jsonpath "resource.a[?(@.k ~ 'v')]") EQ 1`},
		{"resource.o[?(@.n=~/(?=u)/)].n == 1", `unsupported(jsonpath "resource.o[?(@.n=~/(?=u)/)].n") EQ 1`},
		{"resource.a[:] == 1", `unsupported(jsonpath "resource.a[:]") EQ 1`},
		{"subject.l[:] == 1", `unsupported(jsonpath "subject.l[:]") EQ 1`},
		{"foo[:] == 1", `unsupported(jsonpath "foo[:]") EQ 1`},
		{"resource['k'] == 1", `resource['k'] EQ 1`},
		{"resource.o[?(@.n=~/u.*/i && @.g==null)].n == 1", `resource.o[?(@.n=~/u.*/i && @.g==null)].n EQ 1`},
		{"resource.o[?(@.n=~/u.*/i && @.g == 'x')].n == 1", `resource.o[?(@.n=~/u.*/i && @.g == 'x')].n EQ 1`},
		{"resource.a[1:2] == 1", `resource.a[1:2] EQ 1`},
		{"resource..id == 1", `resource..id EQ 1`},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			t.Parallel()
			c, err := ParseCondition(tc.text, PlaceRuleCondition, "")
			if err != nil {
				t.Fatalf("ParseCondition(%q): %v", tc.text, err)
			}
			if got := FormatCondition(c); got != tc.want {
				t.Errorf("ParseCondition(%q) = %s, want %s", tc.text, got, tc.want)
			}
		})
	}
}
