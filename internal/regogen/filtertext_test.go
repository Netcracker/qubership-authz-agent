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
