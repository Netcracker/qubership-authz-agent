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

	"authz-agent/internal/costcheck"
	"authz-agent/internal/jsonvalue"
)

// nestedRSQL is a==1 inside n groups.
func nestedRSQL(n int) string {
	return strings.Repeat("(", n) + "a==1" + strings.Repeat(")", n)
}

// alternatingRSQL is a==1 inside n groups that alternate between an AND and
// an OR, so that the parser cannot flatten one into the next.
func alternatingRSQL(n int) string {
	return strings.Repeat("a==1;(a==1,(", n/2) + "a==1" + strings.Repeat("))", n/2)
}

func TestNegateRSQLNegatesGroupsUpToTheDepthOfAJSONDocument(t *testing.T) {
	if got, ok := negateRSQL(nestedRSQL(jsonvalue.MaxDepth)); !ok || got != "a!=1" {
		t.Errorf("negateRSQL(a==1 in %d groups) = %q, %v, want %q, true", jsonvalue.MaxDepth, got, ok, "a!=1")
	}
	if _, ok := negateRSQL(alternatingRSQL(jsonvalue.MaxDepth)); !ok {
		t.Errorf("negateRSQL(a==1 in %d alternating groups) refused the text", jsonvalue.MaxDepth)
	}
}

func TestNegateRSQLRefusesOneGroupPastTheDepthOfAJSONDocument(t *testing.T) {
	if got, ok := negateRSQL(nestedRSQL(jsonvalue.MaxDepth + 1)); ok {
		t.Errorf("negateRSQL(a==1 in %d groups) = %q, true, want a refusal", jsonvalue.MaxDepth+1, got)
	}
}

// The child process has the stack of [costcheck.MaxStack], which a parser
// that recursed once per group would exhaust.
func TestNegateRSQLSurvivesAMillionGroups(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{"nested", nestedRSQL(1 << 20)},
		{"alternating", alternatingRSQL(1 << 20)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			costcheck.Deep(t, costcheck.Known{}, func() { negateRSQL(tc.text) })
		})
	}
}
