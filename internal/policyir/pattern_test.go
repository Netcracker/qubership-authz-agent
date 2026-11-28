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
	"regexp"
	"strings"
	"testing"
)

// The agent refuses a pattern whose regular expression package regexp does
// not compile, and only such a pattern. A ? is a wildcard, so a pattern
// cannot write a lookahead.
func TestPatternRefusedNamesAPatternRegexpDoesNotCompile(t *testing.T) {
	for _, tc := range []struct {
		text, want string
	}{
		{"a)|(b", "MATCH pattern \"a)|(b\" is not a valid regular expression: error parsing regexp: unexpected ): `a)|(b`"},
		{`(a)\1`, "MATCH pattern \"(a)\\\\1\" is not a valid regular expression: error parsing regexp: invalid escape sequence: `\\1`"},
		{"a|b", ""},
		{"/api/**/items/()", ""},
		{"(?=a)b", ""},
		{`\Qa)`, ""},
	} {
		if got := patternRefused(tc.text); got != tc.want {
			t.Errorf("patternRefused(%q) = %q, want %q", tc.text, got, tc.want)
		}
	}
}

// A pattern whose expression compiles only without the anchors, nested as
// deep as package regexp allows, is refused for the anchored expression.
func TestPatternRefusedGivesTheErrorOfTheAnchoredExpression(t *testing.T) {
	text := strings.Repeat("(", 999) + "a" + strings.Repeat(")", 999)
	got := patternRefused(text)
	if !strings.Contains(got, "expression nests too deeply: `^(?:(((") || strings.Contains(got, `\E`) {
		t.Errorf("patternRefused(999 nested groups) = %q, want the error of the anchored expression, with no \\E",
			got[strings.Index(got, "error parsing"):][:80])
	}
}

// An anchored pattern matches a value whole, and a \Q that no \E closes
// quotes the rest of the pattern, as it does in Java, rather than the anchor.
func TestAnchoredMatchesTheWholeValue(t *testing.T) {
	for _, tc := range []struct {
		text, value string
		want        bool
	}{
		{"a|b", "a", true},
		{"a|b", "ab", false},
		{"/api/*/items", "/api/7/items", true},
		{"/api/*/items", "/api/7/8/items", false},
		{`\Qa)`, "a)", true},
		{`\Qa)`, "a", false},
		{`\Qa\E|b`, "b", true},
	} {
		rx, err := Pattern{Text: tc.text}.Anchored()
		if err != nil {
			t.Errorf("Pattern{%q}.Anchored() error: %v", tc.text, err)
			continue
		}
		if got := regexp.MustCompile(rx).MatchString(tc.value); got != tc.want {
			t.Errorf("%q (from pattern %q) matches %q = %v, want %v", rx, tc.text, tc.value, got, tc.want)
		}
	}
}
