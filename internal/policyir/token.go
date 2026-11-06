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

// attrScanner finds the legacy lexer's attribute token at any position of one
// text in time proportional to the token's length. The token is a name, then
// characters of [isAttrChar], and bracketed parts whose text may hold spaces.
// A space is part of the token only where a ']' later closes the run of
// attribute characters and spaces it starts, so a scan from every operand of
// a long condition would read the rest of the text again; the tables, built
// once in one pass from the end, hold where each such run ends.
type attrScanner struct {
	s string
	// runEnd[j] is the first index at or after j whose byte is neither an
	// attribute character nor a space.
	runEnd []int
	// openEnd[j] is the index after the ']' that closes the bracketed part
	// whose '[' stands at j-1, or -1 when none does.
	openEnd []int
}

func newAttrScanner(s string) *attrScanner {
	n := len(s)
	a := &attrScanner{s: s, runEnd: make([]int, n+1), openEnd: make([]int, n+1)}
	a.runEnd[n] = n
	a.openEnd[n] = -1
	for j := n - 1; j >= 0; j-- {
		if isAttrChar(s[j]) || s[j] == ' ' {
			a.runEnd[j] = a.runEnd[j+1]
		} else {
			a.runEnd[j] = j
		}
	}
	for j := n - 1; j >= 0; j-- {
		k := a.runEnd[j]
		switch {
		case k == n:
			a.openEnd[j] = -1
		case s[k] == '[':
			a.openEnd[j] = a.openEnd[k+1]
		case s[k] == ']' && k > j:
			a.openEnd[j] = k + 1
		default:
			a.openEnd[j] = -1
		}
	}
	return a
}

// tokenLen returns the length of the attribute token that starts at i, the
// longest the lexer matches there, or 0 when none starts there.
func (a *attrScanner) tokenLen(i int) int {
	s := a.s
	if i >= len(s) || !isNameStart(s[i]) {
		return 0
	}
	// j is the end of the longest token so far. A ']' closes a run only
	// where at least one character since seg stands before it: seg follows the
	// first letter of the name, or the last ']'.
	j, seg := i+1, i+1
	for {
		for j < len(s) && isAttrChar(s[j]) {
			j++
		}
		if j == len(s) {
			return j - i
		}
		next := -1
		switch s[j] {
		case ' ':
			// A space opens a run that only a ']' ends.
			if k := a.runEnd[j]; k < len(s) && s[k] == ']' {
				next = k + 1
			}
		case '[':
			next = a.openEnd[j+1]
		case ']':
			if j > seg {
				next = j + 1
			}
		}
		if next < 0 {
			return j - i
		}
		j, seg = next, next
	}
}

// wildcardLen returns the length of the legacy lexer's wildcard token at the
// start of s: letters, digits, '_', '.', and the characters of
// "/%?()=#*:-".
func wildcardLen(s string) int {
	n := 0
	for n < len(s) && isWildcardChar(s[n]) {
		n++
	}
	return n
}

func isNameStart(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_'
}

// isAttrChar reports whether an attribute token holds c outside brackets: a
// letter, a digit, '_', or one of the JSONPath characters "$@,:?*(=)-.~></&|!'".
func isAttrChar(c byte) bool {
	if isNameStart(c) || c >= '0' && c <= '9' {
		return true
	}
	switch c {
	case '$', '@', ',', ':', '?', '*', '(', '=', ')', '-', '.', '~', '>', '<', '/', '&', '|', '!', '\'':
		return true
	}
	return false
}

func isWildcardChar(c byte) bool {
	if isNameStart(c) || c >= '0' && c <= '9' {
		return true
	}
	switch c {
	case '.', '/', '%', '?', '(', ')', '=', '#', '*', ':', '-':
		return true
	}
	return false
}
