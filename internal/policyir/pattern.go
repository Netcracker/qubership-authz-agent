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
	"fmt"
	"regexp"
	"strings"
)

// Regexp returns the regular expression that p.Text stands for, without
// anchors: ** any characters of a URI, * and ? such characters other than /,
// any number of them for * and one for ?, () one or more of them, and every
// other character as itself in a regular expression, so a metacharacter
// such as . or | keeps its meaning. The wildcards are read left to right.
func (p Pattern) Regexp() string {
	const any = `[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]`
	const noSlash = `[A-Za-z0-9\-._~:?#\[\]@!$&'()*+,;=%]`
	text := p.Text
	var b strings.Builder
	for i := 0; i < len(text); {
		switch {
		case strings.HasPrefix(text[i:], "**"):
			b.WriteString(any + "*")
			i += 2
		case text[i] == '*':
			b.WriteString(noSlash + "*")
			i++
		case strings.HasPrefix(text[i:], "()"):
			b.WriteString(noSlash + "+")
			i += 2
		case text[i] == '?':
			b.WriteString(noSlash)
			i++
		default:
			b.WriteByte(text[i])
			i++
		}
	}
	return b.String()
}

// Anchored returns [Pattern.Regexp] anchored at both ends, which a value
// matches whole, or the error package regexp gives: for the expression
// without the anchors, which would otherwise balance a pattern such as
// a)|(b, and then for the anchored one. A \Q that no \E closes quotes the
// rest of the pattern, so the expression closes it before the anchor.
func (p Pattern) Anchored() (string, error) {
	body := p.Regexp()
	if _, err := regexp.Compile(body); err != nil {
		return "", err
	}
	rx := "^(?:" + body + ")$"
	_, err := regexp.Compile(rx)
	if err == nil {
		return rx, nil
	}
	quoted := "^(?:" + body + `\E)$`
	if _, qerr := regexp.Compile(quoted); qerr == nil {
		return quoted, nil
	}
	return "", err
}

// patternRefused returns why the agent does not evaluate the MATCH pattern
// text, or "" when it does: the agent refuses a pattern that
// [Pattern.Anchored] refuses.
func patternRefused(text string) string {
	if _, err := (Pattern{Text: text}).Anchored(); err != nil {
		return fmt.Sprintf("MATCH pattern %q is not a valid regular expression: %v", text, err)
	}
	return ""
}

// conditionRefused returns the reason [patternRefused] gives for the first
// MATCH or NOT MATCH pattern of c it refuses, or "" when there is none. A nil
// c has none.
func conditionRefused(c *Condition) string {
	if c == nil {
		return ""
	}
	for _, d := range c.Disjuncts {
		for _, a := range d {
			cmp, ok := a.(Compare)
			if !ok || (cmp.Op != OpMatch && cmp.Op != OpNotMatch) {
				continue
			}
			if p, ok := cmp.Right.(Pattern); ok {
				if why := patternRefused(p.Text); why != "" {
					return why
				}
			}
		}
	}
	return ""
}

// trueCondition is the condition true at place: the target an isolated node
// gets when its own target holds the pattern that isolates it.
func trueCondition(place Place) *Condition {
	return &Condition{Place: place, Disjuncts: [][]Atom{{Const{Value: true}}}}
}

// isolatedTarget is the target of a set isolated for another reason, whose
// target c is kept: c, or the condition true when c holds a pattern
// [patternRefused] refuses, which the generator could not translate.
func isolatedTarget(c *Condition) *Condition {
	if conditionRefused(c) != "" {
		return trueCondition(PlaceSetTarget)
	}
	return c
}
