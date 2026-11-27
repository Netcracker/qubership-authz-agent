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

	"authz-agent/internal/policyir"
)

// dialectText writes a text of one dialect from the filter's own syntax and
// the texts it embeds: an author's predicate, or a text written before by a
// dialectText. The filter writes the syntax it puts around and between the
// texts of predicates through it, the $nor that negates a MongoDB predicate
// aside, so that the syntax after an embedded text is read as syntax: where an
// SQL text may end inside a line comment, dialectText writes a line feed
// before whatever follows it. A text it embeds last stays as written.
type dialectText struct {
	d policyir.Dialect
	b strings.Builder
	// mayEndInLineComment is set where the text written last may end inside
	// a line comment.
	mayEndInLineComment bool
}

func newDialectText(d policyir.Dialect) *dialectText { return &dialectText{d: d} }

// syntax writes s, the filter's own syntax.
func (w *dialectText) syntax(s string) *dialectText {
	w.endLineComment()
	w.b.WriteString(s)
	return w
}

// text writes s, a text of the dialect the filter embeds whole.
func (w *dialectText) text(s string) *dialectText {
	w.endLineComment()
	w.b.WriteString(s)
	w.mayEndInLineComment = w.d == policyir.DialectSQL && sqlMayEndInLineComment(s)
	return w
}

// group writes s in the brackets open and closing.
func (w *dialectText) group(open, s, closing string) *dialectText {
	return w.syntax(open).text(s).syntax(closing)
}

// endLineComment writes a line feed where the text written last may end
// inside a line comment.
func (w *dialectText) endLineComment() {
	if w.mayEndInLineComment {
		w.b.WriteByte('\n')
		w.mayEndInLineComment = false
	}
}

func (w *dialectText) String() string { return w.b.String() }

// sqlMayEndInLineComment reports whether the SQL text s may end inside a line
// comment: whether -- or the # of MySQL follows the last line feed of s. A
// line comment ends at a line feed, so one opened before it is closed. The
// answer is true as well where the opener stands inside a quote, a
// dollar-quoted string, or a block comment that closes within s: the line
// feed then follows plain code and is whitespace, and servers quote by rules
// too different to read here.
func sqlMayEndInLineComment(s string) bool {
	last := s[strings.LastIndexByte(s, '\n')+1:]
	return strings.Contains(last, "--") || strings.Contains(last, "#")
}
