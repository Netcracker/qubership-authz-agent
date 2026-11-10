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

package main

import (
	"go/scanner"
	"go/token"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// changeRunes is the longest code, before or after a mutation, that the
// console prints whole; a longer one is cut there and marked with "...".
const changeRunes = 50

// change is the code a mutant replaces and the code that replaces it. An
// empty before is an insertion, and an empty after a removal.
type change struct {
	before, after string
}

// changeOf returns the shortest code in which the two sides of diff differ,
// comparing Go tokens and, inside string and character literals, words, so
// that whitespace, line breaks, and comments do not count. mutago prints the
// node it mutated anew, with its own line breaks and indentation, so the
// lines of a diff can differ well beyond the change. Where the change
// starts with mutago's noop, the code it replaces counts as removed. ok is
// false when diff has no hunk, or its sides have the same tokens.
func changeOf(diff string) (c change, ok bool) {
	before, after := sides(diff)
	a, b := pieces(before), pieces(after)
	head := 0
	for head < len(a) && head < len(b) && a[head].text == b[head].text {
		head++
	}
	b = withoutNoop(after, b, head)
	tail := 0
	for tail < len(a)-head && tail < len(b)-head && a[len(a)-1-tail].text == b[len(b)-1-tail].text {
		tail++
	}
	a, b = a[head:len(a)-tail], b[head:len(b)-tail]
	if len(a) == 0 && len(b) == 0 {
		return change{}, false
	}
	return change{before: span(before, a), after: span(after, b)}, true
}

// noop matches the start of the statement that mutago writes, on a line of
// its own, in place of code it removes, so that the mutant still compiles: a
// blank assignment of the names that code used, such as
// "_, _ = fmt.Errorf, err".
var noop = regexp.MustCompile(`^_(, _)* = `)

// withoutNoop returns ps, the pieces of src, without those of the line that
// ps[at] starts when that line is mutago's noop.
func withoutNoop(src string, ps []piece, at int) []piece {
	if at == len(ps) {
		return ps
	}
	line, _, _ := strings.Cut(src[ps[at].start:], "\n")
	if !noop.MatchString(line) {
		return ps
	}
	end, next := ps[at].start+len(line), at
	for next < len(ps) && ps[next].end <= end {
		next++
	}
	return slices.Delete(slices.Clone(ps), at, next)
}

// sides returns the lines of the hunks of diff as they were before and after
// the mutation, without the diff's file and hunk headers.
func sides(diff string) (before, after string) {
	var b, a strings.Builder
	inHunk := false
	for _, l := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(l, "@@"):
			inHunk = true
		case !inHunk || l == "":
		case l[0] == ' ':
			b.WriteString(l[1:] + "\n")
			a.WriteString(l[1:] + "\n")
		case l[0] == '-':
			b.WriteString(l[1:] + "\n")
		case l[0] == '+':
			a.WriteString(l[1:] + "\n")
		}
	}
	return b.String(), a.String()
}

// piece is a Go token, or a word or a quote of a string or character literal,
// with the offsets of its first byte and of the byte after it.
type piece struct {
	text       string
	start, end int
}

// pieces splits src into the pieces changeOf compares. It leaves out comments
// and semicolons: the scanner inserts a semicolon at a line end, and mutago
// prints statements that a semicolon separated on one line on lines of their
// own.
func pieces(src string) []piece {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, []byte(src), nil, 0)
	var out []piece
	for {
		pos, tok, lit := s.Scan()
		switch tok {
		case token.EOF:
			return out
		case token.SEMICOLON:
			continue
		}
		text := lit
		if text == "" {
			text = tok.String()
		}
		start := file.Offset(pos)
		if tok == token.STRING || tok == token.CHAR {
			out = append(out, words(text, start)...)
			continue
		}
		out = append(out, piece{text: text, start: start, end: start + len(text)})
	}
}

// words splits the literal lit, which starts at offset start, into its quotes
// and the runs of characters between its spaces, so that a mutant that
// changes the verb %w of a format string to %v shows those two verbs alone.
func words(lit string, start int) []piece {
	var out []piece
	from := -1
	flush := func(to int) {
		if from != -1 {
			out = append(out, piece{text: lit[from:to], start: start + from, end: start + to})
			from = -1
		}
	}
	for i, r := range lit {
		switch {
		case unicode.IsSpace(r):
			flush(i)
		case r == '"' || r == '`' || r == '\'':
			flush(i)
			from = i
			flush(i + 1)
		case from == -1:
			from = i
		}
	}
	flush(len(lit))
	return out
}

// span returns the text of src from the first of ps to the last of them, as
// one line: each of its lines without the blanks around it, joined by spaces.
func span(src string, ps []piece) string {
	if len(ps) == 0 {
		return ""
	}
	lines := strings.Split(src[ps[0].start:ps[len(ps)-1].end], "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(l)
	}
	return strings.Join(lines, " ")
}

// label returns c as the report shows it: "`before` → `after`", or
// "removes `before`" or "adds `after`" when a side is empty. Unless full is
// set, each side is cut to changeRunes.
func (c change) label(full bool) string {
	before, after := c.before, c.after
	if !full {
		before, after = cut(before, changeRunes), cut(after, changeRunes)
	}
	switch {
	case c.after == "":
		return "removes `" + before + "`"
	case c.before == "":
		return "adds `" + after + "`"
	}
	return "`" + before + "` → `" + after + "`"
}
