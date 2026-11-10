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
	"go/ast"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// maxSourceRunes is the longest source line, or mutant description on the
// console, that the report prints whole; a longer one is cut there and marked
// with "...".
const maxSourceRunes = 120

// sourceFile is what the report shows of one Go file: its lines and the
// functions that span them.
type sourceFile struct {
	lines []string
	funcs []funcSpan
}

// funcSpan is a function, or a function literal, and the lines it spans.
type funcSpan struct {
	name        string
	first, last int
	literal     bool
}

// sources reads each Go file once, however many lines of it the report shows.
type sources map[string]sourceFile

func newSources() sources {
	return sources{}
}

// get returns the file at path, reading it on first use.
func (s sources) get(path string) sourceFile {
	f, ok := s[path]
	if !ok {
		f = readSource(path)
		s[path] = f
	}
	return f
}

// readSource reads and parses the Go file at path. A file that cannot be read
// yields no lines, and one that cannot be parsed no functions, so the report
// prints its mutants without them.
func readSource(path string) sourceFile {
	data, err := os.ReadFile(path)
	if err != nil {
		return sourceFile{}
	}
	f := sourceFile{lines: strings.Split(string(data), "\n")}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, data, parser.SkipObjectResolution)
	if err != nil {
		return f
	}
	line := func(p token.Pos) int { return fset.Position(p).Line }
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := funcName(fn)
		f.funcs = append(f.funcs, funcSpan{name: name, first: line(fn.Pos()), last: line(fn.End())})
		ast.Inspect(fn, func(n ast.Node) bool {
			if lit, ok := n.(*ast.FuncLit); ok {
				f.funcs = append(f.funcs, funcSpan{name: name, first: line(lit.Pos()), last: line(lit.End()), literal: true})
			}
			return true
		})
	}
	return f
}

// funcName returns the name of fn as a reader searches for it: "checkTimes",
// "(*Writer).request" for a pointer receiver, "Code.String" for a value one.
func funcName(fn *ast.FuncDecl) string {
	if fn.Recv == nil {
		return fn.Name.Name
	}
	recv := ast.Unparen(fn.Recv.List[0].Type)
	if star, ok := recv.(*ast.StarExpr); ok {
		return "(*" + typeName(star.X) + ")." + fn.Name.Name
	}
	return typeName(recv) + "." + fn.Name.Name
}

// typeName returns the name of a receiver type, without its type parameters,
// or "?" for a receiver that is no such name, as in source that does not
// compile.
func typeName(expr ast.Expr) string {
	switch t := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return typeName(t.X)
	case *ast.IndexListExpr:
		return typeName(t.X)
	}
	return "?"
}

// line returns the text of line n, 1-based, without its surrounding blanks and
// cut to maxSourceRunes, or "" when the file has no such line.
func (f sourceFile) line(n int) string {
	if n < 1 || n > len(f.lines) {
		return ""
	}
	return cut(strings.TrimSpace(f.lines[n-1]))
}

// cut returns s cut to maxSourceRunes, with "..." after a cut.
func cut(s string) string {
	text := []rune(s)
	if len(text) > maxSourceRunes {
		return string(text[:maxSourceRunes]) + "..."
	}
	return s
}

// function returns the innermost function that spans line n, as "checkTimes"
// or "a function literal in checkTimes", or "" outside every function.
func (f sourceFile) function(n int) string {
	var best *funcSpan
	for i := range f.funcs {
		s := &f.funcs[i]
		if n < s.first || n > s.last {
			continue
		}
		if best == nil || s.last-s.first < best.last-best.first {
			best = s
		}
	}
	switch {
	case best == nil:
		return ""
	case best.literal:
		return "a function literal in " + best.name
	}
	return best.name
}

// buildTag returns the build constraint that leaves the file at path out of
// the default build, as its //go:build line or as "its file name" for a
// GOOS or GOARCH suffix, or "" when the default build includes the file.
func buildTag(path string) string {
	dir, name := filepath.Split(path)
	included, err := build.Default.MatchFile(dir, name)
	if err != nil || included {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if constraint.IsGoBuild(l) {
			return l
		}
		if strings.HasPrefix(l, "package ") {
			break
		}
	}
	return "its file name"
}
