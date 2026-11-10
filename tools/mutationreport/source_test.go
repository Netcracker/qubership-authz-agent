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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeFile writes content to name in a new temporary directory and returns
// the file's path.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const functions = `package p

var before = 1

func checkTimes() {
	_ = 1
}

func (w *Writer) request() {
	run(func() {
		_ = 2
	})
}

func (c Code) String() string {
	return ""
}

func (c *Cache[K, V]) Get() {
	_ = 3
}

func (s *Set[T]) Has() {
	_ = 4
}

func (p (*Paren)) Do() {
	_ = 5
}

func oneLine() { run(func() {}) }

var x = 4

func (q *pkg.Q) Do() {
	_ = 6
}
`

func TestFunction_NamesTheInnermostFunctionAsAReaderSearchesForIt(t *testing.T) {
	src := readSource(writeFile(t, "f.go", functions))
	tests := []struct {
		name string
		line int
		want string
	}{
		{"package clause", 1, ""},
		{"declaration before every function", 3, ""},
		{"function", 6, "checkTimes"},
		{"pointer receiver", 9, "(*Writer).request"},
		{"function literal", 11, "a function literal in (*Writer).request"},
		{"value receiver", 16, "Code.String"},
		{"receiver with type parameters", 20, "(*Cache).Get"},
		{"receiver with a type parameter", 24, "(*Set).Has"},
		{"parenthesized receiver", 28, "(*Paren).Do"},
		{"function literal on the function's only line", 31, "oneLine"},
		{"declaration outside every function", 33, ""},
		{"receiver that is no type name", 36, "(*?).Do"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := src.function(tt.line); got != tt.want {
				t.Errorf("function(%d) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestFunction_AFileThatDoesNotParseHasNoFunctions(t *testing.T) {
	src := readSource(writeFile(t, "f.go", "package p\n\nfunc ok() {\n\t_ = 1\n}\n\nfunc broken( {\n"))
	if got := src.function(4); got != "" {
		t.Errorf("function(4) = %q, want \"\"", got)
	}
	if got := src.line(7); got != "func broken( {" {
		t.Errorf("line(7) = %q, want the source text", got)
	}
}

func TestSources_ReadEachFileOnce(t *testing.T) {
	p := writeFile(t, "f.go", "package p\n")
	s := newSources()
	if got := s.get(p).line(1); got != "package p" {
		t.Fatalf("get(%s).line(1) = %q, want %q", p, got, "package p")
	}
	if err := os.WriteFile(p, []byte("package changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := s.get(p).line(1); got != "package p" {
		t.Errorf("second get(%s).line(1) = %q, want the text read first, %q", p, got, "package p")
	}
}

func TestLine_TrimsTheLineAndCutsItAt120Runes(t *testing.T) {
	long := strings.Repeat("é", 121)
	src := readSource(writeFile(t, "f.go", "package p\n\t\tx := 1  \n"+long+"\n"+strings.Repeat("é", 120)+"\n"))
	tests := []struct {
		name string
		line int
		want string
	}{
		{"surrounding blanks", 2, "x := 1"},
		{"line of 120 runes", 4, strings.Repeat("é", 120)},
		{"line of 121 runes", 3, strings.Repeat("é", 120) + "..."},
		{"line 0", 0, ""},
		{"line past the end", 99, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := src.line(tt.line); got != tt.want {
				t.Errorf("line(%d) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestReadSource_AFileThatCannotBeReadHasNoLines(t *testing.T) {
	src := readSource(filepath.Join(t.TempDir(), "missing.go"))
	if got := src.line(1); got != "" {
		t.Errorf("line(1) = %q, want \"\"", got)
	}
}

func TestBuildTag_NamesTheConstraintThatLeavesAFileOut(t *testing.T) {
	tests := []struct {
		name, file, content, want string
	}{
		{"go:build line", "routes.go", "// Copyright\n\n//go:build paritytest\n\npackage p\n", "//go:build paritytest"},
		{"no constraint", "plain.go", "package p\n", ""},
		{"satisfied constraint", "tagged.go", "//go:build !paritytest\n\npackage p\n", ""},
		{"CRLF line ends", "crlf.go", "//go:build paritytest\r\n\r\npackage p\r\n", "//go:build paritytest"},
		{"malformed constraint", "bad.go", "//go:build (\n\npackage p\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildTag(writeFile(t, tt.file, tt.content)); got != tt.want {
				t.Errorf("buildTag(%s) = %q, want %q", tt.file, got, tt.want)
			}
		})
	}
}

func TestBuildTag_NamesTheFileNameForAnotherOperatingSystem(t *testing.T) {
	other := "windows"
	if runtime.GOOS == "windows" {
		other = "linux"
	}
	name := "x_" + other + ".go"
	content := "package p\n\n// A comment that reads //go:build x is not a constraint after the package clause.\n//go:build x\n"
	if got := buildTag(writeFile(t, name, content)); got != "its file name" {
		t.Errorf("buildTag(%s) = %q, want %q", name, got, "its file name")
	}
}
