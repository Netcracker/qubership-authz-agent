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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newResult returns a completed run against origin/main of the changed
// files, which writes into the directory out.
func newResult(s summary, changed ...string) *result {
	return &result{dir: "out", base: "origin/main", mergeBase: "5de690df7f2718da", status: 4, changed: changed, summary: &s}
}

// sourceOf returns sources that hold path with lines, all inside function f.
func sourceOf(path string, lines ...string) sources {
	return sources{path: {lines: lines, funcs: []funcSpan{{name: "f", first: 1, last: len(lines)}}}}
}

// fileHeaders returns the lines of a report that open a file.
func fileHeaders(report string) []string {
	var heads []string
	for _, l := range strings.Split(report, "\n") {
		if strings.HasPrefix(l, "  ") && !strings.HasPrefix(l, "   ") && strings.Contains(l, ".go") {
			heads = append(heads, strings.TrimSpace(l))
		}
	}
	return heads
}

func TestRender_ListsEachChangedLineOnceWithItsMutantsAndWhatToDo(t *testing.T) {
	r := newResult(summary{Total: 4, Killed: 1, Escaped: 2, Errored: 1}, "a/a.go")
	r.mutants = []mutant{
		{File: "a/a.go", Line: 3, Mutator: "statement/return", Description: "Replaces a return value with its zero value", TestFiles: []string{"a/a_test.go"}},
		{File: "a/a.go", Line: 2, Mutator: "branch/if", Description: "Removes an if-block body", TestFiles: []string{"a/a_test.go", "a/b_test.go"}},
		{File: "a/a.go", Line: 3, Mutator: "expression/remove", errored: true},
	}
	want := `Mutation testing of changed lines against origin/main (5de690df), packages ./a
  4 mutants: 1 killed, 2 survived, 1 errored
  ordered by listed mutants per file, then by line

  a/a.go (tests of the package: a_test.go, b_test.go)
    2: if ok {
        survived: Removes an if-block body (branch/if), in f
    3: return x
        survived: Replaces a return value with its zero value (statement/return), in f
        errored: expression/remove, in f

Listed mutants on 2 lines in 1 file.

For each surviving mutant, decide which case it is:
  - the tests miss behavior the change defines: add or strengthen a test through the package's interface
  - no caller can observe the difference, so the mutant is equivalent: say why in the pull request
  - you cannot tell: report it as unresolved
Report each errored mutant as unresolved: no test was shown able to kill it.
Quote the counts above in the pull request.

Full report, with each mutant's diff: out/report.txt
mutago's output: out/mutago.log
`
	if got := r.render(consoleLimits, sourceOf("a/a.go", "package a", "\tif ok {", "\t\treturn x")); got != want {
		t.Errorf("render(consoleLimits) =\n%s\nwant\n%s", got, want)
	}
}

func TestRender_TheFileAddsEachMutantsDiff(t *testing.T) {
	r := newResult(summary{Total: 1, Escaped: 1}, "a.go")
	r.mutants = []mutant{{File: "a.go", Line: 1, Mutator: "expression/error-guard", Description: "Removes an error-guard block",
		KillHint: "Write a test that triggers the error condition", Diff: "--- Original\n+++ New\n@@ -1,1 +1,1 @@\n-if err != nil {\n+if false {\n"}}
	want := `Mutation testing of changed lines against origin/main (5de690df), packages .
  1 mutant: 0 killed, 1 survived, 0 errored
  ordered by listed mutants per file, then by line
  mutago prints each diff from the syntax node it mutated: a diff can span more lines than the change, and its added lines can lose the file's indentation (quality-gates/mutago#354)

  a.go
    1: if err != nil {
        survived: ` + "`err != nil` → `false`" + ` (expression/error-guard), in f
          --- Original
          +++ New
          @@ -1,1 +1,1 @@
          -if err != nil {
          +if false {

Listed mutants on 1 line in 1 file.

` + whatToDo + `
Hints for a test that kills a mutant, by mutator:
  expression/error-guard: Write a test that triggers the error condition
Quote the counts above in the pull request.

mutago's output: out/mutago.log
`
	if got := r.render(noLimits, sourceOf("a.go", "if err != nil {")); got != want {
		t.Errorf("render(noLimits) =\n%s\nwant\n%s", got, want)
	}
}

func TestRender_OrdersFilesByTheirMutantsThenByPath(t *testing.T) {
	r := newResult(summary{Total: 5, Escaped: 5}, "a.go", "b.go", "c.go")
	r.mutants = []mutant{
		{File: "a.go", Line: 1, Mutator: "m"},
		{File: "c.go", Line: 1, Mutator: "m"}, {File: "c.go", Line: 2, Mutator: "m"},
		{File: "b.go", Line: 1, Mutator: "m"}, {File: "b.go", Line: 2, Mutator: "m"},
	}
	got := strings.Join(fileHeaders(r.render(noLimits, sources{})), " ")
	if want := "b.go c.go a.go"; got != want {
		t.Errorf("file order = %s, want %s", got, want)
	}
}

func TestRender_TheConsoleShowsAtMost10Files(t *testing.T) {
	var files []string
	r := newResult(summary{Total: 12, Escaped: 12})
	for i := range 12 {
		f := fmt.Sprintf("f%02d.go", i)
		files = append(files, f)
		r.mutants = append(r.mutants, mutant{File: f, Line: 1, Mutator: "m"})
	}
	r.changed = files
	out := r.render(consoleLimits, sources{})
	if got := len(fileHeaders(out)); got != 10 {
		t.Errorf("render(consoleLimits) shows %d files, want 10", got)
	}
	if !strings.Contains(out, "\n  2 more files\n") {
		t.Errorf("render(consoleLimits) =\n%s\nwant a line saying 2 more files", out)
	}
	if !strings.Contains(out, "Listed mutants on 12 lines in 12 files.") {
		t.Errorf("render(consoleLimits) =\n%s\nwant the counts of every file", out)
	}
}

// Files of 25, 20, and 20 changed lines exceed the console's 50 lines: c.go
// shows 20 of its 25, a.go all 20, b.go 10 of its 20, and d.go none.
func TestRender_TheConsoleShowsAtMost20LinesPerFileAnd50InAll(t *testing.T) {
	r := newResult(summary{Total: 65, Escaped: 65})
	for _, f := range []string{"a.go", "b.go"} {
		for line := 1; line <= 20; line++ {
			r.mutants = append(r.mutants, mutant{File: f, Line: line, Mutator: "m"})
		}
	}
	for line := 1; line <= 25; line++ {
		r.mutants = append(r.mutants, mutant{File: "c.go", Line: line, Mutator: "m"})
	}
	r.mutants = append(r.mutants, mutant{File: "d.go", Line: 1, Mutator: "m"})
	out := r.render(consoleLimits, sources{})
	rows := strings.Count(out, "        survived: m\n")
	if rows != 50 {
		t.Errorf("render(consoleLimits) shows %d lines, want 50", rows)
	}
	for _, more := range []string{"    5 more lines\n", "    10 more lines\n", "\n  1 more file\n"} {
		if !strings.Contains(out, more) {
			t.Errorf("render(consoleLimits) =\n%s\nwant %q", out, more)
		}
	}
}

func TestRender_AnUnlocatedErrorIsListedApart(t *testing.T) {
	r := newResult(summary{Total: 1, Errored: 1}, "a.go")
	r.internalErrors = []string{"cannot build the mutant"}
	out := r.render(consoleLimits, sources{})
	if !strings.Contains(out, "\n  errored without a line: cannot build the mutant\n") {
		t.Errorf("render(consoleLimits) =\n%s\nwant the error text", out)
	}
	if strings.Contains(out, "For each surviving mutant") {
		t.Errorf("render(consoleLimits) =\n%s\nwant no advice on survivors when none survived", out)
	}
}

func TestRender_SaysWhenNoMutantSurvived(t *testing.T) {
	want := `Mutation testing of changed lines against origin/main (5de690df), packages ./a
  3 mutants: 3 killed, 0 survived, 0 errored

No mutant on the changed lines survived.

mutago's output: out/mutago.log
`
	if got := newResult(summary{Total: 3, Killed: 3}, "a/a.go").render(consoleLimits, sources{}); got != want {
		t.Errorf("render(consoleLimits) =\n%s\nwant\n%s", got, want)
	}
}

func TestRender_ANoMutantRunListsTheChangedFiles(t *testing.T) {
	want := `Mutation testing of changed lines against origin/main (5de690df), packages ./a
  no mutant: mutago generated none on the changed lines

  These changed files got no mutant:
    a/a.go

That is expected when no enabled mutator changes the changed lines, as with comments, imports, declarations, and number literals. No test was shown able to fail on them: say so in the pull request.

mutago's output: out/mutago.log
`
	if got := newResult(summary{}, "a/a.go").render(consoleLimits, sources{}); got != want {
		t.Errorf("render(consoleLimits) =\n%s\nwant\n%s", got, want)
	}
}

func TestRender_ANoMutantRunWithDiffExternalSaysHowToRerun(t *testing.T) {
	r := newResult(summary{}, "a/a.go")
	r.diffExternal = "global\tdifft"
	want := `Mutation testing of changed lines against origin/main (5de690df), packages ./a
  no mutant: mutago generated none on the changed lines

  These changed files got no mutant:
    a/a.go

The global git config sets diff.external to "difft", and mutago cannot read the diff an external tool prints, so it found no changed line. To mutate these lines, rerun it as GIT_CONFIG_GLOBAL=/dev/null make mutation-diff. Until then, report the run as not completed.

mutago's output: out/mutago.log
`
	if got := r.render(consoleLimits, sources{}); got != want {
		t.Errorf("render(consoleLimits) =\n%s\nwant\n%s", got, want)
	}
}

func TestDiffExternalAdvice_GivesTheStepForEachScope(t *testing.T) {
	tests := []struct {
		scope, step string
	}{
		{"global", "rerun it as GIT_CONFIG_GLOBAL=/dev/null make mutation-diff"},
		{"system", "rerun it as GIT_CONFIG_NOSYSTEM=1 make mutation-diff"},
		{"local", "run git config --local --unset diff.external, or rerun it from a clone without it"},
		{"worktree", "run git config --worktree --unset diff.external, or rerun it from a clone without it"},
		{"command", "rerun it without the setting"},
	}
	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			got := diffExternalAdvice(tt.scope + "\tdifft")
			if !strings.Contains(got, "To mutate these lines, "+tt.step+".") {
				t.Errorf("diffExternalAdvice(%q) = %q, want the step %q", tt.scope, got, tt.step)
			}
		})
	}
}

func TestRender_NamesAChangedFileTheDefaultBuildLeavesOut(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir("srv", 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"srv/routes.go": "//go:build paritytest\n\npackage srv\n",
		"srv/plain.go":  "package srv\n",
	} {
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name string
		r    *result
		want string
	}{
		{"beside a mutated file", newResult(summary{Total: 1, Killed: 1}, "srv/plain.go", "srv/routes.go"),
			`Mutation testing of changed lines against origin/main (5de690df), packages ./srv
  1 mutant: 1 killed, 0 survived, 0 errored

No mutant on the changed lines survived.

Not mutated: the default build leaves out these changed files, so mutago never saw their lines:
  srv/routes.go (//go:build paritytest)
Say so in the pull request.

mutago's output: out/mutago.log
`},
		{"alone", newResult(summary{}, "srv/routes.go"),
			`Mutation testing of changed lines against origin/main (5de690df), packages ./srv
  no mutant: mutago generated none on the changed lines

Not mutated: the default build leaves out these changed files, so mutago never saw their lines:
  srv/routes.go (//go:build paritytest)
Say so in the pull request.

mutago's output: out/mutago.log
`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.r.render(consoleLimits, sources{}); got != tt.want {
				t.Errorf("render(consoleLimits) =\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

func TestRender_AnIncompleteRunShowsMutagosReasonAndWhatItMeans(t *testing.T) {
	r := newResult(summary{}, "a/a.go")
	r.summary, r.status = nil, 3
	r.log = []string{`Baseline test failed for "authz-agent/a" — fix the build/tests before running mutago:`, "--- FAIL: TestA", "FAIL"}
	want := `Mutation testing of changed lines against origin/main (5de690df), packages ./a
  the run did not complete: mutago exited with status 3

  Baseline test failed for "authz-agent/a" — fix the build/tests before running mutago:
  --- FAIL: TestA
  FAIL

The tests of a changed package failed, or ran longer than the limit, before any mutation. Fix them, or set MUTATION_TIMEOUT to a larger number of seconds when they only need more time.
Report the run as not completed, not as one without survivors.

mutago's output: out/mutago.log
`
	if got := r.render(consoleLimits, sources{}); got != want {
		t.Errorf("render(consoleLimits) =\n%s\nwant\n%s", got, want)
	}
}

func TestRender_AnIncompleteRunShowsTheFirstAndTheLast20LinesOfMutagosOutput(t *testing.T) {
	r := newResult(summary{}, "a.go")
	r.summary, r.status = nil, 3
	r.log = []string{"Cannot load git diff: exit status 128"}
	for i := 1; i <= 30; i++ {
		r.log = append(r.log, fmt.Sprintf("line %d", i))
	}
	out := r.render(consoleLimits, sources{})
	for _, part := range []string{"\n  Cannot load git diff: exit status 128\n  ...\n  line 11\n", "\n  line 30\n", "The first line of mutago's output gives the reason."} {
		if !strings.Contains(out, part) {
			t.Errorf("render(consoleLimits) =\n%s\nwant %q", out, part)
		}
	}
	if strings.Contains(out, "line 10\n") {
		t.Errorf("render(consoleLimits) =\n%s\nwant line 10 left out", out)
	}
}

func TestExitStatus_IsZeroForACompletedRunAndMutagosStatusOtherwise(t *testing.T) {
	tests := []struct {
		name          string
		summary       *summary
		status        int
		noSourceFiles bool
		want          int
	}{
		{"survivors", &summary{Total: 1, Escaped: 1}, 4, false, 0},
		{"every mutant killed", &summary{Total: 1, Killed: 1}, 0, false, 0},
		{"no mutant", &summary{}, 0, false, 0},
		{"no file built", nil, 3, true, 0},
		{"tool error", nil, 3, false, 3},
		{"crash", nil, 2, false, 2},
		{"status 4 without a summary", nil, 4, false, 4},
		{"status 0 without a summary", nil, 0, false, 3},
		{"status 3 with a summary", &summary{Total: 1}, 3, false, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &result{summary: tt.summary, status: tt.status, noSourceFiles: tt.noSourceFiles}
			if got := r.exitStatus(); got != tt.want {
				t.Errorf("exitStatus() = %d, want %d", got, tt.want)
			}
		})
	}
}

// writeRun writes the files mutago leaves after a run into a new directory
// and returns it; an empty content leaves that file out.
func writeRun(t *testing.T, summaryJSON, agenticJSON, log string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{"mutago-summary.json": summaryJSON, "mutago-agentic.json": agenticJSON, "mutago.log": log} {
		if content == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoad_ReadsTheSummaryTheSurvivorsAndTheErroredMutantsOfTheLog(t *testing.T) {
	dir := writeRun(t,
		`{"totalMutantsCount":3,"killedCount":1,"escapedCount":1,"errorCount":1}`,
		`{"mutants":[{"file":"a.go","line":4,"mutator":"branch/if","description":"d","kill_hint":"h","diff":"x","test_files":["a_test.go"]}]}`,
		"\x1b[37;41mESCAPED\x1b[0m a.go:4 (branch/if)\nUNKNOWN exit code for b.go:7 (statement/return)\nINTERNAL ERROR cannot build\n")
	r, err := load(dir, "origin/main", "abc", 4, "global\tdifft\n", []string{"a.go", "b.go"})
	if err != nil {
		t.Fatalf("load() error = %v", err)
	}
	if r.summary == nil || *r.summary != (summary{Total: 3, Killed: 1, Escaped: 1, Errored: 1}) {
		t.Errorf("summary = %+v, want 3 mutants: 1 killed, 1 escaped, 1 errored", r.summary)
	}
	wantMutants := []mutant{
		{File: "a.go", Line: 4, Mutator: "branch/if", Description: "d", KillHint: "h", Diff: "x", TestFiles: []string{"a_test.go"}},
		{File: "b.go", Line: 7, Mutator: "statement/return", errored: true},
	}
	if fmt.Sprint(r.mutants) != fmt.Sprint(wantMutants) {
		t.Errorf("mutants = %+v, want %+v", r.mutants, wantMutants)
	}
	if fmt.Sprint(r.internalErrors) != "[cannot build]" {
		t.Errorf("internalErrors = %q, want [cannot build]", r.internalErrors)
	}
	if r.log[0] != "ESCAPED a.go:4 (branch/if)" {
		t.Errorf("log[0] = %q, want it without color codes", r.log[0])
	}
	if r.diffExternal != "global\tdifft" || r.noSourceFiles {
		t.Errorf("diffExternal = %q, noSourceFiles = %v, want %q and false", r.diffExternal, r.noSourceFiles, "global\tdifft")
	}
	if r.dir != dir || r.base != "origin/main" || r.mergeBase != "abc" || r.status != 4 || fmt.Sprint(r.changed) != "[a.go b.go]" {
		t.Errorf("run = dir %q, base %q, merge base %q, status %d, changed %v; want the arguments of load", r.dir, r.base, r.mergeBase, r.status, r.changed)
	}
}

func TestLoad_ARunThatStoppedEarlyHasNoSummary(t *testing.T) {
	r, err := load(writeRun(t, "", "", noSourceFiles+"\n"), "origin/main", "", 3, "", nil)
	if err != nil {
		t.Fatalf("load() error = %v", err)
	}
	if r.summary != nil || len(r.mutants) != 0 || !r.noSourceFiles {
		t.Errorf("summary = %+v, mutants = %v, noSourceFiles = %v, want none, none, true", r.summary, r.mutants, r.noSourceFiles)
	}
}

func TestLoad_RefusesMissingOrMalformedFiles(t *testing.T) {
	tests := []struct {
		name, summaryJSON, agenticJSON, log, want string
	}{
		{"no mutago.log", "", "", "", "mutago.log"},
		{"malformed summary", "{", "", "x\n", "mutago-summary.json"},
		{"malformed agentic report", "", "[", "x\n", "mutago-agentic.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(writeRun(t, tt.summaryJSON, tt.agenticJSON, tt.log), "origin/main", "", 4, "", nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("load() error = %v, want one that names %s", err, tt.want)
			}
		})
	}
}

func TestRender_ARunWithNoBuiltSourceFileIsANoMutantRun(t *testing.T) {
	r := newResult(summary{}, "a/a.go")
	r.summary, r.status, r.noSourceFiles = nil, 3, true
	want := `Mutation testing of changed lines against origin/main (5de690df), packages ./a
  no mutant: mutago generated none on the changed lines

  These changed files got no mutant:
    a/a.go

That is expected when no enabled mutator changes the changed lines, as with comments, imports, declarations, and number literals. No test was shown able to fail on them: say so in the pull request.

mutago's output: out/mutago.log
`
	if got := r.render(consoleLimits, sources{}); got != want {
		t.Errorf("render(consoleLimits) =\n%s\nwant\n%s", got, want)
	}
}

func TestRender_AnIncompleteRunDoesNotPointToTheFullReport(t *testing.T) {
	r := newResult(summary{}, "a.go")
	r.summary, r.status = nil, 3
	r.mutants = []mutant{{File: "a.go", Line: 1, Mutator: "m", errored: true}}
	r.log = []string{"panic: boom"}
	if out := r.render(consoleLimits, sources{}); strings.Contains(out, "Full report") {
		t.Errorf("render(consoleLimits) =\n%s\nwant no pointer to the full report of a run that did not complete", out)
	}
}

func TestHeader_NamesTheBaseAndTheCommitTheDiffStartsFrom(t *testing.T) {
	tests := []struct {
		name, mergeBase, want string
	}{
		{"long commit", "5de690df7f2718da", "against origin/main (5de690df), packages ."},
		{"short commit", "abc", "against origin/main (abc), packages ."},
		{"no merge base", "origin/main", "against origin/main, packages ."},
		{"no commit", "", "against origin/main, packages ."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newResult(summary{}, "a.go")
			r.mergeBase = tt.mergeBase
			if got := r.header(); got != "Mutation testing of changed lines "+tt.want+"\n" {
				t.Errorf("header() = %q, want it to read %q", got, tt.want)
			}
		})
	}
}

func TestHeader_ListsThePackagesInOrder(t *testing.T) {
	got := newResult(summary{}, "b/x.go", "a/y.go", "z.go", "a/w.go").header()
	if want := "packages . ./a ./b\n"; !strings.HasSuffix(got, want) {
		t.Errorf("header() = %q, want it to end with %q", got, want)
	}
}

// The first line and the last 20 cover 21 lines of output, so nothing is cut,
// and each line is shown once.
func TestRender_AnIncompleteRunWith21LinesOfOutputShowsThemAll(t *testing.T) {
	r := newResult(summary{}, "a.go")
	r.summary, r.status = nil, 3
	for i := 1; i <= 21; i++ {
		r.log = append(r.log, fmt.Sprintf("line %d", i))
	}
	out := r.render(consoleLimits, sources{})
	if strings.Contains(out, "\n  ...\n") {
		t.Errorf("render(consoleLimits) =\n%s\nwant no cut in 21 lines", out)
	}
	for i := 1; i <= 21; i++ {
		if got := strings.Count(out, fmt.Sprintf("  line %d\n", i)); got != 1 {
			t.Errorf("render(consoleLimits) shows line %d %d times, want once", i, got)
		}
	}
}

func TestRender_AnIncompleteRunWithNoOutputSaysSo(t *testing.T) {
	r := newResult(summary{}, "a.go")
	r.summary, r.status = nil, 137
	if out := r.render(consoleLimits, sources{}); !strings.Contains(out, "\n\nmutago printed nothing before it stopped.\n") {
		t.Errorf("render(consoleLimits) =\n%s\nwant it to say mutago printed nothing", out)
	}
}

func TestRender_OrdersTheMutantsOfALineSurvivorsFirstThenByMutator(t *testing.T) {
	r := newResult(summary{Total: 3, Escaped: 2, Errored: 1}, "a.go")
	r.mutants = []mutant{
		{File: "a.go", Line: 1, Mutator: "c/second"},
		{File: "a.go", Line: 1, Mutator: "a/errored", errored: true},
		{File: "a.go", Line: 1, Mutator: "b/first"},
	}
	want := `    1: 
        survived: b/first
        survived: c/second
        errored: a/errored
`
	if got := r.render(consoleLimits, sources{}); !strings.Contains(got, want) {
		t.Errorf("render(consoleLimits) =\n%s\nwant it to contain\n%s", got, want)
	}
}

// a/y.go comes first, with the most mutants, although a/x.go comes first by
// path, and carries the test files of every mutant of package a, in order.
func TestRender_NamesTheTestFilesOfAPackageAtItsFirstFile(t *testing.T) {
	r := newResult(summary{Total: 4, Escaped: 4}, "a/x.go", "a/y.go", "b/z.go")
	r.mutants = []mutant{
		{File: "a/x.go", Line: 1, Mutator: "m", TestFiles: []string{"a/x_test.go", "a/b_test.go"}},
		{File: "a/y.go", Line: 1, Mutator: "m", TestFiles: []string{"a/y_test.go"}},
		{File: "a/y.go", Line: 2, Mutator: "m", TestFiles: []string{"a/y_test.go"}},
		{File: "b/z.go", Line: 1, Mutator: "m", TestFiles: []string{"b/z_test.go"}},
	}
	got := strings.Join(fileHeaders(r.render(consoleLimits, sources{})), "\n")
	want := "a/y.go (tests of the package: b_test.go, x_test.go, y_test.go)\na/x.go\nb/z.go (tests of the package: z_test.go)"
	if got != want {
		t.Errorf("file headers =\n%s\nwant\n%s", got, want)
	}
}

func TestRender_OrdersFilesWithAsManyMutantsByPath(t *testing.T) {
	r := newResult(summary{Total: 4, Escaped: 4})
	for _, f := range []string{"b.go", "a.go", "d.go", "c.go"} {
		r.mutants = append(r.mutants, mutant{File: f, Line: 1, Mutator: "m"})
	}
	got := strings.Join(fileHeaders(r.render(noLimits, sources{})), " ")
	if want := "a.go b.go c.go d.go"; got != want {
		t.Errorf("file order = %s, want %s", got, want)
	}
}

// A mutant that did not compile is skipped, not a survivor; one that is not
// covered, or errored, still needs a reader, even when mutago's files do not
// place it on a line.
func TestRender_DecidesFromTheCountsWhetherAnyMutantNeedsAReader(t *testing.T) {
	tests := []struct {
		name string
		s    summary
		want string
	}{
		{"skipped only", summary{Total: 3, Killed: 1, Skipped: 2}, `  3 mutants: 1 killed, 0 survived, 0 errored, 2 skipped

No mutant on the changed lines survived.
`},
		{"not covered", summary{Total: 2, Killed: 1, NotCovered: 1}, `  2 mutants: 1 killed, 0 survived, 0 errored, 1 not covered

mutago's files place none of the mutants these counts include; mutago.log lists them.

Quote the counts above in the pull request.
`},
		{"errored without a line in the log", summary{Total: 2, Killed: 1, Errored: 1}, `  2 mutants: 1 killed, 0 survived, 1 errored

mutago's files place none of the mutants these counts include; mutago.log lists them.

Report each errored mutant as unresolved: no test was shown able to kill it.
Quote the counts above in the pull request.
`},
		{"errored and not covered", summary{Total: 3, Killed: 1, Errored: 1, NotCovered: 1}, `  3 mutants: 1 killed, 0 survived, 1 errored, 1 not covered

mutago's files place none of the mutants these counts include; mutago.log lists them.

Report each errored mutant as unresolved: no test was shown able to kill it.
Quote the counts above in the pull request.
`},
		{"survived and errored without a line", summary{Total: 3, Killed: 1, Escaped: 1, Errored: 1}, `  3 mutants: 1 killed, 1 survived, 1 errored

mutago's files place none of the mutants these counts include; mutago.log lists them.

` + whatToDo + `
Report each errored mutant as unresolved: no test was shown able to kill it.
Quote the counts above in the pull request.
`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := "Mutation testing of changed lines against origin/main (5de690df), packages .\n" + tt.want + "\nmutago's output: out/mutago.log\n"
			if got := newResult(tt.s, "a.go").render(consoleLimits, sources{}); got != want {
				t.Errorf("render(consoleLimits) =\n%s\nwant\n%s", got, want)
			}
		})
	}
}

func TestRender_TheConsoleCountsMutantsThatPrintTheSameWay(t *testing.T) {
	r := newResult(summary{Total: 6, Escaped: 4, Errored: 2}, "a.go")
	for _, m := range []mutant{
		{Mutator: "composite/field-clear", Description: "Drops a keyed field", Diff: "1"},
		{Mutator: "composite/field-clear", Description: "Drops a keyed field", Diff: "2"},
		{Mutator: "composite/field-clear", Description: "Drops a keyed field", Diff: "3"},
		{Mutator: "statement/return", Description: "Replaces a return value"},
		{Mutator: "branch/if", errored: true},
		{Mutator: "branch/if", errored: true},
	} {
		m.File, m.Line = "a.go", 1
		r.mutants = append(r.mutants, m)
	}
	want := `        3 survived: Drops a keyed field (composite/field-clear)
        survived: Replaces a return value (statement/return)
        2 errored: branch/if
`
	if got := r.render(consoleLimits, sources{}); !strings.Contains(got, want) {
		t.Errorf("render(consoleLimits) =\n%s\nwant it to contain\n%s", got, want)
	}
	if got := strings.Count(r.render(noLimits, sources{}), "        survived: Drops a keyed field"); got != 3 {
		t.Errorf("render(noLimits) lists the field mutant %d times, want 3, each with its diff", got)
	}
}

func TestRender_TheConsoleCutsALongDescription(t *testing.T) {
	long := "Changes: `" + strings.Repeat("x", 130) + "`"
	r := newResult(summary{Total: 1, Escaped: 1}, "a.go")
	r.mutants = []mutant{{File: "a.go", Line: 1, Mutator: "m", Description: long}}
	if got := r.render(consoleLimits, sources{}); !strings.Contains(got, "survived: Changes: `"+strings.Repeat("x", 110)+"... (m)\n") {
		t.Errorf("render(consoleLimits) =\n%s\nwant the description cut to 120 runes", got)
	}
	if got := r.render(noLimits, sources{}); !strings.Contains(got, long+" (m)") {
		t.Errorf("render(noLimits) =\n%s\nwant the whole description", got)
	}
}

func TestRender_TheConsoleKeepsApartMutantsThatPrintDifferently(t *testing.T) {
	r := newResult(summary{Total: 6, Escaped: 5, Errored: 1}, "a.go")
	for _, m := range []mutant{
		{Mutator: "a/one", Description: "first description"},
		{Mutator: "a/one", Description: "second description"},
		{Mutator: "b/two", Description: "shared description"},
		{Mutator: "c/three", Description: "shared description"},
		{Mutator: "d/four"},
		{Mutator: "d/four", errored: true},
	} {
		m.File, m.Line = "a.go", 1
		r.mutants = append(r.mutants, m)
	}
	want := `        survived: first description (a/one)
        survived: second description (a/one)
        survived: shared description (b/two)
        survived: shared description (c/three)
        survived: d/four
        errored: d/four
`
	if got := r.render(consoleLimits, sources{}); !strings.Contains(got, want) {
		t.Errorf("render(consoleLimits) =\n%s\nwant it to contain\n%s", got, want)
	}
}

// The diffs show no change, so the three mutants print mutago's description,
// which they share.
func TestRender_TheFileOrdersMutantsThatPrintTheSameWayByTheirDiff(t *testing.T) {
	r := newResult(summary{Total: 3, Escaped: 3}, "a.go")
	for _, d := range []string{"+c", "+a", "+b"} {
		r.mutants = append(r.mutants, mutant{File: "a.go", Line: 1, Mutator: "m", Description: "d", Diff: d})
	}
	out := r.render(noLimits, sources{})
	a, b, c := strings.Index(out, "          +a\n"), strings.Index(out, "          +b\n"), strings.Index(out, "          +c\n")
	if a < 0 || a > b || b > c {
		t.Errorf("render(noLimits) =\n%s\nwant the diffs +a, +b, +c in that order", out)
	}
}

func TestRender_AnIncompleteRunSkipsBlankLinesBeforeTheFirstOne(t *testing.T) {
	r := newResult(summary{}, "a.go")
	r.summary, r.status = nil, 3
	r.log = []string{"", "  ", "panic: boom", "goroutine 1"}
	out := r.render(consoleLimits, sources{})
	if !strings.Contains(out, "\n\n  panic: boom\n  goroutine 1\n\n") || strings.Count(out, "panic: boom") != 1 {
		t.Errorf("render(consoleLimits) =\n%s\nwant the first line that is not blank once, then the rest", out)
	}
}

// The diffs show no change, so the mutants print mutago's description, and
// they are ordered by it before their diff, so those that print the same way
// are counted together.
func TestRender_TheConsoleCountsMutantsOfOneDescriptionWhenTheirDiffsShowNoChange(t *testing.T) {
	r := newResult(summary{Total: 3, Escaped: 3}, "a.go")
	for _, m := range []mutant{
		{Mutator: "m", Description: "A", Diff: "1"},
		{Mutator: "m", Description: "B", Diff: "2"},
		{Mutator: "m", Description: "A", Diff: "3"},
	} {
		m.File, m.Line = "a.go", 1
		r.mutants = append(r.mutants, m)
	}
	want := "        2 survived: A (m)\n        survived: B (m)\n"
	if got := r.render(consoleLimits, sources{}); !strings.Contains(got, want) {
		t.Errorf("render(consoleLimits) =\n%s\nwant it to contain\n%s", got, want)
	}
}

func TestRender_ShowsTheCodeAMutantChangesInPlaceOfMutagosDescription(t *testing.T) {
	r := newResult(summary{Total: 1, Escaped: 1}, "a.go")
	r.mutants = []mutant{{File: "a.go", Line: 1, Mutator: "expression/errorf-wrap",
		Description: "Changes: `return fmt.Errorf(\"read: %w\", err)` → `return fmt.Errorf(\"read: %v\", err)`",
		Diff:        lineDiff(`return fmt.Errorf("read: %w", err)`, `return fmt.Errorf("read: %v", err)`)}}
	want := "\n        survived: `%w` → `%v` (expression/errorf-wrap)\n"
	if got := r.render(consoleLimits, sources{}); !strings.Contains(got, want) {
		t.Errorf("render(consoleLimits) =\n%s\nwant it to contain %q", got, want)
	}
}

// lineDiff returns a diff in mutago's shape that replaces the line before
// with the line after.
func lineDiff(before, after string) string {
	return "--- Original\n+++ New\n@@ -1,1 +1,1 @@\n-" + before + "\n+" + after + "\n"
}

// The two errorf-wrap mutants downgrade different verbs and carry different
// descriptions; the two field-clear mutants drop different fields and carry
// one description.
func TestRender_TheConsoleCountsMutantsThatChangeTheSameCode(t *testing.T) {
	r := newResult(summary{Total: 4, Escaped: 4}, "a.go")
	for _, m := range []mutant{
		{Mutator: "expression/errorf-wrap", Description: "first verb",
			Diff: lineDiff(`return fmt.Errorf("%w %w", a, b)`, `return fmt.Errorf("%v %w", a, b)`)},
		{Mutator: "expression/errorf-wrap", Description: "second verb",
			Diff: lineDiff(`return fmt.Errorf("%w %w", a, b)`, `return fmt.Errorf("%w %v", a, b)`)},
		{Mutator: "composite/field-clear", Description: "Drops a keyed field",
			Diff: lineDiff(`return T{A: 1, B: 2}`, `return T{B: 2}`)},
		{Mutator: "composite/field-clear", Description: "Drops a keyed field",
			Diff: lineDiff(`return T{A: 1, B: 2}`, `return T{A: 1}`)},
	} {
		m.File, m.Line = "a.go", 1
		r.mutants = append(r.mutants, m)
	}
	want := "        survived: removes `, B: 2` (composite/field-clear)\n" +
		"        survived: removes `A: 1,` (composite/field-clear)\n" +
		"        2 survived: `%w` → `%v` (expression/errorf-wrap)\n"
	if got := r.render(consoleLimits, sources{}); !strings.Contains(got, want) {
		t.Errorf("render(consoleLimits) =\n%s\nwant it to contain\n%s", got, want)
	}
}

// A mutant that errored carries no hint, and a survivor without a kill_hint
// adds no line.
func TestRender_EndsWithTheHintOfEachMutatorOfTheSurvivorsOnce(t *testing.T) {
	r := newResult(summary{Total: 5, Escaped: 4, Errored: 1}, "a.go")
	r.mutants = []mutant{
		{File: "a.go", Line: 2, Mutator: "loop/break", KillHint: "Assert the iteration the loop stops at"},
		{File: "a.go", Line: 1, Mutator: "branch/if", KillHint: "Enter the branch"},
		{File: "a.go", Line: 3, Mutator: "branch/if", KillHint: "Enter the branch"},
		{File: "a.go", Line: 4, Mutator: "numbers/incrementer"},
		{File: "a.go", Line: 5, Mutator: "expression/remove", errored: true},
	}
	want := `  - you cannot tell: report it as unresolved
Hints for a test that kills a mutant, by mutator:
  branch/if: Enter the branch
  loop/break: Assert the iteration the loop stops at
Report each errored mutant as unresolved`
	if got := r.render(consoleLimits, sources{}); !strings.Contains(got, want) {
		t.Errorf("render(consoleLimits) =\n%s\nwant it to contain\n%s", got, want)
	}
}

// mutago v2.10.40 asks for a side effect, while the mutator replaces an
// operand of && or ||.
func TestRender_ReplacesTheHintOfExpressionRemove(t *testing.T) {
	r := newResult(summary{Total: 1, Escaped: 1}, "a.go")
	r.mutants = []mutant{{File: "a.go", Line: 1, Mutator: "expression/remove",
		KillHint: "Write a test that asserts the side effect or state change this expression produces"}}
	want := "\n  expression/remove: Write a test in which this operand alone decides the condition: " +
		"it is false and the other operands of && are true, or it is true and the other operands of || are false\n"
	if got := r.render(consoleLimits, sources{}); !strings.Contains(got, want) {
		t.Errorf("render(consoleLimits) =\n%s\nwant it to contain %q", got, want)
	}
}

// The three mutants replace names that share their first 50 characters; two
// of them replace it with x, and the console prints those two the same way.
func TestRender_TheConsoleCountsMutantsThatPrintTheSameWayOnceCut(t *testing.T) {
	prefix := strings.Repeat("p", 50)
	r := newResult(summary{Total: 3, Escaped: 3}, "a.go")
	for _, m := range []mutant{
		{Diff: lineDiff("v = "+prefix+"a", "v = x")},
		{Diff: lineDiff("v = "+prefix+"b", "v = y")},
		{Diff: lineDiff("v = "+prefix+"c", "v = x")},
	} {
		m.File, m.Line, m.Mutator = "a.go", 1, "m"
		r.mutants = append(r.mutants, m)
	}
	want := "        2 survived: `" + prefix + "...` → `x` (m)\n" +
		"        survived: `" + prefix + "...` → `y` (m)\n"
	if got := r.render(consoleLimits, sources{}); !strings.Contains(got, want) {
		t.Errorf("render(consoleLimits) =\n%s\nwant it to contain\n%s", got, want)
	}
}

// An errored mutant has no diff, so the file has nothing for the note about
// mutago's diffs to explain; TestRender_TheFileAddsEachMutantsDiff shows the
// note above a diff.
func TestRender_TheFileOmitsTheNoteOnDiffsWhenNoMutantHasOne(t *testing.T) {
	r := newResult(summary{Total: 1, Errored: 1}, "a.go")
	r.mutants = []mutant{{File: "a.go", Line: 1, Mutator: "branch/if", errored: true}}
	if got := r.render(noLimits, sources{}); strings.Contains(got, "mutago prints each diff") {
		t.Errorf("render(noLimits) =\n%s\nwant no note on diffs", got)
	}
}
