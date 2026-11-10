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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// limits bounds how much of a report is shown. A zero field means no bound.
type limits struct {
	files, linesPerFile, lines int
}

var (
	// consoleLimits keeps the printed report short enough to read whole; the
	// file holds the rest.
	consoleLimits = limits{files: 10, linesPerFile: 20, lines: 50}
	noLimits      = limits{}
)

// logTail is how many of mutago's last output lines a report of a run that
// did not complete shows.
const logTail = 20

// The texts of mutago's output the report reads, with erroredLine below.
// mutago v2.10.40 prints them; renovate.json keeps a mutago update from merging
// before someone checks them against the new version.
const (
	noSourceFiles  = "Could not find any suitable Go source files"
	baselineFailed = "Baseline test failed for "
	internalError  = "INTERNAL ERROR "
)

var (
	erroredLine = regexp.MustCompile(`^UNKNOWN exit code for (.+):(\d+) \(([^)]+)\)$`)
	ansiCode    = regexp.MustCompile("\x1b\\[[0-9;]*m")
)

// whatToDo tells the reader of surviving mutants how to settle each one.
const whatToDo = `For each surviving mutant, decide which case it is:
  - the tests miss behavior the change defines: add or strengthen a test through the package's interface
  - no caller can observe the difference, so the mutant is equivalent: say why in the pull request
  - you cannot tell: report it as unresolved`

// summary is the part of mutago-summary.json the report uses.
type summary struct {
	Total      int `json:"totalMutantsCount"`
	Killed     int `json:"killedCount"`
	NotCovered int `json:"notCoveredCount"`
	Escaped    int `json:"escapedCount"`
	Errored    int `json:"errorCount"`
	Skipped    int `json:"skippedCount"`
}

// mutant is a mutant the report lists: one that survived, from
// mutago-agentic.json, or one that errored, from mutago's output.
type mutant struct {
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Mutator     string   `json:"mutator"`
	Description string   `json:"description"`
	KillHint    string   `json:"kill_hint"`
	Diff        string   `json:"diff"`
	TestFiles   []string `json:"test_files"`
	errored     bool
}

// result is one mutago run as make mutation-diff started it.
type result struct {
	dir          string
	base         string
	mergeBase    string
	status       int
	diffExternal string
	changed      []string

	summary        *summary
	mutants        []mutant
	internalErrors []string
	log            []string
	noSourceFiles  bool
}

// load reads the files mutago wrote into dir. A missing summary or agentic
// report is not an error, since mutago writes them only when its run
// completes; mutago.log has to be there.
func load(dir, base, mergeBase string, status int, diffExternal string, changed []string) (*result, error) {
	r := &result{
		dir: dir, base: base, mergeBase: mergeBase, status: status,
		diffExternal: strings.TrimSpace(diffExternal), changed: changed,
	}
	var s summary
	switch err := readJSON(filepath.Join(dir, "mutago-summary.json"), &s); {
	case err == nil:
		r.summary = &s
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	var agentic struct {
		Mutants []mutant `json:"mutants"`
	}
	if err := readJSON(filepath.Join(dir, "mutago-agentic.json"), &agentic); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	r.mutants = agentic.Mutants
	data, err := os.ReadFile(filepath.Join(dir, "mutago.log"))
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		line = strings.TrimRight(ansiCode.ReplaceAllString(line, ""), " \r")
		r.log = append(r.log, line)
		if m := erroredLine.FindStringSubmatch(line); m != nil {
			n, _ := strconv.Atoi(m[2])
			r.mutants = append(r.mutants, mutant{File: m[1], Line: n, Mutator: m[3], errored: true})
		}
		if text, ok := strings.CutPrefix(line, internalError); ok {
			r.internalErrors = append(r.internalErrors, text)
		}
		if strings.Contains(line, noSourceFiles) {
			r.noSourceFiles = true
		}
	}
	return r, nil
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// outcome is what a run produced, which decides the shape of its report.
type outcome int

const (
	mutated    outcome = iota // mutago generated mutants and tested them all
	noMutant                  // mutago generated no mutant on the changed lines
	incomplete                // mutago stopped before it reported every mutant
)

func (r *result) outcome() outcome {
	switch {
	case r.noSourceFiles:
		return noMutant
	case r.summary == nil || r.status != 0 && r.status != 4:
		return incomplete
	case r.summary.Total == 0:
		return noMutant
	}
	return mutated
}

// exitStatus is 0 for a run that completed, whatever survived, and for one in
// which mutago found no built file to mutate. For a run that did not complete
// it is mutago's own status, or 3 when mutago exited 0 without a summary.
func (r *result) exitStatus() int {
	if r.outcome() != incomplete {
		return 0
	}
	if r.status != 0 {
		return r.status
	}
	return 3
}

// render returns the report, with as much of it as lim allows. Without limits
// it is the file, which adds each mutant's diff and hint and drops the pointer
// to itself.
func (r *result) render(lim limits, src sources) string {
	var b strings.Builder
	b.WriteString(r.header())
	switch r.outcome() {
	case incomplete:
		r.renderIncomplete(&b)
	case noMutant:
		r.renderNoMutant(&b)
	default:
		r.renderMutants(&b, lim, src)
	}
	r.renderNotBuilt(&b)
	b.WriteString("\n\n")
	if lim != noLimits && r.outcome() == mutated && len(r.mutants) > 0 {
		fmt.Fprintf(&b, "Full report, with each mutant's diff and a hint for the test that kills it: %s\n", path.Join(r.dir, "report.txt"))
	}
	fmt.Fprintf(&b, "mutago's output: %s\n", path.Join(r.dir, "mutago.log"))
	return b.String()
}

func (r *result) header() string {
	ref := r.base
	if r.mergeBase != "" && r.mergeBase != r.base {
		ref += " (" + shortCommit(r.mergeBase) + ")"
	}
	return "Mutation testing of changed lines against " + ref + ", packages " + strings.Join(packages(r.changed), " ") + "\n"
}

func shortCommit(c string) string {
	if len(c) > 8 {
		return c[:8]
	}
	return c
}

// packages returns the directories of the changed files, such as
// "./internal/token/verify", and "." for a file at the root.
func packages(files []string) []string {
	seen := map[string]bool{}
	var dirs []string
	for _, f := range files {
		d := path.Dir(f)
		if d != "." {
			d = "./" + d
		}
		if !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}
	sort.Strings(dirs)
	return dirs
}

func (r *result) renderIncomplete(b *strings.Builder) {
	fmt.Fprintf(b, "  the run did not complete: mutago exited with status %d\n", r.status)
	first, at := firstLine(r.log)
	if at >= 0 {
		b.WriteString("\n  " + first + "\n")
	}
	start := max(at+1, len(r.log)-logTail)
	if start > at+1 {
		b.WriteString("  ...\n")
	}
	for _, l := range r.log[start:] {
		b.WriteString("  " + l + "\n")
	}
	b.WriteString("\n")
	switch {
	case strings.HasPrefix(first, baselineFailed):
		b.WriteString("The tests of a changed package failed, or ran longer than the limit, before any mutation. " +
			"Fix them, or set MUTATION_TIMEOUT to a larger number of seconds when they only need more time.\n")
	case at < 0:
		b.WriteString("mutago printed nothing before it stopped.\n")
	default:
		b.WriteString("The first line of mutago's output gives the reason.\n")
	}
	b.WriteString("Report the run as not completed, not as one without survivors.")
}

// firstLine returns the first line of lines that is not blank, and its index,
// or "" and -1 when there is none.
func firstLine(lines []string) (string, int) {
	for i, l := range lines {
		if strings.TrimSpace(l) != "" {
			return l, i
		}
	}
	return "", -1
}

func (r *result) renderNoMutant(b *strings.Builder) {
	b.WriteString("  no mutant: mutago generated none on the changed lines")
	var built []string
	for _, f := range r.changed {
		if buildTag(f) == "" {
			built = append(built, f)
		}
	}
	if len(built) == 0 {
		return
	}
	b.WriteString("\n\n  These changed files got no mutant:\n")
	for _, f := range built {
		b.WriteString("    " + f + "\n")
	}
	b.WriteString("\n")
	if r.diffExternal != "" {
		b.WriteString(diffExternalAdvice(r.diffExternal))
		return
	}
	b.WriteString("That is expected when no enabled mutator changes the changed lines, as with comments, imports, " +
		"declarations, and number literals. No test was shown able to fail on them: say so in the pull request.")
}

// diffExternalAdvice tells the reader how to rerun without diff.external,
// from the scope and value git config --show-scope --get prints.
func diffExternalAdvice(scopeAndValue string) string {
	scope, value, _ := strings.Cut(scopeAndValue, "\t")
	step := map[string]string{
		"global":   "rerun it as GIT_CONFIG_GLOBAL=/dev/null make mutation-diff",
		"system":   "rerun it as GIT_CONFIG_NOSYSTEM=1 make mutation-diff",
		"local":    "run git config --local --unset diff.external, or rerun it from a clone without it",
		"worktree": "run git config --worktree --unset diff.external, or rerun it from a clone without it",
	}[scope]
	if step == "" {
		step = "rerun it without the setting"
	}
	return fmt.Sprintf("The %s git config sets diff.external to %q, and mutago cannot read the diff an external tool "+
		"prints, so it found no changed line. To mutate these lines, %s. Until then, report the run as not "+
		"completed.", scope, value, step)
}

// renderNotBuilt names the changed files the default build leaves out, whose
// lines mutago never sees, whatever happened to the other files.
func (r *result) renderNotBuilt(b *strings.Builder) {
	var notBuilt []string
	for _, f := range r.changed {
		if tag := buildTag(f); tag != "" {
			notBuilt = append(notBuilt, f+" ("+tag+")")
		}
	}
	if len(notBuilt) == 0 {
		return
	}
	b.WriteString("\n\nNot mutated: the default build leaves out these changed files, so mutago never saw their lines:\n")
	for _, f := range notBuilt {
		b.WriteString("  " + f + "\n")
	}
	b.WriteString("Say so in the pull request.")
}

// fileMutants is one file of the report with its lines that have a listed
// mutant.
type fileMutants struct {
	path  string
	tests []string
	lines []lineMutants
	count int
}

type lineMutants struct {
	number  int
	mutants []mutant
}

// group returns the listed mutants by file and line: the files with the most
// mutants first, then by path; the lines in order; on a line, the survivors
// before the errored ones, each by mutator, description, and diff.
func (r *result) group() []fileMutants {
	byFile := map[string]*fileMutants{}
	byLine := map[string]map[int]*lineMutants{}
	tests := map[string]map[string]struct{}{}
	for _, m := range r.mutants {
		f := byFile[m.File]
		if f == nil {
			f = &fileMutants{path: m.File}
			byFile[m.File] = f
			byLine[m.File] = map[int]*lineMutants{}
			tests[m.File] = map[string]struct{}{}
		}
		f.count++
		l := byLine[m.File][m.Line]
		if l == nil {
			l = &lineMutants{number: m.Line}
			byLine[m.File][m.Line] = l
		}
		l.mutants = append(l.mutants, m)
		for _, t := range m.TestFiles {
			tests[m.File][path.Base(t)] = struct{}{}
		}
	}
	files := make([]fileMutants, 0, len(byFile))
	for name, f := range byFile {
		for _, l := range byLine[name] {
			sort.SliceStable(l.mutants, func(i, j int) bool {
				a, b := l.mutants[i], l.mutants[j]
				if a.errored != b.errored {
					return !a.errored
				}
				if a.Mutator != b.Mutator {
					return a.Mutator < b.Mutator
				}
				if a.Description != b.Description {
					return a.Description < b.Description
				}
				return a.Diff < b.Diff
			})
			f.lines = append(f.lines, *l)
		}
		sort.Slice(f.lines, func(i, j int) bool { return f.lines[i].number < f.lines[j].number })
		for t := range tests[name] {
			f.tests = append(f.tests, t)
		}
		sort.Strings(f.tests)
		files = append(files, *f)
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].count != files[j].count {
			return files[i].count > files[j].count
		}
		return files[i].path < files[j].path
	})
	return files
}

func (r *result) renderMutants(b *strings.Builder, lim limits, src sources) {
	s := r.summary
	parts := []string{
		fmt.Sprintf("%d killed", s.Killed),
		fmt.Sprintf("%d survived", s.Escaped),
		fmt.Sprintf("%d errored", s.Errored),
	}
	if s.NotCovered > 0 {
		parts = append(parts, fmt.Sprintf("%d not covered", s.NotCovered))
	}
	if s.Skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped", s.Skipped))
	}
	fmt.Fprintf(b, "  %d %s: %s\n", s.Total, plural(s.Total, "mutant", "mutants"), strings.Join(parts, ", "))
	files := r.group()
	switch {
	case len(files) > 0 || len(r.internalErrors) > 0:
		renderFiles(b, files, r.internalErrors, lim, src)
	case s.Escaped+s.Errored+s.NotCovered == 0:
		b.WriteString("\nNo mutant on the changed lines survived.")
		return
	default:
		b.WriteString("\nmutago's files place none of the mutants these counts include; mutago.log lists them.\n\n")
	}
	if s.Escaped > 0 {
		b.WriteString(whatToDo + "\n")
	}
	if s.Errored > 0 {
		b.WriteString("Report each errored mutant as unresolved: no test was shown able to kill it.\n")
	}
	b.WriteString("Quote the counts above in the pull request.")
}

// renderFiles writes the listed mutants by file and line, with as many of them
// as lim allows, and their totals.
func renderFiles(b *strings.Builder, files []fileMutants, internalErrors []string, lim limits, src sources) {
	b.WriteString("  ordered by listed mutants per file, then by line\n")
	full := lim == noLimits
	rowsLeft, shownFiles, lines := lim.lines, 0, 0
	for _, f := range files {
		lines += len(f.lines)
		if !full && (shownFiles == lim.files || rowsLeft == 0) {
			continue
		}
		shownFiles++
		b.WriteString("\n  " + f.path)
		if len(f.tests) > 0 {
			b.WriteString(" (tests of the package: " + strings.Join(f.tests, ", ") + ")")
		}
		b.WriteString("\n")
		source := src.get(f.path)
		allowed := len(f.lines)
		if !full {
			allowed = min(allowed, lim.linesPerFile, rowsLeft)
			rowsLeft -= allowed
		}
		for _, l := range f.lines[:allowed] {
			renderLine(b, l, source, full)
		}
		if more := len(f.lines) - allowed; more > 0 {
			fmt.Fprintf(b, "    %d more %s\n", more, plural(more, "line", "lines"))
		}
	}
	if more := len(files) - shownFiles; more > 0 {
		fmt.Fprintf(b, "\n  %d more %s\n", more, plural(more, "file", "files"))
	}
	for _, e := range internalErrors {
		b.WriteString("\n  errored without a line: " + e + "\n")
	}
	fmt.Fprintf(b, "\nListed mutants on %d %s in %d %s.\n\n", lines, plural(lines, "line", "lines"), len(files), plural(len(files), "file", "files"))
}

// renderLine writes one line of a report and its mutants. The console
// prints mutants of one kind on the line once, with their number; the file
// prints each, with its hint and diff.
func renderLine(b *strings.Builder, l lineMutants, source sourceFile, full bool) {
	fmt.Fprintf(b, "    %d: %s\n", l.number, source.line(l.number))
	in := ""
	if fn := source.function(l.number); fn != "" {
		in = ", in " + fn
	}
	for i := 0; i < len(l.mutants); {
		m := l.mutants[i]
		same := 1
		for !full && i+same < len(l.mutants) && sameKind(m, l.mutants[i+same]) {
			same++
		}
		i += same
		status := "survived"
		if m.errored {
			status = "errored"
		}
		if same > 1 {
			status = fmt.Sprintf("%d %s", same, status)
		}
		what := m.Mutator
		if desc := m.Description; desc != "" {
			if !full {
				desc = cut(desc)
			}
			what = desc + " (" + m.Mutator + ")"
		}
		fmt.Fprintf(b, "        %s: %s%s\n", status, what, in)
		if !full {
			continue
		}
		if m.KillHint != "" {
			b.WriteString("          hint: " + m.KillHint + "\n")
		}
		for _, d := range strings.Split(strings.TrimRight(m.Diff, "\n"), "\n") {
			if d != "" {
				b.WriteString("          " + d + "\n")
			}
		}
	}
}

// sameKind reports whether two mutants of one line print the same way.
func sameKind(a, b mutant) bool {
	return a.errored == b.errored && a.Mutator == b.Mutator && a.Description == b.Description
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
