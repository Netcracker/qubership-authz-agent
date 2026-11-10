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
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
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

// hintFixes replaces the kill hints of mutago v2.10.40 that misdescribe their
// mutator. The hint of expression/remove asks for a side effect, while the
// mutator replaces an operand of && with true or of || with false
// (quality-gates/mutago#369).
var hintFixes = map[string]string{
	"expression/remove": "Write a test in which this operand alone decides the condition: " +
		"it is false and the other operands of && are true, or it is true and the other operands of || are false",
}

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
	// change is the code the mutant changes, as changeOf finds it in Diff,
	// or nil when Diff shows none. group sets it on the mutants it returns,
	// not on those of result.mutants.
	change *change
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

// outcome returns what r produced. mutago v2.10.40 exits 0 for a run that
// completed, or 4 when a mutant of it survived.
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
// it is the file, which adds each mutant's diff and drops the pointer to
// itself.
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
		fmt.Fprintf(&b, "Full report, with each mutant's diff: %s\n", path.Join(r.dir, "report.txt"))
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
// mutant, and the test files of its package when it is the first file of
// that package in the report.
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
// before the errored ones, each by mutator, the text that describes it, and
// diff. The first file of each package carries the test files of the
// package's mutants.
func (r *result) group() []fileMutants {
	byFile := map[string]*fileBuilder{}
	tests := map[string]map[string]struct{}{}
	for _, m := range r.mutants {
		f := byFile[m.File]
		if f == nil {
			f = &fileBuilder{lines: map[int]*lineMutants{}}
			byFile[m.File] = f
		}
		f.add(m)
		dir := path.Dir(m.File)
		if tests[dir] == nil {
			tests[dir] = map[string]struct{}{}
		}
		for _, t := range m.TestFiles {
			tests[dir][path.Base(t)] = struct{}{}
		}
	}
	files := make([]fileMutants, 0, len(byFile))
	for name, f := range byFile {
		files = append(files, f.build(name))
	}
	slices.SortFunc(files, compareFiles)
	for i := range files {
		dir := path.Dir(files[i].path)
		for t := range tests[dir] {
			files[i].tests = append(files[i].tests, t)
		}
		sort.Strings(files[i].tests)
		delete(tests, dir)
	}
	return files
}

// fileBuilder collects the mutants of one file for group.
type fileBuilder struct {
	lines map[int]*lineMutants
	count int
}

func (f *fileBuilder) add(m mutant) {
	f.count++
	l := f.lines[m.Line]
	if l == nil {
		l = &lineMutants{number: m.Line}
		f.lines[m.Line] = l
	}
	if c, ok := changeOf(m.Diff); ok {
		m.change = &c
	}
	l.mutants = append(l.mutants, m)
}

// build returns the file named name with its lines in order.
func (f *fileBuilder) build(name string) fileMutants {
	out := fileMutants{path: name, count: f.count}
	for _, l := range f.lines {
		slices.SortStableFunc(l.mutants, compareMutants)
		out.lines = append(out.lines, *l)
	}
	slices.SortFunc(out.lines, func(a, b lineMutants) int { return cmp.Compare(a.number, b.number) })
	return out
}

// compareMutants orders the mutants of one line: the survivors before the
// errored ones, then by mutator, by the text the console prints for them, and
// by diff, so that the mutants the console counts together are adjacent.
func compareMutants(a, b mutant) int {
	return cmp.Or(cmp.Compare(errorRank(a), errorRank(b)), strings.Compare(a.Mutator, b.Mutator),
		strings.Compare(a.text(false), b.text(false)), strings.Compare(a.Diff, b.Diff))
}

// errorRank is 1 for a mutant that errored and 0 for one that survived.
func errorRank(m mutant) int {
	if m.errored {
		return 1
	}
	return 0
}

// compareFiles orders the files of a report: the most mutants first, then by
// path.
func compareFiles(a, b fileMutants) int {
	return cmp.Or(cmp.Compare(b.count, a.count), strings.Compare(a.path, b.path))
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
		r.renderHints(b)
	}
	if s.Errored > 0 {
		b.WriteString("Report each errored mutant as unresolved: no test was shown able to kill it.\n")
	}
	b.WriteString("Quote the counts above in the pull request.")
}

// renderFiles writes the listed mutants by file and line, with as many of them
// as lim allows, and their totals. Without limits, a note on mutago's diffs
// precedes them when a mutant has one.
func renderFiles(b *strings.Builder, files []fileMutants, internalErrors []string, lim limits, src sources) {
	b.WriteString("  ordered by listed mutants per file, then by line\n")
	full := lim == noLimits
	if full && slices.ContainsFunc(files, hasDiff) {
		b.WriteString("  mutago prints each diff from the syntax node it mutated: a diff can span more lines than the " +
			"change, and its added lines can lose the file's indentation (quality-gates/mutago#354)\n")
	}
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
// prints mutants that print the same way once, with their number; the file
// prints each, with its diff.
func renderLine(b *strings.Builder, l lineMutants, source sourceFile, full bool) {
	fmt.Fprintf(b, "    %d: %s\n", l.number, source.line(l.number))
	in := ""
	if fn := source.function(l.number); fn != "" {
		in = ", in " + fn
	}
	for i := 0; i < len(l.mutants); {
		m, same := l.mutants[i], 1
		if !full {
			same = runLength(l.mutants[i:])
		}
		i += same
		fmt.Fprintf(b, "        %s: %s%s\n", statusWord(m, same), describe(m, full), in)
		if full {
			renderDetails(b, m)
		}
	}
}

// runLength returns how many mutants at the start of ms print the same way as
// the first of them.
func runLength(ms []mutant) int {
	n := 1
	for n < len(ms) && sameKind(ms[0], ms[n]) {
		n++
	}
	return n
}

// statusWord returns "survived" or "errored" for m, after their number n when
// more than one of them print the same way.
func statusWord(m mutant, n int) string {
	word := "survived"
	if m.errored {
		word = "errored"
	}
	if n > 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return word
}

// describe returns what m changes and its mutator.
func describe(m mutant, full bool) string {
	text := m.text(full)
	if text == "" {
		return m.Mutator
	}
	return text + " (" + m.Mutator + ")"
}

// text returns what m changes: the code from its diff, or mutago's
// description when the diff shows none. Unless full is set, the text is cut.
//
// mutago's description is the whole line before and after when the diff
// replaces one line, and the mutator's general text otherwise, which for
// expression/remove names a different mutation (quality-gates/mutago#369).
func (m mutant) text(full bool) string {
	switch {
	case m.change != nil:
		return m.change.label(full)
	case full:
		return m.Description
	}
	return cut(m.Description, maxSourceRunes)
}

// renderDetails writes the diff of m, which only the file shows.
func renderDetails(b *strings.Builder, m mutant) {
	for _, d := range strings.Split(strings.TrimRight(m.Diff, "\n"), "\n") {
		if d != "" {
			b.WriteString("          " + d + "\n")
		}
	}
}

// sameKind reports whether two mutants of one line print the same way on the
// console.
func sameKind(a, b mutant) bool {
	return a.errored == b.errored && a.Mutator == b.Mutator && a.text(false) == b.text(false)
}

// hasDiff reports whether a mutant of f has a diff; one that errored has none.
func hasDiff(f fileMutants) bool {
	for _, l := range f.lines {
		if slices.ContainsFunc(l.mutants, func(m mutant) bool { return m.Diff != "" }) {
			return true
		}
	}
	return false
}

// renderHints writes the kill hint of each mutator of the survivors once, in
// the order of the mutators' names, taking it from hintFixes where that has
// one.
func (r *result) renderHints(b *strings.Builder) {
	hints := map[string]string{}
	for _, m := range r.mutants {
		if hint := cmp.Or(hintFixes[m.Mutator], m.KillHint); !m.errored && hint != "" {
			hints[m.Mutator] = hint
		}
	}
	if len(hints) == 0 {
		return
	}
	b.WriteString("Hints for a test that kills a mutant, by mutator:\n")
	for _, name := range slices.Sorted(maps.Keys(hints)) {
		b.WriteString("  " + name + ": " + hints[name] + "\n")
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
