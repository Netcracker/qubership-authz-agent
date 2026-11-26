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

// Package costcheck holds test helpers for the cost rule of AGENTS.md: input
// too big or too deep fails its request or load, not the process.
//
// Only tests import it.
package costcheck

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

// childEnv names the test a child copy of the test binary runs the act of.
const childEnv = "COSTCHECK_CHILD"

// childDone is the line a child prints once the act has returned. A child that
// exits with status 0 and does not print it ran no act, such as when the
// -test.run pattern matched no test.
const childDone = "costcheck: act returned"

// MaxStack is the goroutine stack limit of a child, 64 MiB (67108864 bytes).
// It is small enough that an unbounded recursion overflows it within a second
// and large enough for a parser whose depth limit is jsonvalue.MaxDepth.
const MaxStack = 64 << 20

// childTimeout bounds one child run.
const childTimeout = 2 * time.Minute

// Run is the outcome of an act run in a child process.
type Run struct {
	// Crashed reports that the child exited with a non-zero status: a fatal
	// error such as a stack overflow, a panic, a call to os.Exit with a
	// non-zero code, or a failure that act reported through t.
	Crashed bool
	// Output is what the child printed to stdout and stderr.
	Output string
}

// InSubprocess runs act in a child copy of the test binary whose goroutine
// stack is limited to maxStack bytes, so that a crash fails the calling test
// instead of killing the test binary.
//
// The child runs the calling test again, and InSubprocess calls act only
// there; in the parent it starts the child and returns its outcome, and act
// is not called. In the child InSubprocess does not return: the test ends
// after act. So everything the calling test does before InSubprocess must be
// deterministic and free of side effects outside the process. A test calls
// InSubprocess at most once: the child is selected by the name of the test,
// so a second call would run the act of the first one again. A failure
// that act reports through t in the child, such as t.Errorf, fails the child
// test and is returned as a crash, with the report in [Run.Output].
func InSubprocess(t *testing.T, maxStack int, act func()) Run {
	t.Helper()
	if os.Getenv(childEnv) == t.Name() {
		debug.SetMaxStack(maxStack)
		act()
		fmt.Println(childDone)
		// The rest of the calling test belongs to the parent. SkipNow keeps a
		// failure that act reported.
		t.SkipNow()
	}
	ctx, cancel := context.WithTimeout(t.Context(), childTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run="+runPattern(t.Name()), "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"="+t.Name())
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("child run of %s did not finish within %v; output:\n%s", t.Name(), childTimeout, out.String())
	}
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatalf("start a child run of %s: %v", t.Name(), err)
	}
	if err == nil && !strings.Contains(out.String(), childDone) {
		t.Fatalf("child run of %s exited with status 0 and never ran the act; output:\n%s", t.Name(), out.String())
	}
	return Run{Crashed: err != nil, Output: out.String()}
}

// runPattern returns the -test.run pattern that selects exactly the test or
// subtest named name.
func runPattern(name string) string {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		parts[i] = "^" + regexp.QuoteMeta(p) + "$"
	}
	return strings.Join(parts, "/")
}

// Known is an entry of a list of known violations: a case that still kills
// the process. The zero Known is no entry.
type Known struct {
	// Finding is the id of the finding and a phrase that states the defect.
	Finding string
	// Frame is part of the name of a function on the stack of the crash, such
	// as regogen.(*rsqlParser). A crash whose innermost frames do not name it
	// is another defect, not this violation.
	Frame string
}

// Deep runs act, which feeds input nested far deeper than any limit, in a
// child process with the stack limited to [MaxStack], and fails t when the
// child crashes.
//
// For a case on the list of known violations, known is its entry, and the
// roles swap: a crash in known.Frame is logged, and a run that survives fails
// t, so that the fix also deletes the entry from the list.
func Deep(t *testing.T, known Known, act func()) {
	t.Helper()
	failed, report := verdict(t.Name(), InSubprocess(t, MaxStack, act), known)
	switch {
	case failed:
		t.Error(report)
	case report != "":
		t.Log(report)
	}
}

// verdict returns whether the run r of the case name fails the check, and
// the report to print, "" for a case that survives and is no known violation.
func verdict(name string, r Run, known Known) (failed bool, report string) {
	ex := Excerpt(r.Output)
	switch {
	case r.Crashed && known.Finding == "":
		return true, "input nested deep killed the process instead of failing the request or load:\n" + ex
	case r.Crashed && !strings.Contains(ex, known.Frame):
		return true, fmt.Sprintf("input nested deep killed the process outside %s, where the known violation %s crashes:\n%s",
			known.Frame, known.Finding, ex)
	case r.Crashed:
		return false, fmt.Sprintf("known violation %s:\n%s", known.Finding, ex)
	case known.Finding != "":
		return true, fmt.Sprintf("input nested deep no longer kills the process: delete the entry for %s from the list of known violations (%s)",
			name, known.Finding)
	}
	return false, ""
}

// excerptFrames is how many stack frames [Excerpt] keeps.
const excerptFrames = 12

// Excerpt returns the part of a child's output that names the crash. For a
// fatal error or a panic it is the error line and the function names of the
// innermost frames of the goroutine that crashed, which name the functions
// that recursed, even where the test printed its --- FAIL line first, as it
// does for a panic on its own goroutine. For a test that failed without
// either, it is the failure report. With none of these, it is the whole
// output.
func Excerpt(output string) string {
	lines := strings.Split(output, "\n")
	for i, l := range lines {
		if !strings.HasPrefix(l, "fatal error:") && !strings.HasPrefix(l, "panic:") {
			continue
		}
		out := []string{l}
		frames := false
		for _, f := range lines[i+1:] {
			switch {
			case strings.HasPrefix(f, "goroutine "):
				frames = true
			case frames && f == "":
				return strings.Join(out, "\n")
			case frames && !strings.HasPrefix(f, "\t"):
				out = append(out, "  "+f[:strings.LastIndexByte(f, '(')+1]+"…)")
				if len(out) > excerptFrames {
					return strings.Join(out, "\n")
				}
			}
		}
		return strings.Join(out, "\n")
	}
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "--- FAIL:") {
			return strings.Join(lines[max(0, i-excerptFrames):i+1], "\n")
		}
	}
	return output
}
