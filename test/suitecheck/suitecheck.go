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

// Package suitecheck makes a testify suite binary run with
// SUITE_REQUIRE_CHECKS=true fail a run in which no test of the suite ran to
// the end. A Go test binary exits 0 when its -test.run pattern selects no
// test, and when every test it selects skips; a suite binary that uses this
// package exits 1 instead and prints how to select a test that runs.
//
// The suite embeds [Suite] in place of suite.Suite, and the TestMain of its
// package calls [Main].
package suitecheck

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/suite"
)

// requireEnv names the environment variable that, set to "true", makes [Main]
// fail a run in which no test of the suite ran to the end. The test-stand
// chart sets it for the suite Job.
const requireEnv = "SUITE_REQUIRE_CHECKS"

// Names are the words of a suite that the hint of [Main] uses.
type Names struct {
	// Suite is the test function that runs the suite, such as TestRuntimeSuite.
	Suite string
	// Unit is what the suite calls a test that [Suite] records, a subtest or
	// a method without subtests, such as step or case.
	Unit string
	// Example is a -test.run pattern that selects a Unit of the suite that
	// does not skip.
	Example string
}

// checks is the count every [Suite] of the binary records and [Main] reads.
var checks count

// count counts the tests of a suite that ran without skipping and the ones
// that skipped.
type count struct {
	ran     int
	skipped int
	// firstSkipped is the full name of the first test that skipped.
	firstSkipped string
}

func (c *count) record(t *testing.T) {
	if t.Skipped() {
		c.skipped++
		if c.firstSkipped == "" {
			c.firstSkipped = t.Name()
		}
		return
	}
	c.ran++
}

// Suite is embedded in a testify suite in place of suite.Suite and records
// each test of the suite that called no Run of its own: a subtest, or a method
// without subtests. A method that runs subtests is not recorded itself, and
// neither is a subtest that -test.run filters out, since it never runs.
//
// A suite that defines BeforeTest or AfterTest of its own has to call the
// embedded Suite's, which it otherwise hides from testify. The suite runs its
// tests one at a time, which the unguarded state relies on.
type Suite struct {
	suite.Suite
	// calledRun reports whether the test that is running has called Run.
	calledRun bool
}

// Run runs subtest as a subtest named name, as [suite.Suite.Run] does, and
// records it when subtest calls no Run of its own.
func (s *Suite) Run(name string, subtest func()) bool {
	s.calledRun = true
	return s.Suite.Run(name, func() {
		s.calledRun = false
		// Deferred, so that a subtest that skips or fails, which ends its
		// goroutine, is recorded too.
		defer func() {
			if !s.calledRun {
				checks.record(s.T())
			}
			// The test that called this Run is not recorded itself.
			s.calledRun = true
		}()
		subtest()
	})
}

// BeforeTest implements [suite.BeforeTest]: the method about to run has called
// no Run yet.
func (s *Suite) BeforeTest(_, _ string) {
	s.calledRun = false
}

// AfterTest implements [suite.AfterTest] and records the method when it called
// no Run. Testify calls it after a method that skipped or failed as well.
func (s *Suite) AfterTest(_, _ string) {
	if !s.calledRun {
		checks.record(s.T())
	}
}

// Main runs the tests of m and exits with their exit code. Where
// SUITE_REQUIRE_CHECKS is "true", the tests passed, and no test of a [Suite]
// ran to the end, it prints to standard error why the run checked nothing and
// how to select a test, in the words of names, and exits 1.
func Main(m *testing.M, names Names) {
	// checks is read only after m.Run has recorded into it.
	code := m.Run()
	code, hint := verdict(code, os.Getenv(requireEnv) == "true", checks, names,
		flag.Lookup("test.run").Value.String(), flag.Lookup("test.skip").Value.String())
	_, _ = os.Stderr.WriteString(hint)
	os.Exit(code)
}

// verdict returns the exit code of the binary and the hint to print before it
// exits. code is the exit code of m.Run, and run and skip are the values of
// -test.run and -test.skip. Where required is true, code is 0, and c holds no
// test that ran to the end, exit is 1 and hint says why the run checked nothing
// and how to select a test. Otherwise exit is code and hint is empty.
func verdict(code int, required bool, c count, n Names, run, skip string) (exit int, hint string) {
	if code != 0 || !required || c.ran > 0 {
		return code, ""
	}
	selection := fmt.Sprintf(`-test.run "%s"`, run)
	if skip != "" {
		selection += fmt.Sprintf(` with -test.skip "%s"`, skip)
	}
	hint = fmt.Sprintf("%s checked nothing: no %s ran to the end, and %s=true fails such a run.\n", n.Suite, n.Unit, requireEnv)
	if c.skipped == 0 {
		hint += fmt.Sprintf("%s selects no %s of %s.\n", selection, n.Unit, n.Suite)
	} else {
		hint += fmt.Sprintf("Every %s that %s selects skipped: %d in all, the first being %s.\n", n.Unit, selection, c.skipped, c.firstSkipped) +
			"Under -test.v, each --- SKIP line gives its reason.\n"
	}
	return 1, hint +
		fmt.Sprintf("Correct the pattern so that it selects a %s of %s that does not skip, such as %s.\n", n.Unit, n.Suite, n.Example) +
		fmt.Sprintf("A part after the method name, if the pattern has one, has to match a %s of that method.\n", n.Unit) +
		"The Troubleshooting section of docs/local-integration-tests.md shows where each stand sets the pattern.\n"
}
