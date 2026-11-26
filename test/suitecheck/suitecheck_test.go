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

package suitecheck

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

// TestMain applies Main only in the processes the TestMain_ tests start, so a
// run of this package's tests does not depend on SUITE_REQUIRE_CHECKS.
func TestMain(m *testing.M) {
	if os.Getenv(fixtureEnv) != "true" {
		os.Exit(m.Run())
	}
	Main(m, Names{Suite: "TestCheckedSuiteFixture", Unit: "step", Example: "^TestCheckedSuiteFixture$/^TestOneStepRuns$"})
}

// fixtureEnv names the variable that makes TestCheckedSuiteFixture run its
// suite.
const fixtureEnv = "SUITE_CHECKS_FIXTURE"

type fixtureSuite struct {
	Suite
}

func (s *fixtureSuite) TestOneStepRuns() {
	s.Run("runs", func() {})
}

func (s *fixtureSuite) TestOneStepSkips() {
	s.Run("skips", func() { s.T().Skip("fixture step") })
}

func (s *fixtureSuite) TestNoSteps() {}

func (s *fixtureSuite) TestSkipsWithoutSteps() {
	s.T().Skip("fixture method")
}

func (s *fixtureSuite) TestNestedSteps() {
	s.Run("outer", func() {
		s.Run("inner", func() {})
	})
}

func (s *fixtureSuite) TestFailsOutsideSteps() {
	s.Run("runs", func() {})
	s.T().Fatal("fixture method")
}

// TestCheckedSuiteFixture runs fixtureSuite in the processes that the
// TestMain_ tests start.
func TestCheckedSuiteFixture(t *testing.T) {
	if os.Getenv(fixtureEnv) != "true" {
		t.Skip(fixtureEnv + " is not true; the TestMain_ tests set it for the processes they start")
	}
	suite.Run(t, new(fixtureSuite))
}

// runFixture runs this test binary with args, SUITE_CHECKS_FIXTURE=true, and
// SUITE_REQUIRE_CHECKS set to require, or unset where require is empty, and
// returns its exit code and standard error.
func runFixture(t *testing.T, require string, args []string) (int, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, requireEnv+"=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, fixtureEnv+"=true")
	if require != "" {
		cmd.Env = append(cmd.Env, requireEnv+"="+require)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, stderr.String()
	case errors.As(err, &exit):
		return exit.ExitCode(), stderr.String()
	default:
		t.Fatalf("run %s %q: %v", os.Args[0], args, err)
		return 0, ""
	}
}

// Every hint starts with hintStart and ends with hintTail, whichever branch
// verdict takes.
const (
	hintStart = "TestCheckedSuiteFixture checked nothing:"
	hintTail  = "Correct the pattern so that it selects a step of TestCheckedSuiteFixture that does not skip, such as ^TestCheckedSuiteFixture$/^TestOneStepRuns$.\n" +
		"A part after the method name, if the pattern has one, has to match a step of that method.\n" +
		"The Troubleshooting section of docs/local-integration-tests.md shows where each stand sets the pattern.\n"
)

func TestMain_PrintsNoHint(t *testing.T) {
	for _, tc := range []struct {
		name    string
		require string
		args    []string
		want    int
	}{
		{
			name:    "a step that runs passes",
			require: "true",
			args:    []string{"-test.run", "^TestCheckedSuiteFixture$/^TestOneStepRuns$"},
			want:    0,
		},
		{
			name:    "a method without steps passes",
			require: "true",
			args:    []string{"-test.run", "^TestCheckedSuiteFixture$/^TestNoSteps$"},
			want:    0,
		},
		{
			name:    "a nested step passes",
			require: "true",
			args:    []string{"-test.run", "^TestCheckedSuiteFixture$/^TestNestedSteps$"},
			want:    0,
		},
		{
			name:    "a step that runs beside one that skips passes",
			require: "true",
			args:    []string{"-test.run", "^TestCheckedSuiteFixture$/^(TestOneStepRuns|TestOneStepSkips)$"},
			want:    0,
		},
		{
			name: "a pattern that selects no test passes without SUITE_REQUIRE_CHECKS",
			args: []string{"-test.run", "^TestCheckedSuiteFixtur$"},
			want: 0,
		},
		{
			name:    "a pattern that selects no test passes with SUITE_REQUIRE_CHECKS=false",
			require: "false",
			args:    []string{"-test.run", "^TestCheckedSuiteFixtur$"},
			want:    0,
		},
		{
			name:    "a failed method whose steps the pattern filters out keeps its failure",
			require: "true",
			args:    []string{"-test.run", "^TestCheckedSuiteFixture$/^TestFailsOutsideSteps$/^typo$"},
			want:    1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, stderr := runFixture(t, tc.require, tc.args)

			if got != tc.want {
				t.Errorf("exit code of %q with %s=%q = %d, want %d; stderr:\n%s", tc.args, requireEnv, tc.require, got, tc.want, stderr)
			}
			if strings.Contains(stderr, hintStart) {
				t.Errorf("stderr of %q with %s=%q =\n%s\nwant no %q in it", tc.args, requireEnv, tc.require, stderr, hintStart)
			}
		})
	}
}

func TestMain_FailsWithAHint(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		// wantLine is the line of the hint that names the pattern.
		wantLine string
	}{
		{
			name:     "a pattern that selects no test",
			args:     []string{"-test.run", "^TestCheckedSuiteFixtur$"},
			wantLine: `-test.run "^TestCheckedSuiteFixtur$" selects no step of TestCheckedSuiteFixture.`,
		},
		{
			name:     "a method whose steps the pattern filters out",
			args:     []string{"-test.run", "^TestCheckedSuiteFixture$/^TestOneStepRuns$/^typo$"},
			wantLine: `-test.run "^TestCheckedSuiteFixture$/^TestOneStepRuns$/^typo$" selects no step of TestCheckedSuiteFixture.`,
		},
		{
			name:     "a step whose nested steps the pattern filters out",
			args:     []string{"-test.run", "^TestCheckedSuiteFixture$/^TestNestedSteps$/^outer$/^typo$"},
			wantLine: `-test.run "^TestCheckedSuiteFixture$/^TestNestedSteps$/^outer$/^typo$" selects no step of TestCheckedSuiteFixture.`,
		},
		{
			name: "a step that -test.skip filters out",
			args: []string{"-test.run", "^TestCheckedSuiteFixture$/^TestOneStepRuns$",
				"-test.skip", "^TestCheckedSuiteFixture$/^TestOneStepRuns$/^runs$"},
			wantLine: `-test.run "^TestCheckedSuiteFixture$/^TestOneStepRuns$" with -test.skip "^TestCheckedSuiteFixture$/^TestOneStepRuns$/^runs$" selects no step of TestCheckedSuiteFixture.`,
		},
		{
			name:     "a step that skips",
			args:     []string{"-test.run", "^TestCheckedSuiteFixture$/^TestOneStepSkips$"},
			wantLine: `Every step that -test.run "^TestCheckedSuiteFixture$/^TestOneStepSkips$" selects skipped: 1 in all, the first being TestCheckedSuiteFixture/TestOneStepSkips/skips.`,
		},
		{
			name:     "a step and a method without steps that skip",
			args:     []string{"-test.run", "^TestCheckedSuiteFixture$/^(TestOneStepSkips|TestSkipsWithoutSteps)$"},
			wantLine: `Every step that -test.run "^TestCheckedSuiteFixture$/^(TestOneStepSkips|TestSkipsWithoutSteps)$" selects skipped: 2 in all, the first being TestCheckedSuiteFixture/TestOneStepSkips/skips.`,
		},
		{
			name:     "a method whose steps the pattern filters out beside a method without steps that skips",
			args:     []string{"-test.run", "^TestCheckedSuiteFixture$/^(TestOneStepRuns|TestSkipsWithoutSteps)$/^typo$"},
			wantLine: `Every step that -test.run "^TestCheckedSuiteFixture$/^(TestOneStepRuns|TestSkipsWithoutSteps)$/^typo$" selects skipped: 1 in all, the first being TestCheckedSuiteFixture/TestSkipsWithoutSteps.`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, stderr := runFixture(t, "true", tc.args)

			if got != 1 {
				t.Errorf("exit code of %q with %s=true = %d, want 1; stderr:\n%s", tc.args, requireEnv, got, stderr)
			}
			for _, want := range []string{hintStart, tc.wantLine + "\n"} {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr of %q with %s=true =\n%s\nwant it to contain\n%s", tc.args, requireEnv, stderr, want)
				}
			}
			if !strings.HasSuffix(stderr, hintTail) {
				t.Errorf("stderr of %q with %s=true =\n%s\nwant it to end with\n%s", tc.args, requireEnv, stderr, hintTail)
			}
		})
	}
}

func TestVerdict_UsesTheNamesOfTheSuite(t *testing.T) {
	names := Names{Suite: "TestParitySuite", Unit: "case", Example: "^TestParitySuite$/^TestRow01ApiVersion$"}
	for _, tc := range []struct {
		name   string
		checks count
		want   string
	}{
		{
			name:   "no case selected",
			checks: count{},
			want: "TestParitySuite checked nothing: no case ran to the end, and SUITE_REQUIRE_CHECKS=true fails such a run.\n" +
				`-test.run "^TestParitySuite$/^typo$" selects no case of TestParitySuite.` + "\n" +
				"Correct the pattern so that it selects a case of TestParitySuite that does not skip, such as ^TestParitySuite$/^TestRow01ApiVersion$.\n" +
				"A part after the method name, if the pattern has one, has to match a case of that method.\n" +
				"The Troubleshooting section of docs/local-integration-tests.md shows where each stand sets the pattern.\n",
		},
		{
			name:   "every case selected skipped",
			checks: count{skipped: 2, firstSkipped: "TestParitySuite/TestRow02/a"},
			want: "TestParitySuite checked nothing: no case ran to the end, and SUITE_REQUIRE_CHECKS=true fails such a run.\n" +
				`Every case that -test.run "^TestParitySuite$/^typo$" selects skipped: 2 in all, the first being TestParitySuite/TestRow02/a.` + "\n" +
				"Under -test.v, each --- SKIP line gives its reason.\n" +
				"Correct the pattern so that it selects a case of TestParitySuite that does not skip, such as ^TestParitySuite$/^TestRow01ApiVersion$.\n" +
				"A part after the method name, if the pattern has one, has to match a case of that method.\n" +
				"The Troubleshooting section of docs/local-integration-tests.md shows where each stand sets the pattern.\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exit, hint := verdict(0, true, tc.checks, names, "^TestParitySuite$/^typo$", "")

			if exit != 1 || hint != tc.want {
				t.Errorf("verdict(0, true, %+v, %+v, ...) = %d,\n%s\nwant 1,\n%s", tc.checks, names, exit, hint, tc.want)
			}
		})
	}
}
