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
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_WritesTheWholeReportAndPrintsTheShortOne(t *testing.T) {
	dir := writeRun(t,
		`{"totalMutantsCount":1,"escapedCount":1}`,
		`{"mutants":[{"file":"a.go","line":1,"mutator":"branch/if","kill_hint":"Write a test"}]}`,
		"ESCAPED a.go:1 (branch/if)\n")
	var stdout, stderr bytes.Buffer
	status := run([]string{"-dir", dir, "-base", "origin/main", "-merge-base", "abc", "-status", "4", "a.go"}, &stdout, &stderr)
	if status != 0 {
		t.Errorf("run() = %d, want 0 for a completed run; stderr: %s", status, stderr.String())
	}
	report, err := os.ReadFile(filepath.Join(dir, "report.txt"))
	if err != nil {
		t.Fatalf("report.txt: %v", err)
	}
	if !strings.Contains(string(report), "hint: Write a test") {
		t.Errorf("report.txt =\n%s\nwant the mutant's hint", report)
	}
	if !strings.Contains(stdout.String(), "Full report, with each mutant's diff") || strings.Contains(stdout.String(), "hint:") {
		t.Errorf("stdout =\n%s\nwant the short report, which points to the file", stdout.String())
	}
}

// failingWriter fails every write, as a closed pipe does.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("broken pipe")
}

func TestRun_ReturnsTwoWhenTheReportCannotBePrinted(t *testing.T) {
	dir := writeRun(t, `{"totalMutantsCount":1,"killedCount":1}`, "", "x\n")
	var stderr bytes.Buffer
	if status := run([]string{"-dir", dir, "-base", "origin/main", "-status", "0", "a.go"}, failingWriter{}, &stderr); status != 2 {
		t.Errorf("run() = %d, want 2", status)
	}
	if !strings.Contains(stderr.String(), "broken pipe") {
		t.Errorf("stderr = %q, want the write error", stderr.String())
	}
}

func TestRun_ReturnsMutagosStatusForARunThatDidNotComplete(t *testing.T) {
	dir := writeRun(t, "", "", "Cannot load git diff: exit status 128\n")
	var stdout, stderr bytes.Buffer
	if status := run([]string{"-dir", dir, "-base", "nosuchref", "-status", "3", "a.go"}, &stdout, &stderr); status != 3 {
		t.Errorf("run() = %d, want 3; stdout:\n%s", status, stdout.String())
	}
}

func TestRun_ReturnsTwoForAUsageOrFileError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no flags", nil, "-dir, -base, and -status are required"},
		{"no -dir", []string{"-base", "origin/main", "-status", "0"}, "-dir, -base, and -status are required"},
		{"no -base", []string{"-dir", missing, "-status", "0"}, "-dir, -base, and -status are required"},
		{"no -status", []string{"-dir", missing, "-base", "origin/main"}, "-dir, -base, and -status are required"},
		{"unknown flag", []string{"-dir", writeRun(t, "", "", "x\n"), "-base", "origin/main", "-status", "0", "-colour"}, "flag provided but not defined"},
		{"no mutago.log", []string{"-dir", missing, "-base", "origin/main", "-status", "0"}, "mutago.log"},
		{"report not writable", []string{"-dir", writeRunWithoutRoomForTheReport(t), "-base", "origin/main", "-status", "0"}, "report.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if status := run(tt.args, &stdout, &stderr); status != 2 {
				t.Errorf("run(%q) = %d, want 2", tt.args, status)
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("run(%q) stderr = %q, want it to contain %q", tt.args, stderr.String(), tt.want)
			}
		})
	}
}

// writeRunWithoutRoomForTheReport returns a directory with mutago.log in which
// report.txt cannot be written, because a directory of that name is there.
func writeRunWithoutRoomForTheReport(t *testing.T) string {
	t.Helper()
	dir := writeRun(t, "", "", "x\n")
	if err := os.Mkdir(filepath.Join(dir, "report.txt"), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The test runs its own binary again, which then calls main with no flags:
// main exits with the status run returns.
func TestMain_ExitsWithTheStatusRunReturns(t *testing.T) {
	if os.Getenv("MUTATION_REPORT_MAIN") == "1" {
		os.Args = []string{"mutation-report"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMain_ExitsWithTheStatusRunReturns$")
	cmd.Env = append(os.Environ(), "MUTATION_REPORT_MAIN=1")
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 {
		t.Errorf("main() with no flags ended with %v, want exit status 2", err)
	}
}
