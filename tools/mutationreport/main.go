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

// Mutation-report prints the result of a mutago run for make mutation-diff:
// each changed line with a mutant that no test killed, grouped by file, and
// what to do about it. It reads mutago-agentic.json, mutago-summary.json, and
// mutago.log from the directory -dir names, writes the whole report there as
// report.txt, and prints a shorter one.
//
// It exits 0 when mutago completed its run, with or without survivors, or
// found no built file to mutate; with mutago's own exit status when the run
// did not complete, or 3 when mutago exited 0 without its summary; and 2 on a
// usage error or a file it cannot read or write.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main with its arguments and output streams passed in; it returns the
// exit status.
func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mutation-report", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", "", "directory that holds mutago's files and receives report.txt")
	base := flags.String("base", "", "the ref the diff starts from, as MUTATION_BASE names it")
	mergeBase := flags.String("merge-base", "", "the commit the diff starts from")
	status := flags.Int("status", -1, "mutago's exit status")
	diffExternal := flags.String("diff-external", "", "the output of git config --show-scope --get diff.external")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *dir == "" || *base == "" || *status < 0 {
		_, _ = fmt.Fprintln(stderr, "mutation-report: -dir, -base, and -status are required; the changed files follow the flags")
		return 2
	}
	r, err := load(*dir, *base, *mergeBase, *status, *diffExternal, flags.Args())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mutation-report: %v\n", err)
		return 2
	}
	sources := newSources()
	if err := os.WriteFile(filepath.Join(*dir, "report.txt"), []byte(r.render(noLimits, sources)), 0o644); err != nil {
		_, _ = fmt.Fprintf(stderr, "mutation-report: %v\n", err)
		return 2
	}
	if _, err := fmt.Fprint(stdout, r.render(consoleLimits, sources)); err != nil {
		_, _ = fmt.Fprintf(stderr, "mutation-report: %v\n", err)
		return 2
	}
	return r.exitStatus()
}
