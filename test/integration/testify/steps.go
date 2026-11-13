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

package runtimetest

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// stepResult is the outcome recorded for one catalog step. Status is PASS,
// FAIL, or SKIP.
type stepResult struct {
	Name    string
	Status  string
	Elapsed time.Duration
	// SkipReason is the reason passed to stepLog.skip for a SKIP step, and
	// empty for a step that skipped another way.
	SkipReason string
}

// stepRunner is the part of a testify suite that stepLog.run uses.
type stepRunner interface {
	Run(name string, subtest func()) bool
	T() *testing.T
}

// stepLog records the outcome of each catalog step a run executes.
type stepLog struct {
	mu      sync.Mutex
	results []stepResult
	// skipReason stores the reason passed to skip for the running step until
	// run records it.
	skipReason string
}

// run runs fn as the subtest name of s, records its outcome, and returns it.
// A subtest that skipped is recorded as SKIP, although s.Run reports it as
// passed.
func (l *stepLog) run(s stepRunner, name string, fn func()) stepResult {
	start := time.Now()
	skipped := false
	passed := s.Run(name, func() {
		// Skip ends the subtest through runtime.Goexit, which still runs this
		// deferred call while s.T() is the subtest's.
		defer func() { skipped = s.T().Skipped() }()
		fn()
	})
	r := stepResult{Name: name, Status: "PASS", Elapsed: time.Since(start)}
	switch {
	case !passed:
		r.Status = "FAIL"
	case skipped:
		r.Status = "SKIP"
		r.SkipReason = l.skipReason
	}
	l.skipReason = ""
	l.add(r)
	return r
}

// skip skips the running step's subtest t and stores reason for run to
// record. reason says what the stand lacks, such as the environment variable
// that turns the step on.
func (l *stepLog) skip(t *testing.T, reason string) {
	t.Helper()
	l.skipReason = reason
	t.Skip(reason)
}

func (l *stepLog) add(r stepResult) {
	l.mu.Lock()
	l.results = append(l.results, r)
	l.mu.Unlock()
}

// fullRunErrors returns a message for each step of catalog that a full run
// (FULL_RUNTIME_SUITE=true) fails on: a step with no entry in results, and a
// step whose entry in results is SKIP. A step whose entry is FAIL gets no
// message here, since its own subtest has already failed.
func fullRunErrors(results []stepResult, catalog []StepEntry) []string {
	recorded := make(map[string]bool, len(results))
	for _, r := range results {
		recorded[r.Name] = true
	}
	var errs []string
	for _, e := range catalog {
		if !recorded[e.Name] {
			errs = append(errs, fmt.Sprintf("catalog step %q was never executed", e.Name))
		}
	}
	const where = "where that is an environment variable of the suite, set it in suite.env of " +
		"test/k8s/test-stand-values.yaml on kind, or on the runtime-suite service of " +
		"test/docker/compose.yaml under Docker"
	for _, r := range results {
		if r.Status != "SKIP" {
			continue
		}
		if r.SkipReason != "" {
			errs = append(errs, fmt.Sprintf("catalog step %q was skipped: %s. A full run (FULL_RUNTIME_SUITE=true) "+
				"runs every catalog step: give the stand what the reason says it lacks; %s", r.Name, r.SkipReason, where))
			continue
		}
		errs = append(errs, fmt.Sprintf("catalog step %q was skipped with no reason recorded. A full run "+
			"(FULL_RUNTIME_SUITE=true) runs every catalog step: the condition that skips it in the step's code "+
			"shows what the stand lacks; %s", r.Name, where))
	}
	return errs
}
