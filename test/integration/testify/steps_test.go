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
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

type probeSuite struct {
	suite.Suite
}

func newProbeSuite(t *testing.T) *probeSuite {
	p := new(probeSuite)
	p.SetT(t)
	return p
}

// failedRun reports every subtest as failed without running it.
type failedRun struct {
	t *testing.T
}

func (f failedRun) Run(string, func()) bool { return false }

func (f failedRun) T() *testing.T { return f.t }

func TestStepLog_RecordsASkippedStepWithItsReason(t *testing.T) {
	p := newProbeSuite(t)
	var l stepLog

	l.run(p, "skipped", func() { l.skip(p.T(), "profile off") })
	l.run(p, "skipped through T", func() { p.T().Skip("no reason kept") })
	l.run(p, "passed", func() {})

	want := []stepResult{
		{Name: "skipped", Status: "SKIP", SkipReason: "profile off"},
		{Name: "skipped through T", Status: "SKIP"},
		{Name: "passed", Status: "PASS"},
	}
	if len(l.results) != len(want) {
		t.Fatalf("stepLog results = %+v, want %d entries", l.results, len(want))
	}
	for i, w := range want {
		got := l.results[i]
		if got.Name != w.Name || got.Status != w.Status || got.SkipReason != w.SkipReason {
			t.Errorf("stepLog result %d = %s %s %q, want %s %s %q",
				i, got.Name, got.Status, got.SkipReason, w.Name, w.Status, w.SkipReason)
		}
	}
}

func TestStepLog_RecordsADirectSkipWithoutAReason(t *testing.T) {
	p := newProbeSuite(t)
	var l stepLog

	r := l.run(p, "skipped", func() { p.T().Skip("skipped through T") })

	if r.Status != "SKIP" || r.SkipReason != "" {
		t.Errorf("stepLog.run() of a step that calls T().Skip = %s %q, want SKIP \"\"", r.Status, r.SkipReason)
	}
}

func TestStepLog_RecordsAFailedRunAsFail(t *testing.T) {
	var l stepLog

	r := l.run(failedRun{t}, "failed", func() {})

	if r.Status != "FAIL" {
		t.Errorf("stepLog.run() of a subtest that failed = %s, want FAIL", r.Status)
	}
}

func TestFullRunErrors_RefusesOnlyTheSkippedStep(t *testing.T) {
	results := []stepResult{
		{Name: "passed", Status: "PASS"},
		{Name: "failed", Status: "FAIL"},
		{Name: "skipped", Status: "SKIP", SkipReason: "M2M Keycloak profile not active (M2M_KEYCLOAK_PROFILE != true)"},
	}

	errs := fullRunErrors(results, catalogOf("passed", "failed", "skipped"))

	if len(errs) != 1 || !strings.Contains(errs[0], `"skipped"`) || !strings.Contains(errs[0], "M2M_KEYCLOAK_PROFILE != true") {
		t.Errorf("fullRunErrors() = %q; want one message, naming the step \"skipped\" and its reason; "+
			"the FAIL step has already failed its own subtest", errs)
	}
}

func TestFullRunErrors_NamesAStepSkippedWithoutAReason(t *testing.T) {
	errs := fullRunErrors([]stepResult{{Name: "skipped", Status: "SKIP"}}, catalogOf("skipped"))

	if len(errs) != 1 || !strings.Contains(errs[0], `"skipped"`) || !strings.Contains(errs[0], "no reason recorded") {
		t.Errorf("fullRunErrors() = %q; want one message naming the step \"skipped\" and saying no reason was recorded", errs)
	}
}

func TestFullRunErrors_RefusesAStepNeverExecuted(t *testing.T) {
	errs := fullRunErrors([]stepResult{{Name: "ran", Status: "PASS"}}, catalogOf("ran", "missing"))

	if len(errs) != 1 || !strings.Contains(errs[0], `catalog step "missing" was never executed`) {
		t.Errorf("fullRunErrors() = %q; want one message naming the step \"missing\"", errs)
	}
}

func catalogOf(names ...string) []StepEntry {
	entries := make([]StepEntry, len(names))
	for i, name := range names {
		entries[i] = StepEntry{Name: name}
	}
	return entries
}
