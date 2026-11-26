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

package costcheck

import (
	"strings"
	"testing"
)

// nest returns the depth of a string of n opening brackets, read by
// recursive descent, or -1 once the depth passes limit. A negative limit
// leaves the depth unbounded.
func nest(s string, limit int) int {
	if s == "" || s[0] != '(' {
		return 0
	}
	if limit == 0 {
		return -1
	}
	d := nest(s[1:], limit-1)
	if d < 0 {
		return -1
	}
	return d + 1
}

func TestInSubprocessReportsAStackOverflowAsACrash(t *testing.T) {
	deep := strings.Repeat("(", 1<<20)
	r := InSubprocess(t, 1<<20, func() { t.Logf("depth %d", nest(deep, -1)) })
	if !r.Crashed {
		t.Fatalf("an unbounded recursion over %d brackets: Crashed = false, want true; output:\n%s", len(deep), r.Output)
	}
	if ex := Excerpt(r.Output); !strings.Contains(ex, "stack overflow") || !strings.Contains(ex, "costcheck.nest") {
		t.Errorf("Excerpt(output) = %q, want the stack overflow and the frame of costcheck.nest", ex)
	}
}

func TestInSubprocessReportsAnActThatReturnsAsSurviving(t *testing.T) {
	deep := strings.Repeat("(", 1<<20)
	r := InSubprocess(t, MaxStack, func() {
		if d := nest(deep, 1000); d != -1 {
			t.Errorf("nest(%d brackets, limit 1000) = %d, want -1", len(deep), d)
		}
	})
	if r.Crashed {
		t.Fatalf("a recursion bounded at depth 1000: Crashed = true, want false; output:\n%s", r.Output)
	}
}

func TestInSubprocessReportsAFailedAssertionInTheChildAsACrash(t *testing.T) {
	r := InSubprocess(t, MaxStack, func() { t.Error("deliberate failure in the child") })
	if !r.Crashed || !strings.Contains(r.Output, "deliberate failure in the child") {
		t.Errorf("a child whose act calls t.Error: Crashed = %v, want true, and the output should carry the message; output:\n%s",
			r.Crashed, r.Output)
	}
}

func TestRunPatternSelectsOnlyTheNamedSubtest(t *testing.T) {
	if got, want := runPattern("TestA/b_(c)"), `^TestA$/^b_\(c\)$`; got != want {
		t.Errorf("runPattern(%q) = %q, want %q", "TestA/b_(c)", got, want)
	}
}

func TestVerdictFailsAnUnlistedCrashAndAListedCaseThatSurvives(t *testing.T) {
	const overflow = "fatal error: stack overflow\n\ngoroutine 7 [running]:\nregogen.(*rsqlParser).join(0x1)\n\t/x.go:1\n"
	rsql := Known{Finding: "F82: the RSQL parser recurses per bracket", Frame: "regogen.(*rsqlParser)"}
	for _, tc := range []struct {
		name       string
		run        Run
		known      Known
		wantFailed bool
		wantReport string
	}{
		{"an unlisted case that survives", Run{}, Known{}, false, ""},
		{"an unlisted case that crashes", Run{Crashed: true, Output: overflow}, Known{}, true, "killed the process instead"},
		{"a listed case that crashes in its frame", Run{Crashed: true, Output: overflow}, rsql, false, "known violation F82"},
		{"a listed case that crashes elsewhere", Run{Crashed: true, Output: overflow},
			Known{Finding: rsql.Finding, Frame: "regogen.mongoTree"}, true, "outside regogen.mongoTree"},
		{"a listed case that survives", Run{}, rsql, true, "delete the entry for TestX"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			failed, report := verdict("TestX", tc.run, tc.known)
			if failed != tc.wantFailed || !strings.Contains(report, tc.wantReport) || (tc.wantReport == "") != (report == "") {
				t.Errorf("verdict(%+v, %+v) = %v, %q; want %v and a report holding %q",
					tc.run, tc.known, failed, report, tc.wantFailed, tc.wantReport)
			}
		})
	}
}

func TestExcerptKeepsTheFramesOfAPanicReportedAfterTheFailedTest(t *testing.T) {
	const output = "=== RUN   TestP\n--- FAIL: TestP (0.00s)\npanic: boom [recovered, repanicked]\n\n" +
		"goroutine 4 [running]:\nregogen.(*rsqlParser).join(0x1)\n\t/x.go:1\n\nFAIL\n"
	if ex := Excerpt(output); !strings.Contains(ex, "panic: boom") || !strings.Contains(ex, "regogen.(*rsqlParser).join(") {
		t.Errorf("Excerpt(output) = %q, want the panic line and the frame of regogen.(*rsqlParser).join", ex)
	}
}
