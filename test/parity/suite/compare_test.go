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

package paritysuite

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"authz-agent/test/parity/suite/model"
)

// A case written before its golden was captured has to be told apart from a
// case whose golden exists and disagrees: the first skips, the second fails.
func TestCompare_MissingGoldenIsReportedAsNotRecorded(t *testing.T) {
	t.Parallel()
	gc := &GoldenComparator{goldenRoot: t.TempDir()}
	decision := true

	err := gc.Compare(PSUITE_ROW_2_CHECK_RESOURCE_V1, "never-recorded", &decision)

	if !errors.Is(err, ErrGoldenNotRecorded) {
		t.Fatalf("Compare with no golden file: want ErrGoldenNotRecorded, got %v", err)
	}
}

func TestCompare_MismatchingGoldenIsNotReportedAsNotRecorded(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dir := filepath.Join(root, "check-resource-v1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "recorded-false.json"), []byte("false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gc := &GoldenComparator{goldenRoot: root}
	decision := true

	err := gc.Compare(PSUITE_ROW_2_CHECK_RESOURCE_V1, "recorded-false", &decision)

	var mismatch *GoldenMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("Compare(true) against golden false: want *GoldenMismatchError, got %v", err)
	}
	if errors.Is(err, ErrGoldenNotRecorded) {
		t.Fatalf("Compare(true) against golden false must not report ErrGoldenNotRecorded: %v", err)
	}
}

// The body of a refusal that a golden records beside the status takes no part
// in the comparison, for every outcome that can carry one: the status alone
// decides, whether the message is on the golden's side, on the answer's, or on
// both with other wording.
func TestCompare_RefusalMessageIsIgnored(t *testing.T) {
	t.Parallel()
	outcomes := []struct {
		id     ParityEndpointID
		dir    string
		answer func(status int, message any) any
	}{
		{PSUITE_LOAD_POLICY_SETS, "load-policy-sets-v1", func(status int, message any) any {
			return &model.PolicyLoadOutcome{Status: status, Message: message}
		}},
		{PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, "check-resource-v1-outcome", func(status int, message any) any {
			return &model.CheckResourceOutcome{Status: status, Message: message}
		}},
		{PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, "check-filter-v1-outcome", func(status int, message any) any {
			return &model.FilterOutcome{Status: status, Message: message}
		}},
		{PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1_OUTCOME, "check-resource-bulk-v1-outcome", func(status int, message any) any {
			return &model.CheckResourceBulkOutcome{Status: status, Message: message}
		}},
		{PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1_OUTCOME, "check-resource-bulk-operations-v1-outcome", func(status int, message any) any {
			return &model.CheckResourceBulkOperationsOutcome{Status: status, Message: message}
		}},
	}
	goldens := map[string]string{
		"with-a-message":    `{"status": 400, "message": {"message": "the stand's wording"}}`,
		"without-a-message": `{"status": 400}`,
	}
	cases := []struct {
		name    string
		golden  string
		status  int
		message any
		matches bool
	}{
		{"no message against a golden with one", "with-a-message", http.StatusBadRequest, nil, true},
		{"another message against a golden with one", "with-a-message", http.StatusBadRequest, "other wording", true},
		{"a message against a golden without one", "without-a-message", http.StatusBadRequest, "other wording", true},
		{"another status", "with-a-message", http.StatusConflict, nil, false},
	}
	for _, o := range outcomes {
		root := t.TempDir()
		dir := filepath.Join(root, o.dir, "regular")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, golden := range goldens {
			if err := os.WriteFile(filepath.Join(dir, name+".json"), []byte(golden), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		gc := &GoldenComparator{goldenRoot: root}
		for _, tc := range cases {
			t.Run(o.dir+"/"+tc.name, func(t *testing.T) {
				err := gc.Compare(o.id, "regular/"+tc.golden, o.answer(tc.status, tc.message))
				if (err == nil) != tc.matches {
					t.Errorf("Compare(status %d, message %v) against %s = %v, want a match: %t",
						tc.status, tc.message, goldens[tc.golden], err, tc.matches)
				}
			})
		}
	}
}

// TestNormalizeRsqlInElements_SortsInClauseBothDirections pins the
// D-AF-AA (2026-04-19) comparator-allowlist contract: for RSQL `in`
// clauses, element order is set-semantic, so `("a","b")` and `("b","a")`
// must normalize to the same string. The parity comparator relies on
// this to diff-empty the `PSUITE_ROW_10_CHECK_FILTER_V2` /
// `general-pip-dict` leaf where legacy emits reversed insertion order
// and authz-agent emits forward index order.
func TestNormalizeRsqlInElements_SortsInClauseBothDirections(t *testing.T) {
	t.Parallel()
	forward := `id=in=("row10-dict-1", "row10-dict-2");amount=le="1000"`
	reverse := `id=in=("row10-dict-2", "row10-dict-1");amount=le="1000"`
	if normalizeRsqlInElements(forward) != normalizeRsqlInElements(reverse) {
		t.Fatalf("forward and reverse element orders must normalize to the same string\nforward:  %s\nreverse:  %s\nnormfwd:  %s\nnormrev:  %s",
			forward, reverse, normalizeRsqlInElements(forward), normalizeRsqlInElements(reverse))
	}
}

// TestNormalizeRsqlInElements_DoesNotCollapseDistinctSets guards
// against silent element-drops — two `in` clauses with different
// element sets must NOT normalize to the same string.
func TestNormalizeRsqlInElements_DoesNotCollapseDistinctSets(t *testing.T) {
	t.Parallel()
	a := `id=in=("alpha", "beta")`
	b := `id=in=("alpha", "gamma")`
	if normalizeRsqlInElements(a) == normalizeRsqlInElements(b) {
		t.Fatalf("distinct element sets must not normalize equal: %q vs %q", a, b)
	}
}

// TestNormalizeRsqlInElements_PreservesSingleElement confirms the
// normalizer is a no-op on single-element `in` clauses and on
// expressions without any `in` clause.
func TestNormalizeRsqlInElements_PreservesSingleElement(t *testing.T) {
	t.Parallel()
	single := `id=in=("only")`
	if got := normalizeRsqlInElements(single); got != single {
		t.Fatalf("single-element in clause must round-trip; got %q", got)
	}
	plain := `status=="OPEN"`
	if got := normalizeRsqlInElements(plain); got != plain {
		t.Fatalf("expression without in clause must round-trip; got %q", got)
	}
}

// TestNormalizeRsqlInElements_HandlesMultipleInClauses exercises the
// tokenizer when the same expression carries more than one `in` clause
// (future-proofing for richer predicates).
func TestNormalizeRsqlInElements_HandlesMultipleInClauses(t *testing.T) {
	t.Parallel()
	expr := `id=in=("b", "a");tag=in=("z", "y", "x")`
	got := normalizeRsqlInElements(expr)
	want := `id=in=("a", "b");tag=in=("x", "y", "z")`
	if got != want {
		t.Fatalf("multi-in normalization mismatch\nwant: %s\ngot:  %s", want, got)
	}
}
