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

import "testing"

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
