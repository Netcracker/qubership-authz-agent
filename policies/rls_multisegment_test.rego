# Copyright 2024-2026 Netcracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

package rls_multisegment_test

import rego.v1

# NEW-1 regression matrix (Step 2.4). The GENERAL PIP contract needs RLS leaf
# resolution to resolve MULTI-SEGMENT subject/resource refs — map-extract
# `subject.<alias>.<name>` and `${resource.attrs.X}`. This matrix proves that:
#   (a) multi-segment refs resolve correctly (via the general ref_value →
#       path_lookup path, which already walks depth ≤ 4), and
#   (b) existing SINGLE-segment refs are unchanged (still take the fast path).
# The `count(path)==1` guard on the eq/neq fast-path (simple_arg_supported)
# routes any multi-segment ref to the general path, so NO hot-path change is
# required — the fast path is deliberately left untouched to avoid regression.

eq_ast(scope, path, const) := {"op": "eq", "args": [{"ref": {"scope": scope, "path": path}}, {"const": const}]}

rule_of(ast) := {"conditionAst": ast}

# ── (b) single-segment still resolves + still uses the fast path ──────────

test_single_segment_subject_eq_matches if {
	data.rls.condition_allows(rule_of(eq_ast("subject", ["cid"], "C1")), {}, {"cid": "C1"})
}

test_single_segment_subject_eq_differs if {
	not data.rls.condition_allows(rule_of(eq_ast("subject", ["cid"], "C1")), {}, {"cid": "C2"})
}

test_single_segment_resource_eq_matches if {
	data.rls.condition_allows(rule_of(eq_ast("resource", ["ownerId"], "O1")), {"ownerId": "O1"}, {})
}

test_single_segment_uses_fast_path if {
	# simple_ast_supported gates the fast path; single-segment refs are supported.
	data.rls.simple_ast_supported(eq_ast("subject", ["cid"], "C1"))
}

# ── (a) multi-segment resolves via the general path (map-extract) ─────────

test_multi_segment_subject_eq_matches if {
	# subject.<alias>.<name> (map-extract binds an object under the alias)
	data.rls.condition_allows(rule_of(eq_ast("subject", ["allowed", "name"], "X")), {}, {"allowed": {"name": "X"}})
}

test_multi_segment_subject_eq_differs if {
	not data.rls.condition_allows(rule_of(eq_ast("subject", ["allowed", "name"], "Y")), {}, {"allowed": {"name": "X"}})
}

test_multi_segment_resource_attrs_eq if {
	# ${resource.attrs.X}
	data.rls.condition_allows(rule_of(eq_ast("resource", ["attrs", "region"], "EU")), {"attrs": {"region": "EU"}}, {})
}

test_multi_segment_does_not_use_fast_path if {
	# the count(path)==1 guard excludes multi-segment from the fast path, so it
	# routes to the general ref_value/path_lookup (which walks multi-segment).
	not data.rls.simple_ast_supported(eq_ast("subject", ["allowed", "name"], "X"))
}

test_multi_segment_depth3 if {
	data.rls.condition_allows(rule_of(eq_ast("subject", ["a", "b", "c"], "deep")), {}, {"a": {"b": {"c": "deep"}}})
}

test_multi_segment_depth4 if {
	data.rls.condition_allows(rule_of(eq_ast("resource", ["a", "b", "c", "d"], "x")), {"a": {"b": {"c": {"d": "x"}}}}, {})
}

test_multi_segment_depth5 if {
	data.rls.condition_allows(rule_of(eq_ast("subject", ["a", "b", "c", "d", "e"], "deep5")), {}, {"a": {"b": {"c": {"d": {"e": "deep5"}}}}})
}

test_multi_segment_depth6 if {
	data.rls.condition_allows(rule_of(eq_ast("resource", ["a", "b", "c", "d", "e", "f"], "deep6")), {"a": {"b": {"c": {"d": {"e": {"f": "deep6"}}}}}}, {})
}

# Guard: a genuine depth-5/6 value resolves (not silently truncated to null),
# so a neq at that depth does NOT false-positive when the value equals the const.
test_multi_segment_depth5_neq_no_false_positive if {
	not data.rls.condition_allows({"conditionAst": {"op": "neq", "args": [{"ref": {"scope": "subject", "path": ["a", "b", "c", "d", "e"]}}, {"const": "deep5"}]}}, {}, {"a": {"b": {"c": {"d": {"e": "deep5"}}}}})
}

# Same guard at the depth-6 boundary (the ceiling the fix extended path_lookup to):
# a real value at depth 6 must resolve so `neq` does not false-positive, and
# `is_null` does not fire on a genuinely non-null value (both would grant an allow
# they should not if depth 6 silently truncated to null).
test_multi_segment_depth6_neq_no_false_positive if {
	not data.rls.condition_allows({"conditionAst": {"op": "neq", "args": [{"ref": {"scope": "resource", "path": ["a", "b", "c", "d", "e", "f"]}}, {"const": "deep6"}]}}, {"a": {"b": {"c": {"d": {"e": {"f": "deep6"}}}}}}, {})
}

test_multi_segment_depth6_is_null_no_false_positive if {
	not data.rls.condition_allows({"conditionAst": {"op": "is_null", "args": [{"ref": {"scope": "subject", "path": ["a", "b", "c", "d", "e", "f"]}}]}}, {}, {"a": {"b": {"c": {"d": {"e": {"f": "deep6"}}}}}})
}

test_multi_segment_depth5_is_null_no_false_positive if {
	not data.rls.condition_allows({"conditionAst": {"op": "is_null", "args": [{"ref": {"scope": "subject", "path": ["a", "b", "c", "d", "e"]}}]}}, {}, {"a": {"b": {"c": {"d": {"e": "deep5"}}}}})
}

# ── multi-segment IN / contains via the general operator path ─────────────

test_multi_segment_in_matches if {
	data.rls.ast_leaf_allows({"op": "in", "args": [{"const": "C1"}, {"ref": {"scope": "subject", "path": ["allowed", "ids"]}}]}, {}, {"allowed": {"ids": ["C1", "C2"]}})
}

test_multi_segment_in_not_matches if {
	not data.rls.ast_leaf_allows({"op": "in", "args": [{"const": "C9"}, {"ref": {"scope": "subject", "path": ["allowed", "ids"]}}]}, {}, {"allowed": {"ids": ["C1", "C2"]}})
}

# ── null-safety: a missing multi-segment path does not match, no error ────

test_multi_segment_missing_intermediate_no_match if {
	not data.rls.condition_allows(rule_of(eq_ast("subject", ["allowed", "name"], "X")), {}, {"other": {"name": "X"}})
}

test_multi_segment_missing_into_null_no_match if {
	not data.rls.condition_allows(rule_of(eq_ast("subject", ["allowed", "name"], "X")), {}, {"allowed": null})
}
