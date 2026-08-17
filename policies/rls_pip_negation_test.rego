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

package rls_pip_negation_test

import rego.v1

# §D negation fail-closed (ADR-0068, Review-1 owner decision 2026-07-02).
#
# A failed/absent PIP alias must NOT open access under a negative operator. The
# RLS engine resolves a missing key to `null` (path_lookup default), and `null`
# is a definite value, so before the fix `subject.failedPip != 'X'`,
# `NOT(subject.failedPip == 'X')`, and `subject.failedPip is_null` all GRANTED on
# a PIP failure. The fix makes a "known PIP alias + absent from subject" ref
# resolve to UNDEFINED (fail-closed for neg leaves) and guards the two `not`
# clauses so negation over such a ref also fails closed — while leaving genuine
# missing (non-PIP) attributes on the legacy missing==null path.
#
# These tests drive data.rls.condition_allows directly with a subject that omits
# the PIP alias (== the PIP failed) and known_pip_aliases naming it. Every case
# also asserts the CONTRAST — the same operator over a genuine non-PIP attribute
# keeps its legacy semantics — so the fix is proven narrow, not a blanket change.

# known_pip_aliases mock: failedPip / goodPip are PIP aliases; genuineAttr is not.
pip_known := {"failedPip": true, "goodPip": true}

rule_of(ast) := {"conditionAst": ast}

neq_ast(alias, const) := {"op": "neq", "args": [{"ref": {"scope": "subject", "path": [alias]}}, {"const": const}]}

not_eq_ast(alias, const) := {"op": "not", "args": [{"op": "eq", "args": [{"ref": {"scope": "subject", "path": [alias]}}, {"const": const}]}]}

is_null_ast(alias) := {"op": "is_null", "args": [{"ref": {"scope": "subject", "path": [alias]}}]}

not_in_ast(alias, arr) := {"op": "not", "args": [{"op": "in", "args": [{"ref": {"scope": "subject", "path": [alias]}}, {"const": arr}]}]}

# ── neq (fast path) ──────────────────────────────────────────────────────

# FAILED PIP: fast-path neq must fail closed (was: null != 'X' => grant).
test_neq_failed_pip_denies if {
	not data.rls.condition_allows(rule_of(neq_ast("failedPip", "X")), {}, {})
		with data.pip.known_pip_aliases as pip_known
}

# CONTRAST — genuine missing attribute keeps legacy fail-open (null != 'X' grants).
test_neq_genuine_missing_still_grants if {
	data.rls.condition_allows(rule_of(neq_ast("genuineAttr", "X")), {}, {})
		with data.pip.known_pip_aliases as pip_known
}

# A resolved PIP still evaluates neq normally.
test_neq_resolved_pip_grants_when_differs if {
	data.rls.condition_allows(rule_of(neq_ast("goodPip", "X")), {}, {"goodPip": "Y"})
		with data.pip.known_pip_aliases as pip_known
}

test_neq_resolved_pip_denies_when_equal if {
	not data.rls.condition_allows(rule_of(neq_ast("goodPip", "X")), {}, {"goodPip": "X"})
		with data.pip.known_pip_aliases as pip_known
}

# ── NOT(eq) ──────────────────────────────────────────────────────────────

# FAILED PIP: not(eq) must fail closed (was: not false => grant).
test_not_eq_failed_pip_denies if {
	not data.rls.condition_allows(rule_of(not_eq_ast("failedPip", "X")), {}, {})
		with data.pip.known_pip_aliases as pip_known
}

# CONTRAST — not(eq) over a genuine missing attribute keeps legacy grant.
test_not_eq_genuine_missing_still_grants if {
	data.rls.condition_allows(rule_of(not_eq_ast("genuineAttr", "X")), {}, {})
		with data.pip.known_pip_aliases as pip_known
}

# ── is_null ──────────────────────────────────────────────────────────────

# FAILED PIP: is_null must fail closed — a failed PIP is "unknown", not "null".
test_is_null_failed_pip_denies if {
	not data.rls.condition_allows(rule_of(is_null_ast("failedPip")), {}, {})
		with data.pip.known_pip_aliases as pip_known
}

# CONTRAST — is_null over a genuine missing attribute stays true (legacy).
test_is_null_genuine_missing_still_grants if {
	data.rls.condition_allows(rule_of(is_null_ast("genuineAttr")), {}, {})
		with data.pip.known_pip_aliases as pip_known
}

# ── NOT(in) ──────────────────────────────────────────────────────────────

test_not_in_failed_pip_denies if {
	not data.rls.condition_allows(rule_of(not_in_ast("failedPip", ["A", "B"])), {}, {})
		with data.pip.known_pip_aliases as pip_known
}

# ── OR / AND aggregation around a failed-PIP negative operand ─────────────

# OR: failed-PIP neq operand + a sibling that ALSO fails => overall deny.
# Proves the branch is genuinely false, not accidentally allowed.
test_or_failed_pip_neq_and_failing_sibling_denies if {
	ast := {"op": "or", "args": [
		neq_ast("failedPip", "X"),
		{"op": "eq", "args": [{"ref": {"scope": "subject", "path": ["other"]}}, {"const": "yes"}]},
	]}
	not data.rls.condition_allows(rule_of(ast), {}, {"other": "no"})
		with data.pip.known_pip_aliases as pip_known
}

# OR: failed-PIP neq operand + a sibling that MATCHES => allow via the sibling.
# Proves operand-local isolation: the failed operand does not abort the decision.
test_or_failed_pip_neq_with_matching_sibling_allows if {
	ast := {"op": "or", "args": [
		neq_ast("failedPip", "X"),
		{"op": "eq", "args": [{"ref": {"scope": "subject", "path": ["other"]}}, {"const": "yes"}]},
	]}
	data.rls.condition_allows(rule_of(ast), {}, {"other": "yes"})
		with data.pip.known_pip_aliases as pip_known
}

# AND: failed-PIP neq operand + a matching sibling => overall deny (AND requires all).
test_and_failed_pip_neq_denies if {
	ast := {"op": "and", "args": [
		neq_ast("failedPip", "X"),
		{"op": "eq", "args": [{"ref": {"scope": "subject", "path": ["other"]}}, {"const": "yes"}]},
	]}
	not data.rls.condition_allows(rule_of(ast), {}, {"other": "yes"})
		with data.pip.known_pip_aliases as pip_known
}

# ── _arg_has_failed_pip_ref must not descend into const values ────────────
# Review finding: walk() enumerates const values too, so a const literal shaped
# like a ref node ({ref:{scope,path}}) must NOT be mistaken for a real failed-PIP
# ref (that would over-deny a legitimately-evaluable NOT).

test_arg_has_failed_pip_ref_ignores_const_shaped_like_ref if {
	not data.rls._arg_has_failed_pip_ref(
		{"op": "eq", "args": [{"const": {"ref": {"scope": "subject", "path": ["failedPip"]}}}, {"const": "X"}]},
		{},
	)
		with data.pip.known_pip_aliases as pip_known
}

test_arg_has_failed_pip_ref_still_flags_real_ref if {
	data.rls._arg_has_failed_pip_ref(
		{"op": "eq", "args": [{"ref": {"scope": "subject", "path": ["failedPip"]}}, {"const": "X"}]},
		{},
	)
		with data.pip.known_pip_aliases as pip_known
}
