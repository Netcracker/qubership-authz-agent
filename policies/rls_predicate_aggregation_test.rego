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

package rls_predicate_aggregation_test

import rego.v1

fixtures := data.fixtures.identity

valid_token := fixtures.tokens.valid

authn := fixtures.authn

# Helper: extract the aggregated predicate string for a given predicateType from predicates[].
_predicate_of_type(predicates, ptype) := pred if {
	some i
	predicates[i].predicateType == ptype
	pred := predicates[i].predicate
}

# ── rsql: single predicate returned as-is ────────────────────────────────

test_rsql_single_predicate_returned_as_is if {
	policies := {
		"ols": {"ITEM": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"ITEM": {"READ": {"ROLE_VIEWER": [
			{
				"condition": true,
				"predicates": [{"predicate": "dept==engineering", "type": "rsql"}],
			},
		]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Item", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
	_predicate_of_type(result.results[0].predicates, "rsql") == "dept==engineering"
}

# ── rsql: two predicates from two role fragments ──────────────────────────
# Policy has two rule fragments under the same role.

test_rsql_two_fragments_aggregated_flat if {
	policies := {
		"ols": {"ITEM": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"ITEM": {"READ": {"ROLE_VIEWER": [
			{
				"condition": true,
				"predicates": [{"predicate": "dept==engineering", "type": "rsql"}],
			},
			{
				"condition": true,
				"predicates": [{"predicate": "dept==management", "type": "rsql"}],
			},
		]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Item", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
	# D-AF-S (supersedes ADR-0025 parenthesized OR on 2026-04-15):
	# RSQL aggregation emits flat comma-joined predicates matching
	# legacy `access-control`'s aggregator output byte-for-byte.
	# Deterministic sort order: engineering < management.
	_predicate_of_type(result.results[0].predicates, "rsql") == "dept==engineering,dept==management"
}

# ── rsql: three predicates → flat comma-joined ──────────────────────────

test_rsql_three_fragments_aggregated if {
	policies := {
		"ols": {"ITEM": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"ITEM": {"READ": {"ROLE_VIEWER": [
			{"condition": true, "predicates": [{"predicate": "c==1", "type": "rsql"}]},
			{"condition": true, "predicates": [{"predicate": "c==2", "type": "rsql"}]},
			{"condition": true, "predicates": [{"predicate": "c==3", "type": "rsql"}]},
		]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Item", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	# D-AF-S: flat comma-joined RSQL aggregation.
	_predicate_of_type(result.results[0].predicates, "rsql") == "c==1,c==2,c==3"
}

# ── rsql: predicate=true fragments are filtered from output ───────────────

test_rsql_true_predicate_filtered_in_multifragment if {
	policies := {
		"ols": {"ITEM": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"ITEM": {"READ": {"ROLE_VIEWER": [
			{"condition": true, "predicates": [{"predicate": "true", "type": "rsql"}]},
			{"condition": true, "predicates": [{"predicate": "dept==eng", "type": "rsql"}]},
		]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Item", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
	# D-AF-S (2026-04-15): a matching rule with `predicate: "true"`
	# is an **unrestricted rule** (pure OLS — the role is fully
	# authorised with no row-level filter). Per the OLS-plus-RLS
	# collapse semantic, the whole aggregation now collapses to
	# ALLOW with an empty predicate (no `predicates[]` in the
	# canonical response). This mirrors legacy
	# `EvaluationResultBuilder.java:72-93` and closes
	# `TestRow06CheckFilterV1AggOlsPlusRls`. Pre-Step-5 behavior
	# was to filter the "true" predicate and keep the restrictive
	# one; that was off-contract.
	not result.results[0].predicates
}

# ── D-AF-S: OLS-only rule absorbs restrictive RLS rule on same locator ──

# This is the explicit OLS-plus-RLS collapse case that row 6's
# `TestRow06CheckFilterV1AggOlsPlusRls` fixture (AGG row 64)
# exercises against the legacy server: part A is a pure-OLS row
# (no `condition`/`conditionAst` at all and no predicates beyond
# the default `true` shortcut), part B is a restrictive RLS row
# on the same (resourceType, operation, role) with a non-trivial
# rsql predicate. Legacy's `EvaluationResultBuilder.java:72-93`
# picks part A and drops part B; the canonical response returns
# ALLOW with no `predicates[]`.
test_ols_only_rule_absorbs_restrictive_rls_rule if {
	policies := {
		"ols": {"ITEM": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"ITEM": {"READ": {"ROLE_VIEWER": [
			# Part A: pure-OLS row. The normalizer emits this shape
			# when a simplified policy has neither `condition` nor
			# `rsqlPredicate` (docs/ai/policy-format.md
			# "Normalization rule for this and similar cases").
			{
				"condition": true,
				"predicates": [{"predicate": "true", "type": "rsql"}],
			},
			# Part B: restrictive RLS row on the same locator.
			{
				"condition": true,
				"predicates": [{"predicate": "ownerId==${subject.id}", "type": "rsql"}],
			},
		]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Item", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
	# Part A absorbs part B: no predicates emitted.
	not result.results[0].predicates
}

# ── rsql: all predicates=true → no predicates in output ──────────────────

test_rsql_all_true_predicates_no_predicates_in_output if {
	policies := {
		"ols": {"ITEM": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"ITEM": {"READ": {"ROLE_VIEWER": [
			{"condition": true, "predicates": [{"predicate": "true", "type": "rsql"}]},
			{"condition": true, "predicates": [{"predicate": "true", "type": "rsql"}]},
		]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Item", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
	not result.results[0].predicates
}

# ── canonical: predicates[] contains rsql entry ──────────────────────────

test_predicates_array_contains_rsql_entry if {
	policies := {
		"ols": {"ITEM": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"ITEM": {"READ": {"ROLE_VIEWER": [
			{
				"condition": true,
				"predicates": [{"predicate": "dept==engineering", "type": "rsql"}],
			},
			{
				"condition": true,
				"predicates": [{"predicate": "dept==management", "type": "rsql"}],
			},
		]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Item", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
	# ADR-0029: canonical response uses predicates[] array.
	# D-AF-S (2026-04-15): flat comma-joined RSQL aggregation.
	is_array(result.results[0].predicates)
	_predicate_of_type(result.results[0].predicates, "rsql") == "dept==engineering,dept==management"
}

# ── canonical: sql predicate in predicates[] ─────────────────────────────

test_predicates_array_contains_sql if {
	policies := {
		"ols": {"ITEM": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"ITEM": {"READ": {"ROLE_VIEWER": [
			{
				"condition": true,
				"predicates": [{"predicate": "dept = 'engineering'", "type": "sql"}],
			},
			{
				"condition": true,
				"predicates": [{"predicate": "dept = 'management'", "type": "sql"}],
			},
		]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Item", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
	# No rsql entry; sql entry present.
	not _predicate_of_type(result.results[0].predicates, "rsql")
	_predicate_of_type(result.results[0].predicates, "sql") == "dept = 'engineering' OR dept = 'management'"
}

# ── canonical: mongodb predicate in predicates[] ──────────────────────────

test_predicates_array_contains_mongodb if {
	policies := {
		"ols": {"ITEM": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"ITEM": {"READ": {"ROLE_VIEWER": [
			{
				"condition": true,
				"predicates": [{"predicate": "{\"dept\": \"engineering\"}", "type": "mongodb"}],
			},
			{
				"condition": true,
				"predicates": [{"predicate": "{\"dept\": \"management\"}", "type": "mongodb"}],
			},
		]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Item", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
	mongodb_pred := _predicate_of_type(result.results[0].predicates, "mongodb")
	contains(mongodb_pred, "\"$or\"")
	contains(mongodb_pred, "\"dept\": \"engineering\"")
	contains(mongodb_pred, "\"dept\": \"management\"")
}

# ── canonical: mixed rsql and sql preserved as separate entries ───────────

test_mixed_rsql_and_sql_in_predicates_array if {
	policies := {
		"ols": {"ITEM": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"ITEM": {"READ": {"ROLE_VIEWER": [
			{
				"condition": true,
				"predicates": [
					{"predicate": "dept==engineering", "type": "rsql"},
					{"predicate": "dept = 'engineering'", "type": "sql"},
				],
			},
			{
				"condition": true,
				"predicates": [
					{"predicate": "dept==management", "type": "rsql"},
					{"predicate": "dept = 'management'", "type": "sql"},
				],
			},
		]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Item", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
	is_array(result.results[0].predicates)
	# D-AF-S (2026-04-15): flat comma-joined RSQL aggregation.
	_predicate_of_type(result.results[0].predicates, "rsql") == "dept==engineering,dept==management"
	_predicate_of_type(result.results[0].predicates, "sql") == "dept = 'engineering' OR dept = 'management'"
}

# ── canonical: predicates[] ordering is rsql before sql (ADR-0029) ───────

test_predicates_array_order_rsql_before_sql if {
	policies := {
		"ols": {"ITEM": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"ITEM": {"READ": {"ROLE_VIEWER": [
			{
				"condition": true,
				"predicates": [
					{"predicate": "dept==engineering", "type": "rsql"},
					{"predicate": "dept = 'engineering'", "type": "sql"},
				],
			},
		]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Item", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
	preds := result.results[0].predicates
	count(preds) == 2
	preds[0].predicateType == "rsql"
	preds[1].predicateType == "sql"
}

# ── canonical: result always has rlsIgnored + results (endpoint-agnostic) ──

test_canonical_result_shape_is_always_rls_ignored_plus_results if {
	policies := {
		"ols": {"ITEM": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"ITEM": {"READ": {"ROLE_VIEWER": [
			{"condition": true, "predicates": [{"predicate": "dept==engineering", "type": "rsql"}]},
		]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Item", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	# Canonical top-level shape must always be present.
	is_boolean(result.rlsIgnored)
	is_array(result.results)
	# No legacy-shaped fields at top level.
	object.get(result, "calculationResult", null) == null
	object.get(result, "filterCondition", null) == null
	object.get(result, "rsqlFilterCondition", null) == null
}
