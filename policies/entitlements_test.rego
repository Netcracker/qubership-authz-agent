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

package entitlements_test

import rego.v1

# ─────────────────────────────────────────────────────────────────────────
# ADR-0054 / D-AG-11 / D-AG-12 — entitlements runtime unit tests.
#
# Two layers exercised here:
#
#  1. Pure pivot of the EA V3 response body into the compact
#     {resourceType: {name: [resourceId, ...]}} map the rls layer
#     consumes. No HTTP, no subject context — pure function.
#  2. rls.rego evaluation of the six operator variants
#     (CONTAINS / CONTAINS ANY / IN with ENT on RHS / NOT CONTAINS /
#     IS EMPTY + chained .as(...) union) against an enriched subject
#     pre-populated with entitledResources. The AST shapes are the
#     exact shapes the simplified-policy parser emits under ADR-0054.
#
# The resolver's HTTP stage is covered by the runtime testify and
# parity suites where a real pip-stub can be pinned.
# ─────────────────────────────────────────────────────────────────────────

# ── build_entitlements_map (pure pivot) ──────────────────────────────────

test_build_entitlements_map_single_name if {
	body := {"entitlements": [{
		"resourceType": "PARITY_CONTRACT",
		"references": [{
			"name": "Owner",
			"resources": [
				{"resourceId": "id-1"},
				{"resourceId": "id-2"},
			],
		}],
	}]}
	result := data.pip.build_entitlements_map(body)
	sort(result.PARITY_CONTRACT.Owner) == ["id-1", "id-2"]
}

test_build_entitlements_map_multi_name_multi_rt if {
	body := {"entitlements": [
		{
			"resourceType": "PARITY_CONTRACT",
			"references": [
				{"name": "Owner", "resources": [{"resourceId": "id-1"}]},
				{"name": "Accountant", "resources": [{"resourceId": "id-2"}]},
			],
		},
		{
			"resourceType": "PARITY_ACCOUNT",
			"references": [{"name": "Owner", "resources": [{"resourceId": "acc-1"}]}],
		},
	]}
	result := data.pip.build_entitlements_map(body)
	sort(result.PARITY_CONTRACT.Owner) == ["id-1"]
	sort(result.PARITY_CONTRACT.Accountant) == ["id-2"]
	sort(result.PARITY_ACCOUNT.Owner) == ["acc-1"]
}

test_build_entitlements_map_empty_body if {
	data.pip.build_entitlements_map({"entitlements": []}) == {}
}

test_build_entitlements_map_missing_entitlements_key if {
	data.pip.build_entitlements_map({}) == {}
}

# ── Resolver short-circuits when config is absent or subject is empty ────

test_resolve_entitlements_no_config_returns_empty if {
	result := data.pip.resolve_entitlements_map({"id": "user-1"})
		with data.pips as {}
	result == {}
}

test_resolve_entitlements_blank_url_returns_empty if {
	result := data.pip.resolve_entitlements_map({"id": "user-1"})
		with data.pips.remote.entitlements as {"url": ""}
	result == {}
}

test_resolve_entitlements_empty_subject_id_returns_empty if {
	result := data.pip.resolve_entitlements_map({"id": ""})
		with data.pips.remote.entitlements as {
			"url": "http://stub:8080",
			"httpTimeoutSeconds": 5,
			"httpRetries": 3,
		}
	result == {}
}

# ── rls.rego: six-operator matrix over a populated entitledResources ────

# Helper that builds an enriched subject with `entitledResources` pre-
# materialised. In production the `enriched_subject` gets this key from
# `_entitlement_pip_values` in authorize.rego; unit tests inject it
# directly so the rls.rego operators run without crossing the resolver
# boundary.
enriched_with(refs) := {
	"id": "user-1",
	"name": "tester",
	"type": "USER",
	"roles": ["ROLE_PARITY_READER"],
	"scopes": [],
	"entitledResources": refs,
}

ent_tree_owner_only := {"PARITY_CONTRACT": {"Owner": ["id-1"]}}
ent_tree_owner_accountant := {"PARITY_CONTRACT": {"Owner": ["id-1"], "Accountant": ["id-2"]}}
ent_tree_owner_multi := {"PARITY_CONTRACT": {"Owner": ["id-1", "id-2"]}}
ent_tree_empty := {"PARITY_CONTRACT": {"Owner": []}}
ent_tree_missing_rt := {}

# AST shape emitted by parseEntitlementOperand: `{ref: {scope: "entitlements", resourceType, names}}`.
ent_ref(rt, names) := {"ref": {"scope": "entitlements", "resourceType": rt, "names": names}}

# CONTAINS ------------------------------------------------------------------

test_contains_allows_hit if {
	ast := {"op": "contains", "args": [ent_ref("PARITY_CONTRACT", ["Owner"]), {"ref": {"scope": "resource", "path": ["id"]}}]}
	data.rls.ast_leaf_allows(ast, {"id": "id-1"}, enriched_with(ent_tree_owner_only))
}

test_contains_denies_miss if {
	ast := {"op": "contains", "args": [ent_ref("PARITY_CONTRACT", ["Owner"]), {"ref": {"scope": "resource", "path": ["id"]}}]}
	not data.rls.ast_leaf_allows(ast, {"id": "id-99"}, enriched_with(ent_tree_owner_only))
}

# CONTAINS ANY --------------------------------------------------------------

test_contains_any_allows_intersection if {
	ast := {"op": "contains_any", "args": [ent_ref("PARITY_CONTRACT", ["Owner"]), {"ref": {"scope": "resource", "path": ["relatedIds"]}}]}
	data.rls.ast_leaf_allows(ast, {"relatedIds": ["id-1", "id-99"]}, enriched_with(ent_tree_owner_multi))
}

test_contains_any_denies_disjoint if {
	ast := {"op": "contains_any", "args": [ent_ref("PARITY_CONTRACT", ["Owner"]), {"ref": {"scope": "resource", "path": ["relatedIds"]}}]}
	not data.rls.ast_leaf_allows(ast, {"relatedIds": ["id-99"]}, enriched_with(ent_tree_owner_multi))
}

# IN with ENT on RHS --------------------------------------------------------

test_in_rhs_allows_hit if {
	ast := {"op": "in", "args": [{"ref": {"scope": "resource", "path": ["id"]}}, ent_ref("PARITY_CONTRACT", ["Owner"])]}
	data.rls.ast_leaf_allows(ast, {"id": "id-1"}, enriched_with(ent_tree_owner_only))
}

test_in_rhs_denies_miss if {
	ast := {"op": "in", "args": [{"ref": {"scope": "resource", "path": ["id"]}}, ent_ref("PARITY_CONTRACT", ["Owner"])]}
	not data.rls.ast_leaf_allows(ast, {"id": "id-99"}, enriched_with(ent_tree_owner_only))
}

# IS EMPTY ------------------------------------------------------------------

test_is_empty_true_when_bucket_empty if {
	ast := {"op": "is_empty", "args": [ent_ref("PARITY_CONTRACT", ["Owner"])]}
	data.rls.ast_leaf_allows(ast, {}, enriched_with(ent_tree_empty))
}

test_is_empty_true_when_resource_type_missing if {
	ast := {"op": "is_empty", "args": [ent_ref("PARITY_CONTRACT", ["Owner"])]}
	data.rls.ast_leaf_allows(ast, {}, enriched_with(ent_tree_missing_rt))
}

test_is_empty_false_when_bucket_populated if {
	ast := {"op": "is_empty", "args": [ent_ref("PARITY_CONTRACT", ["Owner"])]}
	not data.rls.ast_leaf_allows(ast, {}, enriched_with(ent_tree_owner_only))
}

# NOT CONTAINS --------------------------------------------------------------

test_not_contains_allows_when_missing if {
	inner := {"op": "contains", "args": [ent_ref("PARITY_CONTRACT", ["Owner"]), {"ref": {"scope": "resource", "path": ["id"]}}]}
	ast := {"op": "not", "args": [inner]}
	data.rls.ast_condition_allows(ast, {"id": "id-99"}, enriched_with(ent_tree_owner_only))
}

test_not_contains_denies_when_present if {
	inner := {"op": "contains", "args": [ent_ref("PARITY_CONTRACT", ["Owner"]), {"ref": {"scope": "resource", "path": ["id"]}}]}
	ast := {"op": "not", "args": [inner]}
	not data.rls.ast_condition_allows(ast, {"id": "id-1"}, enriched_with(ent_tree_owner_only))
}

# Chained / multi-name .as(...) evaluates as UNION (D-AG-12) ---------------

test_multi_as_union_hits_first_bucket if {
	ast := {"op": "contains", "args": [ent_ref("PARITY_CONTRACT", ["Owner", "Accountant"]), {"ref": {"scope": "resource", "path": ["id"]}}]}
	data.rls.ast_leaf_allows(ast, {"id": "id-1"}, enriched_with(ent_tree_owner_accountant))
}

test_multi_as_union_hits_second_bucket if {
	ast := {"op": "contains", "args": [ent_ref("PARITY_CONTRACT", ["Owner", "Accountant"]), {"ref": {"scope": "resource", "path": ["id"]}}]}
	data.rls.ast_leaf_allows(ast, {"id": "id-2"}, enriched_with(ent_tree_owner_accountant))
}

test_multi_as_union_misses_outside_either_bucket if {
	ast := {"op": "contains", "args": [ent_ref("PARITY_CONTRACT", ["Owner", "Accountant"]), {"ref": {"scope": "resource", "path": ["id"]}}]}
	not data.rls.ast_leaf_allows(ast, {"id": "id-3"}, enriched_with(ent_tree_owner_accountant))
}

# ── entitlement_ref_value pure: union + sort deterministic ───────────────

test_entitlement_ref_value_sorted_union if {
	tree := {"PARITY_CONTRACT": {"Owner": ["id-2", "id-1"], "Accountant": ["id-3"]}}
	value := data.rls.entitlement_ref_value(
		{"scope": "entitlements", "resourceType": "PARITY_CONTRACT", "names": ["Owner", "Accountant"]},
		{"entitledResources": tree},
	)
	value == ["id-1", "id-2", "id-3"]
}

test_entitlement_ref_value_returns_empty_for_unknown_rt if {
	value := data.rls.entitlement_ref_value(
		{"scope": "entitlements", "resourceType": "UNKNOWN", "names": ["Owner"]},
		{"entitledResources": {"PARITY_CONTRACT": {"Owner": ["id-1"]}}},
	)
	value == []
}

test_entitlement_ref_value_returns_empty_for_unknown_name if {
	value := data.rls.entitlement_ref_value(
		{"scope": "entitlements", "resourceType": "PARITY_CONTRACT", "names": ["Reviewer"]},
		{"entitledResources": {"PARITY_CONTRACT": {"Owner": ["id-1"]}}},
	)
	value == []
}

# ── Empty-user matrix (D-AG-15) ──────────────────────────────────────────

test_empty_user_contains_is_false if {
	ast := {"op": "contains", "args": [ent_ref("PARITY_CONTRACT", ["Owner"]), {"ref": {"scope": "resource", "path": ["id"]}}]}
	not data.rls.ast_leaf_allows(ast, {"id": "id-1"}, enriched_with({}))
}

test_empty_user_is_empty_is_true if {
	ast := {"op": "is_empty", "args": [ent_ref("PARITY_CONTRACT", ["Owner"])]}
	data.rls.ast_leaf_allows(ast, {}, enriched_with({}))
}
