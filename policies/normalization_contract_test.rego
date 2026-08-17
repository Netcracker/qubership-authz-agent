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

package normalization_contract_test

import rego.v1

fixtures := data.fixtures.identity

valid_token := fixtures.tokens.valid

authn := fixtures.authn

# --- condition=true fallback ---

test_condition_true_fallback_allows_rls if {
	policies := {
		"ols": {"PRODUCT": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"PRODUCT": {"READ": {"ROLE_VIEWER": [
			{
				"condition": true,
				"predicates": [{"predicate": "true", "type": "rsql"}],
			},
		]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Product", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
}

# --- predicate=true is filtered from canonical predicate output ---

test_predicate_true_filtered_from_output if {
	policies := {
		"ols": {"PRODUCT": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"PRODUCT": {"READ": {"ROLE_VIEWER": [
			{
				"condition": true,
				"predicates": [{"predicate": "true", "type": "rsql"}],
			},
		]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Product", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
	not result.results[0].predicates
}

# --- non-trivial predicate is preserved ---

test_nontrivial_predicate_preserved if {
	policies := {
		"ols": {"PRODUCT": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"PRODUCT": {"READ": {"ROLE_VIEWER": [
			{
				"condition": true,
				"predicates": [{"predicate": "ownerId==${subject.id}", "type": "rsql"}],
			},
		]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Product", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
	some i
	result.results[0].predicates[i].predicateType == "rsql"
	# D-AF-R (OQ-AF-6, 2026-04-15): canonical subject attribute
	# `id` renders UNQUOTED in predicates; only PIP-resolved
	# (non-canonical) scalar strings are JSON-quoted.
	result.results[0].predicates[i].predicate == "ownerId==user-allow"
}

# --- role-scoped RLS layout: different roles get different rules ---

test_role_scoped_rls_uses_matching_role_rules if {
	policies := {
		"ols": {"PRODUCT": {"READ": ["ROLE_VIEWER", "ROLE_EDITOR"]}},
		"rls": {"PRODUCT": {"READ": {
			"ROLE_VIEWER": [{
				"condition": true,
				"predicates": [{"predicate": "viewer_pred", "type": "rsql"}],
			}],
			"ROLE_EDITOR": [{
				"condition": true,
				"predicates": [{"predicate": "editor_pred", "type": "rsql"}],
			}],
		}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Product", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
	some i
	result.results[0].predicates[i].predicateType == "rsql"
	contains(result.results[0].predicates[i].predicate, "viewer_pred")
}

# --- ALL/ALL global policy with explicit roles via globalAccessRoles (ADR-0040) ---

test_global_all_all_wildcard_access_allows_ols_only if {
	policies := {
		"ols": {},
		"rls": {},
		"globalAccessRoles": {"byRole": {"ROLE_VIEWER": {"all": true}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "AnyResource", "operation": "ANY_OP"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": true,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
}

test_global_all_all_wildcard_access_allows_even_when_rls_evaluated if {
	policies := {
		"ols": {},
		"rls": {},
		"globalAccessRoles": {"byRole": {"ROLE_VIEWER": {"all": true}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "AnyResource", "operation": "ANY_OP"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
	not result.results[0].predicates
}

test_global_all_all_wildcard_access_no_predicates_no_reason if {
	policies := {
		"ols": {},
		"rls": {},
		"globalAccessRoles": {"byRole": {"ROLE_VIEWER": {"all": true}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "AnyResource", "operation": "ANY_OP"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	not result.results[0].predicates
	not result.results[0].reason
}

# --- empty OLS denies (no open-access through empty leaves) ---

test_empty_ols_denies if {
	policies := {
		"ols": {},
		"rls": {},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "AnyResource", "operation": "ANY_OP"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": true,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == false
}

# --- explicit OLS roles with globalAccessRoles wildcard (ADR-0040) ---

test_explicit_ols_roles_with_global_access_wildcard_no_match if {
	policies := {
		"ols": {
			"PRODUCT": {"READ": ["ROLE_ADMIN"]},
		},
		"rls": {"PRODUCT": {"READ": {"ROLE_ADMIN": [
			{
				"condition": true,
				"predicates": [{"predicate": "true", "type": "rsql"}],
			},
		]}}},
		"globalAccessRoles": {"byRole": {"ROLE_GLOBAL": {"all": true}}},
	}

	# Subject has ROLE_VIEWER which matches neither ROLE_GLOBAL nor ROLE_ADMIN
	result := data.authorize with input as {
		"resources": [{"resourceType": "Product", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == false
}

# --- missing condition and missing predicate: policy with only roles/type/op ---

test_condition_missing_predicate_missing_rls_allows_when_no_ast if {
	policies := {
		"ols": {"WIDGET": {"CREATE": ["ROLE_VIEWER"]}},
		"rls": {"WIDGET": {"CREATE": {"ROLE_VIEWER": [
			{},
		]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Widget", "operation": "CREATE"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
}

# --- malformed policy: rls entry with bad condition type is treated as deny ---

test_malformed_rls_wrong_condition_type_denies if {
	policies := {
		"ols": {"PRODUCT": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"PRODUCT": {"READ": {"ROLE_VIEWER": [
			{"condition": 42, "predicates": [{"predicate": "x", "type": "rsql"}]},
		]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Product", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == false
}

# --- Rego is endpoint-agnostic: canonical output even when extra fields are present ---

test_rego_ignores_unknown_extra_fields if {
	policies := {
		"ols": {"PRODUCT": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"PRODUCT": {"READ": {"ROLE_VIEWER": [
			{
				"condition": true,
				"predicates": [{"predicate": "true", "type": "rsql"}],
			},
		]}}},
	}

	# Extra unknown fields must not break Rego or change the canonical output shape.
	result := data.authorize with input as {
		"resources": [{"resourceType": "Product", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
		"unknownField": "ignored",
		"anotherExtra": 42,
	}
		with data.authn as authn
		with data.policies as policies

	result.rlsIgnored == false
	result.results[0].isAllowed == true
}

# --- Canonical output has required top-level fields ---

test_canonical_output_has_rls_ignored_and_results if {
	policies := {
		"ols": {"PRODUCT": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"PRODUCT": {"READ": {"ROLE_VIEWER": [{"condition": true, "predicates": [{"predicate": "true", "type": "rsql"}]}]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Product", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
	}
		with data.authn as authn
		with data.policies as policies

	is_boolean(result.rlsIgnored)
	is_array(result.results)
}

# --- canonical result has required fields per entry ---

test_canonical_result_entry_has_resource_type_operation_is_allowed if {
	policies := {
		"ols": {"PRODUCT": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"PRODUCT": {"READ": {"ROLE_VIEWER": [{"condition": true, "predicates": [{"predicate": "true", "type": "rsql"}]}]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Product", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
	}
		with data.authn as authn
		with data.policies as policies

	entry := result.results[0]
	is_string(entry.resourceType)
	is_string(entry.operation)
	is_boolean(entry.isAllowed)
}

# --- predicates[] present in canonical result for non-trivial predicate ---

test_predicates_array_included_when_non_empty if {
	policies := {
		"ols": {"PRODUCT": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"PRODUCT": {"READ": {"ROLE_VIEWER": [
			{
				"condition": true,
				"predicates": [{"predicate": "ownerId==${subject.id}", "type": "rsql"}],
			},
		]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Product", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
	# predicates[] should be present since there is a non-trivial rsql predicate (ADR-0029).
	is_array(result.results[0].predicates)
	some i
	result.results[0].predicates[i].predicateType == "rsql"
	# D-AF-R (OQ-AF-6, 2026-04-15): canonical subject attribute
	# `id` renders UNQUOTED in predicates; only PIP-resolved
	# (non-canonical) scalar strings are JSON-quoted.
	result.results[0].predicates[i].predicate == "ownerId==user-allow"
}

# --- no predicates[] when all predicates are trivial (predicate=true) ---

test_no_predicates_array_when_all_trivial if {
	policies := {
		"ols": {"PRODUCT": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"PRODUCT": {"READ": {"ROLE_VIEWER": [
			{
				"condition": true,
				"predicates": [{"predicate": "true", "type": "rsql"}],
			},
		]}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Product", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
	not result.results[0].predicates
}

# --- ignoreRls=true: no predicates[] in result ---

test_rls_not_required_no_predicates_in_result if {
	policies := {
		"ols": {"PRODUCT": {"READ": ["ROLE_VIEWER"]}},
		"rls": {},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Product", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": true,
	}
		with data.authn as authn
		with data.policies as policies

	result.rlsIgnored == true
	result.results[0].isAllowed == true
	not result.results[0].predicates
}
