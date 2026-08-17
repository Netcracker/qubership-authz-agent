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

package wildcard_access_contract_test

import rego.v1

fixtures := data.fixtures.identity

valid_token := fixtures.tokens.valid

authn := fixtures.authn

# ── Request-level short-circuit: all ────────────────────────────────────

test_wildcard_all_allows_any_resource if {
	policies := {
		"ols": {},
		"rls": {},
		"globalAccessRoles": {"byRole": {"ROLE_VIEWER": {"all": true}}},
	}

	result := data.authorize with input as {
		"resources": [
			{"resourceType": "Customer", "operation": "READ"},
			{"resourceType": "Order", "operation": "DELETE"},
		],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
	result.results[1].isAllowed == true
}

test_wildcard_all_no_predicates if {
	policies := {
		"ols": {},
		"rls": {},
		"globalAccessRoles": {"byRole": {"ROLE_VIEWER": {"all": true}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Order", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
	not result.results[0].predicates
}

test_wildcard_all_no_deny_reason if {
	policies := {
		"ols": {},
		"rls": {},
		"globalAccessRoles": {"byRole": {"ROLE_VIEWER": {"all": true}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Order", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	not result.results[0].reason
}

# ── Per-resource short-circuit: operations ──────────────────────────────

test_wildcard_operations_match if {
	policies := {
		"ols": {},
		"rls": {},
		"globalAccessRoles": {"byRole": {"ROLE_VIEWER": {"operations": {"READ": true}}}},
	}

	result := data.authorize with input as {
		"resources": [
			{"resourceType": "Customer", "operation": "READ"},
			{"resourceType": "Order", "operation": "READ"},
		],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
	result.results[1].isAllowed == true
	not result.results[0].predicates
	not result.results[1].predicates
}

test_wildcard_operations_no_match_different_op if {
	policies := {
		"ols": {},
		"rls": {},
		"globalAccessRoles": {"byRole": {"ROLE_VIEWER": {"operations": {"READ": true}}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Customer", "operation": "DELETE"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": true,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == false
}

test_wildcard_operations_no_deny_reason if {
	policies := {
		"ols": {},
		"rls": {},
		"globalAccessRoles": {"byRole": {"ROLE_VIEWER": {"operations": {"READ": true}}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Order", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	not result.results[0].reason
}

# ── Per-resource short-circuit: resourceTypes ───────────────────────────

test_wildcard_resource_types_match if {
	policies := {
		"ols": {},
		"rls": {},
		"globalAccessRoles": {"byRole": {"ROLE_VIEWER": {"resourceTypes": {"ORDER": true}}}},
	}

	result := data.authorize with input as {
		"resources": [
			{"resourceType": "ORDER", "operation": "READ"},
			{"resourceType": "ORDER", "operation": "DELETE"},
		],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
	result.results[1].isAllowed == true
	not result.results[0].predicates
}

test_wildcard_resource_types_no_match_different_rt if {
	policies := {
		"ols": {},
		"rls": {},
		"globalAccessRoles": {"byRole": {"ROLE_VIEWER": {"resourceTypes": {"ORDER": true}}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Customer", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": true,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == false
}

# ── Multi-resource mixed: some wildcard, some exact OLS -> RLS ──────────

test_mixed_wildcard_and_exact if {
	policies := {
		"ols": {"CUSTOMER": {"READ": ["ROLE_VIEWER"]}},
		"rls": {"CUSTOMER": {"READ": {"ROLE_VIEWER": [
			{
				"condition": true,
				"predicates": [{"predicate": "ownerId==${subject.id}", "type": "rsql"}],
			},
		]}}},
		"globalAccessRoles": {"byRole": {"ROLE_VIEWER": {"operations": {"DELETE": true}}}},
	}

	result := data.authorize with input as {
		"resources": [
			{"resourceType": "Customer", "operation": "DELETE"},
			{"resourceType": "Customer", "operation": "READ", "resource": {"id": "cust-1"}},
			{"resourceType": "Invoice", "operation": "DELETE"},
		],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	# DELETE wildcard-matched
	result.results[0].isAllowed == true
	not result.results[0].predicates

	# READ goes through exact OLS -> RLS
	result.results[1].isAllowed == true
	is_array(result.results[1].predicates)

	# Invoice DELETE wildcard-matched
	result.results[2].isAllowed == true
	not result.results[2].predicates
}

# ── Normal OLS -> RLS path still works when no wildcard-access role ─────

test_no_wildcard_access_normal_ols_rls if {
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
	is_array(result.results[0].predicates)
}

test_no_wildcard_access_normal_deny if {
	policies := {
		"ols": {},
		"rls": {},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Product", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": true,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == false
}

# ── Wildcard role not in subject: no short-circuit ──────────────────────

test_wildcard_role_not_in_subject_denies if {
	policies := {
		"ols": {},
		"rls": {},
		"globalAccessRoles": {"byRole": {"ROLE_SUPERADMIN": {"all": true}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Product", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": true,
	}
		with data.authn as authn
		with data.policies as policies

	# Subject has ROLE_VIEWER, not ROLE_SUPERADMIN
	result.results[0].isAllowed == false
}

# ── rlsIgnored reflects effective mode, not wildcard bypass ─────────────

test_rls_ignored_reflects_input_mode if {
	policies := {
		"ols": {},
		"rls": {},
		"globalAccessRoles": {"byRole": {"ROLE_VIEWER": {"all": true}}},
	}

	result_rls_true := data.authorize with input as {
		"resources": [{"resourceType": "Order", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": false,
	}
		with data.authn as authn
		with data.policies as policies

	result_rls_true.rlsIgnored == false

	result_rls_false := data.authorize with input as {
		"resources": [{"resourceType": "Order", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": true,
	}
		with data.authn as authn
		with data.policies as policies

	result_rls_false.rlsIgnored == true
}

# ── Case insensitivity: wildcard lookup matches uppercased keys ─────────

test_wildcard_operations_case_insensitive if {
	policies := {
		"ols": {},
		"rls": {},
		"globalAccessRoles": {"byRole": {"ROLE_VIEWER": {"operations": {"READ": true}}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "Customer", "operation": "read"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": true,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
}

test_wildcard_resource_types_case_insensitive if {
	policies := {
		"ols": {},
		"rls": {},
		"globalAccessRoles": {"byRole": {"ROLE_VIEWER": {"resourceTypes": {"ORDER": true}}}},
	}

	result := data.authorize with input as {
		"resources": [{"resourceType": "order", "operation": "READ"}],
		"subject": sprintf("Bearer %v", [valid_token]),
		"ignoreRls": true,
	}
		with data.authn as authn
		with data.policies as policies

	result.results[0].isAllowed == true
}
