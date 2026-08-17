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

package policy_language_contract_test

import rego.v1

test_policy_language_fixture_integrity if {
  names := case_names
  invalid := [name |
    name := names[_]
    case := fixture_cases[name]
    not case_is_valid(name, case)
  ]
  print({"policy_language_invalid_fixture_cases": invalid})
  count(invalid) == 0
}

test_policy_language_authorize_against_spec if {
  names := case_names
  failed := [name |
    name := names[_]
    case := fixture_cases[name]
    actual := evaluate_case(name, case)
    expected := expected_case(case)
    # ADR-0069 adds a non-deterministic requestId echo; strip before shape compare.
    object.remove(actual, {"requestId"}) != expected
  ]
  print({"policy_language_failed_cases": failed})
  count(failed) == 0
}

case_names := sort(object.keys(fixture_cases))

fixture_suite := normalize_object(data.fixtures.policy_language)
fixture_tokens := normalize_object(object.get(fixture_suite, "tokens", {}))
fixture_cases := normalize_object(object.get(fixture_suite, "cases", {}))
identity_fixtures := normalize_object(data.fixtures.identity)

suite_resource_type := sprintf("%v", [object.get(fixture_suite, "resourceType", "PolicyLanguageResource")])
suite_operation := sprintf("%v", [object.get(fixture_suite, "operation", "READ")])
suite_role := upper(sprintf("%v", [object.get(fixture_suite, "role", "ROLE_LANG")]))

evaluate_case(name, case) := actual if {
  subject_token := case_subject_token(name)

  request := {
    "resources": [
      {
        "resourceType": case_resource_type(case),
        "operation": case_operation(case),
        "resource": normalize_object(object.get(case, "resource", {}))
      }
    ],
    "subject": subject_token,
    "ignoreRls": false
  }

  policies := {
    "ols": {
      upper(case_resource_type(case)): {
        upper(case_operation(case)): [case_role(case)]
      }
    },
    "rls": {
      upper(case_resource_type(case)): {
        upper(case_operation(case)): {
          case_role(case): [case_rule(case)]
        }
      }
    }
  }

  pips := normalize_object(object.get(case, "pips", {}))

  actual := data.authorize
    with input as request
    with data.authn as normalize_object(object.get(identity_fixtures, "authn", {}))
    with data.policies as policies
    with data.pips as pips
}

case_subject_token(name) := sprintf("Bearer %v", [token]) if {
  token := sprintf("%v", [object.get(fixture_tokens, name, "")])
  token != ""
}

expected_case(case) := {
  "rlsIgnored": false,
  "results": [expected_result_item(case)]
}

expected_result_item(case) := {
  "resourceType": case_resource_type(case),
  "operation": case_operation(case),
  "isAllowed": true,
  "predicates": [{"predicate": expected_predicate, "predicateType": "rsql"}],
} if {
  expected_decision(case) == "ALLOW"
  expected_predicate := sprintf("%v", [object.get(case, "expectedPredicate", "")])
  expected_predicate != ""
}

expected_result_item(case) := {
  "resourceType": case_resource_type(case),
  "operation": case_operation(case),
  "isAllowed": true
} if {
  expected_decision(case) == "ALLOW"
  expected_predicate := sprintf("%v", [object.get(case, "expectedPredicate", "")])
  expected_predicate == ""
}

expected_result_item(case) := {
  "resourceType": case_resource_type(case),
  "operation": case_operation(case),
  "isAllowed": false,
  "reason": sprintf("ABAC validations failed for roles {%v}", [case_role(case)]),
} if {
  expected_decision(case) != "ALLOW"
}

expected_decision(case) := upper(sprintf("%v", [object.get(case, "expectedDecision", "DENY")]))

case_rule(case) := {
  "condition": object.get(case, "condition", false),
  "predicates": [
    {
      "predicate": case_policy_predicate(case),
      "type": "rsql"
    }
  ]
} if {
  object.get(case, "condition", "__missing__") != "__missing__"
}

case_rule(case) := {
  "conditionAst": normalize_object(object.get(case, "conditionAst", {})),
  "predicates": [
    {
      "predicate": case_policy_predicate(case),
      "type": "rsql"
    }
  ]
} if {
  object.get(case, "condition", "__missing__") == "__missing__"
}

case_resource_type(case) := sprintf("%v", [object.get(case, "resourceType", suite_resource_type)])
case_operation(case) := sprintf("%v", [object.get(case, "operation", suite_operation)])
case_role(case) := upper(sprintf("%v", [object.get(case, "role", suite_role)]))
case_policy_predicate(case) := sprintf("%v", [object.get(case, "policyPredicate", "true")])

case_is_valid(name, case) if {
  expression := sprintf("%v", [object.get(case, "expression", "")])
  expression != ""

  expected := upper(sprintf("%v", [object.get(case, "expectedDecision", "")]))
  is_expected_decision(expected)

  role := case_role(case)
  role != ""

  subject := normalize_object(object.get(case, "subject", {}))
  count(object.keys(subject)) > 0

  simplified := normalize_object(object.get(case, "simplifiedPolicy", {}))
  count(object.keys(simplified)) > 0
  roles := normalize_array(object.get(simplified, "roles", []))
  count(roles) > 0

  case_subject_token(name) != ""
  has_condition_shape(case)
}

has_condition_shape(case) if {
  object.get(case, "condition", "__missing__") != "__missing__"
}

has_condition_shape(case) if {
  ast := normalize_object(object.get(case, "conditionAst", {}))
  count(object.keys(ast)) > 0
}

is_expected_decision("ALLOW")
is_expected_decision("DENY")

normalize_array(value) := value if {
  is_array(value)
}

normalize_array(value) := [] if {
  not is_array(value)
}

normalize_object(value) := value if {
  is_object(value)
}

normalize_object(value) := {} if {
  not is_object(value)
}
