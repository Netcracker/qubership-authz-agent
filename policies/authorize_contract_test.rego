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

package authorize_contract_test

import rego.v1

fixtures := data.fixtures.identity

# Evaluates authorize rule against a case fixture.
evaluate(case) := actual if {
  request := request_for_case(case)
  policies := policies_for_case(case)
  actual := data.authorize
    with input as request
    with data.authn as fixtures.authn
    with data.policies as policies
}

expected(case) := normalize_object(object.get(case, "golden", {})) if {
  object.get(case, "golden", "__missing__") != "__missing__"
}

expected(case) := {
  "rlsIgnored": object.get(case, "rlsIgnored", false),
  "results": normalize_array(object.get(case, "results", []))
} if {
  object.get(case, "golden", "__missing__") == "__missing__"
}

# ADR-0069 adds a non-deterministic `requestId` echo to data.authorize (uuid when
# the inbound id is absent, as in these fixtures). Strip it before the shape
# compare; its presence/value is asserted directly in the requestId echo tests.
matches_golden(case) if {
  object.remove(evaluate(case), {"requestId"}) == expected(case)
}

# ADR-0069: requestId is echoed on every canonical response. When the inbound
# input.requestId is present it wins verbatim; when absent OPA generates a
# non-empty id. Uses a golden case's own input so the full pipeline runs.
test_authorize_echoes_inbound_request_id if {
  case := data.fixtures.authorize.canonical_rls_default_true_when_omitted
  request := object.union(request_for_case(case), {"requestId": "R-echo-123"})
  actual := data.authorize
    with input as request
    with data.authn as fixtures.authn
    with data.policies as policies_for_case(case)
  actual.requestId == "R-echo-123"
}

test_authorize_generates_request_id_when_absent if {
  case := data.fixtures.authorize.canonical_rls_default_true_when_omitted
  actual := data.authorize
    with input as request_for_case(case)
    with data.authn as fixtures.authn
    with data.policies as policies_for_case(case)
  actual.requestId != ""
}

test_authorize_canonical_rls_default_true_when_omitted if {
  case := data.fixtures.authorize.canonical_rls_default_true_when_omitted
  matches_golden(case)
}

test_authorize_canonical_rls_true_allow_with_predicate if {
  case := data.fixtures.authorize.canonical_rls_true_allow_with_predicate
  matches_golden(case)
}

test_authorize_canonical_rls_true_ols_allow_but_rls_deny if {
  case := data.fixtures.authorize.canonical_rls_true_ols_allow_but_rls_deny
  matches_golden(case)
}

test_authorize_canonical_rls_true_ols_deny_short_circuit if {
  case := data.fixtures.authorize.canonical_rls_true_ols_deny_short_circuit
  matches_golden(case)
}

test_authorize_canonical_multi_resource_order_preserved if {
  case := data.fixtures.authorize.canonical_multi_resource_order_preserved
  matches_golden(case)
}

request_for_case(case) := normalize_object(object.get(case, "input", {})) if {
  object.get(case, "input", "__missing__") != "__missing__"
  token_ref := sprintf("%v", [object.get(normalize_object(object.get(case, "input", {})), "subjectTokenRef", "")])
  token_ref == ""
}

request_for_case(case) := object.union(
  object.remove(raw, ["subjectTokenRef"]),
  {"subject": subject_from_token_ref(token_ref)}
) if {
  raw := normalize_object(object.get(case, "input", {}))
  token_ref := sprintf("%v", [object.get(raw, "subjectTokenRef", "")])
  token_ref != ""
}

request_for_case(case) := {
  "resources": normalize_array(object.get(case, "resources", [])),
  "subject": subject_from_token_ref(token_ref),
  "ignoreRls": object.get(case, "ignoreRls", false)
} if {
  object.get(case, "input", "__missing__") == "__missing__"
  token_ref := sprintf("%v", [object.get(case, "subjectTokenRef", "")])
  token_ref != ""
}

request_for_case(case) := {
  "resources": normalize_array(object.get(case, "resources", [])),
  "subject": object.get(case, "subject", {}),
  "ignoreRls": object.get(case, "ignoreRls", false)
} if {
  object.get(case, "input", "__missing__") == "__missing__"
  token_ref := sprintf("%v", [object.get(case, "subjectTokenRef", "")])
  token_ref == ""
}

policies_for_case(case) := normalize_object(object.get(case, "policies", {})) if {
  object.get(case, "policies", "__missing__") != "__missing__"
}

policies_for_case(case) := {
  "ols": normalize_object(object.get(case, "ols", {})),
  "rls": normalize_object(object.get(case, "rls", {}))
} if {
  object.get(case, "policies", "__missing__") == "__missing__"
}

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

subject_from_token_ref(token_ref) := sprintf("Bearer %v", [token]) if {
  token := sprintf("%v", [object.get(fixtures.tokens, token_ref, "")])
  token != ""
}
