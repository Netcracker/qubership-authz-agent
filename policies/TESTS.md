# OPA Test Suites

## Purpose

This directory contains contract-focused tests for the Authz Agent OPA layer.
The suites are specification-first and aligned with the policy grammar and
limitation documentation in the internal access-control source repository,
and with the current project docs in `docs/ai/`.

## Suite Inventory

1. `authorize_contract_test.rego`
   - Validates canonical `/access/v1/authorize` behavior against golden fixtures.
   - Covers the canonical decision matrix:
     - omitted `ignoreRls` defaults to `false` (RLS evaluated);
     - explicit `ignoreRls=true` keeps OLS-only behavior;
     - explicit `ignoreRls=false` covers OLS allow + RLS allow, OLS allow + RLS deny, and OLS deny short-circuit;
     - multi-resource order is preserved;
     - canonical `predicates[]` emission and omission rules stay stable.
   - Fixture source: `fixtures/authorize/<case>/{input.json,policies.json,golden.json,simplified-policies.json}`.
2. `policy_language_contract_test.rego`
   - Validates policy language semantics through canonical authorize evaluation.
   - Uses normalized `conditionAst`/`condition` fixtures and asserts expected `ALLOW`/`DENY` plus canonical `predicates[]` behavior.
   - Fixture source: `fixtures/policy_language/cases.json`.
3. `token_auth_contract_test.rego`
   - Validates authentication and subject normalization behavior for bearer-token inputs.
   - Covers:
     - valid token;
     - service token;
     - expired token;
     - wrong issuer;
     - unknown `kid`;
     - no roles;
     - object-form `subject` rejection;
     - anonymous compatibility mode;
     - `realm_access.roles`-only role derivation (ADR-0019);
     - non-realm claims (`groups`, `authorities`, direct `roles`, `resource_access.*.roles`) ignored;
     - large role-cardinality corner cases.
4. `normalization_contract_test.rego`
   - Validates normalized OLS/RLS data behavior without waiting for the future loader/import path.
   - Covers:
     - `condition=true` fallback;
     - `predicate=true` fallback and canonical predicate omission;
     - role-scoped RLS selection;
     - wildcard access-role normalization and behavior for explicit-role `ALL/ALL`,
       `ALL/<operation>`, and `<resourceType>/ALL`;
     - unconditional-allow short-circuit semantics for all three wildcard buckets;
     - malformed normalization entries;
     - filter and bulk remapping behavior.
5. `test/scripts/test-envoy-runtime.sh`
   - Starts Keycloak plus `authz-agent` through Docker Compose.
   - Executes the Testify integration suite from the host via `go test`.
   - Uploads simplified runtime policies through the guarded pap-client endpoint during suite setup.
   - Mounts writable authn bootstrap data through the Compose-managed runtime volume.
   - Mirrors the implemented legacy check-endpoint integration coverage from
     the internal access-control source repository
     (`CheckEndpointTest.java` and `CheckEndpointV2Test.java`).

## Subject Contract

All canonical authorize contract paths, including Rego policy suites, must provide `subject` as bearer token string.
Predecoded object-form `subject` is not part of the contract and must not be used as a test-only bypass.

## Canonical Case Matrix

`authorize_contract_test.rego` is expected to keep the following combinations covered:

| Area | Required combinations |
| --- | --- |
| `ignoreRls` mode | omitted => `false` (RLS evaluated), explicit `false`, explicit `true` |
| OLS/RLS outcome | OLS allow + RLS allow, OLS allow + RLS deny, OLS deny short-circuit |
| Canonical response shape | `rlsIgnored`, `results[]` order, `predicates[]` present for non-trivial allow, omitted for `DENY`, omitted for OLS-only or `predicate=true` |
| Input shape | signed bearer-token `subject`, multi-resource payload, stable fixture-based golden responses |

## Token Auth Matrix

`token_auth_contract_test.rego` is expected to cover the following identity combinations:

| Area | Required combinations |
| --- | --- |
| Token validity | valid, expired, wrong issuer, unknown `kid` |
| Subject type | user token, service token, anonymous compatibility flow, `verifiedTokens` cache-hit fast path |
| Role cardinality | zero roles, single role, many roles, many roles with one match, many roles with no match |
| Role claim sources | `realm_access.roles` only (ADR-0019); non-realm claims (`groups`, `authorities`, direct `roles`, `resource_access.*.roles`) verified as ignored |
| Role normalization | uppercase normalization, duplicate elimination |
| Rejection paths | object-form `subject` rejected even with internal flags |

Large-role corner cases should stay covered by helper-level tests that prove:

1. very large role lists are deduplicated and normalized;
2. one matching role among many still grants OLS access;
3. many non-matching roles still deny access.
4. duplicate role names with different casing in `realm_access.roles` collapse to one normalized role.

The many-role input matrix must explicitly include:

| Case | Required combinations |
| --- | --- |
| Matching role amid noise | `ROLE_VIEWER` present once logically in `realm_access.roles`, plus at least 40 unrelated roles |
| No matching role | large `realm_access.roles` payload without `ROLE_VIEWER` |
| Case-folded duplicates | lower/mixed/upper-case duplicates for the same logical role in `realm_access.roles` |

## Policy Language Coverage Matrix

The `policy_language` suite covers all documented condition operators and key grammar semantics:

| Grammar area | Covered by cases |
| --- | --- |
| `EQUALS`, `NOT EQUALS`, `==`, `!=`, `=` | `equals_keyword_case_insensitive_allow`, `equals_double_equals_allow`, `equals_single_equals_allow`, `not_equals_keyword_deny`, `not_equals_bang_equals_allow`, `equals_operand_order_literal_left_allow` |
| `CONTAINS`, `NOT CONTAINS` | `contains_allow`, `not_contains_deny` |
| `CONTAINS ANY`, `NOT CONTAINS ANY` | `contains_any_allow`, `not_contains_any_allow` |
| `IN`, `NOT IN` | `in_allow`, `not_in_deny` |
| `MATCH`, `NOT MATCH` | `match_allow`, `not_match_allow` |
| `IS EMPTY`, `IS NOT EMPTY` | `is_empty_allow`, `is_not_empty_allow` |
| `GREATER THAN`, `>` | `greater_than_word_allow`, `greater_than_symbol_allow` |
| `GREATER THAN OR EQUALS TO`, `>=` | `greater_or_equal_word_allow`, `greater_or_equal_symbol_allow` |
| `LESS THAN`, `<` | `less_than_word_allow`, `less_than_symbol_allow` |
| `LESS THAN OR EQUALS TO`, `<=` | `less_or_equal_word_allow`, `less_or_equal_symbol_allow` |
| `IS NULL`, `IS NOT NULL` | `is_null_allow`, `is_not_null_allow` |
| `IS SUBSET`, `IS NOT SUBSET` | `is_subset_allow`, `is_not_subset_allow` |
| Boolean literals (`true`, `false`) | `boolean_true_allow`, `boolean_false_deny` |
| Boolean precedence (`AND` over `OR`) and parentheses | `and_priority_over_or_allow`, `parenthesized_expression_deny` |
| Special operator `has access` + nesting depth limit | `has_access_allowed`, `has_access_denied`, `has_access_nested_depth_limit_deny` |
| JSONPath resource expressions (multi-valued) | `jsonpath_multivalue_contains_any_allow` |

## Runtime Coverage Matrix

`test/scripts/test-envoy-runtime.sh` plus the Testify suite are expected to keep the following runtime combinations covered:

| Area | Required combinations |
| --- | --- |
| Canonical authorize | omitted `ignoreRls` => `rlsIgnored=false`, auth failures, malformed requests, multi-resource ordering |
| Legacy check/resource | `Incoming-Token` precedence, `401` mapping, tenant invariance, null body => `400`, missing required fields => `400`, wrong address => `404` |
| Legacy check/resource/bulk | denied IDs, empty array, malformed entries, null body => `400`, missing required fields => `400`, tenant invariance, large payload of 3000 allowed IDs with non-restrictive RLS, wrong address => `404` |
| Legacy check/filter | `calculationResult`, deny/allow paths, tenant invariance, missing `resourceType` => `400`, wrong address => `404` |
| Public boundary | `/authorize` and `/v1/data/authorize` not exposed; not-yet-implemented legacy routes return `404` |
| Runner behavior | Compose stack detached from host-side Go test execution, step-level PASS/FAIL reporting, catalog-validated coverage |

## Fixture Conventions

For each `policy_language` case:

1. `expression` stores the source language expression.
2. `conditionAst` or `condition` stores normalized Rego-evaluable representation.
3. `policyPredicate` defines the RSQL predicate attached to the normalized rule.
4. `expectedDecision` and optional `expectedPredicate` define the golden canonical authorize outcome.
5. `simplifiedPolicy` stores a simplified-policy sample that could produce this normalized rule.

## Notes

1. These tests intentionally validate full documented language behavior, even if current Rego implementation is not yet fully aligned.
2. Rego policy implementation files are intentionally not modified by this test suite.
3. `test/scripts/test-opa.sh` uses `policies/`; runtime stacks use mounted data from `test/integration/runtime/opa/runtime-data/` plus runtime-generated authn data.

## Token Toolkit for Tests

Use repository scripts to generate valid signed tokens for Rego/policy fixtures:

1. Generate provider key/JWKS material:

```bash
test/scripts/token-testkit/generate-rsa-jwks.sh
```

1. Generate a standard token fixture set:

```bash
test/scripts/token-testkit/generate-token-fixture-set.sh
```

1. Generate one-off token:

```bash
test/scripts/token-testkit/mint-jwt.sh --help
```

Default generation path is `/tmp/authz-token-testkit`.

To refresh the committed Rego fixtures used by the suites above:

```bash
test/scripts/token-testkit/refresh-rego-fixtures.sh
```

Runtime/integration auth checks intentionally do not use these repository fixture outputs; they request real tokens from Keycloak through `test/scripts/test-envoy-runtime.sh`.
