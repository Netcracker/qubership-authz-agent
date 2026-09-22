# Parity Test Suite

The parity suite replays 129 captured test cases against the authz-agent and
compares the answers with golden files recording how the legacy access-control
service answered the same requests.

## What the goldens are

The JSON files under [`suite/testdata/golden/`](suite/testdata/golden/) are a
**frozen capture** of the legacy `access-control` service's behaviour. They
were recorded against a running instance of the legacy service (which is not
part of this repository) and committed as the reference baseline.

They cannot be regenerated from this repository. If you change authz-agent
behaviour in a way that alters the answers to these cases, the affected
goldens must be updated by hand (or the divergence recorded in
[`suite/accepted_divergences.go`](suite/accepted_divergences.go) with a
rationale). The goldens are evidence of which cases the authz-agent matches
the legacy service on; they are not a test oracle that can be refreshed
without access to the original service.

## Prerequisites

1. **Docker**, **kind**, **kubectl**, and **helm** on the host.
2. **Go 1.24+** to run the suite module's own unit tests (`cd test/parity/suite && go test ./...`).

## Run the replay suite

```bash
make parity        # cluster, images, harness, chart, suite in namespace authz-parity
make parity-logs   # artifacts into test/artifacts/kind/parity/
```

`make parity` runs the shared `e2e-cluster` and `e2e-images` targets first (every image the replay needs, including
the suite image built from [`suite/Dockerfile`](suite/Dockerfile)), then:

| Target | What it does |
| --- | --- |
| `parity-harness` | Namespace `authz-parity`; Keycloak as `idp` in dev mode with the two realm imports; `pip-mock` with the request-args rule set; `entitlements-mock`; the M2M client-credentials Secret |
| `parity-install` | `helm upgrade --install` of the stub chart with [`test/k8s/parity/policy-admin-values.yaml`](../k8s/parity/policy-admin-values.yaml), then of the agent chart with [`test/k8s/parity/values.yaml`](../k8s/parity/values.yaml) |
| `parity-suite` | The Job from [`test/k8s/parity/parity-suite-job.yaml`](../k8s/parity/parity-suite-job.yaml); its log is streamed |

Expected result: 135/135 cases green against authz-agent, and the cases that wait for a golden skipped (see
[Cases waiting for a golden](#cases-waiting-for-a-golden)). CI runs the same targets (job `Parity on kind` in
`.github/workflows/integration-tests.yaml`).

The suite addresses `authz-agent`, `idp`, `pip-mock`, and `entitlements-mock` by Service name; nothing is published on
the host. To look at the stack from the host, port-forward, for example
`kubectl --context kind-authz-e2e -n authz-parity port-forward svc/authz-agent 28100:8080`.

### Iterating

After a change to the suite, `make e2e-images parity-suite` rebuilds the images and reruns the Job; the harness and
the chart stay. After a change to the product, run `make e2e-images parity-restart parity-suite`: the images keep their
tags, so the running Pods have to be restarted to pick the new build up. `make parity-install parity-suite` picks up
changed chart values.

### Teardown

```bash
kubectl --context kind-authz-e2e delete namespace authz-parity   # the replay only
make e2e-down                                                     # the whole cluster
```

## Identity provider

The `idp` Deployment runs the public Keycloak image (`quay.io/keycloak/keycloak`, the version the goldens were
captured against). The two realm import files
([`cloud-common-realm.json`](../k8s/parity/idp-seed/cloud-common-realm.json) and
[`parity-realm.json`](../k8s/parity/idp-seed/parity-realm.json)) use only built-in Keycloak protocol mappers and
require no custom SPI extensions. The suite calls the standard OIDC token endpoint
(`/auth/realms/parity/protocol/openid-connect/token`) for `client_credentials` and `password` grants; no custom
Keycloak REST APIs are involved.

`KC_HTTP_RELATIVE_PATH=/auth` is set so the realm is reachable at `/auth/realms/parity/...` (Keycloak dropped the
`/auth` prefix in v17; the parity fixtures carry that prefix throughout, so it is restored via config). It prefixes the
management endpoints too, which is why the probes hit `/auth/health/ready`.

## Goldens, accepted divergences, and the divergence backlog

The 129 committed goldens represent the legacy service's answers. The
authz-agent is expected to match all of them; cases where it intentionally
differs are listed in
[`suite/accepted_divergences.go`](suite/accepted_divergences.go) with a
recorded rationale (decision ID + reason string).

When authz-agent behaviour changes in a way that affects a previously-green
case:

- If the new behaviour is correct (i.e. the legacy answer was a bug): add an
  entry to `accepted_divergences.go` with the rationale.
- If the new behaviour is a regression: fix the regression.
- The golden files themselves should not be edited — they are the record of
  what the legacy service did, not a living test spec.

## A GENERAL PIP returns a string to a condition and anything to a template

Which converter a PIP value meets depends on how the policy reads the alias, and only one of the two casts.

A PIP alias standing as one operand of a condition resolves through `SingleOperandVisitor` to `PipReturnType.SINGLE`,
whose converter is `SinglePipDataConverter`. It declares `PipDataConverter<String>` and casts the JSONPath match to
`String` with no check. A GENERAL PIP whose JSON holds a number or a boolean therefore raises a `ClassCastException`
inside the rule; the rule fails with a `DenyEffectException` logged as `Can not calculate rule with id <uuid>`, and the
decision is `false` whatever the condition says.

A condition fixture that pins a GENERAL PIP to `{"value": 1000}` consequently does not record a comparison — it records
the exception path, and it would record the same `false` for every condition and every resource. Pin `{"value": "1000"}`
instead: the comparison operators coerce the string, so `resource.amount <= subject.x` still answers by magnitude and
the golden means what the case name says. That is why the two-tenant fixtures below use strings and why `t8a` and `t8b`
differ by tenant rather than both denying.

A `${subject.x}` placeholder in an `rsqlPredicate` template takes the other route and is unaffected.
`SpelContextStrLookup.lookup` asks `DataProviderGetter` for the alias, `AllOperandsVisitor` answers with
`PipReturnType.MULTIPLE`, the value stays a `Set`, and `collectionToDelimitedString(coll, ",", "\"", "\"")` renders it.
Nothing casts, so `{"value": 1000}` and `{"value": "1000"}` both render `amount=lt="1000"`. The cases in
`test_row06_sub_cases_test.go` pin a number, a boolean and a string and all of them record real substitutions;
`TestRow06CheckFilterV1GeneralScalarNumberAsString` is the string twin of the number case and exists to hold that
equality in place.

## Cases waiting for a golden

Some cases are written before access-control has answered them, so that the answers can be recorded on a live
access-control outside this repository. Such a case compares through `requirePendingGolden` instead of
`requireGolden`: while its golden file is missing, it skips and prints the answer it got, for example
`golden check-resource-v1/semantics/s2b-neq-attribute-absent is not recorded yet; the authz-agent profile answered false`. Once the
golden is committed, the case compares like any other. A case that uses `requireGolden` still fails when its golden is
missing.

| Test | What it asks access-control | Goldens under `suite/testdata/golden/` |
| --- | --- | --- |
| `TestRow02CheckResourceV1MissingResourceAttribute`, `…MissingAttributeUnderOr`, `…MissingAttributeBesideAllowingPolicy`, `…MissingPIPAttribute`, `…FailedGeneralPIP`, `…GeneralPIPJsonPathMatchesNothing`, `…ExpressionShape` | What a condition answers when an attribute it reads is missing, and how `OR`, `AND`, and long expressions evaluate | `check-resource-v1/semantics/` |
| `TestRow06CheckFilterV1MissingPIPAttribute` | Which predicate survives when a policy reads a TOKEN PIP with no value | `check-filter-v1/semantics/` |
| `TestRow02CheckResourceV1NullValueUnderOperators`, `…ValueCoercion`, `…GeneralPIPNotFound`, `…GeneralPIPNullBody` | Where a null value stops being a value, how operators coerce types, and how a GENERAL PIP answering 404 or a null body resolves | `check-resource-v1/semantics/` |
| `TestRow02CheckResourceV1RequestKeyCase`, `…ResourceNotAnObject` | What a lowercase resource type or operation, and a resource that is not an object, get, status included | `check-resource-v1-outcome/semantics/` |
| `TestRow03CheckResourceBulkV1MissingAttributeInOneResource` | Whether a policy that stops on one resource of a bulk request affects the other | `check-resource-bulk-v1/semantics/` |
| `TestRow06CheckFilterV1ConditionBesidePredicate`, `…PlaceholderOfFailedGeneralPIP` | Whether a filter applies a policy's condition to its predicate, and what a placeholder of a failed PIP renders, status included | `check-filter-v1-outcome/semantics/` |
| `TestLoadSimplifiedPoliciesConditionSyntax` | Whether the upload accepts parentheses, a standalone `NOT`, irregular spacing and case, and subject attributes no seeded policy uses | `load-simplified-policies-v1/condition-syntax/` |
| `TestRegularPolicySetCases` | How access-control evaluates regular policy sets: combining algorithms, ALLOW and DENY effects, nested sets, targets against conditions, predicates of several rules in a filter, and set lifecycle. Legacy profile only; the agent does not load regular policy sets | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestIsolatedPolicyCases` | Operator forms, attribute paths, subject attributes, literals, whitespace, declarations, and policy shapes the PAP may refuse, uploaded one case at a time into `PARITY_ISOLATED` | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/`, `check-filter-v1-outcome/isolated/` |
| `TestIsolatedConditionFormCases` | Forms the agent's own condition parser accepts and no golden records: the negated operators, the word forms of the comparisons, the single equals sign, the `/…/` regex literal, `FALSE` as a whole condition, and the `denied` access operator; plus `subject.scopes`, `subject.permissions` in a condition together with the `MAPPING` PIP that grants one, the `FILTERED` PIP, signed and fractional literals, and JSON Path beyond a plain or bracketed path | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestPermissionScopeIterateCases` | What `iterate.foreach` over `subject.permissionScope` evaluates: once per grant, or once over the grants merged into one map. It declares a `PERMISSION_SCOPE` PIP against pip-mock, pins three candidate wire formats in turn, and sends a literal-operand probe beside the scoped requests, so a shape access-control does not parse is told from one it does. Legacy profile only | `load-simplified-policies-v1/permission-scope/`, `load-policy-sets-v1/permission-scope/`, `check-resource-v1-outcome/permission-scope/` |
| `TestTenantScopedDecisions` | Which tenant a decision is scoped to, given the token, `tenant_id`, and the `Tenant` header | `check-resource-v1/tenant/`, `check-filter-v1/tenant/` |
| `TestTranslatorMatchDialectCases` | Which wildcard dialect `MATCH` speaks on a path: a star between segments and inside one, a double star away from the end and against zero segments, `?`, a trailing separator, a doubled separator, a query string, a percent-encoded separator, case, a pattern with no metacharacter, and a brace placeholder. Every case pairs a URI the pattern should select with one it should not | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestTranslatorValueSemanticsCases` | How equality, membership, and the relational operators treat a value whose JSON type or written form is not the literal's: the decimal forms of a number, an integer past the precision of a float64, an exponent, a relational operator over a string, a boolean, a null and a collection, case outside ASCII, and `CONTAINS` over numbers and over an object | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestTranslatorPolicySetCases` | What a regular policy set decides when every rule it holds is a DENY that did not apply, when the policy target kept the request from the DENY, and when a policy holds no rule; what a rule whose condition reads a failed or missing GENERAL PIP does to the allowing rule beside it, under each accepted algorithm; what `check/filter` returns for a resource type whose policy is a deny list; and what the filter carries when two sets name one rule id. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestInterpreterNullAndAbsenceCases` | What a condition answers over a null value under `<`, `>=`, `IS NOT NULL` and `IS NOT EMPTY`; whether `IS EMPTY`, `IS NOT EMPTY`, `NOT MATCH`, `NOT CONTAINS ANY`, `IS NOT SUBSET` and a JSON Path that selects nothing evaluate to a value or end the rule, each on the left of an `OR` whose right operand is true, with the operands swapped as the control; and the relational operators at the boundary `5` against `5.0` | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestInterpreterPermissionCaseCases` | Whether `subject.permissions CONTAINS` ignores case, against a permission a `MAPPING` PIP grants in mixed case | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestInterpreterDeadFormCases` | Whether the five forms the PAP accepts and always answers false (`resource['x']`, `!= null`, `MATCH` against an attribute, `MATCH` against a `/…/` literal, `subject allowed … on resource`) are false leaves or end the rule, each on the left of an `OR`; and what `!= null` does in a DENY rule and beside an allowing rule. The regular cases run on the legacy profile only | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/`, `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/` |
| `TestInterpreterCombiningCases` | What a policy with no rule for the operation, a policy with a false target, and a nested set with no applicable rule contribute to a set whose algorithm differs from theirs; every pair of distinct accepted algorithms over the requests of the `algorithm-*` cases. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/` |
| `TestInterpreterIterateAlgorithmCases`, `TestInterpreterIterateBindingCases` | How the passes of an iterating set are combined under `PERMIT_UNLESS_DENY` and `DENY_OVERRIDES`, and with no grant at all; whether `iterate.foreach` accepts `subject.roles` and `resource.items`; whether `subject.permissionScope` is readable outside an iterating set. Legacy profile only | `load-simplified-policies-v1/scope-iterate/`, `load-policy-sets-v1/scope-iterate/`, `check-resource-v1-outcome/scope-iterate/`, `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/` |
| `TestInterpreterFilterCases` | What `check/filter` returns for a rule with a condition and no predicate, alone and beside a rule with a predicate, for a rule with neither, for four groups of predicates on one type, for a request with no operation or the operation `ALL`, and for a target that reads the resource. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestInterpreterOperationAllCases` | Whether a simplified policy with `operation: ALL` evaluates its condition, and whether its predicate reaches a filter | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/`, `check-filter-v1-outcome/isolated/` |
| `TestInterpreterRegularLoadCases` | Whether the policy-set upload accepts `subject.isM2M`, an undeclared subject attribute, `operation` and `subject.permissions.<suffix>` in a rule condition. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/` |
| `TestInterpreterSetTargetCases` | Whether the policy-set upload accepts a set whose target reads `resource.service`, `resource.uri` under `MATCH`, `resource.id`, an attribute no policy names, and `resource.service` with no `resourceType` beside it; and what such a target decides on a request that carries the attribute, another value, no such attribute, no such attribute beside a sibling set that allows on its own, and on a filter request. Legacy profile only; the set with no `resourceType` is emptied when the test ends | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestInterpreterConfigExportCases` | What `GET /access/v3/config/policySets` and `GET /access/v3/config/pips`, the reads the agent loads its configuration from, carry for regular sets of every form, two simplified policies, and one PIP of each type, read with the tenant of the upload, the other tenant, no tenant, an unknown tenant, and a tenant in the query beside another in the `Tenant` header. The recorded body drops the envelope's `hash` and `lastModificationTimestamp` and keeps only the elements the case uploaded, ordered by their text. Legacy profile only; the reads that name tenant B skip without a two-tenant stand | `load-simplified-policies-v1/config-export/`, `load-policy-sets-v1/config-export/`, `config-policy-sets-v3/config-export/`, `config-pips-v3/config-export/` |

The cases sent repeatedly (`…MissingAttributeBesideAllowingPolicy`) fail when identical requests get different
answers, golden or not.

`TestLoadSimplifiedPoliciesConditionSyntax` skips on the `authz-agent` profile: authz-policy-admin stores a policy
without validating its condition, so the upload status says nothing about the agent. For the same reason
the cases that upload one policy at a time compare the upload status only on the legacy profile; on both
profiles they send the requests of a case whose upload was accepted, and on the `authz-agent` profile they wait for a
pull after each upload. `TestIsolatedPolicyCases`, `TestIsolatedConditionFormCases`,
`TestTranslatorMatchDialectCases`, `TestTranslatorValueSemanticsCases`, `TestInterpreterNullAndAbsenceCases`,
`TestInterpreterPermissionCaseCases`, `TestInterpreterDeadFormCases` and `TestInterpreterOperationAllCases` share the
`PARITY_ISOLATED` domain and the `runIsolatedCases` runner behind it, and differ in which cases they carry, so that a
recording run can be filtered to one of them. `TestRegularPolicySetCases`, `TestPermissionScopeIterateCases`,
`TestTranslatorPolicySetCases` and the `TestInterpreter*` functions that upload regular sets reach the same domain for
the PIPs their sets read, and are filtered the same way.

### Two-tenant stand

`TestTenantScopedDecisions` needs the legacy PAP, so it skips on the `authz-agent` profile, where authz-policy-admin keys
a domain without the tenant. It also needs two tenants, each with its own realm, and skips unless all four of these are
set:

| Variable | Value |
| --- | --- |
| `PARITY_MT_TENANT_A_ID` | Identifier of tenant A, the stand's default tenant, as the PAP stores it |
| `PARITY_MT_TENANT_A_IDP_BASE_URL` | Base URL of tenant A's realm, ending in `/realms/<realm>` |
| `PARITY_MT_TENANT_B_ID` | Identifier of tenant B |
| `PARITY_MT_TENANT_B_IDP_BASE_URL` | Base URL of tenant B's realm |

Each realm needs a user with `ROLE_MT_READER` and a user with `ROLE_MT_ADMIN`, by default `mt-a` and `mt-a-admin` in
tenant A and `mt-b` and `mt-b-admin` in tenant B; `PARITY_MT_TENANT_{A,B}_USER` and `PARITY_MT_TENANT_{A,B}_ADMIN_USER`
override the names. The users log in with the suite's end-user client and `PARITY_END_USER_PASSWORD`, and the M2M token
comes from `PARITY_IDP_BASE_URL`. The policies are in `suite/testdata/fixtures/tenants/`; both tenants receive them in
the domain `PARITY_MT`.

The committed goldens were recorded on a stand where tenant A is the tenant access-control reports at
`GET /access/v1/technical/defaultTenant` and its users live in the `parity` realm, and tenant B is a tenant identifier
that exists nowhere else on the stand, with its users in a realm of its own. Tenant B needs the separate realm so that
at least one case carries a token minted outside tenant A's realm; access-control accepts such a token in
`Incoming-Token`, because the tenant of a decision comes from `tenant_id` or the `Tenant` header and never from the
end-user token. That is what `t3` and `t4` record: tenant B's user reading tenant A's data succeeds, since only the
query parameter and the header select a tenant.

Tenant A's wildcard row (`t9b`) has `component`, `resourceType`, and `operation` all set to `ALL`. The legacy PAP
accepts `resourceType: ALL` only on a global-access policy, and
`SimplifiedPolicyMappingService.isGlobalAccessSimplifiedPolicy` decides that on `component == "ALL"` alone — a global
policy must also carry `operation: ALL` and no `condition` and no `rsqlPredicate`. With any other `component` the
upload is rejected with `simplified policy 'resourceType' field ALL is only allowed for global access policy`, in every
tenant including the default one; nothing about the rule is tenant-specific.

## Directory layout

```text
test/parity/
├── README.md                            (this file)
├── opa-body-snapshots/                  (9 OPA request/response captures for reference)
└── suite/                               (Go/testify parity suite)
    ├── Dockerfile                       (suite image for the kind run)
    ├── config.go
    ├── compare.go                       (golden read/diff; no write/record path)
    ├── accepted_divergences.go
    ├── testdata/
    │   ├── golden/                      (129 committed golden JSON files)
    │   └── fixtures/                    (seed policies and PIPs)
    └── test_row*.go                     (one file per parity endpoint row)
```

The harness lives under [`test/k8s/parity/`](../k8s/parity/): the manifests, the chart values, and the realm imports
in `idp-seed/`.
