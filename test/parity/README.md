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

What a GENERAL PIP value does depends on where the policy reads it.

In a condition, a GENERAL PIP whose JSON value is a number fails the rule: under `<=`, `>=`, `==` and `IS NOT NULL`
the condition is false alone and on the left of an `OR` whose right operand is true (`nv-number-*`). Beside an
unconditional ALLOW rule of the same policy, a rule reading a number or a boolean makes the whole answer false
(`non-string-pip-beside-allow-*`). The same value as a string is compared as usual (`nv-string-*`).

A condition fixture that pins a GENERAL PIP to `{"value": 1000}` consequently does not record a comparison: it would
record the same `false` for every condition and every resource. Pin `{"value": "1000"}` instead: the comparison
operators coerce the string, so `resource.amount <= subject.x` still answers by magnitude and the golden means what the
case name says. That is why the two-tenant fixtures below use strings and why `t8a` and `t8b` differ by tenant rather
than both denying.

A `${subject.x}` placeholder in an `rsqlPredicate` template is unaffected: `{"value": 1000}` and `{"value": "1000"}`
both render `amount=lt="1000"`. The cases in
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
| `TestRow02CheckResourceV1MissingResourceAttribute`, `…MissingAttributeUnderOr`, `…MissingAttributeBesideAllowingPolicy`, `…MissingPIPAttribute`, `…FailedGeneralPIP`, `…GeneralPIPJsonPathMatchesNothing`, `…ExpressionShape` | What a condition answers when an attribute it reads is missing, and how `OR`, `AND`, and long expressions evaluate | `check-resource-v1/semantics/`, `pip-call/semantics/` |
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
| `TestTranslatorMatchDialectCases` | Which wildcard dialect `MATCH` speaks on a path: a star between segments and inside one, a double star away from the end and against zero segments, `?`, a trailing separator, a doubled separator, a query string, a percent-encoded separator, case, a pattern with no metacharacter, a brace placeholder, a pair of parentheses, two question marks, and a star against a space, an angle bracket, a double quote and non-ASCII letters. Every case pairs a URI the pattern should select with one it should not | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestTranslatorValueSemanticsCases` | How equality, membership, and the relational operators treat a value whose JSON type or written form is not the literal's: the decimal forms of a number, an integer past the precision of a float64, an exponent, a relational operator over a string, a boolean, a null and a collection, case outside ASCII, and `CONTAINS` over numbers and over an object | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestTranslatorPolicySetCases` | What a regular policy set decides when every rule it holds is a DENY that did not apply, when the policy target kept the request from the DENY, and when a policy holds no rule; what a rule whose condition reads a failed or missing GENERAL PIP does to the allowing rule beside it, under each accepted algorithm; what `check/filter` returns for a resource type whose policy is a deny list; and what the filter carries when two sets name one rule id. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestInterpreterNullAndAbsenceCases` | What a condition answers over a null value under each of `<`, `<=`, `>`, `>=`, `IS NOT NULL` and `IS NOT EMPTY`; whether `IS EMPTY`, `IS NOT EMPTY`, `NOT MATCH`, `NOT CONTAINS ANY`, `IS NOT SUBSET` and a JSON Path that selects nothing (under `NOT CONTAINS` and `IS EMPTY`, since a selection is a collection) evaluate to a value or end the rule, each on the left of an `OR` whose right operand is true, with the operands swapped as the control; and the relational operators at the boundary `5` against `5.0` | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestInterpreterPermissionCaseCases` | Whether `subject.permissions CONTAINS` ignores case, against a permission a `MAPPING` PIP grants in mixed case | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestInterpreterDeadFormCases` | Whether the four forms the PAP accepts and always answers false (`resource['x']`, `!= null`, `MATCH` against an attribute, `MATCH` against a `/…/` literal) are false leaves or end the rule, each on the left of an `OR`; and what `!= null` does in a DENY rule and beside an allowing rule. The regular cases run on the legacy profile only | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/`, `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/` |
| `TestInterpreterCombiningCases` | What a policy with no rule for the operation, a policy with a false target, and a nested set with no applicable rule contribute to a set whose algorithm differs from theirs or matches it; every pair of distinct accepted algorithms over the requests of the `algorithm-*` cases. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/` |
| `TestInterpreterIterateAlgorithmCases`, `TestInterpreterIterateBindingCases` | How the passes of an iterating set are combined under `PERMIT_UNLESS_DENY`, `DENY_OVERRIDES` and `PERMIT_OVERRIDES`, with one grant, and with no grant at all; whether `iterate.foreach` accepts `subject.roles` and `resource.items`; whether `subject.permissionScope` is readable outside an iterating set. Legacy profile only | `load-simplified-policies-v1/scope-iterate/`, `load-policy-sets-v1/scope-iterate/`, `check-resource-v1-outcome/scope-iterate/`, `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/` |
| `TestInterpreterFilterCases` | What `check/filter` returns for a rule with a condition and no predicate, alone and beside a rule with a predicate, for a rule with neither, for four groups of predicates on one type, for a request with no operation or the operation `ALL`, and for a target that reads the resource. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestInterpreterOperationAllCases` | Whether a simplified policy with `operation: ALL` evaluates its condition, and whether its predicate reaches a filter | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/`, `check-filter-v1-outcome/isolated/` |
| `TestInterpreterRegularLoadCases` | Whether the policy-set upload accepts `subject.isM2M`, an undeclared subject attribute, `operation` and `subject.permissions.<suffix>` in a rule condition. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/` |
| `TestInterpreterSetTargetCases` | Whether the policy-set upload accepts a set whose target reads `resource.service`, `resource.uri` under `MATCH`, `resource.id`, an attribute no policy names, and `resource.service` with no `resourceType` beside it, and whether a `resourceType` spelled in lower case matches a request in upper case; and what such a target decides on a request that carries the attribute, another value, no such attribute, no such attribute beside a sibling set that allows on its own, and on a filter request. Legacy profile only; the set with no `resourceType` is emptied when the test ends | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestInterpreterSubstitutionCases` | How each source of a placeholder is rendered by each of the five predicate dialects of `check/filter`, one regular set per source with the same placeholder in every predicate field: `subject.roles`, a TOKEN scalar, a HEADER scalar, and a GENERAL PIP answering a string, a number, a boolean, a list of two, of one, and of none, the literal `null`, an object, a string with characters RSQL gives meaning to, and a 500. The pip-mock call log is read after each GENERAL source. Legacy profile only | `load-policy-sets-v1/regular/`, `check-filter-v1-outcome/regular/` |
| `TestInterpreterPermissionListCases` | What `subject.permissions` holds, rendered through `${subject.permissions}` in the rsql and sql predicates of a filter: with no `MAPPING` PIP, with one for another role, with one for the reader's role, with two granting different permissions, with two granting the same permission, and with one granting an empty list; plus `${subject.scopes}` and `${subject.roles}` beside it. Legacy profile only | `load-policy-sets-v1/regular/`, `check-filter-v1-outcome/regular/` |
| `TestInterpreterAccessOperatorCases` | What `subject allowed 'READ' on resource` and `subject denied 'READ' on resource` evaluate beside a policy that decides `READ` on a condition, and where a chain of six nested such decisions is cut off. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/` |
| `TestInterpreterBarePathCases` | Whether a path with no `resource.` prefix (`a == 'y'`, `owner.id == subject.id`) is accepted and names an attribute of the resource, in a simplified policy and in a rule of a regular set | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/`, `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/` |
| `TestInterpreterDenyPredicateCases` | What `check/filter` carries for the predicates of two DENY rules beside two ALLOW rules, every rule with all five predicate fields, under each of the four combining algorithms of the policy, and once under `DENY_OVERRIDES` without the custom predicate. Legacy profile only | `load-policy-sets-v1/regular/`, `check-filter-v1-outcome/regular/` |
| `TestInterpreterPIPDeclarationCases` | Whether a HEADER PIP splits the header `a,b` and a `defaultValue` of `x, y` into a list; whether a TOKEN PIP reads a claim by a path (`$.department`, `$.realm_access.roles`); whether a MAPPING PIP may be keyed on `subject.id` or on a TOKEN PIP, with a mapping keyed on a role the reader does not hold as the control | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestInterpreterTerminalEffectCases` | Whether an ALLOW rule that decides a `DENY_UNLESS_PERMIT` policy stops the rule beside it, which reads a GENERAL PIP, from being evaluated; the pip-mock call count is recorded where the PIP rule decides and logged where the first rule allows. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `pip-call/` |
| `TestInterpreterIterateNodeAlgorithmCases` | Which algorithm combines the passes of an iterating set when the set and its `iterate` node name opposite ones. Legacy profile only | `load-simplified-policies-v1/scope-node/`, `load-policy-sets-v1/scope-node/`, `check-resource-v1-outcome/scope-node/` |
| `TestInterpreterTenantClaimCases` | What a `tenant-id` claim in the token does to a decision, status included: a claim for tenant A against tenant A, against tenant B by the query parameter and by the `Tenant` header, and with no tenant named; a claim for tenant B with no tenant named; a claim for a tenant no stand has and an empty claim against tenant A; the claim in the end-user token beside a claimless M2M token; and a claimless M2M token as the control. The policy is in tenant A only. The cases that name tenant B skip without a two-tenant stand and on the `authz-agent` profile | `check-resource-v1-outcome/tenant-claim/` |
| `TestRound7FilterCases` | What `check/filter` returns for a rule with no predicate whose condition reads the subject's roles, with a condition on the resource as the control, and for a request with no operation against rules on `UPDATE` and `LIST` only, with `UPDATE` spelled out as the control. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestRound7IteratePermitOverridesCases` | How the passes of a `PERMIT_OVERRIDES` iterating set are combined when a pass over a grant of another region denies: a `DENY_UNLESS_PERMIT` policy with one ALLOW conditioned on the region, and a `DENY_OVERRIDES` policy with a DENY beside an unconditional ALLOW, under two grants, one grant, and none. Legacy profile only | `load-simplified-policies-v1/scope-iterate-permit-overrides/`, `load-policy-sets-v1/scope-iterate-permit-overrides/`, `check-resource-v1-outcome/scope-iterate-permit-overrides/` |
| `TestRound7SetTargetRefusalCases` | Whether the policy-set upload refuses a set target that reads a missing attribute, or two sets whose policies share one `policyId`, each on its own. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/` |
| `TestRound7FailedPIPCases` | What a rule whose condition reads a GENERAL PIP answering 500 or 404 does beside an ALLOW of the same policy, under `PERMIT_UNLESS_DENY` and `DENY_OVERRIDES`, the two algorithms under which every rule is evaluated whatever order the stand evaluates them in; each case reads PIPs of its own and the pip-mock call log is checked after it. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/` |
| `TestRound7PIPCacheCases` | Whether a GENERAL PIP declared `cacheable: false` is read on every request: one value pinned and read, then another, read 5 and 70 seconds after the change; the pip-mock call count is logged after every request. Legacy profile only | `load-simplified-policies-v1/pip-cache-cacheable-false/`, `load-policy-sets-v1/pip-cache-cacheable-false/`, `check-resource-v1-outcome/pip-cache-cacheable-false/`, `pip-call/` |
| `TestRound8MappingExportCases` | What `GET /access/v3/config/pips` carries for the MAPPING PIPs of tenant A and tenant B, read with tenant A, no tenant, and tenant B, narrowed to the elements naming the case's permissions; and whether a reader of tenant A holds the permission tenant B's PIP grants. The read that names tenant B skips without a two-tenant stand. Legacy profile only | `load-simplified-policies-v1/mapping-export/`, `config-pips-v3/mapping-export/`, `check-resource-v1-outcome/mapping-export/` |
| `TestRound8FailedPIPScopeCases` | How far the failure of a GENERAL PIP answering 500 reaches when the policy reading it sits beside a policy that allows, and when the set reading it sits beside a set that allows, both under `DENY_UNLESS_PERMIT`; each case uploads its sets several times and records one golden for the uploads whose request reached the PIP and one for those whose request did not. Legacy profile only | `load-simplified-policies-v1/failed-pip-scope/`, `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/` |
| `TestRound9IterateFilterCases` | What `check/filter` returns for an iterating set in the form product policies give it (a rule whose target and condition read `subject.permissionScope.region` and whose `customPredicate` passes it as a parameter) under each of the four algorithms of the `iterate` node, with all five predicate fields, and with a literal predicate as the control; asked under no grant, one grant with one value and with two, two grants, two grants of which one lacks the key, and a scope service answering 500, with `check/resource` requests in regions `r1` and `r2` as the controls that each grant was read. Legacy profile only | `load-simplified-policies-v1/scope-filter/`, `load-policy-sets-v1/scope-filter/`, `check-filter-v1-outcome/scope-filter/`, `check-resource-v1-outcome/scope-filter/` |
| `TestRound9EmptyHeaderAndClaimCases` | What every operator answers over a HEADER PIP whose header is absent and over a TOKEN PIP whose claim is absent, alone and on the left of an `OR` with a true right operand; `IS NULL` over an empty resource collection; an absent header in a predicate | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/`, `check-filter-v1-outcome/isolated/` |
| `TestRound9RightOperandCases` | What `IN` and `==` answer when the attribute on their right is an absent header, an absent claim, or a GENERAL PIP answering 500, and `IN` over either of two headers with one of them absent | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestRound9SingleElementListCases` | What `==`, `!=`, `IN` and `CONTAINS` answer over a header holding one value and over a claim that is a list of one element | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestRound9PlainArrayEqualityCases` | What `==` and `!=` answer over a resource attribute that is a JSON array | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestRound9IsNullOverDeadFormsCases` | What `IS NULL` answers over `resource['x']` and over the literal `null` | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestRound9TokenDefaultListCases` | Whether the `defaultValue` of a TOKEN PIP is split on commas, as a HEADER PIP's is | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestRound9DenyRuleWithoutPredicateCases` | What `check/filter` does with a DENY rule that has no predicate and a true condition, beside an ALLOW with a predicate and beside an unrestricted ALLOW, under each policy algorithm, with a false condition as the control. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestRound9FalseConditionWithoutPredicateCases` | What `check/filter` does with an ALLOW rule that has no predicate and a subject condition that is false, alone and beside a predicate, with a true condition as the control. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestRound9FilterAlgebraCases` | What `check/filter` answers for a `PERMIT_UNLESS_DENY` policy whose DENY rules are on another operation, a `DENY_OVERRIDES` set with a policy that has no rule on the operation, and a DENY without a predicate in one policy beside a predicate in another, each with its control; an unrestricted ALLOW beside a predicate is the control of `TestRound9FalseConditionWithoutPredicateCases`. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestRound9UnresolvedPlaceholderCases` | What `check/filter` and `check/resource` answer when one rule's predicate names an undeclared placeholder, or `${subject.permissions}` with no MAPPING PIP, beside a rule with a predicate that resolves. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestRound9SubjectScalarSubstitutionCases` | How `${subject.name}` and `${subject.type}` render in the five predicate dialects, with `${subject.id}` as the control. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestRound9SimplifiedGroupCases` | Which simplified policies `check/filter` brackets as one group: two policies of one type in two domains, in two components, and on the type spelled in two cases, with one domain, component and type as the control. Uploads into `PARITY_ISOLATED` and `PARITY_ISOLATED_B` | `load-simplified-policies-v1/simplified-group/`, `check-filter-v1-outcome/simplified-group/` |
| `TestRound9TwinPIPDeclarationCases` | Which declaration a GENERAL PIP name resolves to when two domains of one tenant declare it at different addresses, read by a simplified policy of each domain and by a regular set; the pip-mock call count per address is logged after every request. Legacy profile only | `load-simplified-policies-v1/twin-pip/`, `load-policy-sets-v1/twin-pip/`, `check-resource-v1-outcome/twin-pip/`, `pip-call/` |
| `TestRound9NonStringPIPValueCases` | What a rule whose condition reads a GENERAL PIP answering a number or a boolean does beside an ALLOW of the same policy, under `PERMIT_UNLESS_DENY` and `DENY_OVERRIDES`, in the shape of `TestRound7FailedPIPCases`. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/` |
| `TestRound9PIPCacheCacheableCases` | `TestRound7PIPCacheCases` for a GENERAL PIP declared `cacheable: true` with no `cachePeriod`. Legacy profile only | `load-simplified-policies-v1/pip-cache-cacheable-true/`, `load-policy-sets-v1/pip-cache-cacheable-true/`, `check-resource-v1-outcome/pip-cache-cacheable-true/`, `pip-call/` |
| `TestRound10ProductMappingCases` | Whether a `MAPPING` PIP declared with a `productMapping` alone grants its permission in a decision, alone in the tenant, beside a `customMapping` of another domain for a role the reader does not hold, and beside one for the reader's role; the v3 export of the tenant's PIPs after each step. Legacy profile only | `load-simplified-policies-v1/product-mapping/`, `check-resource-v1-outcome/product-mapping/`, `config-pips-v3/product-mapping/` |
| `TestRound10SetAlgorithmFilterCases` | What `check/filter` returns under each of the four set algorithms for a policy with an ALLOW predicate, a `DENY_OVERRIDES` policy with a DENY predicate, and both. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestRound10FailedPIPFilterCases` | What `check/filter` and `check/resource` answer when an ALLOW or a DENY without a predicate reads a GENERAL PIP answering 500 beside an ALLOW with a predicate, with a PIP answering a value as the control; each request is recorded under the class the pip-mock call log puts it in. Legacy profile only | `load-simplified-policies-v1/failed-pip-filter/`, `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestRound10CustomizationCases` | Whether the decisions and `GET /access/v3/config/policySets` follow a `CUSTOMER`-level customization that disables one rule and replaces another, before and after the import. Legacy profile only | `load-policy-sets-v1/customization/`, `import-customization-v1/customization/`, `check-resource-v1-outcome/customization/`, `config-policy-sets-v3/customization/` |
| `TestRound10FilterResourceConditionCases` | What `check/filter` does with an ALLOW without a predicate whose condition or target reads the resource: `IS NULL` in the condition and in the target, and an `OR` with a subject operand in either order, alone and beside a predicate, with `resource.x == 'a'` beside a predicate as the control. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestRound10IterateSetAlgorithmCases` | How the set algorithm combines an `iterate` node of another algorithm over no grants, and what the node does with a grant whose key holds no value, a scope service answering 404, a body that is not a scope, and an `iterate` block with no algorithm; one grant of `r1` is the control. Legacy profile only | `load-simplified-policies-v1/scope-set-algorithm/`, `load-policy-sets-v1/scope-set-algorithm/`, `check-filter-v1-outcome/scope-set-algorithm/`, `check-resource-v1-outcome/scope-set-algorithm/` |
| `TestRound10DenyListFilterCases` | What `check/filter` returns for a `PERMIT_UNLESS_DENY` deny list of DENY rules on `resource.uri MATCH` with no predicate, alone and beside an ALLOW with a predicate. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestRound10EitherSourceCases` | What `resource.customerId IN <TOKEN> OR resource.customerId IN <GENERAL>` answers when either source holds the id, neither does, and the GENERAL PIP answers 500; a request whose TOKEN operand holds is recorded under the class the pip-mock call log puts it in | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestRound10RequestAttributesCases` | What a GENERAL PIP sends in its `requestAttributes` when the value is a literal, the control, or a placeholder over a TOKEN PIP, `subject.roles`, a string, an object, or an absent resource attribute, with the decision that reads the PIP; the call count and the `requestAttributes` pip-mock received are recorded | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/`, `pip-call/isolated/` |
| `TestRound10DeadFormNotNullCases`, `TestRound10EmptyCollectionNotNullCases`, `TestRound10NullOperandCases`, `TestRound10SingleValueHeaderCases`, `TestRound10UndeclaredPlaceholderCheckCases` | What `IS NOT NULL` answers over `resource['x']`, the literal `null`, and an empty array; what `IN`, `CONTAINS`, `CONTAINS ANY`, `IS SUBSET` and `MATCH` answer over null; what `NOT IN`, `MATCH`, `CONTAINS ANY` and `IS SUBSET` answer over a header holding one value, and what a header sent empty resolves to; and what `check/resource` answers for the policy of `x20-undeclared-placeholder` | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/`, `check-filter-v1-outcome/isolated/` |
| `TestRound10NonStringPIPOperatorCases` | What `<=`, `>=`, `== '1000'` and `IS NOT NULL` answer over a GENERAL PIP answering the number 1000, alone and on the left of an `OR`, with the PIP on either side, and whether a policy that does not read the PIP is affected; every case repeated with the string `"1000"` as the control | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestRound10PIPFailureScopeCases` | The two shapes of `TestRound8FailedPIPScopeCases` with a GENERAL PIP answering 404, the number 1000, and the string `"1000"` as the control; each upload is recorded under the class the pip-mock call log puts it in. Legacy profile only | `load-simplified-policies-v1/pip-scope/`, `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/` |
| `TestRound10MappingTenantIsolationCases` | Whether a `MAPPING` PIP of tenant B grants its permission in tenant B, and not in tenant A, with tenant A's own as the control. Needs a two-tenant stand; skips on the `authz-agent` profile | `load-simplified-policies-v1/mapping-tenant-isolation/`, `check-resource-v1-outcome/mapping-tenant-isolation/` |
| `TestRound10TenantFromTokenCases` | Whether a decision takes its tenant from a user's token when the request names none, and whether a user of tenant A reads a policy of tenant B by naming tenant B. Needs a two-tenant stand; skips on the `authz-agent` profile | `load-simplified-policies-v1/tenant-from-token/`, `check-resource-v1-outcome/tenant-from-token/` |
| `TestRound10TwoDomainMappingCases` | What `subject.permissions` and the v3 export hold when two domains of one tenant declare a `MAPPING` PIP each, and what `domainPIPs/{domain}`, `permissions/list/{role}` with each `level`, and `/access/v1/pips` answer. Legacy profile only | `load-simplified-policies-v1/two-domain-mapping/`, `check-resource-v1-outcome/two-domain-mapping/`, `config-pips-v3/two-domain-mapping/`, `pap-read/two-domain-mapping/` |
| `TestRound10NullBodyAndRightOperandCases` | `IS EMPTY` and `IS NULL` over a GENERAL PIP whose body is `null`, and an absent header or claim on the right of `IN` and `==`, each alone | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestRound10ResourceTypeAllUploadCases` | Which simplified policies with `resourceType: ALL` the upload accepts: another component, an operation other than `ALL`, a condition, a predicate, with the global form as the control. Legacy profile only | `load-simplified-policies-v1/resource-type-all/` |
| `TestRound10PathPatternAndWordOperatorCases` | What `MATCH /ab.*/` selects on values of the path form, and whether `LESS THAN OR EQUAL` is accepted without `TO` | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestRound10RepeatedValuesAndHeadersCases` | How the five predicate dialects render a GENERAL PIP answering `["b", "a", "a"]`, and whether a GENERAL PIP declaration takes `headers` as a string and as an object, with no `headers` as the control. Legacy profile only | `load-policy-sets-v1/regular/`, `check-filter-v1-outcome/regular/`, `load-simplified-policies-v1/pip-headers/`, `config-pips-v3/pip-headers/` |
| `TestRound10PolicyWithoutAlgorithmCases` | What a policy with no algorithm and no rule on the operation does beside an allowing policy under a `DENY_OVERRIDES` set, with a `DENY_UNLESS_PERMIT` policy as the control; and `/api-version` of the stand. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `api-version/` |
| `TestRound11AbsentKeyProbeCases`, `TestRound11NullProbeCases`, `TestRound11EmptyCollectionCases`, `TestRound11NullBodyProbeCases`, `TestRound11NullLiteralAndRightOperandCases` | Whether `!=`, `NOT IN`, `NOT CONTAINS` and `>` over an absent key, and `==`, `<`, `<=`, `>=`, `IS EMPTY`, `NOT CONTAINS`, `NOT CONTAINS ANY` and `NOT MATCH` over null, are false or end the rule, each on the left of an `OR`; what `==`, `!=`, `IS NOT EMPTY` and `IS SUBSET` answer over an empty array; what `NOT CONTAINS` answers alone over a JSON Path that selects nothing; whether `IS EMPTY` over an index past the end and over a GENERAL PIP whose body is `null` is false or ends the rule; and the literal `null` on the left of `==` and an absent key on its right, each on the left of an `OR` | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestRound11FailedPIPOnTheRightScopeCases` | What a GENERAL PIP answering 500 on the right of `IN` does beside an allowing policy, under a `DENY_UNLESS_PERMIT` set and under a `DENY_OVERRIDES` set whose reading policy is `PERMIT_OVERRIDES`; each upload is recorded under the class the pip-mock call log puts it in. Legacy profile only | `load-simplified-policies-v1/rf-failed-pip-on-the-right/`, `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/` |
| `TestRound11ScopeOutsideIterateCases` | What `subject.permissionScope.region` resolves to in a set that does not iterate, under `IS EMPTY` alone, on the left of an `OR`, and under `IS NULL`. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/` |
| `TestRound11IterateNodeUnderSetCases` | What a `PERMIT_UNLESS_DENY` `iterate` node over no grants gives a `DENY_UNLESS_PERMIT` set above it, with one grant of `r1` as the control. Legacy profile only | `load-simplified-policies-v1/scope-node-under-a-set/`, `load-policy-sets-v1/scope-node-under-a-set/`, `check-filter-v1-outcome/scope-node-under-a-set/`, `check-resource-v1-outcome/scope-node-under-a-set/` |
| `TestRound11PIPCallsPerRequestCases` | How many calls a GENERAL PIP receives when one condition reads it twice, with a condition that reads it once as the control | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/`, `pip-call/isolated/` |
| `TestRound11PIPCachePerSubjectCases` | Whether a GENERAL PIP declared `cacheable: true` serves one subject's cached value to another subject after its answer changed, with the first subject's second read as the control | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/`, `pip-call/isolated/` |
| `TestRound11TenantParameterAgainstHeaderCases` | Which tenant a decision is taken in when `tenant_id` and the `Tenant` header name different tenants, with the header alone and `tenant_id` alone as the controls. Needs a two-tenant stand; skips on the `authz-agent` profile | `load-simplified-policies-v1/tenant-param-against-header/`, `check-resource-v1-outcome/tenant-param-against-header/` |
| `TestRound11DeclaredNameCases`, `TestRound11FilteredDeclarationCases` | Whether the upload refuses `subject.isM2M` when a PIP of that name is declared, and a `MAPPING` PIP named `subject.permissions` with no suffix, each with a control; which of a top-level `resourceType` and a `.filtered` name a `FILTERED` declaration needs | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestRound11FilterNodeCases` | What `check/filter` returns for a set nested in a `DENY_OVERRIDES` set beside a policy with a predicate, when the nested set's target reads the resource and when none of its policies applies, under each of the four algorithms; and for a policy with a predicate beside a policy with no rule on `LIST` under `PERMIT_OVERRIDES` and `PERMIT_UNLESS_DENY` sets. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestRound12ScopeOutsideIterateControlCases` | Whether a read of `subject.permissionScope` in a set that does not iterate ends the rule or leaves the policy unreached: the set of `TestRound11ScopeOutsideIterateCases` with a rule on `CONTROL` whose condition is `true` and reads no scope, and on `MIXED` a rule that reads the scope beside a rule whose condition is `true`. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/` |
| `TestRound12NotApplicableFilterCases` | What `check/filter` returns for a `PERMIT_UNLESS_DENY` set none of whose policies applies to `LIST`, and for a `DENY_OVERRIDES` set of a policy that allows `LIST` without a predicate beside a policy with a predicate, with the policy without a predicate alone as the control. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestRound12IterateNodeInAFilterCases` | What `check/filter` returns for a nested set whose `DENY_OVERRIDES` `iterate` node has no grants, inside a `DENY_OVERRIDES` set beside a policy with a predicate, with one grant of `r1` as the control. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestRound13IterateCases` | What an `iterate` node over zero, one, and two grants gives the sets around it, under each of the four node algorithms; whether a pass with no policy that applies takes its set's algorithm; whether a set nested in an iterating set sees the grant; what a scope key no grant carries reads as. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestRound13ScopeOutsideIterateCases` | Whether a read of `subject.permissionScope` in a set that does not iterate ends its rule or the whole answer, in a DENY rule and in a policy target, and what the filter does with it in a predicate and in a condition. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestRound13FilterCases` | What `check/filter` returns for a policy that allows `LIST` without a predicate beside a predicate under `PERMIT_OVERRIDES` and `PERMIT_UNLESS_DENY`, beside a DENY predicate under `DENY_OVERRIDES`, for a nested set none of whose policies applies, under each algorithm, as the only child of a `DENY_UNLESS_PERMIT` set, and for such a `PERMIT_UNLESS_DENY` set beside a predicate. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestRound13PAPSyntaxCases` | Whether the PAP accepts a literal left over after a comparison, and an attribute as a list element | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestRound13CellCases` | What each operator answers over an absent key, `null`, `[]`, an empty JSON Path selection, an index past the end, a HEADER PIP with no header, a GENERAL PIP whose body is `null`, and a GENERAL PIP that answers 500, in every cell of the operator-by-state table no golden fixes; every operator over the failing PIP also on the left of a true `OR` | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/` |
| `TestRound13FailingPIPInADenyRuleCases` | Whether a GENERAL PIP that answers 500 ends the `DENY` rule that reads it or the whole answer, under every operator, in a `PERMIT_UNLESS_DENY` policy. Legacy profile only | `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/` |
| `TestRound14OperandKindCases`, `…RightStateCases`, `…ValueCases`, `…SyntaxCases`, `…JSONPathCases`, `…TargetCases`, `…IteratePassCases` | Forms of the condition language no earlier case asks: every kind of operand on either side of every operator, the right operand in each special state, the JSON types of a resource value against literals of each type, operand pairs and lexical forms the PAP may refuse, JSON Path forms, and a failed PIP, an absent attribute, or `subject.permissionScope` outside `iterate` in the target of a rule, a policy, and a set, and how the filter writes an `iterate` pass that gives two groups. All but `…IteratePassCases` are data, see [Cases kept as data](#cases-kept-as-data) | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/`, `load-policy-sets-v1/regular/`, `check-resource-v1-outcome/regular/`, `check-filter-v1-outcome/regular/` |
| `TestInterpreterConfigExportCases` | What `GET /access/v3/config/policySets` and `GET /access/v3/config/pips`, the reads the agent loads its configuration from, carry for regular sets of every form, two simplified policies, and one PIP of each type, read with the tenant of the upload, the other tenant, no tenant, an unknown tenant, and a tenant in the query beside another in the `Tenant` header. The recorded body drops the envelope's `hash` and `lastModificationTimestamp` and keeps only the elements the case uploaded, ordered by their text. Legacy profile only; the reads that name tenant B skip without a two-tenant stand | `load-simplified-policies-v1/config-export/`, `load-policy-sets-v1/config-export/`, `config-policy-sets-v3/config-export/`, `config-pips-v3/config-export/` |

The cases sent repeatedly (`…MissingAttributeBesideAllowingPolicy`) fail when identical requests get different
answers, golden or not.

`TestLoadSimplifiedPoliciesConditionSyntax` skips on the `authz-agent` profile: authz-policy-admin stores a policy
without validating its condition, so the upload status says nothing about the agent. For the same reason
the cases that upload one policy at a time compare the upload status only on the legacy profile; on both
profiles they send the requests of a case whose upload was accepted, and on the `authz-agent` profile they wait for a
pull after each upload. `TestIsolatedPolicyCases`, `TestIsolatedConditionFormCases`,
`TestTranslatorMatchDialectCases`, `TestTranslatorValueSemanticsCases`, `TestInterpreterNullAndAbsenceCases`,
`TestInterpreterPermissionCaseCases`, `TestInterpreterDeadFormCases`, `TestInterpreterOperationAllCases`,
`TestInterpreterBarePathCases`, `TestInterpreterPIPDeclarationCases` and the `TestRound9*`, `TestRound10*`, `TestRound11*`, `TestRound13*` and `TestRound14*` functions
that upload one policy at a time share the
`PARITY_ISOLATED` domain and the `runIsolatedCases` runner behind it, and differ in which cases they carry, so that a
recording run can be filtered to one of them. `TestRegularPolicySetCases`, `TestPermissionScopeIterateCases`,
`TestTranslatorPolicySetCases`, the `TestRound12*`, `TestRound13*` and `TestRound14*` functions and the `TestInterpreter*` functions that upload regular sets reach the same domain for
the PIPs their sets read, and are filtered the same way.

### Cases kept as data

The cases of a function that only uploads PIPs, simplified policies, and policy sets and then sends requests can live in
a JSON file under `suite/testdata/cases/` instead of Go; the function calls `runCaseFile` with the file's path. A file
declares the pip-mock routes to pin, the PIPs its cases name by key, and the cases. A case without `sets` is a
simplified policy with `condition` on `READ`, or on `operation` when set, for the reader; a case with `sets` is one
upload of policy sets, whose ids the suite derives from the case id as it does for Go cases. `{{resourceType}}` in a
condition, a target, or a resource string stands for the case's resource type, and `{{resourceTypeLowerCase}}` for the
same in lower case. The format is defined by `caseFile` in `suite/case_files_test.go`. `about`, on the file and on a
case, is a note for the reader; nothing reads it. `TestCaseFilesAreWellFormed` reads every file without a stand and
fails on an unknown field, a PIP a case names and its file does not declare, and a case id two cases share: run `go test
-run TestCaseFilesAreWellFormed ./test/parity/suite/` before handing a file over for recording.

A file is usually written by a generator beside it, such as `suite/testdata/cases/round14/generate.py`: edit the
generator and rerun it rather than the JSON. Cases that wait between steps or change the stand in between, such as a
cache expiry or a customization import, stay in Go.

To record goldens, run one function per fresh stand:

```bash
go test -tags integration -count=1 -run '^TestParitySuite$/^TestRound10ProductMappingCases$' ./test/parity/suite/
```

The functions share domains, pip-mock routes, and the PIP caches of the stand, and a function that stops halfway can
leave sets or customizations behind. A stand of its own keeps one function's leftovers out of the next one's answers.

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

`TestInterpreterTenantClaimCases` mints its tokens from five more clients of the `parity` realm, declared in
[`parity-realm.json`](../k8s/parity/idp-seed/parity-realm.json) with a hardcoded `tenant-id` claim: `parity-m2m-tenant-a`
and `parity-end-user-tenant-a` carry `default`, the kind harness's tenant; `parity-m2m-tenant-b` carries the placeholder
`parity-tenant-b`; `parity-m2m-tenant-unknown` carries `7f3c2e1a-0b9d-4c6e-8a5f-2d1b3c4e5f60`; and
`parity-m2m-tenant-empty` carries the empty string. On a stand whose tenant A is not `default`, `parity-m2m-tenant-a`
and `parity-end-user-tenant-a` have to carry tenant A's identifier, and on a two-tenant stand `parity-m2m-tenant-b`
has to carry tenant B's; the test decodes each token and fails when the claim is not the value it assumes.
`PARITY_CLAIM_{M2M_TENANT_A,M2M_TENANT_B,M2M_TENANT_UNKNOWN,M2M_TENANT_EMPTY,END_USER_TENANT_A}_CLIENT_{ID,SECRET}`
override the client ids and secrets. The cases against tenant A run on every stand; the cases that name tenant B
need the legacy PAP and the same four `PARITY_MT_TENANT_*` variables as `TestTenantScopedDecisions`.

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
