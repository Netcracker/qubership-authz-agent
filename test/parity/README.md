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
| `parity-install` | `helm upgrade --install` with [`test/k8s/parity/values.yaml`](../k8s/parity/values.yaml) |
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
| `TestLoadSimplifiedPoliciesConditionSyntax` | Whether the upload accepts a condition outside the grammar | `load-simplified-policies-v1/condition-syntax/` |
| `TestIsolatedPolicyCases` | Operator forms, attribute paths, subject attributes, literals, whitespace, declarations, and policy shapes the PAP may refuse, uploaded one case at a time into `PARITY_ISOLATED` | `load-simplified-policies-v1/isolated/`, `check-resource-v1-outcome/isolated/`, `check-filter-v1-outcome/isolated/` |
| `TestTenantScopedDecisions` | Which tenant a decision is scoped to, given the token, `tenant_id`, and the `Tenant` header | `check-resource-v1/tenant/`, `check-filter-v1/tenant/` |

The cases sent repeatedly (`…MissingAttributeBesideAllowingPolicy`) fail when identical requests get different
answers, golden or not.

`TestLoadSimplifiedPoliciesConditionSyntax` skips on the `authz-agent` profile: authz-policy-admin stores a policy
without validating its condition, so the upload status says nothing about the agent. For the same reason
`TestIsolatedPolicyCases` compares the upload status only on the legacy profile; on both profiles it sends the
requests of a case whose upload was accepted, and on the `authz-agent` profile it waits for a pull after each upload.

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
