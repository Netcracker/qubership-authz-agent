# Kind end-to-end harness

Manifests and chart values for running the runtime suite against the Helm
chart on a kind cluster. The Makefile targets below apply them; you do not
apply them by hand. CI runs the same targets one step at a time.

| File | What it is |
| --- | --- |
| `keycloak.yaml` | Keycloak with the realm imports from `authn/` |
| `authn/` | The realm imports, their description, and the M2M client credentials |
| `pip-stub.yaml` | The PIP stub the uploaded PIP definitions call |
| `entitlements-mock.yaml` | A second stub instance for the entitlements endpoint |
| `values.yaml` | Chart values that point the agent at the harness Services |
| `runtime-suite-job.yaml` | The suite itself, built from `test/integration/testify/Dockerfile` |
| `runtime-suite-rbac.yaml` | ServiceAccount and Role the suite uses to restart the OPA container |
| `authz-agent-direct.yaml` | A Service on the public listener of the service standing in for the OPA container, for the manual swap described below |

The ConfigMap with the realm imports and the M2M client-credentials Secret
are generated from the files under `authn/` by `make e2e-harness`, so they
have no manifest of their own.

`parity/` holds the same shape for the parity replay suite (`test/parity`):
Keycloak as `idp` with the realm imports from `parity/idp-seed/`,
`pip-mock` with the request-args rule set, `entitlements-mock`, chart values
with the parity realm as an explicit trusted provider, and the suite Job built
from `test/parity/suite/Dockerfile`. It runs in its own namespace, so its
Keycloak can be named `idp`, the issuer host in the parity realm's tokens,
next to the e2e namespace's `keycloak`.

## Run

```bash
make e2e          # cluster, images, harness, chart, suite
make e2e-logs     # collect artifacts into test/artifacts/kind/
make parity       # the parity replay: harness, chart, suite in namespace authz-parity
make parity-logs  # its artifacts, into test/artifacts/kind/parity/
make e2e-down     # delete the cluster
```

Step by step, in the order `make e2e` runs them:

| Target | What it does |
| --- | --- |
| `e2e-cluster` | Creates the kind cluster `authz-e2e` unless it exists |
| `e2e-images` | Builds the six product images, pip-stub, and the suite image, then loads them into the cluster |
| `e2e-harness` | Namespace, realm ConfigMap, client-credentials Secret, Keycloak and the stubs; waits until they are Ready |
| `e2e-install` | `make copy-policies`, then `helm upgrade --install` with `values.yaml` and `--wait` |
| `e2e-suite` | Runs the Job, streams its log, and fails if the Job did not complete |
| `e2e-single` | Installs the chart with `AUTHZ_SINGLE_SERVICE_ENABLED=true` and runs the suite against the one-container Pod; CI runs it after `e2e-suite` |
| `e2e-restart` | Restarts the Deployments that run local images and waits for them; needed after `e2e-images` on a running stand, because the tags do not change |

The parity targets mirror these: `parity-harness`, `parity-install`,
`parity-suite`, `parity-restart`, and `parity-logs`, all in `PARITY_NAMESPACE`. `parity` runs the
cluster and image targets first, then the three.

`KIND_CLUSTER`, `E2E_NAMESPACE`, `PARITY_NAMESPACE`, and `E2E_ARTIFACTS`
override the defaults. `E2E_HELM_ARGS` adds arguments to both chart installs;
`E2E_BASE_URL` and `PARITY_AC_BASE_URL` set where the suites send their
requests, the chart's Service by default.

## The two topologies

The chart assembles the agent Pod either as the five containers or as the one
container of ADR 0080, and `AUTHZ_SINGLE_SERVICE_ENABLED` selects between them.
Both are tested against the same harness:

```bash
make e2e-install e2e-suite   # five containers, the default
make e2e-single              # the same chart with the switch on, then the suite
make e2e-install             # back to the five containers
```

`make e2e-single` reinstalls the chart with the switch and runs the suite with
`SINGLE_SERVICE=true`, which skips `TestOPARestart` alone: its one container is
the one that is gone. Every other group, the data API lockdown and the
two-transport comparison included, gates both topologies. The Service and the
Deployment keep their names, so nothing else changes. `make parity-single` is
the parity counterpart. CI runs both topologies on every pull request.

Separately, and as a manual aid rather than a target of CI, the single
service's binary can stand in for the OPA container of the five-container Pod:

```bash
E2E_HELM_ARGS='--set OPA_IMAGE=local/authz-agent:ci' make e2e-install e2e-suite
E2E_HELM_ARGS='--set OPA_IMAGE=local/authz-agent:ci' E2E_BASE_URL=http://authz-agent-direct:8080 make e2e-install e2e-suite
```

The first line keeps Envoy in front of it; the second sends the suite to the
service's own listener, which `authz-agent-direct.yaml` exposes.

## What runs

`runtime-suite-job.yaml` runs the whole Testify suite, including the two
coverage checks that need a full run (`FULL_RUNTIME_SUITE=true`). Groups that
inspect what OPA received, such as `TestOPARequestParity`, read the decision
logs the agent serves at `/internal/v1/decision-logs` instead of a capture
proxy: the collector through Envoy in the five-container topology, the single
service's own store in the other.

`TestOPARestart` restarts the OPA container through the API server: the Job
runs as the `runtime-suite` ServiceAccount from `runtime-suite-rbac.yaml`,
which may list Pods and add ephemeral containers to them, nothing more.
