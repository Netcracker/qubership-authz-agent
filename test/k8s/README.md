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
| `authz-agent-direct.yaml` | A Service on the single service's own public listener, for the runs described under "Testing the single service" |
| `authz-agent-single.yaml` | The single service as one container next to the chart's Pod, with a Service of its own, for `make e2e-single` |

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
| `e2e-images` | Builds the five product images, pip-stub, and the suite image, then loads them into the cluster |
| `e2e-harness` | Namespace, realm ConfigMap, client-credentials Secret, Keycloak and the stubs; waits until they are Ready |
| `e2e-install` | `make copy-policies`, then `helm upgrade --install` with `values.yaml` and `--wait` |
| `e2e-suite` | Runs the Job, streams its log, and fails if the Job did not complete |
| `e2e-restart` | Restarts the Deployments that run local images and waits for them; needed after `e2e-images` on a running stand, because the tags do not change |

The parity targets mirror these: `parity-harness`, `parity-install`,
`parity-suite`, `parity-restart`, and `parity-logs`, all in `PARITY_NAMESPACE`. `parity` runs the
cluster and image targets first, then the three.

`KIND_CLUSTER`, `E2E_NAMESPACE`, `PARITY_NAMESPACE`, and `E2E_ARTIFACTS`
override the defaults. `E2E_HELM_ARGS` adds arguments to both chart installs;
`E2E_BASE_URL` and `PARITY_AC_BASE_URL` set where the suites send their
requests, the chart's Service by default.

## Testing the single service

The service under `components/authz-agent` can stand in for the OPA container
of the chart, and the suites can reach it either through Envoy or directly:

```bash
E2E_HELM_ARGS='--set OPA_IMAGE=local/authz-agent:ci' make e2e-install e2e-suite
E2E_HELM_ARGS='--set OPA_IMAGE=local/authz-agent:ci' E2E_BASE_URL=http://authz-agent-direct:8080 make e2e-install e2e-suite
```

Without `E2E_BASE_URL`, Envoy stays in front and forwards the decisions to the
service. With `E2E_BASE_URL=http://authz-agent-direct:8080`, the suite goes to
the service's own public listener, which the `authz-agent-direct` Service from
`e2e-harness` exposes on port 8080. The parity targets take
`PARITY_AC_BASE_URL` the same way.

`make e2e-single` goes one step further: it starts the service as one container
of its own, from `authz-agent-single.yaml`, running the trusted providers, the
policy pull, the M2M token, and the decision-log store itself, and points the
suite at it with `E2E_BASE_URL`, `E2E_OPA_DIRECT_URL`, and `E2E_AGENT_SELECTOR`.
The chart has to be installed: the Deployment reads its ConfigMaps and Secrets
and pulls from its policy-admin. `make parity-single` is the parity counterpart,
from `parity/authz-agent-single.yaml`.

Re-running `e2e-harness` on its own replaces the Keycloak pod, and a dev-mode
Keycloak mints new realm keys on every start. Restart the agent afterwards
(`kubectl rollout restart deploy/authz-agent`) so its JWKS bootstrap picks the
new keys up, or the suite fails at `setup.wait_for_agent`.
The first run on a fresh cluster is slower: the node pulls Keycloak and OPA
from their registries, later runs reuse them.

`make e2e-logs` writes every container log on the node (`kind export logs`),
the namespace events, and the decision logs downloaded through Envoy.

## What runs

`runtime-suite-job.yaml` runs the whole Testify suite, including the two
coverage checks that need a full run (`FULL_RUNTIME_SUITE=true`). Groups that
inspect what OPA received, such as `TestOPARequestParity`, read the decision
logs the collector serves through Envoy instead of a capture proxy.

`TestOPARestart` restarts the OPA container through the API server: the Job
runs as the `runtime-suite` ServiceAccount from `runtime-suite-rbac.yaml`,
which may list Pods and add ephemeral containers to them, nothing more.
