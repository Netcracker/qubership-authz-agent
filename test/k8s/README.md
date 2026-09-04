# Kind end-to-end harness

Manifests and chart values for running the runtime suite against the Helm
chart on a kind cluster. The Makefile targets below apply them; you do not
apply them by hand. CI runs the same targets one step at a time.

| File | What it is |
| --- | --- |
| `keycloak.yaml` | Keycloak with the realm imports from `test/integration/runtime/authn/keycloak/` |
| `pip-stub.yaml` | The PIP stub the uploaded PIP definitions call |
| `entitlements-mock.yaml` | A second stub instance for the entitlements endpoint |
| `values.yaml` | Chart values that point the agent at the harness Services |
| `runtime-suite-job.yaml` | The suite itself, built from `test/integration/testify/Dockerfile` |

The ConfigMap with the realm imports and the M2M client-credentials Secret
are generated from the files under `test/integration/runtime/authn/keycloak/`
by `make e2e-harness`, so they have no manifest of their own.

`parity/` holds the same shape for the parity replay suite (`test/parity`):
Keycloak as `idp` with the realm imports from `test/parity/compose/idp-seed/`,
`pip-mock` with the request-args rule set, `entitlements-mock`, chart values
with the parity realm as an explicit trusted provider, and the suite Job built
from `test/parity/suite/Dockerfile`. It runs in its own namespace so its
Service names match the Compose parity stack.

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

The parity targets mirror these: `parity-harness`, `parity-install`,
`parity-suite`, and `parity-logs`, all in `PARITY_NAMESPACE`. `parity` runs the
cluster and image targets first, then the three.

`KIND_CLUSTER`, `E2E_NAMESPACE`, `PARITY_NAMESPACE`, and `E2E_ARTIFACTS`
override the defaults.

Re-running `e2e-harness` on its own replaces the Keycloak pod, and a dev-mode
Keycloak mints new realm keys on every start. Restart the agent afterwards
(`kubectl rollout restart deploy/authz-agent`) so its JWKS bootstrap picks the
new keys up, or the suite fails at `setup.wait_for_agent`.
The first run on a fresh cluster is slower: the node pulls Keycloak and OPA
from their registries, later runs reuse them.

`make e2e-logs` writes every container log on the node (`kind export logs`),
the namespace events, and the decision logs downloaded through Envoy.

## What runs and what does not

`runtime-suite-job.yaml` filters the suite to the groups that only talk HTTP
to the installed chart. The rest needs work that is tracked separately:

| Group | Blocker |
| --- | --- |
| `TestHealth` | Needs the degraded agent instances (two more releases) and drops the Compose wiring step |
| `TestReadiness`, `TestOPAMountModeRestartDiskLayout` | Use `docker compose exec`; port to `kubectl exec` |
| `TestOPARestart` | Uses `docker compose restart`; port to an ephemeral container that signals OPA |
| `TestOPARequestParity` | Needs the capture Envoy config, which the chart does not ship |
| `TestDecisionLogs` | The collector leaks the M2M token through `nd_builtin_cache` keys; the suite rejects logs with full JWTs |
| `TestZZDecisionLogsCatalogCoverage`, `TestZZZResponseReachabilityCoverage` | Assert coverage of the whole catalog; full runs only |
