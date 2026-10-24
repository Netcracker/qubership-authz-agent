# Running the integration tests locally, from scratch

Step-by-step guide: bring up a kind cluster on a clean machine, build the images, install the Helm chart with the test
harness around it, and run the **runtime integration tests**: the Testify suite under `test/integration/testify/`,
executed as a Job inside that cluster. CI runs the same Makefile targets
(`.github/workflows/integration-tests.yaml`).

> Scope: runtime integration only. OPA contract tests, the chart render check, and the parity replay are in
> [Related checks](#7-related-checks) at the end.

---

## 1. What these tests are

- Orchestrator: the `e2e-*` targets in the [Makefile](../Makefile). `make e2e` runs them in order.
- The harness: the test-stand chart in `helm-templates/authz-test-stand`, installed with
  [test/k8s/test-stand-values.yaml](../test/k8s/test-stand-values.yaml). It runs Keycloak, which imports the realms of
  `test/k8s/authn/` at start, the `pip-stub` the uploaded PIP definitions call, a second stub instance as
  `entitlements-mock`, and the `tenant-manager` emulator that names the identifier of a tenant realm. Chart values
  under [test/k8s/](../test/k8s/) point the agent at them.
- The agent under test comes from the Helm chart in `helm-templates/authz-agent`, installed with `test/k8s/values.yaml`;
  its policy source, the `authz-policy-admin` stub, from `helm-templates/authz-policy-admin` with
  `test/k8s/policy-admin-values.yaml`.
- The suite runs as the Job of the test stand, a `helm test` hook, built from `test/integration/testify/Dockerfile`.
  Every target is a Service name, so no port has to leave the cluster.
- The step catalog (source of truth) is [test/readme.md](../test/readme.md) plus `test/integration/testify/catalog.go`;
  dedicated validation tests enforce that the two stay in sync.

---

## 2. Prerequisites

| Tool | Why | Check |
| --- | --- | --- |
| **Docker** 23.0 or later, where BuildKit is the default builder | builds the images, writes the test-stand files with `docker build --output`, and runs the kind node | `docker info` |
| **kind** | the cluster | `kind version` |
| **kubectl** | streams the Job log, restarts Deployments | `kubectl version --client` |
| **helm** 3.19 or later, or 4.x | installs the charts, runs the suite Job | `helm version` |
| **Go 1.24+** (the version `test/integration/testify/go.mod` declares) | the structural tests and `go vet`; the suite itself is compiled inside its image | `go version` |

The targets use no tool feature newer than these versions; `kubectl` and `kind` may be any version that supports the
cluster.

You do **not** need a local OPA binary for the runtime tests (the agent carries the engine). It is only needed for the
Rego contract tests (section 7).

`kind`, `kubectl`, and `helm` install from their release pages or a package manager (Homebrew on macOS). On a
Debian/Ubuntu-family host Docker installs with:

```bash
sudo apt-get update
sudo apt-get install -y docker.io
sudo usermod -aG docker "$USER"   # then start a new login session (or: newgrp docker)
```

Verify the daemon works without sudo:

```bash
docker run --rm hello-world
```

> **GOROOT caveat.** If your shell exports a `GOROOT` that points at a *different* Go toolchain than the `go` on your
> `PATH`, `go test` fails with `[build failed]`. Either unset it for the run (`env -u GOROOT <command>`) or remove the
> stale `export GOROOT=...` from your shell profile. Confirm with `go env GOROOT`.

---

## 3. Resources

The cluster is one kind node. The harness plus the agent need roughly 2 CPUs and 4 GB of memory free for Docker;
Keycloak is the heaviest part. No host port is published. The first run pulls Keycloak into the node, which takes
minutes on a slow network; later runs reuse it.

---

## 4. Building the images

`make e2e-images` builds and loads everything the cluster needs:

| Image | Dockerfile |
| --- | --- |
| `local/authz-agent:ci`, `local/authz-policy-admin:ci` | `build/*/Dockerfile`, the product images |
| `local/pip-stub:ci` | `test/integration/pipstub/Dockerfile` |
| `local/tenant-manager:ci` | `test/integration/tenantmanager/Dockerfile`, the tenant-manager emulator |
| `local/authz-runtime-suite:ci` | `test/integration/testify/Dockerfile`, the suite compiled with `go test -c -tags integration` |
| `local/authz-parity-suite:ci` | `test/parity/suite/Dockerfile`, used by `make parity` |

The images are built for the host platform and loaded with `kind load`; the node runs the same architecture, so
nothing is emulated. Keycloak is pulled by the node from its registry.

---

## 5. Run (happy path)

From the repository root:

```bash
make e2e
```

Step by step, in the order `make e2e` runs them:

| Target | What it does |
| --- | --- |
| `e2e-cluster` | Creates the kind cluster `authz-e2e` unless it exists |
| `e2e-images` | Builds the images above and loads them into the cluster |
| `e2e-harness` | Generates the realm files (`make test-stand-files`), then installs the test-stand chart: Keycloak, the stubs, the tenant-manager emulator, and the client-credentials Secret; waits until they are Ready. The suite Job is a `helm test` hook, which `e2e-suite` runs |
| `e2e-install` | `helm upgrade --install` of the stub chart with its dev resource profile and `test/k8s/policy-admin-values.yaml`, then of the agent chart with its dev resource profile and `test/k8s/values.yaml`, each with `--wait` |
| `e2e-suite` | Runs the suite Job with `helm test`, streams its log, and fails if the Job did not complete |

Each step prints a `STEP PASS/FAIL <name> <ms>` line. The Job sets `FULL_RUNTIME_SUITE=true`, so the run ends with the
two catalog coverage checks. Expected: `--- PASS: TestRuntimeSuite` with 19 groups.

Artifacts:

```bash
make e2e-logs     # every container log on the node, the namespace events, and the decision logs, into test/artifacts/kind/
make e2e-down     # delete the cluster
```

---

## 6. Iterating

- Changed the suite only: `make e2e-images e2e-suite`. The harness and the chart stay; the Job is recreated.
- Changed product code: `make e2e-images e2e-restart e2e-suite`. The images are rebuilt under the same tags, and a
  running Pod keeps the old content until it is restarted; `e2e-restart` restarts every Deployment that runs a local
  image and waits until it is Ready again. Without it the suite tests the previous build.
- Changed values of the agent or authz-policy-admin chart: `make e2e-install e2e-suite`.
- Changed test-stand values (`test/k8s/test-stand-values.yaml`), the suite's env and args included: `make e2e-harness
  e2e-suite`. `e2e-suite` runs the Job as the release last installed it.
- Changed a realm file: `make e2e-harness e2e-suite`. The harness replaces the Keycloak Pod, and a dev-mode Keycloak
  mints new realm keys on every start, so the harness also restarts the agent, whose JWKS bootstrap holds the old keys,
  and waits until it is Ready.
- Another agent URL: `make e2e-suite E2E_BASE_URL=<url>` (`PARITY_AC_BASE_URL` for `parity-suite`) writes the URL into
  the installed test-stand release, together with any realm edit not yet applied, and runs the suite against it. The URL
  stays in the release for later runs until `make e2e-harness` restores the default.

- A subset: set `RUNTIME_SUITE_RUN` (a `-test.run` regular expression) on the test-stand release, with
  `FULL_RUNTIME_SUITE` set to `false` so the coverage checks do not fail on a filtered run, then run `make e2e-suite`:

  ```bash
  helm --kube-context kind-authz-e2e -n authz-e2e upgrade authz-test-stand helm-templates/authz-test-stand \
    --reuse-values --set suite.env.RUNTIME_SUITE_RUN='^TestRuntimeSuite$/^TestCheckResource$' --set-string suite.env.FULL_RUNTIME_SUITE=false
  ```

  `make e2e-harness` restores the values of `test/k8s/test-stand-values.yaml`.
- Poking at the stack from the host, for example with the Postman collection in `test/`:

  ```bash
  kubectl --context kind-authz-e2e -n authz-e2e port-forward svc/authz-agent 8080:8080 8181:8181
  kubectl --context kind-authz-e2e -n authz-e2e port-forward svc/keycloak 5556:8080
  ```

  The environment file `test/authz-agent-runtime.postman_environment.json` targets these ports; set its
  `keycloak_base_url` to `http://localhost:5556/auth/realms/authz-test`.

Structural tests without a cluster (catalog and readme validation, spec lint):

```bash
cd test/integration/testify
go test -v -count=1 ./...    # no -tags integration
```

---

## 7. Related checks

OPA / Rego contract tests, no cluster needed:

```bash
mise install                   # puts the opa version mise.toml pins on PATH
test/scripts/test-opa.sh
```

Chart render check and parity replay:

```bash
test/scripts/test-chart-render.sh
make parity                    # see test/parity/README.md
```

The minimum CI gate for compatibility-sensitive changes is listed in [test/readme.md](../test/readme.md).

---

## 8. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `go test` → `[build failed]` | `GOROOT` points at a different toolchain than `go` on `PATH`. Unset it or fix your profile (section 2). |
| `make e2e-cluster` fails | Docker is not running, or your user cannot reach `docker.sock` (section 2). |
| `make e2e-suite` prints `The runtime-suite container did not start within 180 seconds:`, or `make parity-suite` the same for `parity-suite`, and a Pod in `ErrImageNeverPull` | The images are not in the cluster; run `make e2e-images`. On a slow node whose container does start, raise `SUITE_START_SECONDS` (180). |
| `make e2e-harness` or `make parity-harness` fails with `exists and cannot be imported into the current release: invalid ownership metadata` | The cluster still holds the harness objects an older `make e2e` or `make parity` created with `kubectl apply`. Run `make e2e-down` once, then rerun `make e2e` or `make parity`. |
| `make e2e-harness` or `make parity-harness` runs out of its 10-minute wait | Check `kubectl -n authz-e2e get pods` (or `-n authz-parity`). A stub or tenant-manager Pod in `ErrImageNeverPull`: the images are not in the cluster, run `make e2e-images`. Keycloak still starting on the first run: the node is still pulling it, rerun the harness target. |
| `setup.wait_for_agent` fails after Keycloak restarted outside `make e2e-harness` | Keycloak has new realm keys and the agent holds the old ones: `kubectl --context kind-authz-e2e -n authz-e2e rollout restart deploy/authz-agent` (namespace `authz-parity` for the parity stand). |
| A long suite stops at 10 minutes with `panic: test timed out after 10m0s`, or `make e2e-suite` or `make parity-suite` fails after 15 minutes while the Job still runs | Three limits bound a suite run: `-test.timeout` in `suite.args` (600s), `suite.activeDeadlineSeconds` of the Job (900), and the `helm test` wait, `E2E_SUITE_TIMEOUT` or `PARITY_SUITE_TIMEOUT` (15m). Raise them together, each no lower than the one before: the first two in the stand's values file, which `make e2e-harness` or `make parity-harness` applies, and the third on the suite target, for example `make parity-suite PARITY_SUITE_TIMEOUT=5h30m`. |
| Need logs after a run | `make e2e-logs`, then look under `test/artifacts/kind/`. |
| Cluster left behind | `make e2e-down`. |
