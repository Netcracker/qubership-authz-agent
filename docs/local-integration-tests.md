# Running the integration tests locally, from scratch

Step-by-step guide: bring up a working setup on a clean machine, build every
image the runtime stack needs, and run the **runtime integration tests** — the
`Testify` suite that starts the whole stack via Docker Compose and drives it
from `go test` on the host.

> Scope: runtime integration only (`test/integration/testify/`).
> OPA contract tests and the full "CI gate" are in
> [Related checks](#7-related-checks) at the end.

---

## 1. What these tests are

- Orchestrator: [test/scripts/test-envoy-runtime.sh](../test/scripts/test-envoy-runtime.sh).
- It brings up the Compose stack defined in
  [test/integration/runtime/docker-compose.yml](../test/integration/runtime/docker-compose.yml):
  `keycloak`, `envoy`, `opa-bootstrap`, `opa`, `pap-client`, `decision-log-collector`,
  `pip-stub`, `entitlements-mock`, `authz-policy-admin`,
  `opa-partial-permissive-bootstrap`, `opa-partial-permissive`, `pap-client-partial-permissive`,
  `opa-partial-strict-bootstrap`, `opa-partial-strict`, `pap-client-partial-strict`.
- Then, from the **host**, it runs the Go suite in
  [test/integration/testify/](../test/integration/testify/) with
  `go test -tags integration ./...`.
- The step catalog (source of truth) is [test/readme.md](../test/readme.md) plus
  `test/integration/testify/catalog.go`; dedicated validation tests enforce
  that the two stay in sync.

---

## 2. Prerequisites

| Tool | Why | Check |
| --- | --- | --- |
| **Docker** + `compose` v2 plugin | build & run the stack | `docker compose version` |
| **Go 1.24.0+** (the version `test/integration/testify/go.mod` declares) | run the Testify suite on the host | `go version` |
| **curl** | health checks / artifact download | `curl --version` |
| **bash**, **sed**, `sha256sum`/`shasum`/`openssl` | scripts, OPA install | — |

You do **not** need a local OPA binary for the runtime tests (OPA runs in a
container). It is only needed for the local Rego contract tests (section 7).

On a Debian/Ubuntu-family host the toolchain can be installed with:

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-v2 curl
sudo usermod -aG docker "$USER"   # then start a new login session (or: newgrp docker)
```

If the system Go is older than 1.24.0, install the official toolchain from
<https://go.dev/dl/> and put it first on `PATH`. Verify the daemon works
without sudo:

```bash
docker run --rm hello-world
```

> **GOROOT caveat.** If your shell exports a `GOROOT` that points at a
> *different* Go toolchain than the `go` on your `PATH`, `go test` fails with
> `[build failed]`. Either unset it for the run (`env -u GOROOT <command>`) or
> remove the stale `export GOROOT=...` from your shell profile — a modern Go
> install resolves its own GOROOT. Confirm with `go env GOROOT`.

---

## 3. Ports used by the stack

Make sure these are free, otherwise Compose won't come up:

| Port | Service |
| --- | --- |
| 18080 | authz-agent (Envoy, public HTTP) |
| 19901 | authz-agent admin (Envoy) |
| 18181 | OPA-direct (host alias for cross-transport parity tests) |
| 15556 | Keycloak |
| 18081 / 18082 | degraded backends (permissive / strict) |
| 19999 | pip-stub |
| 19998 | entitlements-mock |
| 18090 | authz-policy-admin (policy-pull source) |

Every port can be overridden via an env var (see the top of
[test-envoy-runtime.sh](../test/scripts/test-envoy-runtime.sh)), e.g.
`AUTHZ_AGENT_HTTP_PORT=28080 test/scripts/test-envoy-runtime.sh`.

Quick occupancy check: `ss -ltnp | grep -E ':(18080|15556|19999)'`.

---

## 4. Building the images

The runtime stack uses **7** images. Five are **built locally** from this repo;
two are **pulled** from public registries.

| Image (tag) | Kind | Dockerfile | Build context | Used by services |
| --- | --- | --- | --- | --- |
| `authz-pap-client:local` | built | `build/pap-client/Dockerfile` | repo root (`.`) | `opa-bootstrap`, `opa`, `pap-client`, `opa-partial-*` |
| `decision-log-collector:local` | built | `build/collector/Dockerfile` | repo root (`.`) | `decision-log-collector` |
| `pip-stub:local` | built | `test/integration/pipstub/Dockerfile` | `test/integration/pipstub` | `pip-stub`, `entitlements-mock` |
| `authz-policy-admin:local` | built | `build/authz-policy-admin/Dockerfile` | repo root (`.`) | `authz-policy-admin` |
| `quay.io/keycloak/keycloak:26.0` | pulled | — | — | `keycloak` |
| `envoyproxy/envoy:v1.31-latest` | pulled | — | — | `envoy` (stock image + mounted config/Lua) |

> The `opa-bootstrap`, `opa`, and `opa-partial-*` services all use the
> `authz-pap-client:local` image (bootstrap runs `pap-client bootstrap`, the
> main container runs `pap-client`). Likewise `entitlements-mock` reuses
> `pip-stub:local`.
>
> `build/envoy/Dockerfile` is the **production** Envoy image and is **not** used
> by the integration stack — the test `envoy` service runs the stock upstream
> image with a mounted [envoy.yaml](../test/integration/runtime/envoy.yaml)
> and the Lua from `configs/envoy/lua/`.

### 4.1 One-call build script (recommended)

Builds all five local images with the correct tags and pulls the two base
images, in a single call:

```bash
test/scripts/build-runtime-images.sh
```

The target platform and the base image refs can be overridden via env vars:

```bash
DOCKER_PLATFORM=linux/amd64 test/scripts/build-runtime-images.sh
KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:26.0 test/scripts/build-runtime-images.sh
```

`DOCKER_PLATFORM` defaults to `linux/amd64` in both this script and
[test-envoy-runtime.sh](../test/scripts/test-envoy-runtime.sh) (the latter exports
it as `DOCKER_DEFAULT_PLATFORM`, so *every* image in the stack — pulled ones
included — resolves to that platform). Every repo-local Dockerfile
cross-compiles its Go binary on the build host (`--platform=$BUILDPLATFORM` plus
`GOOS`/`GOARCH`), so a non-native target costs nothing at build time; the
containers themselves still run under emulation.

See [build-runtime-images.sh](../test/scripts/build-runtime-images.sh).

### 4.2 Build through Compose

Compose can build the five local images itself (the wrapper in section 5 does
exactly this via `up -d --build`):

```bash
docker compose -p authz-agent-runtime-test \
  -f test/integration/runtime/docker-compose.yml build
```

### 4.3 Build each image explicitly

If you want to build them one by one, run them from the repository root. These
commands match what Compose builds, with identical tags:

```bash
# 1. pap-client (used by opa-bootstrap and pap-client containers). Context is the repo root.
docker build -t authz-pap-client:local \
  -f build/pap-client/Dockerfile .

# 2. Decision-log collector. Context is the repo root.
docker build -t decision-log-collector:local \
  -f build/collector/Dockerfile .

# 3. PIP stub (also reused as the entitlements mock).
docker build -t pip-stub:local \
  -f test/integration/pipstub/Dockerfile test/integration/pipstub

# 4. authz-policy-admin (the Policy Administration Point; policy-pull source for pap-client).
docker build -t authz-policy-admin:local \
  -f build/authz-policy-admin/Dockerfile .

# 5. Pull the two base images.
docker pull quay.io/keycloak/keycloak:26.0
docker pull envoyproxy/envoy:v1.31-latest
```

### 4.4 Verify the images exist

```bash
docker images | grep -E 'authz-pap-client|decision-log-collector|pip-stub|authz-policy-admin'
```

---

## 5. Run (happy path)

From the repository root:

```bash
test/scripts/test-envoy-runtime.sh
```

What the wrapper does, in order:

1. `docker compose down -v` — clean up any previous run.
2. Lint `openapi.yaml` and render the runtime configs
   (`test/scripts/render-runtime-configs.sh` → `test/.runtime-configs/`).
3. `docker compose up -d --build` — build the five local images (section 4) and
   start the full stack.
4. Run the Testify suite from the host with `FULL_RUNTIME_SUITE=true` (requires
   that **every** catalog step executed).
5. Collect artifacts into `test/artifacts/` (decision logs + per-service logs).
6. On exit, `docker compose down -v` (via `trap`) — the stack is not left running.

Each step prints a `STEP PASS/FAIL <name> <ms>` line. On suite failure the
wrapper dumps the logs of `keycloak`, `envoy`, `opa`, `decision-log-collector`,
`pip-stub`, and the degraded backends.

> The wrapper builds images itself, so running
> `test/scripts/build-runtime-images.sh` first is optional. Pre-building is
> useful to surface build errors separately, or to warm the cache before a
> filtered run.

The first run is slower (Docker pulls and builds images); later runs reuse the
layer cache.

---

## 6. Running a subset of tests

Arguments are forwarded to `go test`. If you pass `-run`, the wrapper drops the
catalog-completeness flag (`FULL_RUNTIME_SUITE=false`) so a filtered run does
not fail on "incompleteness":

```bash
# One sub-suite
test/scripts/test-envoy-runtime.sh -run TestRuntimeSuite/TestCheckResourceBulk

# Verbose
test/scripts/test-envoy-runtime.sh -run TestAuthorize -v
```

### Debugging: stack and tests separately

Handy when iterating on tests without recreating the stack each time:

```bash
# 1. Build images once (section 4), then bring the stack up manually
test/scripts/render-runtime-configs.sh
docker compose -f test/integration/runtime/docker-compose.yml up -d --build

# 2. Run go test as many times as you like
cd test/integration/testify
BASE_URL=http://localhost:18080 \
  KC_BASE_URL=http://localhost:15556/auth/realms/authz-test \
  KC_CLIENT_ID=authz-agent \
  KC_CLIENT_SECRET=authz-agent-secret \
  PIP_STUB_URL=http://localhost:19999 \
  go test -v -count=1 -timeout 600s -tags integration ./...

# 3. Tear the stack down
docker compose -f test/integration/runtime/docker-compose.yml down -v
```

> The full set of env vars the suite expects is the `NAME=value \` block passed
> to `go test` in [test-envoy-runtime.sh](../test/scripts/test-envoy-runtime.sh).
> Everything omitted above (`AUTHZ_POLICY_ADMIN_URL`, `AUTHZ_PAP_CLIENT_PULL_INTERVAL`,
> `ENTITLEMENTS_MOCK_URL`, …) falls back to a default in
> `test/integration/testify/helpers.go` that matches the Compose ports.

### Structural tests without a stack

Catalog↔readme validation and other "dry" checks run without Docker:

```bash
cd test/integration/testify
go test -v -count=1 ./...    # no -tags integration
```

---

## 7. Related checks

### OPA / Rego contract tests (no Docker)

```bash
test/scripts/install-opa.sh    # installs opa into test/tools/opa/ (OPA_VERSION defaults to 1.14.0)
test/scripts/test-opa.sh
```

### Minimum CI gate

For compatibility-sensitive changes, run both (from
[test/readme.md](../test/readme.md)):

```bash
test/scripts/test-opa.sh
test/scripts/test-envoy-runtime.sh
```

---

## 8. Expected reds (NOT regressions)

- **parity ~122/130** — a documented backlog of 8 divergences. This is
  diagnosis, not breakage.
- **`health.healthy_permissive.degraded`** occasionally returns `503` /
  `successCount:0` on a cold stack. Re-run — it is a warm-up flake, not a
  regression.

---

## 9. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `go test` → `[build failed]` | `GOROOT` points at a different toolchain than `go` on `PATH`. Unset it (`env -u GOROOT <command>`) or fix your profile (section 2). |
| `error: required command not found: docker` | Docker not installed / not on PATH (section 2). |
| Compose fails on start, port in use | free the ports in section 3 or override via env var. |
| `permission denied` on docker.sock | add yourself to the `docker` group and start a new login session (`newgrp docker`). |
| `exec format error`, or a build/run step failing only on a non-x86 host | the stack targets `linux/amd64` (section 4.1), so a non-x86 host needs binfmt/QEMU registered: `docker run --privileged --rm tonistiigi/binfmt --install all`. Docker Desktop registers them for you. |
| Image build fails on `go mod download` | network/proxy issue inside the build; retry, or pre-pull the Go base image. |
| Stack left running after Ctrl-C | `docker compose -p authz-agent-runtime-test -f test/integration/runtime/docker-compose.yml down -v`. |
| Need logs after a run | see `test/artifacts/*.log` and `test/artifacts/decision-logs.jsonl`. |
