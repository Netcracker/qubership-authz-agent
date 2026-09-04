# qubership-authz-agent

An OPA-based authorization proxy for Kubernetes.  The deliverable is a **Helm
chart** that assembles the agent Pod; there is no single image called
`authz-agent`.  The agent is a Pod composed of:

- [`openpolicyagent/opa`](https://hub.docker.com/r/openpolicyagent/opa) — the upstream OPA image, used unmodified and pinned by digest
- `authz-agent-pap-client` — Policy Administration Point client: bootstraps OPA's data directory, pulls policies and PIPs, and pushes live updates over OPA's Data API
- `authz-agent-envoy` — Envoy proxy carrying Lua filters that rewrite legacy access-control HTTP requests into OPA queries and back
- `authz-agent-collector` — decision-log receiver, accepts OPA's decision-log batch stream
- `authz-agent-token-fetcher` — sidecar that obtains and refreshes the M2M OAuth2 credential

In addition, `authz-policy-admin` is a standalone Deployment (its own Service
and PersistentVolumeClaim) that acts as the primary policy source.  Its image
name has no `authz-agent-` prefix because it is not a container of the agent
Pod.

## Maturity

**Pre-1.0, no releases yet.**  The component has no published release and no
stable API commitment.  The access-control-compatible API surface — the legacy
check endpoints that Envoy rewrites — is deliberately partly unimplemented:
only the paths that the test suites exercise are wired.  The deployment assumes
a Kubernetes cluster running the Netcracker platform (Keycloak realm structure,
M2M credential provisioning, optional service-mesh route registration).  A
team deploying this without the platform will need to supply their own identity
provider and adjust the Helm values accordingly.

## Policy source

[`authz-policy-admin`](components/authz-policy-admin/README.md) is the
supported policy source.  Enable it with `AUTHZ_POLICY_ADMIN_ENABLED=true` in
the Helm chart and load simplified policies and PIPs over its unauthenticated
HTTP API.

Pulling policies from the platform's access-control service is also supported:
set `AUTHZ_PAP_CLIENT_SOURCE_URL` to the access-control service URL.  When
that is set, `authz-policy-admin` is not needed and can be disabled.

## Chart

The Helm chart is at `charts/authz-agent/`.

```sh
# Render chart templates (requires policies to be staged first)
make copy-policies
helm template charts/authz-agent
```

## Building images

Each image has its own Dockerfile under `build/`:

```sh
# Build an image locally
docker build -t authz-agent-pap-client:local -f build/pap-client/Dockerfile .
docker build -t authz-agent-envoy:local       -f build/envoy/Dockerfile .
docker build -t authz-agent-collector:local   -f build/collector/Dockerfile .
docker build -t authz-agent-token-fetcher:local -f build/token-fetcher/Dockerfile .
docker build -t authz-policy-admin:local      -f build/authz-policy-admin/Dockerfile .
```

CI builds all five via `.github/docker-dev-config.json`.

## Testing

See `test/BASELINE.md` for recorded baseline results.  All suites below were
verified from a clean clone on public images.

### Prerequisites

- Go 1.24+
- [OPA CLI](https://www.openpolicyagent.org/docs/latest/#1-download-opa) (for Rego tests; also installable via `bash test/scripts/install-opa.sh`)
- Docker and Docker Compose (for integration, parity and load suites)
- `helm` (for chart render test)

### Unit tests — Go

```sh
# Root module (four binaries + shared packages): 249 tests
go test -count=1 ./...

# Parity replay module
cd test/parity/suite && go test -count=1 ./...

# Integration testify module (non-integration tests only without a running stack)
cd test/integration/testify && go test -count=1 ./...

# Pip-stub module
cd test/integration/pipstub && go test -count=1 ./...
```

### Unit tests — Rego

```sh
# 352 policy tests
opa test policies/
```

### Chart render

```sh
bash test/scripts/test-chart-render.sh
```

### Integration test suite

Requires Docker Compose and externally reachable images (public by default).

```sh
# Build local images first
bash test/scripts/build-runtime-images.sh

# Render Envoy/OPA configs from templates
bash test/scripts/render-runtime-configs.sh

# Run all integration tests (starts the compose stack automatically)
bash test/scripts/test-envoy-runtime.sh
```

Expected: ~164 PASS, 0 FAIL, 2 SKIP (m2m-keycloak tests require
`RUN_M2M_KEYCLOAK_PROFILE=true`).

### Kind end-to-end

Installs the Helm chart on a kind cluster and runs the runtime suite against
it from inside the cluster. This is the integration check CI runs
(`.github/workflows/integration-tests.yaml`); the Compose stack above is the
older local harness. Requires Docker, `kind`, `kubectl`, and `helm`.

```sh
make e2e          # cluster, images, harness, chart, suite
make e2e-logs     # container logs, events, decision logs into test/artifacts/kind/
make e2e-down     # delete the cluster
```

See [test/k8s/README.md](test/k8s/README.md) for the individual targets and
for the suite groups the kind run does not cover yet.

### Parity replay

Replays recorded HTTP requests against the agent and compares responses against
golden files captured from the legacy access-control service.  The goldens are
a frozen capture; they cannot be regenerated from this repository (see
`test/parity/README.md`).

```sh
# Build images (uses public base images)
bash test/parity/scripts/build-images.sh

# Run replay
PARITY_PROFILE=authz-agent bash test/parity/scripts/run-parity-suite.sh
```

Expected: 135/135 PASS.

The same replay runs on kind against the Helm chart, which is what CI does:

```sh
make parity
```

### Load harness smoke check

```sh
bash test/svt/scripts/up
```

The script starts the SVT compose stack, sends one authorisation request, and
tears the stack down.  Expected: 200 OK.

## Development

After cloning, enable the bundled pre-commit hook so every commit is linted
with the same tools and configuration the CI uses (`.github/linters/`):

```sh
make install-hooks
```

`make lint` runs the same checks over the whole tree. See
[CONTRIBUTING.md](CONTRIBUTING.md) for details.
