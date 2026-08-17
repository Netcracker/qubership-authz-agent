# authz-agent-ADR-0031: Compose Topology Split for Per-Component Load Tracking

*Archived internal engineering document, restored for reference. Component names and paths reflect the tree at the time of writing and may differ from the current layout.*

## Status

Accepted

## Context

The SVT and runtime integration Compose stacks use a single `authz-agent` container that bundles
Envoy, OPA, and policy-admin. This makes it impossible to attribute CPU, memory, and network
usage to individual components during load testing. The load-testing preparation plan
(ADR-0030) identifies per-component observability as a prerequisite for meaningful benchmark
analysis.

The target deployment model runs Envoy as a sidecar for the backend authz runtime. The Compose
topology should mirror this model while keeping Envoy as the only public entrypoint.

Additionally, OPA decision-log ingestion shares the backend container, so decision-log collector load is
attributed to the authorization runtime rather than being isolated.

## Decision

Split the single `authz-agent` Compose service into three services:

1. **`envoy`** — standalone Envoy proxy (public entrypoint, ports 8080/9901).
   Uses the upstream `envoyproxy/envoy:v1.31-latest` image directly with mounted
   `envoy-split.yaml` and Lua scripts. No CPU/RAM limits in this task.

2. **`opa`** — backend authz runtime (OPA + policy-admin + JWKS bootstrap).
   Uses the dedicated `authz-backend:local` image built from `image/Dockerfile.backend`.
   The backend-only entrypoint (`start-backend.sh`) starts OPA and policy-admin without Envoy.
   OPA listens on `0.0.0.0:8181`, policy-admin on `0.0.0.0:8182`.

3. **`decision-log-collector`** — dedicated decision-log ingest and download service.
   Uses the dedicated `decision-log-collector:local` image built from
   `image/Dockerfile.collector` and runs a standalone collector binary on port `8183`.

### Routing changes

Envoy upstream clusters switch from `127.0.0.1` (loopback) to Compose service DNS names:

- `opa_cluster` → `opa:8181`
- `policy_admin_cluster` → `opa:8182`
- `decision_log_cluster` → `decision-log-collector:8183`

OPA decision-log shipping target changes from `http://127.0.0.1:8182` to
`http://decision-log-collector:8183`.

### Healthcheck changes

- Envoy: `curl -sf http://localhost:9901/ready` (Envoy admin readiness).
- Backend (opa): `wget -q -O /dev/null http://localhost:8182/health` (policy-admin health,
  bypasses Envoy).
- Decision-log-collector: `wget -q -O /dev/null http://localhost:8183/healthz`.

### Degraded health scenarios

Degraded agents (`opa-partial-permissive`, `opa-partial-strict`) run backend-only containers
without their own Envoy. Tests probe health directly on the policy-admin port (`8182`).

### Grafana dashboard

SVT dashboard shows separate CPU, memory, and file-system I/O panels for the three measured
containers: `envoy`, `opa`, and `decision-log-collector`. Network I/O remains a shared
measured-set panel with separate series per container.

## Consequences

1. Per-component CPU, memory, and file-system I/O attribution is possible during load runs, with
   network I/O retained as a shared measured-set view.
2. Decision-log collector load is isolated from authorization runtime.
3. External clients still see one logical service (Envoy is the only public entrypoint).
4. Public API contracts and OPA decision boundary are unchanged.
5. Existing environment variable names are preserved.
6. The original single-container `image/Dockerfile` and `start-authz-stack.sh` remain
   unchanged for production use; split-mode assets are additive.
7. Runtime integration tests and SVT require three containers instead of one, increasing
   local Docker resource usage.

## References

- [ADR-0030: Local Compose Load-Testing Stack](20260330-authz-agent-adr-0030-local-compose-jmeter-load-testing-stack.md)
- [Load Testing Preparation Plan](../plans/20260330-load-testing-preparation-plan.md)
- Handover: Envoy Compose Split
- ADR-0026: Health Endpoint
