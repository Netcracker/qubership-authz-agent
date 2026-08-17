# authz-agent-ADR-0030: Local Docker Compose Load-Testing Stack with JMeter and cAdvisor/Prometheus/Grafana

*Archived internal engineering document, restored for reference. Component names and paths reflect the tree at the time of writing and may differ from the current layout.*

## Status

Accepted

## Context

The repository now has an active load-testing preparation plan, but the first implementation phase
needs concrete, stable decisions before any Compose assets or benchmark scenarios are added.

ADR-0031 later refined the local topology from a single bundled container to a split
`envoy` + `opa` + `decision-log-collector` Compose stack while preserving the local
`JMeter` + `cAdvisor` + `Prometheus` + `Grafana` execution model defined here.

The agreed requirements for the first load-testing wave are:

1. target `1000 RPS` through Envoy against the local Authz Agent stack, with per-component
   attribution available for the split runtime topology defined later in ADR-0031;
2. first deliverable is environment preparation for testing;
3. test execution is local;
4. application/runtime services and supporting tooling run via Docker Compose;
5. resource measurements must be collected through `cAdvisor` and visualized via `Prometheus` +
   `Grafana`; and
6. request load must be generated via `JMeter`.

Without a durable decision on the local stack, future implementation work could drift between
multiple generators, monitoring approaches, and execution models, making results hard to compare.

## Decision

1. The first load-testing target is `1000 RPS` through Envoy against the local Authz Agent stack.
   Stage acceptance uses a `±25 RPS` tolerance band and is evaluated separately for canonical and
   legacy runs over the configured stage duration.
2. The first milestone is environment preparation; throughput tuning is deferred until the local
   stack, assets, and measurements are in place.
3. Load testing executes locally via Docker Compose.
4. The local load-testing Compose stack must preserve the current runtime boundary:
   `envoy` as the only public entrypoint, backend `opa`, separate `decision-log-collector`,
   the IdP dependency (`Keycloak` in the current runtime tests), and the existing policy/PIP
   upload flow remain part of the environment.
5. All repository-managed load-testing assets must live under `tests/svt/`.
6. `JMeter` is the standard load generator for this effort.
7. `cAdvisor` is the source for container resource metrics; `Prometheus` scrapes those metrics; and
   `Grafana` provides visualization for benchmark analysis.
8. `JMeter` is the source of truth for request throughput and latency metrics; the observability
   stack is the source of truth for container resource usage during runs.
9. Scope for the first benchmark wave is limited to the currently implemented public surface:
   `POST /access/v1/authorize`, `POST /access/v1/check/resource`,
   `POST /access/v1/check/resource/bulk`, `POST /access/v1/check/filter`, and optional `GET /health`
   smoke checks.
10. Every load-testing scenario must be measured twice:
    - once through the canonical endpoint flow; and
    - once through the corresponding legacy endpoint flow.
    The request composition must be semantically identical across the pair even when transport
    shapes differ.
11. The first minimal paired measurement scope must include all implemented legacy endpoint
    families and the corresponding canonical request types.
12. User/request distribution is driven from CSV data.
13. Wrapper orchestration uses repository-managed scripts:
    - `up` for bootstrap/update;
    - `run` for paired measurement execution; and
    - `down` for deterministic teardown of the local SVT environment.
14. The requested initial backend container limit baseline is `4 CPU` and `8G RAM`, but the
    first validated runnable backend profile uses `8 CPU` and `8G RAM` because canonical authorize
    saturates `4 CPU` at roughly `850 RPS`. Envoy and the decision-log service remain uncapped in
    this stage unless a future benchmark handover explicitly changes that.
15. The first-stage host baseline is the current local machine:
    - OS: Ubuntu 24.04.4 LTS
    - kernel: `6.18.7-76061807-generic`
    - CPU: AMD Ryzen 9 8945HS with `16` logical CPUs / `8` physical cores
    - memory: `92 GiB` RAM, `8 GiB` swap
    - container runtime: Docker Engine `29.3.1`, Docker Compose `v5.1.1`
16. After each execution, the `run` wrapper must preserve `JTL`, dashboard-ready metrics, and a
    Prometheus time-series snapshot.
17. Deferred legacy/v2 endpoints remain out of scope and keep their current `404` behavior unless a
    future committed handover re-activates them.
18. Load-testing execution remains separate from the default functional compatibility gate
    (`tests/scripts/test-opa.sh` and `tests/scripts/test-envoy-runtime.sh`).

## Consequences

### Positive

1. The repository now has one fixed local load-testing stack, one fixed load generator, and one
   fixed repository root for SVT assets.
2. Benchmark assets can be added incrementally under `tests/svt/` without reopening layout choices
   on every task.
3. Resource visualization is standardized across runs through `Prometheus` + `Grafana`.
4. Canonical-vs-legacy result pairs become directly comparable because both are built from the same
   semantic request set.
5. Fixed container limits and fixed exported artifacts improve comparability between local runs.
6. The first-stage benchmark wave is anchored to one explicit host baseline rather than informal
   local-machine assumptions.
7. Local setup and teardown become explicit and repeatable instead of relying on manual Compose
   commands.
8. The plan stays aligned with the current runtime boundary instead of benchmarking a synthetic
   bypass path.
9. ADR-0031 owns the split-topology details; this ADR remains the durable decision for the local
   load-testing workflow, tooling, artifact set, and throughput target.

### Trade-offs

1. Local Docker Compose results are host-specific and must not be treated as production capacity
   claims without explicit host/limit metadata.
2. `JMeter` and the system under test share local host resources unless Compose isolation and
   container limits are defined carefully.
3. `cAdvisor` exposes container-level metrics only; it does not replace request-level latency data
   from `JMeter`.
4. Each scenario now requires paired canonical and legacy execution, which increases runtime and
   fixture-maintenance effort.
5. Fixed limits (`8 CPU`, `8G RAM` in the current validated profile) can reduce host flexibility
   during local execution.
6. The accepted `±25 RPS` band reflects practical convergence behavior of the JMeter rate limiter;
   it is tighter than a simple lower-bound target but less brittle than demanding a literal single
   integer throughput value in every run.
7. Results remain specific to the recorded local host and still should not be treated as production
   capacity claims.
8. Additional artifact capture after every run increases storage usage under `tests/svt/artifacts/`.
9. Wrapper ownership now includes teardown behavior, so documentation and scripts must stay
   synchronized when Compose options change.
10. Additional Compose services (`JMeter`, `cAdvisor`, `Prometheus`, `Grafana`) increase setup and
   maintenance overhead for the load-testing environment.

## References

1. `docs/plans/20260330-load-testing-preparation-plan.md`
2. `docs/handovers/20260330-svt-environment-and-basic-jmeter-task.md`
3. `tests/integration/runtime/docker-compose.yml`
4. `image/README.md`
5. `docs/decisions/20260331-authz-agent-adr-0031-compose-topology-split-for-load-tracking.md`
