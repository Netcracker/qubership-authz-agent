# authz-agent-ADR-0034: Additive OPA-Direct SVT Profile for Backend-Isolated Diagnostics

*Archived internal engineering document, restored for reference. Component names and paths reflect the tree at the time of writing and may differ from the current layout.*

## Status

Superseded by authz-agent-ADR-0061. Statements below are historical — the OPA-direct profile is preserved under the new naming (`ignoreRls` replaces `rlsRequired` in the normalized OPA input body).

## Context

ADR-0030 fixed the primary SVT benchmark model around the client-visible Envoy boundary. That
remains the compatibility benchmark because real clients reach Authz Agent through Envoy and Envoy
Lua transformations are part of the externally observed path.

At the same time, recent latency investigation needs a second benchmark view that isolates backend
OPA decision cost from Envoy overhead without changing the product runtime architecture. The
repository already has a split local topology (`envoy` + `opa` + `decision-log-collector`), and
the JMeter runner executes from inside the same Compose network, so an internal-only diagnostic
profile can target OPA directly without exposing any new public route.

The new profile must stay comparable to the main SVT scenario by reusing the same workload meaning,
dataset composition, and call-family ratios.

## Decision

1. Add an **internal-only, additive** SVT benchmark profile that targets backend OPA directly at
   `POST /v1/data/authorize/result` over the Compose network.
2. The new profile does **not** replace the Envoy-boundary benchmark from ADR-0030. Envoy-boundary
   runs remain the primary compatibility and client-visible performance benchmark.
3. The OPA-direct profile must reuse the same semantic workload mix as the main SVT baseline:
   - one-resource authorization;
   - filter-style authorization; and
   - bulk authorization.
4. The OPA-direct profile must reuse the same CSV datasets and the same `1/3 : 1/3 : 1/3`
   stage-level throughput split across those three call families as the main baseline profile.
5. The OPA-direct requests must send the same normalized OPA input body that Envoy would send for
   the corresponding semantic call family, including:
   - `authorizationToken`;
   - `authorizationType`;
   - `requestHeaders`;
   - `decisionLogPipTrace`;
   - normalized `resources`;
   - `subject`; and
   - `rlsRequired`.
6. The profile is internal to the local SVT stack only:
   - OPA remains unexposed on the public host interface;
   - JMeter reaches OPA through Compose DNS (`opa:8181`);
   - no public API contract or runtime routing is changed.
7. The OPA-direct profile uses its own JMeter plan, scenario document, wrapper script, and
   artifacts so it can be executed independently from the main Envoy-boundary paired benchmark.
8. Results from the OPA-direct profile are diagnostic and must not be presented as public-route or
   compatibility-route benchmark results.

## Consequences

### Positive

1. Backend decision cost can now be measured without Envoy/Lua overhead.
2. The same semantic workload mix can be compared across two paths:
   Envoy-boundary and OPA-direct.
3. The additive profile stays compatible with the current architecture because it does not expose
   new public routes and does not alter OPA or Envoy runtime behavior.

### Trade-offs

1. The repository now maintains two benchmark profiles for the same semantic dataset.
2. OPA-direct results are easier to misuse unless documentation clearly distinguishes them from the
   primary Envoy-boundary benchmark.
3. The diagnostic profile still includes backend-side behavior such as decision logging, so it is
   not a pure in-process Rego microbenchmark.

## References

1. `docs/decisions/20260330-authz-agent-adr-0030-local-compose-jmeter-load-testing-stack.md`
2. `docs/decisions/20260331-authz-agent-adr-0031-compose-topology-split-for-load-tracking.md`
3. `docs/plans/20260330-load-testing-preparation-plan.md`
4. `tests/svt/jmeter/plans/baseline-authz.jmx`
