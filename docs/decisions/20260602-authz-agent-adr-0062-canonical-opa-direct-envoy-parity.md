# authz-agent-ADR-0062: Canonical OPA-Direct And Envoy Parity

*Archived internal engineering document, restored for reference. Component names and paths reflect the tree at the time of writing and may differ from the current layout.*

## Status

Accepted

## Context

Today the canonical authorize call enters the agent at Envoy's public
listener as `POST /access/v1/authorize`, where a per-route Lua filter
(`authorize.lua`) mutates the request body — token verification result,
normalised identity claims, trusted-provider context, and other
injections — before Envoy forwards the rewritten body to OPA at
`POST /v1/data/authorize/result`. OPA evaluates `data.authorize.result`
and returns the canonical response object; Envoy passes it back unchanged
on canonical. The check-family routes (`/access/v1/check/resource*`,
`/access/v1/check/filter`) share the same OPA endpoint and bear their own
per-route Lua filters that translate to and from the canonical Rego
contract.

This shape carries three motivations to change, in this order:

1. **Lower per-request decision-time on canonical** by letting clients
   skip the Envoy hop. The D8 transport-vs-transport SVT report
   under `tests/svt/load-tests/canonical-transport-comparison-<YYYYMMDD>/`
   supplies the numeric proof: <!-- TODO(ADR-0062): backfill p50/p95/p99
   + throughput deltas from the D8 SVT report -->.
2. **Eliminate the Envoy tax** for deployments that adopt the
   OPA-direct path: sidecar CPU and RAM footprint, Lua filter execution
   cost, and an extra deserialise / serialise plus body mutation per
   canonical request.
3. **Unlock the option to retire Envoy entirely on the canonical path**
   in a future task. Once `/v1/data/authorize` is the documented contract
   surface and the canonical client wire-shape is byte-identical to
   OPA's native input, a deployment that does not depend on the
   `/access/v1/check/*` family can be shipped without the Envoy sidecar
   at all.

The OPA-received request body is performance-optimal for the current
Rego policies — `normalized_request`, `pip_resolved`, token-claim
extraction, the rule fan-out — and moving any of that compute around
would regress the decision-time targets the SVT suite enforces. The
canonical contract break must therefore propagate **outward** to the
client wire-shape, not **inward** into Rego: the body OPA sees today
becomes the body the client sends.

The check-family routes (`/access/v1/check/resource*`,
`/access/v1/check/filter`) are out of scope for the external contract
break — their client-facing request, response, and HTTP status codes
stay byte-identical. The Envoy/Lua plumbing behind them is in scope,
because retargeting OPA to a single canonical entrypoint means every
route — canonical and check-family alike — must point at
`/v1/data/authorize` rather than `/v1/data/authorize/result`. The
check-family Lua filters absorb that internal change without leaking
any of it to their callers.

The server and every SDK consumer (shared Java wire-schemas, Spring,
Quarkus, Go + Fiber + Gin) deploy together. No external party
currently bills against `/v1/data/authorize/result` as a stable
contract surface. A dual-accept window in Envoy, a deprecation alias,
or a chart major bump would therefore carry an indefinite cost for no
migration benefit. The same hard-cutover precedent applies as in
authz-agent-ADR-0059.

## Decision

1. **OPA's canonical decision endpoint is `POST /v1/data/authorize`.**
   The path `POST /v1/data/authorize/result` is retired from every
   Envoy route, every OPA-direct caller, every integration / parity /
   SVT script, and every doc. The wire path
   `/v1/data/authorize/result` is no longer addressable on the OPA
   listener for this agent.
2. **Rego is restructured into a two-package layout** under
   `helm-templates/authz-agent/files/opa/policies/`:
   + `package authorize_internals` — every existing top-level rule of
     today's `package authorize` is relocated here byte-identical, with
     today's `result` rule renamed to `canonical`.
     `authorize_internals.canonical` is the canonical response object.
     No rule body edits; `normalized_request`, `pip_resolved`,
     token-claim extraction, OLS/RLS evaluation logic all stay exactly
     as today. **Sibling top-level package, not a dotted sub-package
     of `authorize`:** OPA 1.x always exposes a sub-package under its
     parent's data tree, so a dotted `package authorize.internals`
     layout would leak the full internal compute graph
     (`_admission_*`, `normalized_request`, `authorization_evaluation`,
     ~200+ rule outputs) into the wire response of
     `POST /v1/data/authorize` inside the `{"result": ...}` envelope —
     breaking the byte-identity invariant this ADR locks in. A single
     underscore-joined token (`authorize_internals`) keeps the
     internal rules off the canonical wire while preserving every
     other restructure constraint (relocation byte-identity, `result` →
     `canonical` rename, no alias rule, no mirror sub-package).
   + `package authorize` — one thin extraction rule per canonical
     response key (`rlsIgnored`, `results`, `authError`), each body a
     pure read from `data.authorize_internals.canonical.<same-key>`,
     with `default` where today's `result` rule carried a default
     branch.
   After this, `data.authorize` evaluates to the canonical response
   object and `POST /v1/data/authorize` returns OPA's natural
   `{"result": <canonical>}` envelope. **`data.authorize.result` ceases
   to exist as a rule** — there is no `package authorize.result`
   mirror and no alias rule (OPA's recursion check rejects
   `data.authorize.result := data.authorize`). Every consumer migrates
   to `data.authorize` / `/v1/data/authorize` in this same change.
3. **Canonical response wire-shape rebases onto OPA's natural envelope**
   `{"result": <canonical_response>}` on both transports — `POST
   /access/v1/authorize` through Envoy and `POST /v1/data/authorize`
   direct to OPA. OpenAPI, shared Java `AuthorizeResponse`, Spring /
   Quarkus client plumbing, Go client DTO, Postman, fixtures, and docs
   all follow. The internal structure of the canonical response object
   (including the `predicates[]` array defined in
   authz-agent-ADR-0029)
   is preserved verbatim under `result.results[]`.
4. **Canonical request wire-shape rebases onto the OPA-native body.**
   Every field the Envoy `authorize.lua` filter injects today on
   `/access/v1/authorize` is classified as either **(R)** — promoted
   into the canonical request wire-shape and supplied explicitly by the
   client — or **(D)** — dropped because it was never load-bearing. The
   audit and its (R/D) table land in the parent task's *Decisions*
   section before any code change. The "**move into Rego**" option is
   forbidden: Rego compute and the OPA-received body shape are frozen.
   After this rebase, the canonical request body the client sends is
   byte-identical to the body OPA receives.
5. **Envoy stops transforming the canonical route.** On
   `/access/v1/authorize` in `image/deployments/envoy/envoy.yaml`, the
   per-route Lua binding `authorize` is dropped, `prefix_rewrite`
   switches from `/v1/data/authorize/result` to `/v1/data/authorize`,
   and the route reduces to pure routing with zero body mutation.
   `image/deployments/envoy/lua/authorize.lua` is deleted (any helpers
   still needed by check-family filters are extracted into a separate
   shared module or inlined into each consumer before deletion).
6. **Every check-family route switches its `prefix_rewrite` to
   `/v1/data/authorize`** as well — `/access/v1/check/resource`,
   `/access/v1/check/resource/v2`, `/access/v1/check/resource/bulk`,
   `/access/v1/check/resource/bulk/operations`,
   `/access/v1/check/resource/bulk/operations/v2`,
   `/access/v1/check/resource/bulk/v2`, `/access/v1/check/filter`, and
   any other route currently pointing at `/v1/data/authorize/result`.
   The per-route Lua bindings on the check-family routes
   (`check_resource.lua`, `check_resource_v2.lua`,
   `check_resource_bulk.lua`, `check_resource_bulk_operations.lua`,
   `check_resource_bulk_operations_v2.lua`, `check_filter.lua`) stay,
   and each filter's response-handling block is adapted to consume the
   new `{"result": <data.authorize>}` envelope. The check-family
   request-side Lua bodies are not edited — they continue producing the
   same OPA-bound body shape as today. The client-facing wire-shape of
   `/access/v1/check/*` (request body, response body, HTTP status
   codes) is byte-stable; every existing non-canonical integration /
   parity / SVT / Postman test must stay green untouched.
7. **OPA is exposed on a new pod port `opa:8181` and matching Service
   port `8181`** in the Helm chart at
   `helm-templates/authz-agent/templates/deployment.yaml` and
   `helm-templates/authz-agent/templates/service.yaml`. The Service
   port name is `opa`; the port number `8181` is hard-pinned with no
   chart-level value override. OPA's listener binds `0.0.0.0:8181`
   (loopback-only is corrected to wildcard if found during audit).
8. **The new Service port `:8181` is exposed without component-level
   auth or NetworkPolicy.** The chart does not add a bearer-token or
   mTLS auth on the OPA listener, does not ship a NetworkPolicy
   resource, and does not gate the port behind a chart-level toggle.
   Production security on the OPA-direct surface is provided by
   external network controls outside this chart — cluster-level
   network policy, namespace isolation, service mesh policy, ingress
   filtering — and that assumption is documented in the repo-level
   `README.md` Deployment section and `docs/architecture.md` Security
   section.
9. **Hard cutover, no backward compatibility.** Same precedent as
   authz-agent-ADR-0059:
   the canonical contract break lands as one growing MR on
   `feature/authz-agent-api-changes`, anchored by this ADR as the
   single external signal. No dual-accept window in Envoy, no
   deprecation alias, no CHANGELOG entry, no Helm chart major bump
   dictated by this contract change. The agent and every SDK consumer
   deploy together — mismatched server/SDK pairs return `DENY` / `400`
   in both directions; orchestrating the coordinated rollout across
   environments is owned by ops, not by this contract change.
10. **Parity is locked in by two regression test extensions.** A new
    integration parity test fires the same canonical fixture twice —
    once at `POST /access/v1/authorize` on Envoy's service port and
    once at `POST /v1/data/authorize` on the new Service port `:8181`
    — and asserts byte-identical request body shape (evidence: OPA
    decision-log capture or echoed `data.authorize_internals.normalized_request`)
    and byte-identical response body (after `jq -S` normalisation).
    The existing OPA-request parity regression
    (authz-agent-ADR-0032)
    is extended to cover the response side too — request parity stays
    intact, response parity is added under the same harness.
11. **Admission failures move from an HTTP-status signal to an in-envelope
    `authError` object.** Before the rebase, the Envoy canonical route's
    `authorize.lua` filter translated an admission failure (missing or
    invalid admission token, anonymous-mode rejection) into an HTTP `401`
    response carrying a top-level `reason`. With the canonical route reduced
    to pure routing (Decision 5) Envoy no longer inspects the OPA result,
    and the OPA-direct transport has no proxy at all — so OPA always returns
    HTTP `200` and the admission verdict is carried inside the canonical
    envelope as `result.authError`: `result.authError.status` holds the
    numeric code (e.g. `401`) and `result.authError.reason` holds the same
    human-readable text the pre-rebase `401` body carried. The verdict
    (a non-grant) is preserved unchanged; only its transport encoding moves
    from an HTTP status code to an envelope field, identically on both
    transports. The `authError` key is projected by `package authorize`
    (`authError := data.authorize_internals.canonical.authError`) and is
    absent from the envelope on a successful admission.

This ADR amends the following predecessors. None are wholly
superseded; each retains its remaining normative content and is cited
here for the narrow contract surface that changes:

+ authz-agent-ADR-0013
  — the canonical external endpoint `/access/v1/authorize` and the
  non-exposure of OPA paths on the Envoy public listener are
  preserved. The "OPA binds to loopback inside the container" clause
  is lifted: OPA now binds `0.0.0.0:8181` and the chart publishes the
  port on the Service. The "Envoy applies minimal transformation"
  clause is narrowed to legacy check-family routes only; canonical is
  pure routing.
+ authz-agent-ADR-0027
  — Rego stays canonical-only and endpoint-agnostic. The "Envoy owns
  legacy compatibility transformations" boundary holds for the
  check-family routes; on canonical, no Envoy transformation remains
  because the canonical client wire-shape now matches the OPA-native
  body byte-for-byte.
+ authz-agent-ADR-0029
  — the canonical `predicates[]` array contract is preserved inside
  the canonical response object. The wire-shape change is the outer
  envelope (`{"result": <canonical_response>}`); the per-resource
  `predicates[]` structure under `result.results[]` is unchanged.
+ authz-agent-ADR-0032
  — request parity at the OPA boundary is preserved. The only
  allowed route-specific request difference remains
  `x-authz-original-path`. This ADR extends the parity guarantee to
  cover the response side too, under the same regression harness.
+ authz-agent-ADR-0048
  — the OPA path clauses (canonical decision endpoint
  `/v1/data/authorize/result`; Envoy compatibility routes forward to
  `/v1/data/authorize/result`; non-exposure of `/v1/data/authorize/result`
  on the Envoy public listener) are lifted: the canonical decision
  endpoint moves to `POST /v1/data/authorize`, Envoy compat routes
  retarget there, and the non-exposure clause on the Envoy public
  listener now reads as "`/v1/data/authorize` and the retired
  `/v1/data/authorize/result` are both not exposed on Envoy's public
  listener; the new Service port `:8181` is a separate listener".
  The PUT-only policy-upload normative claim (decisions 4 and 5 of
  ADR-0048) is unaffected and remains in force.

## Consequences

### Positive

1. The canonical contract has one transport-agnostic shape on both
   sides. A request body authored for `POST /access/v1/authorize`
   works unchanged at `POST /v1/data/authorize`, and the response
   parses the same way on both endpoints.
2. OPA exposes one canonical evaluation surface (`/v1/data/authorize`)
   for every route in the stack — canonical and check-family alike —
   which is the structural precondition for the future task that
   retires Envoy entirely on canonical-only deployments.
3. The Envoy tax on the canonical path becomes opt-in: deployments
   that adopt the OPA-direct port pay for neither the sidecar's
   CPU/RAM nor the per-request Lua + body-mutation cost. The D8 SVT
   report quantifies the headline numbers.
4. Decision logs and parity assertions converge on a single
   ground-truth path (`data.authorize` / `internals.canonical`); the
   "is the canonical decision at `.result` or at the package root?"
   ambiguity that ADR-0048 had to reconcile is gone.

### Negative

1. **Wire-breaking change** on the canonical request shape. A client
   that previously delegated identity normalisation and token
   verification to the Envoy `authorize.lua` filter must now supply
   the (R)-class fields explicitly. Old-SDK→new-server and
   new-SDK→old-server pairings both return `DENY` / `400`; rollout
   requires coordinated deploys of the agent and every SDK consumer.
   The (R/D) audit table in the parent task's *Decisions* section is
   the authoritative list of new request fields.
2. **Wire-breaking change** on the canonical response envelope.
   Decision-log consumers and any tool that parses the canonical
   response must now read `body.result.<key>` instead of `body.<key>`.
   The shared Java `AuthorizeResponse`, Spring / Quarkus client
   plumbing, Go client DTO, OpenAPI, Postman, and docs land in
   lockstep with the agent.
3. **`data.authorize.result` is gone as a queryable path.** Any
   tooling that hard-codes `POST /v1/data/authorize/result` or
   `data.authorize.result` (SVT profilers, JMeter plans, parity
   scripts, decision-log assertions, integration fixtures) migrates
   within this MR. The parent task's *Final sweep* step is the gate.
4. The check-family Lua filters become responsible for parsing the
   `{"result": <data.authorize>}` envelope on the response side. The
   added complexity is response-side only and self-contained per
   filter; the client-facing wire-shape of `/access/v1/check/*` stays
   byte-stable, verified by leaving every non-canonical test
   untouched.
5. The new Service port `:8181` is reachable from anywhere the chart
   allows pod-to-pod traffic. Operators who do not restrict this at
   the cluster network layer (network policy, namespace isolation,
   service mesh policy, ingress filtering) expose the OPA decision
   surface broadly; the chart explicitly does not ship a
   NetworkPolicy or component-level auth and documents this assumption
   in the repo-level `README.md` and `docs/architecture.md`.
6. Historical handovers under `docs/handovers/**` and superseded ADRs
   under `docs/decisions/superseeded/` retain the old endpoint paths
   (`/v1/data/authorize/result`, `data.authorize.result`). They are
   frozen records of past decisions; a reader who lands on one of them
   must check the current canonical contract for the live shape.
7. **Admission failures no longer surface as HTTP `401`.** A canonical
   client that branched on the HTTP status code to detect an
   authentication / admission failure now receives HTTP `200` on both
   transports and must instead inspect `result.authError` (`status` +
   `reason`) — see Decision 11. This is a wire-breaking change for
   status-code-driven clients; it lands in the same coordinated cutover as
   the request/response envelope rebase (Decision 9), and the SDK consumers
   map `result.authError.status` back onto their own error surfaces. The
   verdict itself is unchanged — an admission failure is still a non-grant
   — only its encoding moved into the envelope.

### Neutral

1. The `predicates[]` array contract under
   authz-agent-ADR-0029
   is preserved verbatim — the change is structural (outer envelope
   plus the two-package Rego layout), not semantic. Decision outcomes
   on canonical and check-family fixtures are unchanged.
2. The Rego compute frozen under D6 means the SVT decision-time
   profile on the Envoy leg of the D8 comparison report is, in
   isolation, expected to match the pre-change Envoy baseline (the
   only Envoy-side change on canonical is removing the per-request
   Lua transform — Rego itself is byte-identical). Any drift in that
   Envoy baseline number is a signal of broken assumptions, not of
   compute changes.

## References

1. Amends authz-agent-ADR-0013
   — lifts the loopback-bind clause, narrows the Envoy canonical
   transformation to zero (canonical route is routing-only).
2. Amends authz-agent-ADR-0027
   — Envoy compatibility transforms remain on the check-family routes
   only; canonical route reduces to pure routing.
3. Amends authz-agent-ADR-0029
   — `predicates[]` array is preserved under `result.results[]`; the
   outer envelope is `{"result": <canonical_response>}`.
4. Amends authz-agent-ADR-0032
   — request parity preserved; parity regression extended to response
   side under the same harness.
5. Amends authz-agent-ADR-0048
   — canonical decision endpoint moves from
   `POST /v1/data/authorize/result` to `POST /v1/data/authorize`;
   PUT-only policy-upload contract preserved.
6. Hard-cutover precedent: authz-agent-ADR-0059
   — same single-ADR-as-external-signal pattern, no dual-accept, no
   CHANGELOG, no chart major bump.
7. `docs/handovers/20260602-canonical-opa-direct-envoy-parity-task.md`
   — execution plan and (R/D) audit table.
8. `tests/svt/load-tests/canonical-transport-comparison-<YYYYMMDD>/`
   — D8 transport-vs-transport perf report supplying the numeric
   backfill for motivation point (i).
9. `helm-templates/authz-agent/files/opa/policies/` — two-package
   Rego layout (`authorize_internals` + `authorize`).
10. `image/deployments/envoy/envoy.yaml` and
    `image/deployments/envoy/lua/` — canonical route Lua binding
    dropped; check-family Lua filters adapted response-side only.
11. `helm-templates/authz-agent/templates/deployment.yaml` and
    `helm-templates/authz-agent/templates/service.yaml` — new `opa:8181`
    container port and matching Service port.
12. `clients/shared/java/wire-schemas/`, `clients/spring/`,
    `clients/quarkus/`, `clients/go/` — SDK wire-DTO surfaces updated in
    lockstep with the contract break.
13. `docs/design/api-spec/openapi.yaml`, Postman collection — public
    contract reference updated to the new request and response shapes.
