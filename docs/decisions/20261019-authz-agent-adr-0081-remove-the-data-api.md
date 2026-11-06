# Remove the data API from the agent

## Status

Accepted. The parts that keep `POST /access/v1/authorize` are superseded by the removal of that route in
[PR #109](https://github.com/Netcracker/qubership-authz-agent/pull/109): the route on ports 8080 and 8181 and in the
mesh routes, its canonical envelopes, the parity test that compared the two ports at that path, and the SVT `canonical`
and `opa-direct` modes, which the load-test workflow no longer offers. The lockdown step for `?explain=full` runs on
`/access/v1/check/resource`. The agent keeps no canonical decision route: its clients call the check routes of the
access-control API on port 8080, and port 8181 serves `/health`, `/ready`, `/api-version`, and `/prometheus`.
`AUTHZ_DATA_DIRS` and `AUTHZ_DATA_IGNORE`, which the Decision names as the start-up source of the store, were removed in
[PR #115](https://github.com/Netcracker/qubership-authz-agent/pull/115): the engine starts with an empty store,
and only the loops in the process fill it.

<!-- markdownlint-disable-next-line MD001 -->
#### Date

2026-10-16

#### Owner

kichasov

#### Participants and approvers

The project architect, who decided to remove the data API on 2026-10-16, and the Netcracker/qubership-authz-agent
maintainers (kichasov), who settled the removal of its guard on 2026-10-19. Assumption: the architect's GitHub
account is added when this record is reviewed.

#### Related ADRs

- [authz-agent-ADR-0080: Replace Envoy, the Lua filters, and the OPA container with one Go service that embeds OPA](20260907-authz-agent-adr-0080-single-go-service-with-embedded-opa.md):
  kept the slice of OPA's REST data API the platform used, guarded by `system.authz`, and left dropping it to a
  decision of its own. This record is that decision and supersedes that part of ADR-0080.
- [authz-agent-ADR-0062: Canonical OPA-Direct And Envoy Parity](20260602-authz-agent-adr-0062-canonical-opa-direct-envoy-parity.md):
  its decisions 1 and 10 make `POST /v1/data/authorize` the canonical decision endpoint and the second transport of
  the parity test, and its decision 7 names the Service port 8181. This record supersedes decisions 1 and 10 and the
  port name of decision 7. The canonical request and response envelopes of its decisions 3, 4, and 11 stand.

## Context

The agent is one Go service with OPA embedded as a library (ADR-0080), and it listens on two ports. Port 8080 serves the
public surface: the check family, `POST /access/v1/authorize`, `/api-version`, `/health`, and
`GET /internal/v1/decision-logs`. Port 8181 serves `/health`, `/ready`, `/api-version`, `/prometheus`, and
`POST /access/v1/authorize`, and it served a slice of OPA's REST data API under `/v1/data`: `POST` for a decision, and
`PUT`, `PATCH`, and `GET` for store documents.

ADR-0080 kept that slice so that the OPA-direct transport of ADR-0062 still reached the service and one suite could gate
both topologies through it. The old topology is gone. `pap-client` ran the policy pull, the trusted-provider reload, and
the M2M token refresh against OPA over HTTP; in the service these loops write the store in the process. No component of
the agent called `/v1/data`. Its remaining callers were tests, the SVT plans, the Postman collection, and the mesh
routes of the canonical API, which rewrote `/access/v1/authorize` to `/v1/data/authorize` on port 8181.

A guard protected the slice. With `AUTHZ_DATA_API_AUTHORIZATION` set to `true`, as the chart set it, the service
evaluated `data.system.authz.allow` before every data API request, and let `PUT` and `PATCH` through only with a write
secret. The chart generated the secret into the Secret `<name>-opa-auth`, and the service loaded it from
`AUTHZ_OPA_AUTH_TOKEN_FILE` as `data.opa_auth_secret`. The guard also ran for the canonical and check routes, where it
refused `?explain`, `?instrument`, `?metrics`, and `?provenance`: on the OPA server, `?explain=full` returned the
evaluation trace, and the trace carried the agent's M2M token. The service reads none of these parameters and returns no
trace.

The Service publishes port 8181 without authentication (ADR-0062 decision 8), so the store of the agent was writable
by any workload that could reach the Service and knew the secret, and by every such workload where the guard was off.

## Decision

We will remove the data API from the agent, together with the guard that protected it.

- The service serves no route under `/v1/data`, and a request there gets 404. No HTTP route reads or writes a store
  document: the store is filled from `AUTHZ_DATA_DIRS` at start and by the loops in the process after that.
- Port 8181 keeps `/health`, `/ready`, `/api-version`, `/prometheus`, and `POST /access/v1/authorize`. Its container
  port and Service port are named `internal`.
- The `system.authz` policy, the `AUTHZ_DATA_API_AUTHORIZATION` and `AUTHZ_OPA_AUTH_TOKEN_FILE` variables,
  `data.opa_auth_secret`, and the chart's `<name>-opa-auth` Secret are removed. The canonical and check routes ignore
  the query parameters their requests do not define, `?explain` included, and return the plain decision.
- The mesh routes of `/access/v1/authorize` on the internal and public gateways end on port 8080 under the path the
  caller sent, as the routes of the check API do.
- The canonical envelopes stay as ADR-0062 defines them, on both ports: `{"input": ...}` in, and `{"result": ...}`
  out, with `decision_id` when the decisions are logged.

### Justification

The data API had no caller left in the agent. Keeping it meant keeping a write path into the store, a secret to
generate and mount, and a policy evaluation in front of every decision, all to protect a surface that nothing used.
Removing the routes closes the write path in the code, where the guard closed it only as long as the configuration
and the secret held.

Alternatives considered:

- **Bind the data API to the loopback interface.** Rejected: it keeps the routes, the guard, and the secret for a
  surface with no caller.
- **Remove the data API and keep the guard on the canonical and check routes.** Rejected: the parameters it refused
  have no effect on the service, so the refusal protects nothing and costs one policy evaluation per request. A change
  that makes the service return a trace has to bring its own protection.

## Consequences

Positive:

- No HTTP request can change what the policies read. A workload that reaches port 8181 gets probes, metrics, and
  decisions, and no write.
- The chart loses a Secret, its volume, and its mount, and every decision loses the guard's policy evaluation.
- The canonical API reaches the service on the internal and public gateways the way the check API does, on port 8080
  and without a path rewrite to keep in step with the service.

Negative:

- The store can no longer be read or changed over HTTP, for a diagnosis or for a load test. The SVT runners do not seed
  verified tokens into `data.authn` in any transport mode, so they measure decisions with token verification, and
  baselines taken with the seed do not compare. The SVT opa-direct plans send `POST /access/v1/authorize` to port 8181.
  The SVT runner that dumped the store for `opa bench` and `opa eval --profile`, and its two wrappers, are deleted.

Neutral:

- This record supersedes ADR-0062 decisions 1 and 10: `POST /access/v1/authorize` is the only decision endpoint, and
  the parity test compares the public port and the internal port at that path. Port 8181 keeps its number from
  ADR-0062 decision 7 under the name `internal`. Decision 8 still holds for it: the Service exposes the port without
  authentication, and the port serves no write.
- The runtime suite checks the removal on kind: its lockdown steps expect 404 for a read and a write under `/v1/data`
  on the internal port, and the plain decision for `?explain=full` on the public canonical route.
