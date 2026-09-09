# Replace Envoy, the Lua filters, and the OPA container with one Go service that embeds OPA

## Status

Accepted

<!-- markdownlint-disable-next-line MD001 -->
#### Date

2026-09-09

#### Owner

kichasov

#### Participants and approvers

Netcracker/qubership-authz-agent maintainers (kichasov). Assumption: the repository maintainers sign off; no other
team is affected until the chart switches.

#### Related ADRs

- [authz-agent-ADR-0062: Canonical OPA-Direct And Envoy Parity](20260602-authz-agent-adr-0062-canonical-opa-direct-envoy-parity.md):
  defines the canonical `/access/v1/authorize` contract this record keeps unchanged. The OPA-direct transport it
  introduced disappears with the OPA container; see Consequences.
- [authz-agent-ADR-0030](20260330-authz-agent-adr-0030-local-compose-jmeter-load-testing-stack.md) and
  [authz-agent-ADR-0031](20260331-authz-agent-adr-0031-compose-topology-split-for-load-tracking.md): the SVT lab
  they describe is not affected by this record.

## Context

The agent Pod runs four containers and two init containers. Envoy serves 13 routes and carries six Lua filters, 3228
lines in total with a hand-written JSON parser, which rewrite every legacy check request into the OPA input envelope
and the OPA result back into the legacy response. OPA runs as the upstream image in server mode, with its REST data
API, a `system.authz` policy, and a shared write secret. `pap-client` (3.4 k lines of Go) bootstraps the JWKS, pulls
policies and PIPs from the access-control v3 API and pushes them into OPA over HTTP, keeps the M2M token fresh in
OPA, reloads trusted providers, serves the health endpoint, and proxies decision logs. `decision-log-collector`
receives OPA's decision logs and strips JWT signatures. `token-fetcher` obtains a Keycloak client-credentials token
for the pull loop.

These parts are glued by two emptyDir volumes, a secret file that one container writes and another reads, a shared
group id so that the two uids can share that file (see the security context in `charts/authz-agent/templates`), and,
in the test suite, an ephemeral container that signals the OPA process because the image has no shell. The Envoy
configuration exists twice (the chart template and the SVT copy) and drifts. Every decision crosses two HTTP hops with
JSON serialization on each.

What the agent implements is the decision subset of the access-control API: `POST /access/v1/authorize`, nine
check-family routes (`/access/v1/check/*`, `/access/v2/check/*`, `/preview/*`), `GET /api-version`, `GET /health`,
and `GET /internal/v1/decision-logs`, as declared in `api/openapi.yaml`. The management and configuration API
stays in access-control, which is also the source the pull loop reads.

The decision logic is seven Rego packages (about 3.5 k lines without tests) using `io.jwt.decode_verify`,
`http.send` for PIP and entitlement calls, and regex, json, and glob builtins over the data documents `authn`,
`policies`, `pips`, and `m2m`. The parity replay (135 recorded cases with frozen goldens from the legacy service) and
the runtime suite (20 groups) pin its behavior.

Platform requirements: services on the Qubership platform use Fiber through `qubership-core-lib-go-fiber-server-utils`
and the `qubership-core-lib-go` libraries (configloader, logging, memlimit, context propagation).

A spike on the branch `spike/opa-embedded` (commit
[22aa625](https://github.com/Netcracker/qubership-authz-agent/commit/22aa62538c958f52d3739a9145596b2f9d1ba8d9))
replaced only the OPA container with a Go binary built on the OPA library (`github.com/open-policy-agent/opa/v1`,
version 1.20.2), an in-memory store, and the Fiber builder. With nothing else changed, the runtime suite passed all 20
groups and the parity replay passed on kind; the suite took 86 s against 88 s with the OPA image, the 3000-id bulk
step 9.4 s against 10.2 s. The 21 policy modules compiled unchanged and the 352 Rego unit tests passed on the
matching OPA CLI.

## Decision

We will replace Envoy, the Lua filters, the OPA container, `pap-client`, `decision-log-collector`, and
`token-fetcher` with one Go service, built as follows.

- **HTTP.** A Fiber v2 application created by the `qubership-core-lib-go-fiber-server-utils` builder with health,
  API version, Prometheus, and tracing endpoints. `qubership-core-lib-go` supplies configuration loading from the
  environment (the `AUTHZ_*` names stay), logging, the memory limit, and context propagation. The TMF error format of
  `qubership-core-lib-go-error-handling` applies to internal endpoints only; the check family keeps its legacy error
  bodies.
- **Handlers instead of Lua.** Go handlers serve the 13 endpoints of `api/openapi.yaml`. They build the same OPA
  input envelope the Lua built and map the result to the legacy response shapes byte for byte. The decision endpoints
  perform no transport-level authentication, as Envoy performed none; the policies validate the tokens.
- **OPA as a library.** The `rego` package of `github.com/open-policy-agent/opa/v1` with an in-memory store. The Rego
  policies are embedded in the binary unchanged, compiled at start, and prepared once. The data documents are written
  into the store by Go code in transactions. The slice of OPA's REST data API that the platform uses is kept and
  served on the same port, guarded by `system.authz` with the same write secret: the canonical transport of ADR-0062
  reaches it, and one suite gates both topologies through it. Dropping that surface is a decision of its own, like
  removing the five-container topology. The inter-query builtin cache is configured so that `http.send` behaves as in
  the server.
- **In-process supporting logic.** The JWKS bootstrap, the policy and PIP pull loop, the trusted-provider reload, the
  mount mode, the M2M token refresh, and the health rules move into the binary as packages, writing into the store
  instead of calling OPA. Decision logs are emitted in-process with the event shape the collector produced (`input`,
  `result`, `nd_builtin_cache`, request-context headers), with the same JWT signature redaction, and served through
  `GET /internal/v1/decision-logs`.
- **Deployment.** One container in the agent Pod and one image; the optional `authz-policy-admin` Deployment stays.
  The chart keeps its parameter names, and `AUTHZ_AGENT_IMAGE` takes the place of the five per-image overrides.
- **Migration.** The service was developed next to the current one, and the runtime suite and the parity replay ran
  against both on kind while one chart rendered either topology behind `AUTHZ_SINGLE_SERVICE_ENABLED`. That switch
  is gone: the chart renders the single service and nothing else, and the Envoy configuration, the Lua filters, the
  four images they came with, and the SVT lab that ran them under Compose are deleted. An installation upgrading
  onto this chart moves from five containers to one in place; the Service, its ports, the Deployment name, and every
  chart parameter but the per-container images and resources are unchanged, and there is no way back short of
  installing an older chart.

### Justification

The current shape costs more than it returns: a JSON parser written in Lua, an Envoy configuration maintained in two
places, four images to build and scan, cross-container file plumbing that needed uid and group work of its own, and
two serialization hops per decision. One process removes all of it, and the spike shows the price is nil: the same
suites pass at the same speed with OPA in-process.

Alternatives considered:

- **Keep the topology and improve it in place.** Rejected: every listed cost stays, and the Lua would still be the
  place where the legacy protocol lives.
- **Keep Envoy and embed OPA into `pap-client` only.** Rejected: it removes one container but keeps the Lua and the
  Envoy configuration, which are the larger maintenance burden.
- **Rewrite the policies in Go.** Rejected: the Rego is the tested decision core with a parity record; rewriting it
  puts 135 goldens at risk for no gain. OPA embeds cleanly, as the spike shows.
- **OPA `sdk` package with bundles instead of the `rego` package.** Rejected: the data changes every pull interval and
  comes from Go code, not from a bundle server; the `rego` package with a store fits, the SDK would need a bundle
  round trip.

## Consequences

Positive:

- One image, one process, one port to operate, debug, and scan. No Lua, no Envoy configuration, no shared volumes,
  no write secret, no uid choreography between containers.
- Decisions stay in-process: no Envoy-to-OPA hop and no double JSON serialization.
- The Rego and its tests, the parity replay, and the runtime suite carry over unchanged as the acceptance gate.

Negative:

- The service reimplements what OPA's server gave for free: the decision-log uploader with `nd_builtin_cache` and
  the inter-query cache configuration. The spike showed two traps to design around: strings from Fiber alias the
  fasthttp request buffer and must be copied before they outlive the handler, and the decision-log queue must be
  drained with its own deadline on shutdown.
- `TestOPARestart` is gone with the container it restarted, and so are its four catalog rows: the documents it
  proved survive a restart now live in the process and are rebuilt at every start. The other groups that address the
  data API, `TestOPALockdown` and `TestAuthorizeEnvoyOpaDirectParity`, gate the service unchanged.
- Deployments that set per-image values (`ENVOY_IMAGE`, `OPA_IMAGE`, `PAP_CLIENT_IMAGE`, `COLLECTOR_IMAGE`,
  `TOKEN_FETCHER_IMAGE`) or per-container resources have to move to `AUTHZ_AGENT_IMAGE` and `AUTHZ_AGENT_*`; the old
  keys are removed from the values schema, so an install still passing them fails validation rather than ignoring
  them.
- The four images stop being published. Anything outside this repository that pulls `authz-agent-pap-client`,
  `authz-agent-envoy`, `authz-agent-collector`, or `authz-agent-token-fetcher` keeps only the tags already
  released.
- The check family keeps its legacy error bodies, so two error formats coexist in one service until the legacy
  routes are retired.

Neutral:

- The mesh route resources in the chart are unaffected.
- The SVT lab under `test/svt` is deleted with the stack it drove: its Compose file, its JMeter plans, and its
  profiler read Envoy's own statistics, which the service does not publish. A load stand for the service is work of
  its own and is not recorded here.
- The `token-fetcher` code runs as a goroutine inside the service: `qubership-core-lib-go` does not provide the
  Keycloak client-credentials token flow.
