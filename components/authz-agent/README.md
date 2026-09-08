# authz-agent service

The authorization agent as one Go service: the embedded Rego policies and the OPA library behind a Fiber server from
the Qubership core libraries. This is the redesign recorded in ADR 0080 under `docs/decisions`, delivered in steps.

## What the service contains

- `internal/engine`: compiles the embedded policies (`policies/`), keeps the data documents in an in-memory store,
  evaluates decisions, and writes documents through the same operations OPA's data API offers.
- `internal/decisionlog`: emits decision events in the shape of OPA's decision log and uploads them to the collector
  in gzip batches, draining the queue on shutdown.
- `internal/legacy`: the check routes of the legacy access-control API. Each route's body and headers become the
  canonical authorize input, and the decision becomes the response shape of that route, as the Lua filters of the
  Envoy container did.
- `internal/server`: the routes, on two listeners. The public surface is what Envoy exposed: the nine check routes,
  the canonical `POST /access/v1/authorize`, `GET /api-version`, `/health` relayed to the pap-client,
  `GET /internal/v1/decision-logs` relayed to the collector, and `404 {"message":"not found"}` for every other
  path. The OPA-compatible surface
  carries `/health`, `/api-version`, `POST /access/v1/authorize`, and, under `/v1/data`, the slice of OPA's REST API
  the other containers of the Pod use: `POST` for a decision, `PUT`, `PATCH`, and `GET` for documents, guarded by
  `data.system.authz.allow` when enabled.
- `main.go` and `config.go`: configuration from the environment through configloader, and the OPA-style command line
  of the chart's OPA container mapped onto it.

Not yet in the service: the policy pull loop, the JWKS bootstrap, the M2M token, the decision-log collector, and the
chart with one container. Until they land, the service stands in for the OPA container of the current chart; the
pap-client of that Pod still answers `/health`, and the collector still serves the decision-log download.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `AUTHZ_PUBLIC_ADDR` | `0.0.0.0:8080` | Listen address of the public surface |
| `AUTHZ_HTTP_ADDR` | `0.0.0.0:8181` | Listen address of the OPA-compatible surface |
| `AUTHZ_PAP_CLIENT_URL` | empty | Base URL of the pap-client that answers `/health`; empty makes the public `/health` the service's own |
| `AUTHZ_DATA_DIRS` | empty | Comma-separated directories whose JSON and YAML files seed the store at start |
| `AUTHZ_DATA_IGNORE` | empty | Comma-separated file name patterns skipped in those directories, such as `..*` |
| `AUTHZ_DATA_API_AUTHORIZATION` | `false` | Guard `/v1/data` with `data.system.authz.allow`; the canonical route is guarded as `/v1/data/authorize` under its own method, the check routes as `POST /v1/data/authorize` |
| `AUTHZ_DECISION_LOG_URL` | empty | Collector base URL, where the decisions go and where `GET /internal/v1/decision-logs` is relayed; empty disables both |
| `AUTHZ_DECISION_LOG_HEADERS` | empty | Comma-separated request headers recorded per decision |

When started with OPA's command line (`run --server --addr ... --ignore=... --authorization=basic --config-file ...
<dirs>`), the flags, the config file's decision log service, and the directories override the variables. In that Pod
Envoy holds port 8080 and the pap-client answers on 8182, so the public surface then defaults to `0.0.0.0:8280` and
`AUTHZ_PAP_CLIENT_URL` to `http://127.0.0.1:8182`.

## Running in place of the OPA container

```bash
make e2e-images
E2E_HELM_ARGS='--set OPA_IMAGE=local/authz-agent:ci' make e2e-install e2e-suite
```

runs the runtime suite through Envoy, which forwards the decisions to the service. To send the suite to the
service's own public surface instead, use the `authz-agent-direct` Service that `make e2e-harness` creates:

```bash
E2E_HELM_ARGS='--set OPA_IMAGE=local/authz-agent:ci' E2E_BASE_URL=http://authz-agent-direct:8080 make e2e-install e2e-suite
```

The parity replay takes the same two variables, with `PARITY_AC_BASE_URL` in place of `E2E_BASE_URL`, on
`make parity-install parity-suite`. Both suites pass either way.
