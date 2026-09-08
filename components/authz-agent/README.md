# authz-agent service

The authorization agent as one Go service: the embedded Rego policies and the OPA library behind a Fiber server from
the Qubership core libraries. This is the first step of the redesign recorded in ADR 0080 under `docs/decisions`.

## What this step contains

- `internal/engine`: compiles the embedded policies (`policies/`), keeps the data documents in an in-memory store,
  evaluates decisions, and writes documents through the same operations OPA's data API offers.
- `internal/decisionlog`: emits decision events in the shape of OPA's decision log and uploads them to the collector
  in gzip batches, draining the queue on shutdown.
- `internal/server`: the routes. `GET /health`, `GET /api-version`, the canonical `POST /access/v1/authorize`, and,
  under `/v1/data`, the slice of OPA's REST API the other containers of the Pod use: `POST` for a decision, `PUT`,
  `PATCH`, and `GET` for documents, guarded by `data.system.authz.allow` when enabled.
- `main.go` and `config.go`: configuration from the environment through configloader, and the OPA-style command line
  of the chart's OPA container mapped onto it.

Not in this step: the check-family handlers that replace the Lua filters, the policy pull loop, the JWKS bootstrap,
the M2M token, and the chart with one container. Until they land, the service stands in for the OPA container of the
current chart.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `AUTHZ_HTTP_ADDR` | `0.0.0.0:8080` | Listen address |
| `AUTHZ_DATA_DIRS` | empty | Comma-separated directories whose JSON and YAML files seed the store at start |
| `AUTHZ_DATA_IGNORE` | empty | Comma-separated file name patterns skipped in those directories, such as `..*` |
| `AUTHZ_DATA_API_AUTHORIZATION` | `false` | Guard `/v1/data` with `data.system.authz.allow` |
| `AUTHZ_DECISION_LOG_URL` | empty | Collector base URL; empty disables decision logs |
| `AUTHZ_DECISION_LOG_HEADERS` | empty | Comma-separated request headers recorded per decision |

When started with OPA's command line (`run --server --addr ... --ignore=... --authorization=basic --config-file ...
<dirs>`), the flags, the config file's decision log service, and the directories override the variables.

## Running in place of the OPA container

```bash
make e2e-images
E2E_HELM_ARGS='--set OPA_IMAGE=local/authz-agent:ci' make e2e-install e2e-suite
```

The runtime suite and the parity replay pass against it; see the pull request that added this step for the numbers.
