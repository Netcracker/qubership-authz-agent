# authz-agent service

The authorization agent as one Go service: the embedded Rego policies and the OPA library behind a Fiber server from
the Qubership core libraries, with the loops that feed the policies in the same process. This is the redesign
recorded in ADR 0080 under `docs/decisions`, delivered in steps.

## What the service contains

- `internal/engine`: compiles the embedded policies (`policies/`), keeps the data documents in an in-memory store,
  evaluates decisions, and writes documents through the same operations OPA's data API offers.
- `internal/decisionlog`: emits decision events in the shape of OPA's decision log, and either uploads them to the
  collector in gzip batches or stores them in the service, with the signature of every JWT removed, for
  `GET /internal/v1/decision-logs`; the queue is drained on shutdown.
- `internal/authn`: the trusted providers. At start it fetches every provider's signing keys, through OIDC discovery
  or from a `jwksUri`, and publishes them as `data.authn`, indexed by key id and by provider; it reloads the file
  when it changes, and its outcome drives `/health` under the bootstrap rules: strict mode wants every provider,
  permissive mode wants one, and a provider marked `required` has to be there in either.
- `internal/pull`: the policies and PIPs. Every interval it fetches the v3 configuration of the policy source with
  the agent's token, converts it to the simplified model, and publishes `data.policies` and `data.pips`; a mounted
  directory with `policies.json` and `pips.json` replaces the source when it exists. The first successful load makes
  the service ready.
- `internal/m2m`: the agent's own token, obtained from the identity provider with client credentials and refreshed
  before it expires, or read from a file another party keeps current. It is sent to the policy source and published
  as `data.m2m.bearerToken` for the PIP calls.
- `internal/legacy`: the check routes of the legacy access-control API. Each route's body and headers become the
  canonical authorize input, and the decision becomes the response shape of that route, as the Lua filters of the
  Envoy container did.
- `internal/server`: the routes, on two listeners. The public surface is what Envoy exposed: the nine check routes,
  the canonical `POST /access/v1/authorize`, `GET /api-version`, `/health` relayed to the pap-client,
  `GET /internal/v1/decision-logs` relayed to the collector, and `404 {"message":"not found"}` for every other
  path. The OPA-compatible surface carries `/health`, `/ready`, `/api-version`, `POST /access/v1/authorize`, and,
  under `/v1/data`, the slice of OPA's REST API the other containers of the Pod use: `POST` for a decision, `PUT`,
  `PATCH`, and `GET` for documents, guarded by `data.system.authz.allow` when enabled.
- `main.go` and `config.go`: configuration from the environment through configloader, and the OPA-style command line
  of the chart's OPA container mapped onto it.

The chart assembles the agent Pod as this one container, or as the five it replaces, and
`AUTHZ_SINGLE_SERVICE_ENABLED` selects between them while both are supported.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `AUTHZ_PUBLIC_ADDR` | `0.0.0.0:8080` | Listen address of the public surface |
| `AUTHZ_HTTP_ADDR` | `0.0.0.0:8181` | Listen address of the OPA-compatible surface |
| `AUTHZ_PAP_CLIENT_URL` | empty | Base URL of the pap-client that answers `/health`; empty makes the public `/health` the service's own |
| `AUTHZ_DATA_DIRS` | empty | Comma-separated directories whose JSON and YAML files seed the store at start |
| `AUTHZ_DATA_IGNORE` | empty | Comma-separated file name patterns skipped in those directories, such as `..*` |
| `AUTHZ_DATA_API_AUTHORIZATION` | `false` | Guard `/v1/data` with `data.system.authz.allow`; the canonical route is guarded as `/v1/data/authorize` under its own method, the check routes as `POST /v1/data/authorize` |
| `AUTHZ_OPA_AUTH_TOKEN_FILE` | empty | File whose token the guard lets write, loaded as `data.opa_auth_secret` |
| `AUTHZ_DECISION_LOG_FILE` | empty | NDJSON file the decisions are stored in and `GET /internal/v1/decision-logs` serves; empty uploads them instead |
| `AUTHZ_DECISION_LOG_URL` | empty | Collector base URL, where the decisions go and where `GET /internal/v1/decision-logs` is relayed when they are not stored; empty disables both |
| `AUTHZ_DECISION_LOG_HEADERS` | empty | Comma-separated request headers recorded per decision |
| `AUTHZ_TRUSTED_PROVIDERS_FILE` | `/etc/authz/trusted-providers.json` | The trusted providers; empty runs without them |
| `AUTHZ_JWKS_BOOTSTRAP_REQUIRED` | `true` | Strict mode: every provider has to bootstrap; `false` wants one |
| `AUTHZ_JWKS_HTTP_TIMEOUT` | `5` | Seconds per discovery or JWKS request |
| `AUTHZ_JWKS_HTTP_RETRIES` | `3` | Attempts per request |
| `AUTHZ_TRUSTED_PROVIDERS_RELOAD_INTERVAL` | `30` | Seconds between checks of the file for a change; `0` never reloads |
| `AUTHZ_TENANT_MANAGER_URL` | `http://tenant-manager:8080` | Resolves a realm written by its tenant display name; empty disables the lookup |
| `AUTHZ_PAP_CLIENT_SOURCE_URL` | empty | Base URL of the policy source; empty disables the pull |
| `AUTHZ_PAP_CLIENT_PULL_INTERVAL` | `30` | Seconds between pulls, and between checks of the mount; `0` disables the pull and the mount |
| `AUTHZ_POLICY_MOUNT_DIR` | `/etc/authz/policies` | Directory with `policies.json` and `pips.json` that replaces the source when it exists |
| `AUTHZ_ENTITLEMENTS_URL`, `AUTHZ_ENTITLEMENTS_HTTP_TIMEOUT`, `AUTHZ_ENTITLEMENTS_HTTP_RETRIES` | empty, `5`, `3` | The entitlements PIP pinned by the deployment; an empty URL adds none |
| `AUTHZ_M2M_TOKEN_URL` | empty | Token endpoint for the client-credentials grant; empty reads the token from `AUTHZ_PAP_CLIENT_TOKEN_FILE` instead |
| `AUTHZ_M2M_CLIENT_ID_FILE`, `AUTHZ_M2M_CLIENT_SECRET_FILE` | `/etc/secret/username`, `/etc/secret/password` | The client credentials |
| `AUTHZ_M2M_RENEW_BEFORE_SECONDS` | `60` | How long before its expiry the token is refreshed |
| `AUTHZ_PAP_CLIENT_TOKEN_FILE` | `/etc/authz/ac-token/token` | The token file, read every 15 seconds, when there is no token endpoint |

A variable set to the empty string switches its feature off where the table says so; an unset variable takes the
default.

`GET /health` is 200 with the counts of the last policy conversion once the trusted providers meet the bootstrap
rules, and 503 with the reason and its details until then. `GET /ready`, on the data API port, adds the policies:
503 with the reason `policies not loaded yet` and the same details until they have loaded once, 200
`{"status":"ready"}` after. A pull that fails later keeps the loaded policies and both verdicts.

When started with OPA's command line (`run --server --addr ... --ignore=... --authorization=basic --config-file ...
<dirs>`), the flags and the directories override the variables, and the config file supplies the decision log service,
its `reporting` bounds, the recorded request headers, and `nd_builtin_cache`; every other setting of that file is
named in a warning at start, so a setting the service cannot act on is not mistaken for one it applies. In that Pod
Envoy holds port 8080 and the pap-client answers on 8182, so the public surface then defaults to `0.0.0.0:8280` and
`AUTHZ_PAP_CLIENT_URL` to `http://127.0.0.1:8182`; the trusted providers and the token file default to off and the
policy pull never runs, since the Pod's other containers run them, and `/health` is the pap-client's.

## Running it

The chart assembles the agent Pod as this one container when
`AUTHZ_SINGLE_SERVICE_ENABLED` is set; the switch is off by default while both
topologies are supported, and every other parameter of the chart keeps its
meaning. On a kind cluster:

```bash
make e2e-images
make e2e-single      # the chart with the switch on, then the runtime suite
make parity-single   # the same in the parity namespace, then the parity replay
make e2e-install     # back to the five-container Pod
```

Both suites pass against either topology. The groups that address OPA
directly, `TestOPALockdown`, `TestOPARestart`, and
`TestAuthorizeEnvoyOpaDirectParity`, are skipped against this one, which has no
OPA of its own; they keep gating the five-container Pod.

## Standing in for the OPA container

Before the chart could assemble the single service, the same binary was tested
in place of the OPA container of the five-container Pod, and that still works:
it reads the OPA command line, relays `/health` to the pap-client, and leaves
the loops to the Pod's other containers. It is a manual aid, not a target of
CI; `test/k8s/README.md` has the commands.
