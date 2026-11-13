# authz-agent service

The authorization agent as one Go service: the embedded Rego policies and the OPA library behind a Fiber server from
the Qubership core libraries, with the loops that feed the policies in the same process. This is the design recorded
in ADR 0080 under `docs/decisions`.

## What the service contains

- `internal/engine`: compiles the embedded policies (`policies/`), keeps the data documents in an in-memory store,
  and evaluates decisions.
- `internal/authn`: the trusted providers. At start it fetches every provider's signing keys, through OIDC discovery
  or from a `jwksUri`, and publishes them as `data.authn`, indexed by key id and by provider; it reloads the file
  when it changes, and its outcome drives `/health` under the bootstrap rules: strict mode wants every provider,
  permissive mode wants one, and a provider marked `required` has to be there in either.
- `internal/pull`: the policies and PIPs. Every interval it fetches the v3 configuration of the policy source with
  the agent's token, converts it to the simplified model, and publishes `data.policies` and `data.pips`. The first
  successful load makes the service ready.
- `internal/m2m`: the agent's own token, obtained from the identity provider with client credentials and refreshed
  before it expires, or read from a file another party keeps current. It is sent to the policy source and published
  as `data.m2m.bearerToken` for the PIP calls.
- `internal/legacy`: the check routes of the legacy access-control API. Each route's body and headers become the
  input of the `authorize` decision, and the decision becomes the response shape of that route.
- `internal/server`: the routes, on two listeners. The public surface carries the nine check routes,
  `GET /api-version`, `/health`, and `404 {"message":"not found"}` for every other path. The internal surface
  carries `/health`, `/ready`, `/api-version`, and `/prometheus`. No route reads or writes a store document: only
  the loops in the process write the store.
- `main.go` and `config.go`: configuration from the environment through configloader.

The chart assembles the agent Pod as this one container. Without Kubernetes, the agent runs under Docker:
[`deploy/docker`](../../deploy/docker/README.md) holds a Compose example and its steps.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `LOGGING_LEVEL_ROOT` | `info` | Level of the platform logger; the chart sets it from its `LOG_LEVEL` value |
| `AUTHZ_PUBLIC_ADDR` | `0.0.0.0:8080` | Listen address of the public surface |
| `AUTHZ_HTTP_ADDR` | `0.0.0.0:8181` | Listen address of the internal surface: the probes, the metrics, and `/api-version` |
| `AUTHZ_TRUSTED_PROVIDERS_FILE` | `/etc/authz/trusted-providers.json` | The trusted providers; empty runs without them |
| `AUTHZ_JWKS_BOOTSTRAP_REQUIRED` | `true` | Strict mode: every provider has to bootstrap; `false` wants one |
| `AUTHZ_JWKS_HTTP_TIMEOUT` | `5` | Seconds per discovery or JWKS request |
| `AUTHZ_JWKS_HTTP_RETRIES` | `3` | Attempts per request |
| `AUTHZ_TRUSTED_PROVIDERS_RELOAD_INTERVAL` | `30` | Seconds between checks of the file for a change; `0` never reloads |
| `AUTHZ_TENANT_MANAGER_URL` | `http://tenant-manager:8080` | Resolves a realm written by its tenant display name; empty disables the lookup |
| `AUTHZ_PAP_CLIENT_SOURCE_URL` | empty | Base URL of the policy source; empty disables the pull |
| `AUTHZ_PAP_CLIENT_PULL_INTERVAL` | `30` | Seconds between pulls; `0` disables the pull |
| `AUTHZ_ENTITLEMENTS_URL`, `AUTHZ_ENTITLEMENTS_HTTP_TIMEOUT`, `AUTHZ_ENTITLEMENTS_HTTP_RETRIES` | empty, `5`, `3` | The entitlements PIP pinned by the deployment; an empty URL adds none |
| `AUTHZ_M2M_TOKEN_URL` | empty | Token endpoint for the client-credentials grant; empty reads the token from `AUTHZ_PAP_CLIENT_TOKEN_FILE` instead |
| `AUTHZ_M2M_CLIENT_ID_FILE`, `AUTHZ_M2M_CLIENT_SECRET_FILE` | `/etc/secret/username`, `/etc/secret/password` | The client credentials |
| `AUTHZ_M2M_RENEW_BEFORE_SECONDS` | `60` | How long before its expiry the token is refreshed |
| `AUTHZ_PAP_CLIENT_TOKEN_FILE` | `/var/run/secrets/tokens/netcracker/token` | The token file, read every 15 seconds, when there is no token endpoint; the default is where the platform's charts mount the netcracker-audience projected token |

A variable set to the empty string switches its feature off where the table says so; an unset variable takes the
default.

The policy source is the only way policies reach the agent.

At the default level the service reports what it could not do: a policy that failed to evaluate or a document it
could not store. `debug` adds a line per decision, per rejected legacy request, per unmatched route and per policy
load. A decision that denies its caller is not reported at either level: it is the answer the policy gave.
Every line carries the request id under `request_id`, the same id the response carries in `X-Request-Id`.

`GET /health` is 200 with the counts of the last policy conversion once the trusted providers meet the bootstrap
rules, and 503 with the reason and its details until then. `GET /ready`, on the internal port, adds the policies:
503 with the reason `policies not loaded yet` and the same details until they have loaded once, 200
`{"status":"ready"}` after. A pull that fails later keeps the loaded policies and both verdicts. An empty
`AUTHZ_PAP_CLIENT_SOURCE_URL` or an `AUTHZ_PAP_CLIENT_PULL_INTERVAL` of `0` disables the pull, and `/ready` then
answers 200 as soon as the trusted providers meet the bootstrap rules, with no policies loaded.

## Running it

On a kind cluster:

```bash
make e2e           # cluster, images, test stand, charts, runtime suite
make parity        # the parity replay in its own namespace
```

Both suites gate the service in CI: the runtime suite in `Kind end-to-end`, the
parity replay in `Parity on kind`.
