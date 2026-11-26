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
- `main.go` and `config.go`: configuration from environment variables.

The chart assembles the agent Pod as this one container.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `LOGGING_LEVEL_ROOT` | `info` | Level of the platform logger: `debug`, `info`, `warn`, `error`, or `fatal`; the chart sets it from its `LOG_LEVEL` value. An environment variable named `LOG_LEVEL`, which the chart does not set, stops the start when it is not empty. Any other variable that the platform logger reads as either name, such as `log_level`, or that hides `LOGGING_LEVEL_ROOT` from it, such as `LOGGING_LEVEL_ROOT_X`, stops the start whatever its value |
| `AUTHZ_PUBLIC_ADDR` | `0.0.0.0:8080` | Listen address of the public surface |
| `AUTHZ_HTTP_ADDR` | `0.0.0.0:8181` | Listen address of the internal surface: the probes, the metrics, and `/api-version` |
| `AUTHZ_TRUSTED_PROVIDERS_FILE` | `/etc/authz/trusted-providers.json` | The trusted providers; empty runs without them |
| `AUTHZ_JWKS_BOOTSTRAP_REQUIRED` | `true` | Strict mode: every provider has to bootstrap; `false` wants one |
| `AUTHZ_JWKS_HTTP_TIMEOUT` | `5` | Seconds per discovery or JWKS request, at least `1` |
| `AUTHZ_JWKS_HTTP_RETRIES` | `3` | Attempts per request, from `1` to `100` |
| `AUTHZ_TRUSTED_PROVIDERS_RELOAD_INTERVAL` | `30` | Seconds between checks of the file for a change, at least `0`; `0` never reloads |
| `AUTHZ_TENANT_MANAGER_URL` | empty | Base URL of tenant-manager. When discovery for a trusted provider fails, the agent looks up the last path segment of its issuer as a tenant display name and retries discovery under the realm name that tenant-manager returns. Empty disables the lookup, so a provider whose issuer ends in a tenant display name does not bootstrap, and its discovery failure says that `AUTHZ_TENANT_MANAGER_URL` is empty. The chart sets it from its `AUTHZ_TENANT_MANAGER_URL` value, `http://tenant-manager:8080` by default |
| `AUTHZ_PAP_CLIENT_SOURCE_URL` | empty | Base URL of the policy source; empty disables the pull |
| `AUTHZ_PAP_CLIENT_PULL_INTERVAL` | `30` | Seconds between pulls, at least `0`; `0` disables the pull |
| `AUTHZ_ENTITLEMENTS_URL`, `AUTHZ_ENTITLEMENTS_HTTP_TIMEOUT`, `AUTHZ_ENTITLEMENTS_HTTP_RETRIES` | empty, `5`, `3` | The entitlements PIP pinned by the deployment, with its timeout in seconds, at least `1`; an empty URL adds none. `AUTHZ_ENTITLEMENTS_HTTP_RETRIES` takes an integer from `1` to `100` and has no effect: each call to the aggregator is one attempt |
| `M2M_AUTH_MODE` | `legacy` | The mode that the platform's deployer passes to every service. It chooses the token the agent sends: `legacy` obtains one from `AUTHZ_OUTGOING_TOKEN_URL` with the client id and the client secret in `AUTHZ_OUTGOING_CLIENT_ID_FILE` and `AUTHZ_OUTGOING_CLIENT_SECRET_FILE`, `k8s` sends the content of `AUTHZ_PAP_CLIENT_TOKEN_FILE`, and `hybrid` sends that content where its path exists at the start and the client credentials token where it does not. The agent chooses once, at the start, and in `hybrid` logs which token it sends. The tokens the agent accepts are the same in every mode. The chart sets it from its value of the same name |
| `AUTHZ_OUTGOING_TOKEN_URL` | empty | Token endpoint for the client-credentials grant; required while `M2M_AUTH_MODE` is `legacy`, its default, or `hybrid` with nothing at the path of `AUTHZ_PAP_CLIENT_TOKEN_FILE`, so an unset or empty endpoint then stops the start. Otherwise the agent sends no request to it. In `legacy` and `hybrid`, the chart sets it from its value of the same name, or, while that value is empty, to `<IDENTITY_PROVIDER_URL>/auth/realms/cloud-common/protocol/openid-connect/token` |
| `AUTHZ_OUTGOING_CLIENT_ID_FILE`, `AUTHZ_OUTGOING_CLIENT_SECRET_FILE` | `/etc/secret/username`, `/etc/secret/password` | The files that hold the client id and the client secret, read at the start and at each renewal while the agent sends the token from `AUTHZ_OUTGOING_TOKEN_URL`; empty takes the default. A path that names no file or that the agent cannot resolve, such as a loop of symbolic links, a file the agent cannot read, anything but a regular file after symbolic links are followed, or a file that is empty or holds white space alone then stops the start |
| `AUTHZ_OUTGOING_RENEW_BEFORE_SECONDS` | `60` | Seconds before its expiry at which the token from `AUTHZ_OUTGOING_TOKEN_URL` is refreshed, at least `0`; the refresh comes no earlier than half the token's lifetime |
| `AUTHZ_PAP_CLIENT_TOKEN_FILE` | `/var/run/secrets/tokens/netcracker/token` | The token file, read every 15 seconds in `k8s`, and in `hybrid` where the path exists at the start; an empty path takes the default. A path that names nothing or that the agent cannot resolve, such as a loop of symbolic links, a file the agent cannot read, anything but a regular file after symbolic links are followed, or a file that is empty or holds white space alone then stops the start, except that in `hybrid` a path that names nothing makes the agent send its client credentials token. The default is where the platform's charts mount the netcracker-audience projected token |

A variable is required only where its row says so. A variable set to the empty string switches its feature off where the
table says so. An unset variable takes the default, and so does an empty number, an empty listen address, an empty
`AUTHZ_JWKS_BOOTSTRAP_REQUIRED`, an empty `M2M_AUTH_MODE`, and an empty `LOGGING_LEVEL_ROOT`.

A number is an integer in decimal digits with an optional sign, and a number of seconds is at most `9223372036`. A
listen address is `<host>:<port>`, where the host is empty, an IP address, or a host name, and the port is from `0` to
`65535`; `0` picks a free port. A URL is an `http` or `https` URL with a host, a port from `1` to `65535` if it has one,
and no user, query, or fragment, written in the characters a URL allows without escaping, so a space is written as
`%20`. `AUTHZ_JWKS_BOOTSTRAP_REQUIRED` is `true` or `false`, and `M2M_AUTH_MODE` is `legacy`, `hybrid`, or `k8s`. The
scheme of a URL, `AUTHZ_JWKS_BOOTSTRAP_REQUIRED`, `M2M_AUTH_MODE`, and `LOGGING_LEVEL_ROOT` are read without regard to
case. A value of another form or outside its range stops the start, and so does a required variable that is unset or
empty, or a file of the agent's token that the agent cannot use: the agent logs one line, at any log level, that names
each such variable with the values it accepts, the setting that requires it, or why the agent cannot use the file, and
exits with status 1 before it listens. For a URL, the line names the rule the value breaks in place of the value, which
can hold a password. For example:

```text
configuration: AUTHZ_PAP_CLIENT_PULL_INTERVAL="2s": expected an integer number of seconds from 0 to 9223372036
```

A listen address can have that form and still fail to bind, for example when its host name does not resolve or its port
is in use. The agent then stops when it opens its listeners, which it does after the trusted providers' bootstrap has
ended, whatever its outcome. The line names the variable, at any log level:

```text
public listener on AUTHZ_PUBLIC_ADDR="0.0.0.0:8080": listen tcp 0.0.0.0:8080: bind: address already in use
```

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
