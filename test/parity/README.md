# Parity Test Suite

The parity suite replays 129 captured test cases against the authz-agent and
compares the answers with golden files recording how the legacy access-control
service answered the same requests.

## What the goldens are

The JSON files under [`suite/testdata/golden/`](suite/testdata/golden/) are a
**frozen capture** of the legacy `access-control` service's behaviour. They
were recorded against a running instance of the legacy service (which is not
part of this repository) and committed as the reference baseline.

They cannot be regenerated from this repository. If you change authz-agent
behaviour in a way that alters the answers to these cases, the affected
goldens must be updated by hand (or the divergence recorded in
[`suite/accepted_divergences.go`](suite/accepted_divergences.go) with a
rationale). The goldens are evidence of which cases the authz-agent matches
the legacy service on; they are not a test oracle that can be refreshed
without access to the original service.

## Prerequisites

1. **Docker + Compose v2** on the host.
2. Local images built (see [Build](#build) below).
3. **Go 1.24+** on the host to run the Go test suite directly.

## Build

Build the two images the parity replay stack needs:

```bash
bash test/parity/scripts/build-images.sh
```

This builds:

| Image tag                      | Dockerfile                    |
| ------------------------------ | ----------------------------- |
| `authz-pap-client:local`       | `build/pap-client/Dockerfile` |
| `decision-log-collector:local` | `build/collector/Dockerfile`  |

The `pip-stub:local` image is built by the integration runtime
(`test/scripts/build-runtime-images.sh` or a prior integration test run)
and is shared between the two suites. Build it if not already present:

```bash
docker build -t pip-stub:local -f test/integration/pipstub/Dockerfile test/integration/pipstub
```

The `authz-policy-admin:local` image is also needed:

```bash
docker build -t authz-policy-admin:local -f build/authz-policy-admin/Dockerfile .
```

The IdP service (`idp`) runs the public Keycloak image
(`quay.io/keycloak/keycloak:26.3.5`). No pre-build step is needed for it —
`docker compose up` pulls it automatically.

## Run the replay suite

```bash
PARITY_PROFILE=authz-agent bash test/parity/scripts/run-parity-suite.sh
```

The script brings up the compose stack (if not already running), waits for all
services to reach healthy (allow up to ~6 minutes for the cold Keycloak
augmentation build), runs the Go/testify suite, and prints the result.

Expected final line when all cases pass:

```text
Parity suite passed: 135/135 cases green against authz-agent.
```

### Running against an already-up stack

If the compose stack is already running, the script reuses it:

```bash
# keep the stack running between runs for fast iteration
PARITY_PROFILE=authz-agent bash test/parity/scripts/run-parity-suite.sh
```

### Teardown

```bash
docker compose -p parity-authz -f test/parity/compose/docker-compose.authz-agent.yml down -v
```

The `-v` flag removes the named volumes so the next `up` starts from a clean
PostgreSQL state (schema re-runs, realm re-imports, fixtures re-seeded).

## Port map

| Env var                   | Default | Service                           |
| ------------------------- | ------- | --------------------------------- |
| `PARITY_AUTHZ_PORT`       | `28100` | Authz Agent Envoy public listener |
| `PARITY_AUTHZ_ADMIN_PORT` | `28182` | pap-client upload port            |
| `PARITY_AUTHZ_PIP_PORT`   | `28191` | pip-mock copy for this profile    |
| `PARITY_AUTHZ_EA_PORT`    | `28192` | entitlements-mock copy            |
| `PARITY_AUTHZ_IDP_PORT`   | `25558` | Keycloak HTTP listener            |

No port in this block collides with the integration runtime block
(`KC_HTTP_PORT=5556`, `AUTHZ_HTTP_PORT=18080`) or the SVT block
(`SVT_KC_PORT=25556`, `SVT_AUTHZ_PORT=28080`).

## Identity provider

The `idp` service uses the public Keycloak image
(`quay.io/keycloak/keycloak:26.3.5`, matching the Keycloak version the goldens
were captured against). The two realm import files
([`compose/idp-seed/cloud-common-realm.json`](compose/idp-seed/cloud-common-realm.json)
and [`compose/idp-seed/parity-realm.json`](compose/idp-seed/parity-realm.json))
use only built-in Keycloak protocol mappers and require no custom SPI
extensions. The suite calls the standard OIDC token endpoint
(`/auth/realms/parity/protocol/openid-connect/token`) for `client_credentials`
and `password` grants — no custom Keycloak REST APIs are involved.

`KC_HTTP_RELATIVE_PATH=/auth` is set so the realm is reachable at
`/auth/realms/parity/...` (Keycloak dropped the `/auth` prefix in v17; the
parity stack wires that prefix throughout, so it is restored via config).

The Keycloak image (`quay.io/keycloak/keycloak`) is UBI9-minimal and contains
no `curl` or `wget`. The compose healthcheck uses bash's `/dev/tcp` built-in
with a raw HTTP/1.0 request against the management port (9000). Note that
`KC_HTTP_RELATIVE_PATH=/auth` prefixes ALL paths, including the management
health endpoint: the correct URL is `http://localhost:9000/auth/health/ready`
(not `/health/ready`).

## Goldens, accepted divergences, and the divergence backlog

The 129 committed goldens represent the legacy service's answers. The
authz-agent is expected to match all of them; cases where it intentionally
differs are listed in
[`suite/accepted_divergences.go`](suite/accepted_divergences.go) with a
recorded rationale (decision ID + reason string).

When authz-agent behaviour changes in a way that affects a previously-green
case:

- If the new behaviour is correct (i.e. the legacy answer was a bug): add an
  entry to `accepted_divergences.go` with the rationale.
- If the new behaviour is a regression: fix the regression.
- The golden files themselves should not be edited — they are the record of
  what the legacy service did, not a living test spec.

## Directory layout

```text
test/parity/
├── README.md                            (this file)
├── opa-body-snapshots/                  (9 OPA request/response captures for reference)
├── compose/
│   ├── docker-compose.authz-agent.yml  (replay stack: authz-agent + IdP + mocks)
│   ├── authz-agent-config/             (envoy.yaml/opa-config.yaml templates)
│   ├── idp-seed/                       (Keycloak realm import + cache config)
│   └── pg-init/                        (postgres init script: two logical DBs)
├── suite/                              (Go/testify parity suite)
│   ├── config.go
│   ├── compare.go                      (golden read/diff; no write/record path)
│   ├── accepted_divergences.go
│   ├── testdata/
│   │   ├── golden/                     (129 committed golden JSON files)
│   │   └── fixtures/                   (seed policies and PIPs)
│   └── test_row*.go                    (one file per parity endpoint row)
└── scripts/
    ├── build-images.sh                 (builds authz-pap-client + collector)
    ├── build-authz-agent.sh            (builds authz-pap-client:local)
    ├── build-decision-log-collector.sh (builds decision-log-collector:local)
    └── run-parity-suite.sh             (compose up → healthy → go test)
```

## Why this suite is not in CI

The replay needs Docker Compose (Keycloak, OPA, Envoy, pap-client, authz-policy-admin
containers). The organisation's shared Go build workflow runs unit-level `go test` only;
Docker-based suites are run locally (`run-parity-suite.sh`) and from release validation,
not from the pull-request workflow. This is the same treatment as the integration compose
suite — see the comment in `.github/workflows/go-build.yaml`.
