# authz-policy-admin

`authz-policy-admin` is the supported policy source for `qubership-authz-agent`.
It implements a subset of the access-control v3 configuration API so that
teams without a platform access-control installation can load policies into the
agent through the same pull path that production uses.

It is deployed as a standalone Deployment (not as a sidecar of the agent Pod)
with its own Service and PersistentVolumeClaim.  Enable it with
`AUTHZ_POLICY_ADMIN_ENABLED=true` in the Helm chart.

## HTTP API

### Simplified-policy API (northbound, for seeding policies)

These paths mirror the access-control v1 simplified-policy surface, so callers
that already load policies into access-control work unchanged.

```text
GET  /access/v1/simplifiedPolicies/domainPolicies/{domainName}
PUT  /access/v1/simplifiedPolicies/domainPolicies/{domainName}

GET  /access/v1/simplifiedPolicies/domainPIPs/{domainName}
PUT  /access/v1/simplifiedPolicies/domainPIPs/{domainName}
```

PUT body for policies: a JSON array of simplified-policy objects.
PUT body for PIPs:     a JSON array of simplified-PIP objects.

The API is **unauthenticated**.  Deploy `authz-policy-admin` only in
development and test namespaces, never in a namespace that is reachable by
untrusted callers.

### v3 config export (southbound, read by the agent's pap-client)

These paths are the pull endpoint that `pap-client` polls at the interval set
by `AUTHZ_PAP_CLIENT_PULL_INTERVAL`.

```text
GET  /access/v3/config/policySets
GET  /access/v3/config/pips
```

Both require an `Authorization` header (the bearer token that pap-client holds;
the value is not validated, only presence-checked).  They return the union of
all domains.

### Health / status

```text
GET  /authz-policy-admin/hash
```

Returns a JSON object with:

```json
{
  "hash":         "<sha256 of policies>",
  "policiesHash": "<sha256 of policies>",
  "pipsHash":     "<sha256 of PIPs>",
  "revision":     <integer, incremented on each upload>,
  "domains":      ["<domain1>", "<domain2>"]
}
```

`hash` and `policiesHash` are the same value; `hash` is kept for callers
written against an earlier version of the stub.  This endpoint is also used
by the Helm chart probes and the Docker Compose health checks.

## Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `AUTHZ_POLICY_ADMIN_PORT` | `18090` | TCP port to listen on |
| `AUTHZ_POLICY_ADMIN_DATA_DIR` | `` (empty) | Directory for persistence. Empty means in-memory only (data lost on restart). The Helm chart always sets this to the PVC mount path. |

## Volumes and persistence

When `AUTHZ_POLICY_ADMIN_DATA_DIR` is set, policies and PIPs are persisted to
disk so that a restart reloads the last uploaded state.  Data is stored as
JSON files under that directory, one file per domain per collection.

In the Helm chart:

- The PVC is named `<release>-authz-policy-admin-data`.
- The default mount path is `AUTHZ_POLICY_ADMIN_DATA_DIR: /var/lib/authz-policy-admin`.
- The storage class and size are controlled by
  `AUTHZ_POLICY_ADMIN_STORAGE_CLASS` and `AUTHZ_POLICY_ADMIN_STORAGE_SIZE`.

## Image

Built from `build/authz-policy-admin/Dockerfile`.  Published as
`authz-policy-admin` (no `authz-agent-` prefix) because it is a standalone
Deployment rather than a container of the agent Pod.

## Relationship to the platform's access-control service

When a platform access-control service is available (for example, in a
production Netcracker environment), set `AUTHZ_PAP_CLIENT_SOURCE_URL` to point
`pap-client` at it directly.  `authz-policy-admin` is then idle and can be
disabled (`AUTHZ_POLICY_ADMIN_ENABLED=false`).

`authz-policy-admin` implements only the subset of the API that the agent uses:
the simplified-policy upload paths and the v3 export paths.  It does not
implement POST / PATCH / DELETE on the PIP path (those return 405), nor any
management or tenant-management surface.
