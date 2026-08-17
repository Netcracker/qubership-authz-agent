# Scenario: Direct OPA Authorization Load Test

## Purpose

Internal-only SVT scenario for backend-isolated diagnostics. Exercises the same semantic workload
mix as the main baseline scenario but sends normalized authorization requests directly to backend
OPA instead of going through Envoy.

## Semantic Coverage

| Semantic Family | Direct OPA Shape | CSV Source |
| ----------------- | ------------------ | ------------ |
| Single-resource authorization | `POST /v1/data/authorize` with one normalized `resources[]` item | `requests.csv` |
| Filter-style authorization | `POST /v1/data/authorize` with one normalized empty-resource item | `requests-filter.csv` |
| Bulk authorization | `POST /v1/data/authorize` with multiple normalized `resources[]` items | `requests-bulk.csv` |

## Dataset

The profile reuses the same datasets as the main baseline scenario:

| Parameter | Value |
| ----------- | ------- |
| Resource types | `ORDER`, `CUSTOMER`, `PRODUCT`, `INVOICE`, `DOCUMENT` |
| Operations per type | `CREATE`, `READ`, `UPDATE`, `DELETE`, `LIST`, `EXPORT`, `IMPORT`, `APPROVE`, `REJECT`, `ARCHIVE` |
| Users | `svt-admin`, `svt-manager`, `svt-operator`, `svt-viewer`, `svt-restricted` |
| Unauthorized share | ~10% of CSV rows result in DENY |
| PIP policies | none (same baseline: first stage excludes GENERAL PIP) |
| Complex RLS user | `svt-restricted` (conditions: `resource.ownerId == subject.email`, `resource.regionId == subject.email`) |

## Execution Model

This scenario has one direct OPA stage with three active thread groups:

- single-resource authorization;
- filter-style authorization; and
- bulk authorization.

The stage-level `target_rps` value is split evenly across those three groups, preserving the same
`1/3 : 1/3 : 1/3` family ratio as one measured phase of the main baseline scenario.

## OPA Request Shape

Every sampler posts a normalized OPA input envelope that matches the Envoy-normalized body for the
same semantic call family:

- `authorizationToken`
- `authorizationType`
- `requestHeaders`
- `decisionLogPipTrace`
- `resources`
- `subject`
- `ignoreRls`

The profile is intentionally internal-only:

- target host is Compose service `opa`;
- target port is `8181`;
- target path is `/v1/data/authorize`; and
- OPA is not exposed on the public host interface for this scenario.

## Token Strategy

Tokens are acquired once by the dedicated `run-opa-direct` wrapper before the measured run and are
passed to JMeter via a properties file. No token acquisition happens inside the JMeter hot path.

## Configurable Properties

| Property | Default | Description |
| ---------- | --------- | ------------- |
| `threads` | `30` | Concurrent threads per active thread group |
| `ramp_seconds` | `5` | Thread ramp-up period |
| `duration_seconds` | `60` | Total test duration |
| `target_rps` | `500` | Aggregate stage-level throughput target (split across 3 groups) |
| `opa_host` | `opa` | Internal Compose hostname |
| `opa_port` | `8181` | Internal backend OPA port |

## Input Files

- `/data/requests.csv` — single-resource request mix
- `/data/requests-filter.csv` — filter-style request mix
- `/data/requests-bulk.csv` — deterministic bulk request mix
- `/tokens.properties` — pre-acquired Keycloak tokens

## Output

- JTL result file for the direct OPA stage
- JMeter HTML dashboard for the direct OPA stage
- Prometheus snapshot metadata
- run metadata with direct-target information
