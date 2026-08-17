# Scenario: Direct OPA Scenario Matrix Runner

## Purpose

Generic internal-only `JMeter` plan for direct OPA runs where each CSV row already contains one
fully built normalized OPA request envelope.

## CSV Contract

The runner expects a CSV file with these columns:

| Column | Meaning |
| -------- | --------- |
| `username` | Key used to resolve `token_${username}` from the properties file |
| `scenarioLabel` | Short human-readable run label added to the sample name |
| `requestClass` | Classification tag used in the sample label |
| `expectedDecision` | Expected aggregate decision: `ALLOW` or `DENY` |
| `requestBodyTemplate` | Full JSON body posted to `POST /v1/data/authorize`; uses placeholder `__TOKEN__` |

`requestBodyTemplate` must already contain the normalized OPA input envelope:

- `authorizationToken`
- `authorizationType`
- `requestHeaders`
- `decisionLogPipTrace`
- `resources`
- `subject`
- `ignoreRls`

The `JSR223` preprocessor replaces every `__TOKEN__` placeholder with the pre-acquired bearer token
for the current row user before the sampler executes.

## Execution Model

- one active thread group;
- one CSV-driven direct OPA request shape per sample;
- aggregate stage-level throughput controlled by `target_rps`;
- measured against internal `opa:8181 /v1/data/authorize`.

## Configurable Properties

| Property | Default | Description |
| ---------- | --------- | ------------- |
| `threads` | `30` | Concurrent threads |
| `ramp_seconds` | `5` | Thread ramp-up period |
| `duration_seconds` | `60` | Total scenario duration |
| `target_rps` | `500` | Aggregate request rate |
| `opa_host` | `opa` | Internal Compose hostname |
| `opa_port` | `8181` | Internal backend OPA port |
| `scenario_csv` | `/scenario/requests.csv` | Scenario-specific CSV mounted into the JMeter container |
