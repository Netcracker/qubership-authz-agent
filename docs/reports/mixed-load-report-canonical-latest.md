# Mixed-Flow Load-Test Report — canonical

Generated: 2026-05-18 06:48:42 UTC
Sweep timestamp: 20260518-094051

## Methodology

- **Mode**: `canonical` — requests traverse Envoy → OPA → decision-log-collector via `POST /access/v1/authorize`.
- **Scenarios (8, share sums to 100%)**: 20% `ols-single-10roles`, 5% `rls-predicate`, 5% `rls-condition`,
  5% `ols-bulk-100`, 25% `rls-condition-2-expression`, 25% `rls-predicate-summary-2-predicates`,
  10% `rls-predicate-pips-2-token-pip`, 5% `wildcard-all-single`. Request shapes from
  `tests/svt/profiler/<scenario>/input-real-token.json`; tokens are live Keycloak tokens issued for
  `svt-mixed-001..008` (see [handover 20260518](../handovers/done/20260518-mixed-load-report-task.md)).
- **RPS levels**: 100, 200, 300, 400, 500, 1000. OPA is restarted before every level (cold-cache per RPS).
- **Load window per RPS**: 60s, 5s ramp, no cooldown inside the plan.
- **Idle baselines**: one `idle-before` + one `idle-after` window (30s each), captured once per sweep at the sweep boundaries (per D-5; OPA-restart-per-RPS makes a per-RPS idle window identical by construction).
- **Bulk slot accounting**: 1 HTTP request = 1 RPS. At 1000 RPS the `ols-bulk-100` thread group fires 50 req/s, each carrying 100 resources internally.
- **PromQL** — CPU: `sum(rate(container_cpu_usage_seconds_total{name=~".*<svc>.*"}[30s]))`; Memory: `sum(container_memory_working_set_bytes{name=~".*<svc>.*"})`; IO net: receive + transmit `bytes_total` rate; IO fs: reads + writes `bytes_total` rate.
- **Auto-promote gate**: any peak CPU or peak memory cell exceeding the baseline by more than 5% blocks the canonical file update. IO columns are rendered for visibility but **not** gated (cAdvisor fs sampling is noisy on cgroup v2 — see Notes).
- **Host baseline**: Ubuntu 24.04.4 LTS, AMD Ryzen 9 8945HS (16 logical / 8 physical), 92 GiB RAM, Docker 29.3.1, Compose v5.1.1, OPA limits 8 CPU / 8G RAM (see [tests/svt/README.md §Host Baseline](../../test/svt/README.md#host-baseline-first-stage)).
- **Other-mode report**: see [mixed-load-report-legacy-latest.md](mixed-load-report-legacy-latest.md) (independent baseline, no cross-mode gating per D-1).

## Idle baselines

| service                | resource    | idle-before-avg | idle-after-avg |
| ---------------------- | ----------- | --------------- | -------------- |
| envoy                  | CPU (cores) | 0.011           | 0.028          |
| envoy                  | Memory      | 33.0 MiB        | 61.9 MiB       |
| envoy                  | IO (net)    | 0.00 MiB/s      | 0.28 MiB/s     |
| envoy                  | IO (fs)     | —               | —              |
| opa                    | CPU (cores) | 0.006           | 0.133          |
| opa                    | Memory      | 36.6 MiB        | 74.1 MiB       |
| opa                    | IO (net)    | 0.00 MiB/s      | 0.18 MiB/s     |
| opa                    | IO (fs)     | 0.00 MiB/s      | 0.00 MiB/s     |
| decision-log-collector | CPU (cores) | 0.007           | 0.019          |
| decision-log-collector | Memory      | 3.0 MiB         | 22.6 MiB       |
| decision-log-collector | IO (net)    | 0.00 MiB/s      | 0.03 MiB/s     |
| decision-log-collector | IO (fs)     | 0.00 MiB/s      | 0.62 MiB/s     |

## Results

### 100 RPS

| service                | resource    | load-peak  | load-avg   |
| ---------------------- | ----------- | ---------- | ---------- |
| envoy                  | CPU (cores) | 0.067      | 0.051      |
| envoy                  | Memory      | 45.4 MiB   | 42.4 MiB   |
| envoy                  | IO (net)    | 0.92 MiB/s | 0.65 MiB/s |
| envoy                  | IO (fs)     | —          | —          |
| opa                    | CPU (cores) | 0.382      | 0.269      |
| opa                    | Memory      | 62.9 MiB   | 54.7 MiB   |
| opa                    | IO (net)    | 0.57 MiB/s | 0.39 MiB/s |
| opa                    | IO (fs)     | 0.06 MiB/s | 0.02 MiB/s |
| decision-log-collector | CPU (cores) | 0.017      | 0.014      |
| decision-log-collector | Memory      | 8.2 MiB    | 7.0 MiB    |
| decision-log-collector | IO (net)    | 0.03 MiB/s | 0.02 MiB/s |
| decision-log-collector | IO (fs)     | 0.39 MiB/s | 0.14 MiB/s |

### 200 RPS

| service                | resource    | load-peak  | load-avg   |
| ---------------------- | ----------- | ---------- | ---------- |
| envoy                  | CPU (cores) | 0.120      | 0.097      |
| envoy                  | Memory      | 51.2 MiB   | 49.2 MiB   |
| envoy                  | IO (net)    | 1.85 MiB/s | 1.46 MiB/s |
| envoy                  | IO (fs)     | —          | —          |
| opa                    | CPU (cores) | 0.764      | 0.600      |
| opa                    | Memory      | 69.4 MiB   | 58.9 MiB   |
| opa                    | IO (net)    | 1.14 MiB/s | 0.89 MiB/s |
| opa                    | IO (fs)     | 0.00 MiB/s | 0.00 MiB/s |
| decision-log-collector | CPU (cores) | 0.029      | 0.022      |
| decision-log-collector | Memory      | 10.2 MiB   | 8.9 MiB    |
| decision-log-collector | IO (net)    | 0.07 MiB/s | 0.05 MiB/s |
| decision-log-collector | IO (fs)     | 0.76 MiB/s | 0.46 MiB/s |

### 300 RPS

| service                | resource    | load-peak  | load-avg   |
| ---------------------- | ----------- | ---------- | ---------- |
| envoy                  | CPU (cores) | 0.177      | 0.145      |
| envoy                  | Memory      | 55.3 MiB   | 53.6 MiB   |
| envoy                  | IO (net)    | 2.78 MiB/s | 2.28 MiB/s |
| envoy                  | IO (fs)     | —          | —          |
| opa                    | CPU (cores) | 1.132      | 0.908      |
| opa                    | Memory      | 65.4 MiB   | 55.3 MiB   |
| opa                    | IO (net)    | 1.70 MiB/s | 1.36 MiB/s |
| opa                    | IO (fs)     | 0.06 MiB/s | 0.02 MiB/s |
| decision-log-collector | CPU (cores) | 0.043      | 0.031      |
| decision-log-collector | Memory      | 13.5 MiB   | 10.4 MiB   |
| decision-log-collector | IO (net)    | 0.11 MiB/s | 0.07 MiB/s |
| decision-log-collector | IO (fs)     | 1.39 MiB/s | 0.83 MiB/s |

### 400 RPS

| service                | resource    | load-peak  | load-avg   |
| ---------------------- | ----------- | ---------- | ---------- |
| envoy                  | CPU (cores) | 0.227      | 0.185      |
| envoy                  | Memory      | 57.7 MiB   | 56.1 MiB   |
| envoy                  | IO (net)    | 3.68 MiB/s | 2.98 MiB/s |
| envoy                  | IO (fs)     | —          | —          |
| opa                    | CPU (cores) | 1.504      | 1.238      |
| opa                    | Memory      | 68.5 MiB   | 62.3 MiB   |
| opa                    | IO (net)    | 2.27 MiB/s | 1.84 MiB/s |
| opa                    | IO (fs)     | 0.06 MiB/s | 0.02 MiB/s |
| decision-log-collector | CPU (cores) | 0.053      | 0.039      |
| decision-log-collector | Memory      | 16.4 MiB   | 13.0 MiB   |
| decision-log-collector | IO (net)    | 0.13 MiB/s | 0.09 MiB/s |
| decision-log-collector | IO (fs)     | 1.99 MiB/s | 1.01 MiB/s |

### 500 RPS

| service                | resource    | load-peak  | load-avg   |
| ---------------------- | ----------- | ---------- | ---------- |
| envoy                  | CPU (cores) | 0.286      | 0.237      |
| envoy                  | Memory      | 59.0 MiB   | 57.8 MiB   |
| envoy                  | IO (net)    | 4.61 MiB/s | 3.83 MiB/s |
| envoy                  | IO (fs)     | —          | —          |
| opa                    | CPU (cores) | 1.909      | 1.572      |
| opa                    | Memory      | 69.6 MiB   | 59.5 MiB   |
| opa                    | IO (net)    | 2.84 MiB/s | 2.33 MiB/s |
| opa                    | IO (fs)     | 0.07 MiB/s | 0.02 MiB/s |
| decision-log-collector | CPU (cores) | 0.058      | 0.049      |
| decision-log-collector | Memory      | 16.5 MiB   | 14.9 MiB   |
| decision-log-collector | IO (net)    | 0.15 MiB/s | 0.12 MiB/s |
| decision-log-collector | IO (fs)     | 2.43 MiB/s | 1.37 MiB/s |

### 1000 RPS

| service                | resource    | load-peak  | load-avg   |
| ---------------------- | ----------- | ---------- | ---------- |
| envoy                  | CPU (cores) | 0.573      | 0.444      |
| envoy                  | Memory      | 66.1 MiB   | 63.8 MiB   |
| envoy                  | IO (net)    | 9.19 MiB/s | 7.23 MiB/s |
| envoy                  | IO (fs)     | —          | —          |
| opa                    | CPU (cores) | 4.072      | 3.149      |
| opa                    | Memory      | 88.6 MiB   | 71.1 MiB   |
| opa                    | IO (net)    | 5.68 MiB/s | 4.32 MiB/s |
| opa                    | IO (fs)     | 0.06 MiB/s | 0.02 MiB/s |
| decision-log-collector | CPU (cores) | 0.146      | 0.100      |
| decision-log-collector | Memory      | 23.3 MiB   | 19.4 MiB   |
| decision-log-collector | IO (net)    | 0.34 MiB/s | 0.23 MiB/s |
| decision-log-collector | IO (fs)     | 4.78 MiB/s | 2.21 MiB/s |

## Peak summary across RPS

### Peak CPU (cores) by RPS

| service                | 100   | 200   | 300   | 400   | 500   | 1000  |
| ---------------------- | ----- | ----- | ----- | ----- | ----- | ----- |
| envoy                  | 0.067 | 0.120 | 0.177 | 0.227 | 0.286 | 0.573 |
| opa                    | 0.382 | 0.764 | 1.132 | 1.504 | 1.909 | 4.072 |
| decision-log-collector | 0.017 | 0.029 | 0.043 | 0.053 | 0.058 | 0.146 |

### Peak Memory by RPS

| service                | 100      | 200      | 300      | 400      | 500      | 1000     |
| ---------------------- | -------- | -------- | -------- | -------- | -------- | -------- |
| envoy                  | 45.4 MiB | 51.2 MiB | 55.3 MiB | 57.7 MiB | 59.0 MiB | 66.1 MiB |
| opa                    | 62.9 MiB | 69.4 MiB | 65.4 MiB | 68.5 MiB | 69.6 MiB | 88.6 MiB |
| decision-log-collector | 8.2 MiB  | 10.2 MiB | 13.5 MiB | 16.4 MiB | 16.5 MiB | 23.3 MiB |

## Notes

- Clean run, no anomalies observed.
- **D-8 cooldown retrofit (2026-05-18).** The original sweep captured the
  `idle-after` window immediately after the 1000 RPS load (`<load_end_ms>
  - 10 ms`), which still picked up transient post-load activity (Envoy
  connection-pool teardown, OPA request cleanup, decision-log-collector
  flush). The handover later mandated a 20 s wall-clock cooldown gap
  before sampling`idle-after`. The`idle-after-avg` cells in the Idle
  baselines table above were re-derived by re-querying Prometheus for
  the shifted window `[<load_end_ms> + 20 000 ms, + 50 000 ms]` against
  the same TSDB; raw range payloads + `summary.json` are committed under
  `tests/svt/load-tests/mixed-flow/artifacts/canonical-20260518-094051/idle-after-d8/`.
  The original (pre-shift)`idle-after/` artifacts are preserved
  alongside for traceability. The shift dropped the headline transient
  cells substantially (e.g. `opa` CPU `1.766 → 0.133` cores, `envoy`
  CPU `0.244 → 0.028` cores, `opa` IO net `2.47 → 0.18 MiB/s`) while
  working-set memory and`decision-log-collector` IO (fs) stayed near
  their pre-shift values, confirming that the gap captures steady-idle
  rather than fully-quiesced state (per the methodology's intent).
