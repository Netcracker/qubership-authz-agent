# Mixed-Flow Load-Test Report — legacy

Generated: 2026-05-18 07:15:39 UTC
Sweep timestamp: 20260518-100747

## Methodology

- **Mode**: `legacy` — requests traverse Envoy → Lua mapping → OPA → decision-log-collector via the legacy compatibility endpoints (`/access/v1/check/resource`, `/access/v1/check/resource/bulk`, `/access/v1/check/filter`).
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
- **Other-mode report**: see [mixed-load-report-canonical-latest.md](mixed-load-report-canonical-latest.md) (independent baseline, no cross-mode gating per D-1).

## Idle baselines

| service                | resource    | idle-before-avg | idle-after-avg |
| ---------------------- | ----------- | --------------- | -------------- |
| envoy                  | CPU (cores) | 0.012           | 0.026          |
| envoy                  | Memory      | 61.9 MiB        | 109.8 MiB      |
| envoy                  | IO (net)    | 0.00 MiB/s      | 0.13 MiB/s     |
| envoy                  | IO (fs)     | —               | —              |
| opa                    | CPU (cores) | 0.006           | 0.069          |
| opa                    | Memory      | 50.5 MiB        | 99.4 MiB       |
| opa                    | IO (net)    | 0.00 MiB/s      | 0.07 MiB/s     |
| opa                    | IO (fs)     | 0.00 MiB/s      | 0.00 MiB/s     |
| decision-log-collector | CPU (cores) | 0.008           | 0.015          |
| decision-log-collector | Memory      | 20.4 MiB        | 37.9 MiB       |
| decision-log-collector | IO (net)    | 0.00 MiB/s      | 0.02 MiB/s     |
| decision-log-collector | IO (fs)     | 0.00 MiB/s      | 0.54 MiB/s     |

## Results

### 100 RPS

| service                | resource    | load-peak  | load-avg   |
| ---------------------- | ----------- | ---------- | ---------- |
| envoy                  | CPU (cores) | 0.084      | 0.061      |
| envoy                  | Memory      | 78.0 MiB   | 72.5 MiB   |
| envoy                  | IO (net)    | 0.77 MiB/s | 0.54 MiB/s |
| envoy                  | IO (fs)     | —          | —          |
| opa                    | CPU (cores) | 0.535      | 0.365      |
| opa                    | Memory      | 62.1 MiB   | 51.5 MiB   |
| opa                    | IO (net)    | 0.58 MiB/s | 0.39 MiB/s |
| opa                    | IO (fs)     | 0.06 MiB/s | 0.02 MiB/s |
| decision-log-collector | CPU (cores) | 0.018      | 0.014      |
| decision-log-collector | Memory      | 24.2 MiB   | 22.5 MiB   |
| decision-log-collector | IO (net)    | 0.03 MiB/s | 0.02 MiB/s |
| decision-log-collector | IO (fs)     | 0.51 MiB/s | 0.17 MiB/s |

### 200 RPS

| service                | resource    | load-peak  | load-avg   |
| ---------------------- | ----------- | ---------- | ---------- |
| envoy                  | CPU (cores) | 0.147      | 0.119      |
| envoy                  | Memory      | 90.5 MiB   | 86.7 MiB   |
| envoy                  | IO (net)    | 1.55 MiB/s | 1.24 MiB/s |
| envoy                  | IO (fs)     | —          | —          |
| opa                    | CPU (cores) | 1.063      | 0.847      |
| opa                    | Memory      | 71.1 MiB   | 61.0 MiB   |
| opa                    | IO (net)    | 1.17 MiB/s | 0.90 MiB/s |
| opa                    | IO (fs)     | 0.06 MiB/s | 0.02 MiB/s |
| decision-log-collector | CPU (cores) | 0.031      | 0.023      |
| decision-log-collector | Memory      | 24.5 MiB   | 23.8 MiB   |
| decision-log-collector | IO (net)    | 0.07 MiB/s | 0.05 MiB/s |
| decision-log-collector | IO (fs)     | 0.96 MiB/s | 0.42 MiB/s |

### 300 RPS

| service                | resource    | load-peak  | load-avg   |
| ---------------------- | ----------- | ---------- | ---------- |
| envoy                  | CPU (cores) | 0.215      | 0.177      |
| envoy                  | Memory      | 98.8 MiB   | 95.5 MiB   |
| envoy                  | IO (net)    | 2.30 MiB/s | 1.88 MiB/s |
| envoy                  | IO (fs)     | —          | —          |
| opa                    | CPU (cores) | 1.596      | 1.298      |
| opa                    | Memory      | 70.6 MiB   | 61.3 MiB   |
| opa                    | IO (net)    | 1.72 MiB/s | 1.38 MiB/s |
| opa                    | IO (fs)     | 0.00 MiB/s | 0.00 MiB/s |
| decision-log-collector | CPU (cores) | 0.046      | 0.033      |
| decision-log-collector | Memory      | 26.1 MiB   | 25.1 MiB   |
| decision-log-collector | IO (net)    | 0.11 MiB/s | 0.07 MiB/s |
| decision-log-collector | IO (fs)     | 1.34 MiB/s | 0.81 MiB/s |

### 400 RPS

| service                | resource    | load-peak  | load-avg   |
| ---------------------- | ----------- | ---------- | ---------- |
| envoy                  | CPU (cores) | 0.288      | 0.235      |
| envoy                  | Memory      | 102.9 MiB  | 100.5 MiB  |
| envoy                  | IO (net)    | 3.10 MiB/s | 2.55 MiB/s |
| envoy                  | IO (fs)     | —          | —          |
| opa                    | CPU (cores) | 2.191      | 1.776      |
| opa                    | Memory      | 76.9 MiB   | 63.1 MiB   |
| opa                    | IO (net)    | 2.30 MiB/s | 1.84 MiB/s |
| opa                    | IO (fs)     | 0.00 MiB/s | 0.00 MiB/s |
| decision-log-collector | CPU (cores) | 0.061      | 0.042      |
| decision-log-collector | Memory      | 29.7 MiB   | 27.1 MiB   |
| decision-log-collector | IO (net)    | 0.15 MiB/s | 0.10 MiB/s |
| decision-log-collector | IO (fs)     | 2.12 MiB/s | 0.96 MiB/s |

### 500 RPS

| service                | resource    | load-peak  | load-avg   |
| ---------------------- | ----------- | ---------- | ---------- |
| envoy                  | CPU (cores) | 0.361      | 0.294      |
| envoy                  | Memory      | 104.7 MiB  | 103.3 MiB  |
| envoy                  | IO (net)    | 3.87 MiB/s | 3.21 MiB/s |
| envoy                  | IO (fs)     | —          | —          |
| opa                    | CPU (cores) | 2.833      | 2.342      |
| opa                    | Memory      | 83.2 MiB   | 70.4 MiB   |
| opa                    | IO (net)    | 2.87 MiB/s | 2.33 MiB/s |
| opa                    | IO (fs)     | 0.06 MiB/s | 0.02 MiB/s |
| decision-log-collector | CPU (cores) | 0.075      | 0.055      |
| decision-log-collector | Memory      | 31.9 MiB   | 30.1 MiB   |
| decision-log-collector | IO (net)    | 0.17 MiB/s | 0.13 MiB/s |
| decision-log-collector | IO (fs)     | 2.56 MiB/s | 1.28 MiB/s |

### 1000 RPS

| service                | resource    | load-peak  | load-avg   |
| ---------------------- | ----------- | ---------- | ---------- |
| envoy                  | CPU (cores) | 0.820      | 0.604      |
| envoy                  | Memory      | 113.9 MiB  | 111.4 MiB  |
| envoy                  | IO (net)    | 7.65 MiB/s | 5.82 MiB/s |
| envoy                  | IO (fs)     | —          | —          |
| opa                    | CPU (cores) | 6.917      | 5.016      |
| opa                    | Memory      | 200.1 MiB  | 117.8 MiB  |
| opa                    | IO (net)    | 5.68 MiB/s | 4.20 MiB/s |
| opa                    | IO (fs)     | 0.08 MiB/s | 0.02 MiB/s |
| decision-log-collector | CPU (cores) | 0.203      | 0.120      |
| decision-log-collector | Memory      | 36.0 MiB   | 33.7 MiB   |
| decision-log-collector | IO (net)    | 0.38 MiB/s | 0.22 MiB/s |
| decision-log-collector | IO (fs)     | 4.21 MiB/s | 2.46 MiB/s |

## Peak summary across RPS

### Peak CPU (cores) by RPS

| service                | 100   | 200   | 300   | 400   | 500   | 1000  |
| ---------------------- | ----- | ----- | ----- | ----- | ----- | ----- |
| envoy                  | 0.084 | 0.147 | 0.215 | 0.288 | 0.361 | 0.820 |
| opa                    | 0.535 | 1.063 | 1.596 | 2.191 | 2.833 | 6.917 |
| decision-log-collector | 0.018 | 0.031 | 0.046 | 0.061 | 0.075 | 0.203 |

### Peak Memory by RPS

| service                | 100      | 200      | 300      | 400       | 500       | 1000      |
| ---------------------- | -------- | -------- | -------- | --------- | --------- | --------- |
| envoy                  | 78.0 MiB | 90.5 MiB | 98.8 MiB | 102.9 MiB | 104.7 MiB | 113.9 MiB |
| opa                    | 62.1 MiB | 71.1 MiB | 70.6 MiB | 76.9 MiB  | 83.2 MiB  | 200.1 MiB |
| decision-log-collector | 24.2 MiB | 24.5 MiB | 26.1 MiB | 29.7 MiB  | 31.9 MiB  | 36.0 MiB  |

## Notes

- Clean run, no anomalies observed.
- **D-8 cooldown retrofit (2026-05-18).** The original sweep captured the
  `idle-after` window immediately after the 1000 RPS load (`<load_end_ms>
  - 11 ms`), which still picked up transient post-load activity (Envoy
  Lua-mapping pool teardown, OPA request cleanup, decision-log-collector
  flush). The handover later mandated a 20 s wall-clock cooldown gap
  before sampling`idle-after`. The`idle-after-avg` cells in the Idle
  baselines table above were re-derived by re-querying Prometheus for
  the shifted window `[<load_end_ms> + 20 000 ms, + 50 000 ms]` against
  the same TSDB; raw range payloads + `summary.json` are committed under
  `tests/svt/load-tests/mixed-flow/artifacts/legacy-20260518-100747/idle-after-d8/`.
  The original (pre-shift)`idle-after/` artifacts are preserved
  alongside for traceability. The shift dropped the headline transient
  cells substantially (e.g. `opa` CPU `2.283 → 0.069` cores, `envoy`
  CPU `0.286 → 0.026` cores, `opa` IO net `2.01 → 0.07 MiB/s`) while
  working-set memory cells stayed essentially unchanged
  (`envoy` `109.8 MiB` and `opa` `99.4 MiB` are saturated working sets,
  not transients), confirming the gap captures steady-idle rather than
  fully-quiesced state.
