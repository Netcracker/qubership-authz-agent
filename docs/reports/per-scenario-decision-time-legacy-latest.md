# Per-Scenario Decision-Time Report — legacy

Generated: 2026-05-18 12:29:15 UTC
Sweep timestamp: 20260518-141320

## Methodology

- **Mode**: `legacy` — requests traverse Envoy → Lua mapping → OPA → decision-log-collector via the legacy compatibility endpoints (`/access/v1/check/resource`, `/access/v1/check/resource/bulk`, `/access/v1/check/filter`).
- **Scenarios**: every benchmark in [docs/reports/bench-report-latest.md](bench-report-latest.md). The inventory below is re-derived at sweep time. Request shapes are copied from the profiler `tests/svt/profiler/<scenario>/input.json` files; tokens are issued by Keycloak for the matching `svt-bench-<scenario>` user.
- **RPS levels**: 100, 200, 300, 400, 500, 1000. OPA is restarted before every (scenario, RPS) tuple (cold-cache per run).
- **Load window per run**: 15s with 3s ramp (per D-20, shortened from the mixed-flow default of 60 s + 5 s so the 336-run sweep fits in ~2–3 h per mode).
- **Inter-scenario gap**: 5s wall-clock break between adjacent scenario blocks (D-21) so Prometheus/cAdvisor exposes a clean visual boundary in Grafana time-series.
- **No idle baselines.** Per owner decision on `2026-05-18`, the per-scenario sweep is too long (168 runs × 2 modes) for idle windows to pay back the runtime. [mixed-load-report-canonical-latest.md](mixed-load-report-canonical-latest.md) publishes the canonical idle baseline for the three services.
- **Bulk slot accounting**: 1 HTTP request = 1 RPS. At 1000 RPS, `ols-bulk-1000` fires 1000 req/s × 1000 resources ≈ 10⁶ decisions/s; the host saturates and the row is flagged in Notes.
- **PromQL** — CPU: `sum(rate(container_cpu_usage_seconds_total{name=~".*<svc>.*"}[30s]))`; Memory: `sum(container_memory_working_set_bytes{name=~".*<svc>.*"})`; IO net: receive + transmit `bytes_total` rate.
- **Response-time stats** (per row): avg / median / p95 / p99 of the JMeter `elapsed` column from `results.jtl`. Nearest-rank percentile.
- **Achieved RPS**: cumulative `summary =` rate from the JMeter Summariser tail. Rows where `achieved_rps < 0.9 × target_rps` are marked with `*` and listed in Notes.
- **Auto-promote gate**: any per-(scenario, RPS) response-time **p95** cell exceeding the baseline by more than 5 % blocks promotion. CPU / memory / IO are rendered for visibility but **not** gated (D-12).
- **Host baseline**: Ubuntu 24.04.4 LTS, AMD Ryzen 9 8945HS (16 logical / 8 physical), 92 GiB RAM, Docker 29.3.1, Compose v5.1.1, OPA limits 8 CPU / 8G RAM (see [tests/svt/README.md §Host Baseline](../../test/svt/README.md#host-baseline-first-stage)).
- **Other-mode report**: see [per-scenario-decision-time-canonical-latest.md](per-scenario-decision-time-canonical-latest.md) (independent baseline, no cross-mode gating per D-15).
- **Companion xlsx**: [per-scenario-decision-time.xlsx](per-scenario-decision-time.xlsx), `legacy` sheet (168 rows × 25 cols, header row sortable).

## Scenario inventory

| Scenario | Group | Legacy endpoint |
| ---------- | ------- | ----------------- |
| `ols-single` | OLS | `/access/v1/check/resource` |
| `ols-single-10roles` | OLS | `/access/v1/check/resource` |
| `ols-single-20roles` | OLS | `/access/v1/check/resource` |
| `ols-single-30roles` | OLS | `/access/v1/check/resource` |
| `ols-single-50roles` | OLS | `/access/v1/check/resource` |
| `ols-single-100roles` | OLS | `/access/v1/check/resource` |
| `ols-bulk-50` | OLS-bulk | `/access/v1/check/resource/bulk` |
| `ols-bulk-100` | OLS-bulk | `/access/v1/check/resource/bulk` |
| `ols-bulk-1000` | OLS-bulk | `/access/v1/check/resource/bulk` |
| `rls-condition-1-expression` | RLS-condition | `/access/v1/check/resource` |
| `rls-condition-2-expression` | RLS-condition | `/access/v1/check/resource` |
| `rls-condition-3-expression` | RLS-condition | `/access/v1/check/resource` |
| `rls-condition-5-expression` | RLS-condition | `/access/v1/check/resource` |
| `rls-predicate` | RLS-predicate | `/access/v1/check/filter` |
| `rls-predicate-summary-2-predicates` | RLS-predicate | `/access/v1/check/filter` |
| `rls-predicate-summary-3-predicates` | RLS-predicate | `/access/v1/check/filter` |
| `rls-predicate-summary-4-predicates` | RLS-predicate | `/access/v1/check/filter` |
| `rls-predicate-summary-5-predicates` | RLS-predicate | `/access/v1/check/filter` |
| `rls-predicate-summary-10-predicates` | RLS-predicate | `/access/v1/check/filter` |
| `rls-predicate-pips-1-token-pip` | RLS-predicate-pips | `/access/v1/check/filter` |
| `rls-predicate-pips-2-token-pip` | RLS-predicate-pips | `/access/v1/check/filter` |
| `rls-predicate-pips-3-token-pip` | RLS-predicate-pips | `/access/v1/check/filter` |
| `rls-predicate-pips-1-header-pip` | RLS-predicate-pips | `/access/v1/check/filter` |
| `rls-predicate-pips-2-header-pip` | RLS-predicate-pips | `/access/v1/check/filter` |
| `rls-predicate-pips-3-header-pip` | RLS-predicate-pips | `/access/v1/check/filter` |
| `rls-predicate-summary-10-predicates-3-token-pip` | RLS-predicate-pips | `/access/v1/check/filter` |
| `wildcard-all-single` | Wildcard | `/access/v1/check/resource` |
| `wildcard-mixed-bulk` | Wildcard | `/access/v1/check/resource/bulk` |

## Results

### `ols-single`

_Group_: OLS. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 93.3 | 0.171 | 0.129 | 79.5 MiB | 78.9 MiB | 2.69 MiB/s | 1.78 MiB/s | 4.547 | 2.899 | 65.5 MiB | 47.3 MiB | 1.35 MiB/s | 0.93 MiB/s | 0.087 | 0.067 | 167.9 MiB | 165.4 MiB | 0.02 MiB/s | 0.02 MiB/s | 4.5 | 4.0 | 8.0 | 14.0 |
| 200 | 179.1* | 0.103 | 0.078 | 83.4 MiB | 81.3 MiB | 0.68 MiB/s | 0.48 MiB/s | 0.425 | 0.290 | 76.7 MiB | 54.4 MiB | 0.46 MiB/s | 0.33 MiB/s | 0.027 | 0.021 | 162.3 MiB | 162.0 MiB | 0.01 MiB/s | 0.01 MiB/s | 6.3 | 4.0 | 13.0 | 56.0 |
| 300 | 278.8 | 0.164 | 0.123 | 85.1 MiB | 83.4 MiB | 1.03 MiB/s | 0.80 MiB/s | 0.822 | 0.606 | 92.7 MiB | 74.7 MiB | 0.76 MiB/s | 0.62 MiB/s | 0.035 | 0.031 | 166.2 MiB | 163.9 MiB | 0.02 MiB/s | 0.01 MiB/s | 10.4 | 6.0 | 31.0 | 80.0 |
| 400 | 369.0 | 0.241 | 0.191 | 86.5 MiB | 84.8 MiB | 1.45 MiB/s | 1.18 MiB/s | 1.275 | 1.043 | 98.3 MiB | 90.9 MiB | 1.08 MiB/s | 0.91 MiB/s | 0.055 | 0.043 | 163.1 MiB | 162.9 MiB | 0.03 MiB/s | 0.02 MiB/s | 15.0 | 8.0 | 54.0 | 100.0 |
| 500 | 460.9 | 0.310 | 0.271 | 87.6 MiB | 85.4 MiB | 1.86 MiB/s | 1.61 MiB/s | 1.674 | 1.360 | 102.6 MiB | 72.2 MiB | 1.32 MiB/s | 1.11 MiB/s | 0.062 | 0.054 | 166.2 MiB | 163.8 MiB | 0.03 MiB/s | 0.03 MiB/s | 22.2 | 16.0 | 65.0 | 126.0 |
| 1000 | 750.2* | 0.538 | 0.385 | 89.5 MiB | 86.9 MiB | 2.92 MiB/s | 2.18 MiB/s | 2.914 | 2.015 | 148.0 MiB | 94.6 MiB | 2.08 MiB/s | 1.50 MiB/s | 0.113 | 0.064 | 166.1 MiB | 164.7 MiB | 0.05 MiB/s | 0.03 MiB/s | 77.0 | 61.0 | 207.0 | 272.0 |

### `ols-single-10roles`

_Group_: OLS. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 92.8 | 0.535 | 0.260 | 87.9 MiB | 86.7 MiB | 2.86 MiB/s | 1.44 MiB/s | 2.876 | 1.382 | 140.2 MiB | 74.7 MiB | 2.04 MiB/s | 1.04 MiB/s | 0.120 | 0.083 | 168.9 MiB | 167.8 MiB | 0.05 MiB/s | 0.04 MiB/s | 4.7 | 4.0 | 8.0 | 12.0 |
| 200 | 186.6 | 0.120 | 0.086 | 87.6 MiB | 86.5 MiB | 0.90 MiB/s | 0.64 MiB/s | 0.545 | 0.363 | 75.0 MiB | 67.6 MiB | 0.66 MiB/s | 0.46 MiB/s | 0.029 | 0.024 | 165.4 MiB | 164.7 MiB | 0.01 MiB/s | 0.01 MiB/s | 6.3 | 5.0 | 13.0 | 39.0 |
| 300 | 278.3 | 0.182 | 0.141 | 88.3 MiB | 87.5 MiB | 1.31 MiB/s | 1.02 MiB/s | 0.859 | 0.664 | 73.2 MiB | 67.3 MiB | 0.92 MiB/s | 0.76 MiB/s | 0.052 | 0.037 | 166.2 MiB | 165.6 MiB | 0.02 MiB/s | 0.02 MiB/s | 7.2 | 6.0 | 17.0 | 32.0 |
| 400 | 368.4 | 0.254 | 0.207 | 88.6 MiB | 87.0 MiB | 1.91 MiB/s | 1.55 MiB/s | 1.049 | 0.960 | 86.2 MiB | 60.6 MiB | 1.21 MiB/s | 1.09 MiB/s | 0.061 | 0.048 | 170.1 MiB | 166.8 MiB | 0.02 MiB/s | 0.02 MiB/s | 7.4 | 5.0 | 19.0 | 46.0 |
| 500 | 447.7* | 0.318 | 0.277 | 88.3 MiB | 87.0 MiB | 2.26 MiB/s | 2.01 MiB/s | 1.634 | 1.290 | 110.7 MiB | 63.3 MiB | 1.70 MiB/s | 1.40 MiB/s | 0.069 | 0.061 | 166.8 MiB | 166.2 MiB | 0.03 MiB/s | 0.03 MiB/s | 13.5 | 6.0 | 55.0 | 122.0 |
| 1000 | 724.2* | 0.514 | 0.376 | 89.3 MiB | 87.7 MiB | 3.19 MiB/s | 2.50 MiB/s | 3.018 | 1.973 | 173.1 MiB | 122.0 MiB | 2.35 MiB/s | 1.78 MiB/s | 0.127 | 0.086 | 170.9 MiB | 169.6 MiB | 0.05 MiB/s | 0.03 MiB/s | 91.1 | 75.0 | 218.0 | 362.0 |

### `ols-single-20roles`

_Group_: OLS. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 93.7 | 0.592 | 0.319 | 88.4 MiB | 87.1 MiB | 3.70 MiB/s | 2.04 MiB/s | 3.406 | 1.762 | 147.3 MiB | 78.5 MiB | 2.69 MiB/s | 1.46 MiB/s | 0.146 | 0.098 | 169.6 MiB | 169.0 MiB | 0.06 MiB/s | 0.04 MiB/s | 6.7 | 5.0 | 12.0 | 28.0 |
| 200 | 186.4 | 0.127 | 0.084 | 88.7 MiB | 87.0 MiB | 0.96 MiB/s | 0.64 MiB/s | 0.645 | 0.456 | 88.1 MiB | 72.9 MiB | 0.69 MiB/s | 0.51 MiB/s | 0.035 | 0.028 | 168.8 MiB | 168.7 MiB | 0.01 MiB/s | 0.01 MiB/s | 11.5 | 8.0 | 26.0 | 55.0 |
| 300 | 274.7 | 0.230 | 0.178 | 88.6 MiB | 86.6 MiB | 1.66 MiB/s | 1.32 MiB/s | 1.269 | 0.946 | 108.2 MiB | 68.0 MiB | 1.22 MiB/s | 0.92 MiB/s | 0.067 | 0.047 | 172.8 MiB | 170.7 MiB | 0.02 MiB/s | 0.01 MiB/s | 15.8 | 10.0 | 54.0 | 103.0 |
| 400 | 357.9* | 0.308 | 0.255 | 89.2 MiB | 87.3 MiB | 2.19 MiB/s | 1.84 MiB/s | 1.738 | 1.376 | 116.2 MiB | 71.5 MiB | 1.57 MiB/s | 1.29 MiB/s | 0.081 | 0.074 | 175.0 MiB | 170.4 MiB | 0.03 MiB/s | 0.02 MiB/s | 28.0 | 22.0 | 79.0 | 142.0 |
| 500 | 433.6* | 0.356 | 0.319 | 88.8 MiB | 87.4 MiB | 2.31 MiB/s | 2.14 MiB/s | 1.993 | 1.763 | 113.5 MiB | 70.0 MiB | 1.69 MiB/s | 1.54 MiB/s | 0.103 | 0.085 | 173.4 MiB | 171.5 MiB | 0.03 MiB/s | 0.03 MiB/s | 35.5 | 20.0 | 112.0 | 235.0 |
| 1000 | 688.4* | 0.595 | 0.447 | 89.6 MiB | 88.5 MiB | 3.90 MiB/s | 2.95 MiB/s | 3.102 | 2.533 | 161.8 MiB | 126.1 MiB | 2.74 MiB/s | 2.22 MiB/s | 0.152 | 0.100 | 171.5 MiB | 171.2 MiB | 0.05 MiB/s | 0.03 MiB/s | 98.9 | 79.0 | 251.0 | 353.0 |

### `ols-single-30roles`

_Group_: OLS. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 91.8 | 0.608 | 0.258 | 87.7 MiB | 87.2 MiB | 3.92 MiB/s | 1.70 MiB/s | 3.102 | 1.324 | 70.3 MiB | 56.1 MiB | 2.66 MiB/s | 1.20 MiB/s | 0.167 | 0.094 | 173.3 MiB | 172.3 MiB | 0.05 MiB/s | 0.03 MiB/s | 6.6 | 6.0 | 12.0 | 20.0 |
| 200 | 185.3 | 0.154 | 0.105 | 89.4 MiB | 87.4 MiB | 1.32 MiB/s | 0.92 MiB/s | 0.882 | 0.538 | 84.6 MiB | 64.8 MiB | 0.96 MiB/s | 0.66 MiB/s | 0.050 | 0.030 | 175.0 MiB | 174.1 MiB | 0.02 MiB/s | 0.01 MiB/s | 11.6 | 9.0 | 25.0 | 51.0 |
| 300 | 274.4 | 0.210 | 0.177 | 89.1 MiB | 87.9 MiB | 1.87 MiB/s | 1.51 MiB/s | 1.303 | 1.005 | 89.5 MiB | 58.5 MiB | 1.41 MiB/s | 1.07 MiB/s | 0.055 | 0.051 | 177.3 MiB | 176.5 MiB | 0.02 MiB/s | 0.02 MiB/s | 12.4 | 10.0 | 28.0 | 62.0 |
| 400 | 364.0 | 0.303 | 0.241 | 89.4 MiB | 87.8 MiB | 2.42 MiB/s | 2.08 MiB/s | 1.817 | 1.444 | 112.3 MiB | 70.1 MiB | 1.74 MiB/s | 1.48 MiB/s | 0.066 | 0.058 | 176.6 MiB | 175.1 MiB | 0.03 MiB/s | 0.02 MiB/s | 19.4 | 14.0 | 47.0 | 83.0 |
| 500 | 446.5* | 0.377 | 0.341 | 89.8 MiB | 88.3 MiB | 2.94 MiB/s | 2.71 MiB/s | 2.287 | 2.043 | 137.5 MiB | 106.8 MiB | 2.16 MiB/s | 1.94 MiB/s | 0.084 | 0.073 | 178.4 MiB | 175.7 MiB | 0.03 MiB/s | 0.03 MiB/s | 34.5 | 22.0 | 113.0 | 192.0 |
| 1000 | 614.4* | 0.658 | 0.462 | 89.9 MiB | 87.6 MiB | 4.43 MiB/s | 3.23 MiB/s | 3.741 | 2.881 | 174.7 MiB | 108.3 MiB | 3.22 MiB/s | 2.57 MiB/s | 0.176 | 0.118 | 178.0 MiB | 176.4 MiB | 0.05 MiB/s | 0.04 MiB/s | 119.6 | 99.0 | 290.0 | 458.0 |

### `ols-single-50roles`

_Group_: OLS. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 92.4 | 0.642 | 0.280 | 87.7 MiB | 87.1 MiB | 4.28 MiB/s | 1.92 MiB/s | 3.279 | 1.542 | 70.2 MiB | 55.0 MiB | 2.81 MiB/s | 1.41 MiB/s | 0.175 | 0.092 | 180.2 MiB | 178.3 MiB | 0.05 MiB/s | 0.03 MiB/s | 8.0 | 7.0 | 14.0 | 30.0 |
| 200 | 177.2* | 0.142 | 0.107 | 89.7 MiB | 88.6 MiB | 1.49 MiB/s | 1.06 MiB/s | 1.010 | 0.604 | 94.4 MiB | 74.3 MiB | 1.09 MiB/s | 0.76 MiB/s | 0.045 | 0.035 | 181.9 MiB | 178.5 MiB | 0.01 MiB/s | 0.01 MiB/s | 16.1 | 12.0 | 38.0 | 119.0 |
| 300 | 275.5 | 0.261 | 0.184 | 89.5 MiB | 88.2 MiB | 2.24 MiB/s | 1.78 MiB/s | 1.783 | 1.272 | 96.6 MiB | 71.5 MiB | 1.66 MiB/s | 1.28 MiB/s | 0.064 | 0.053 | 180.1 MiB | 179.0 MiB | 0.02 MiB/s | 0.02 MiB/s | 26.9 | 21.0 | 63.0 | 111.0 |
| 400 | 348.7* | 0.354 | 0.292 | 89.4 MiB | 88.7 MiB | 2.81 MiB/s | 2.36 MiB/s | 2.616 | 2.082 | 134.3 MiB | 91.7 MiB | 2.31 MiB/s | 1.87 MiB/s | 0.100 | 0.083 | 183.3 MiB | 181.1 MiB | 0.03 MiB/s | 0.03 MiB/s | 46.5 | 35.0 | 135.0 | 192.0 |
| 500 | 440.0* | 0.497 | 0.432 | 90.1 MiB | 88.1 MiB | 4.09 MiB/s | 3.46 MiB/s | 3.247 | 2.758 | 114.7 MiB | 82.4 MiB | 2.91 MiB/s | 2.40 MiB/s | 0.108 | 0.097 | 186.2 MiB | 183.3 MiB | 0.04 MiB/s | 0.03 MiB/s | 48.1 | 36.0 | 129.0 | 173.0 |
| 1000 | 492.7* | 0.563 | 0.509 | 90.6 MiB | 88.9 MiB | 4.45 MiB/s | 4.12 MiB/s | 3.731 | 3.318 | 179.1 MiB | 108.2 MiB | 3.30 MiB/s | 2.96 MiB/s | 0.172 | 0.138 | 186.5 MiB | 184.4 MiB | 0.05 MiB/s | 0.04 MiB/s | 166.3 | 159.0 | 330.0 | 430.0 |

### `ols-single-100roles`

_Group_: OLS. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 92.6 | 0.547 | 0.269 | 89.4 MiB | 88.2 MiB | 4.28 MiB/s | 2.25 MiB/s | 3.425 | 1.706 | 77.6 MiB | 54.0 MiB | 3.04 MiB/s | 1.63 MiB/s | 0.180 | 0.112 | 187.3 MiB | 185.3 MiB | 0.05 MiB/s | 0.03 MiB/s | 14.4 | 12.0 | 22.0 | 72.0 |
| 200 | 182.8 | 0.200 | 0.136 | 89.6 MiB | 88.4 MiB | 2.39 MiB/s | 1.70 MiB/s | 1.527 | 0.988 | 111.7 MiB | 87.0 MiB | 1.71 MiB/s | 1.25 MiB/s | 0.061 | 0.045 | 190.5 MiB | 188.5 MiB | 0.02 MiB/s | 0.01 MiB/s | 26.9 | 27.0 | 44.0 | 77.0 |
| 300 | 265.9* | 0.362 | 0.260 | 90.3 MiB | 89.5 MiB | 3.48 MiB/s | 2.77 MiB/s | 2.750 | 2.100 | 113.6 MiB | 100.6 MiB | 2.77 MiB/s | 2.16 MiB/s | 0.084 | 0.064 | 192.5 MiB | 189.6 MiB | 0.02 MiB/s | 0.02 MiB/s | 38.0 | 29.0 | 81.0 | 204.0 |
| 400 | 347.9* | 0.508 | 0.426 | 91.1 MiB | 89.2 MiB | 4.90 MiB/s | 4.04 MiB/s | 3.443 | 2.816 | 140.0 MiB | 81.4 MiB | 3.70 MiB/s | 2.91 MiB/s | 0.175 | 0.132 | 189.7 MiB | 187.7 MiB | 0.05 MiB/s | 0.04 MiB/s | 41.6 | 27.0 | 127.0 | 219.0 |
| 500 | 374.7* | 0.619 | 0.543 | 90.7 MiB | 89.5 MiB | 5.31 MiB/s | 5.06 MiB/s | 4.114 | 3.444 | 147.4 MiB | 91.2 MiB | 4.01 MiB/s | 3.61 MiB/s | 0.182 | 0.160 | 195.3 MiB | 193.0 MiB | 0.04 MiB/s | 0.04 MiB/s | 85.7 | 67.0 | 215.0 | 327.0 |
| 1000 | 395.0* | 0.627 | 0.588 | 92.7 MiB | 90.7 MiB | 5.38 MiB/s | 5.01 MiB/s | 3.913 | 3.775 | 196.7 MiB | 145.8 MiB | 3.84 MiB/s | 3.70 MiB/s | 0.214 | 0.164 | 197.9 MiB | 193.9 MiB | 0.05 MiB/s | 0.04 MiB/s | 211.7 | 193.0 | 440.0 | 599.0 |

### `ols-bulk-50`

_Group_: OLS-bulk. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource/bulk`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 87.9* | 0.684 | 0.383 | 95.6 MiB | 92.7 MiB | 5.80 MiB/s | 3.23 MiB/s | 3.692 | 2.345 | 106.0 MiB | 65.7 MiB | 3.62 MiB/s | 1.90 MiB/s | 0.146 | 0.091 | 198.7 MiB | 197.6 MiB | 0.05 MiB/s | 0.03 MiB/s | 49.0 | 44.0 | 94.0 | 202.0 |
| 200 | 140.5* | 0.247 | 0.160 | 102.4 MiB | 99.0 MiB | 1.62 MiB/s | 1.21 MiB/s | 4.532 | 2.991 | 139.8 MiB | 91.0 MiB | 1.15 MiB/s | 0.82 MiB/s | 0.068 | 0.055 | 198.0 MiB | 197.2 MiB | 0.02 MiB/s | 0.01 MiB/s | 114.9 | 100.0 | 199.0 | 338.0 |
| 300 | 146.9* | 0.275 | 0.263 | 103.0 MiB | 102.0 MiB | 1.79 MiB/s | 1.73 MiB/s | 4.851 | 4.409 | 183.0 MiB | 115.4 MiB | 1.22 MiB/s | 1.12 MiB/s | 0.113 | 0.100 | 201.6 MiB | 197.5 MiB | 0.03 MiB/s | 0.02 MiB/s | 173.3 | 153.0 | 341.0 | 441.0 |
| 400 | 120.6* | 0.288 | 0.256 | 105.6 MiB | 103.8 MiB | 1.88 MiB/s | 1.65 MiB/s | 4.519 | 4.405 | 202.2 MiB | 124.1 MiB | 1.15 MiB/s | 1.10 MiB/s | 0.105 | 0.092 | 199.9 MiB | 197.4 MiB | 0.03 MiB/s | 0.02 MiB/s | 284.1 | 244.0 | 607.0 | 845.0 |
| 500 | 128.0* | 0.248 | 0.229 | 106.0 MiB | 104.6 MiB | 1.58 MiB/s | 1.44 MiB/s | 4.025 | 3.853 | 228.3 MiB | 132.2 MiB | 0.99 MiB/s | 0.94 MiB/s | 0.098 | 0.085 | 200.3 MiB | 198.7 MiB | 0.02 MiB/s | 0.02 MiB/s | 333.5 | 309.0 | 616.0 | 785.0 |
| 1000 | 129.2* | 0.255 | 0.227 | 106.5 MiB | 105.3 MiB | 1.58 MiB/s | 1.44 MiB/s | 4.608 | 4.422 | 323.6 MiB | 207.0 MiB | 1.13 MiB/s | 1.06 MiB/s | 0.099 | 0.091 | 204.5 MiB | 201.3 MiB | 0.02 MiB/s | 0.02 MiB/s | 669.2 | 577.0 | 1365.0 | 1698.0 |

### `ols-bulk-100`

_Group_: OLS-bulk. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource/bulk`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 80.7* | 0.246 | 0.190 | 108.1 MiB | 106.3 MiB | 1.66 MiB/s | 1.33 MiB/s | 4.482 | 3.454 | 131.5 MiB | 95.7 MiB | 1.13 MiB/s | 0.87 MiB/s | 0.106 | 0.089 | 211.1 MiB | 206.5 MiB | 0.02 MiB/s | 0.02 MiB/s | 97.4 | 95.0 | 141.0 | 194.0 |
| 200 | 81.3* | 0.251 | 0.233 | 109.5 MiB | 108.3 MiB | 1.77 MiB/s | 1.72 MiB/s | 5.116 | 4.528 | 192.9 MiB | 115.9 MiB | 1.17 MiB/s | 1.10 MiB/s | 0.120 | 0.106 | 211.1 MiB | 205.7 MiB | 0.02 MiB/s | 0.02 MiB/s | 208.8 | 196.0 | 332.0 | 429.0 |
| 300 | 77.3* | 0.253 | 0.238 | 110.3 MiB | 109.1 MiB | 1.79 MiB/s | 1.68 MiB/s | 4.932 | 4.716 | 230.4 MiB | 140.7 MiB | 1.12 MiB/s | 1.08 MiB/s | 0.103 | 0.085 | 211.6 MiB | 201.6 MiB | 0.02 MiB/s | 0.02 MiB/s | 328.7 | 306.0 | 569.0 | 692.0 |
| 400 | 81.2* | 0.244 | 0.236 | 112.1 MiB | 109.8 MiB | 1.73 MiB/s | 1.67 MiB/s | 5.072 | 4.747 | 264.8 MiB | 163.9 MiB | 1.15 MiB/s | 1.08 MiB/s | 0.105 | 0.092 | 207.8 MiB | 203.2 MiB | 0.02 MiB/s | 0.02 MiB/s | 421.6 | 388.0 | 751.0 | 933.0 |
| 500 | 80.7* | 0.254 | 0.239 | 111.3 MiB | 109.8 MiB | 1.77 MiB/s | 1.65 MiB/s | 4.759 | 4.377 | 320.3 MiB | 226.5 MiB | 1.07 MiB/s | 0.98 MiB/s | 0.100 | 0.093 | 205.5 MiB | 203.5 MiB | 0.02 MiB/s | 0.02 MiB/s | 529.3 | 486.0 | 992.0 | 1231.0 |
| 1000 | 83.9* | 0.266 | 0.244 | 111.3 MiB | 110.2 MiB | 1.91 MiB/s | 1.72 MiB/s | 4.722 | 4.344 | 425.4 MiB | 220.6 MiB | 1.08 MiB/s | 0.99 MiB/s | 0.119 | 0.104 | 210.0 MiB | 209.1 MiB | 0.02 MiB/s | 0.02 MiB/s | 1033.9 | 987.0 | 1852.0 | 2244.0 |

### `ols-bulk-1000`

_Group_: OLS-bulk. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource/bulk`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 9.0* | 0.247 | 0.176 | 119.2 MiB | 114.8 MiB | 1.74 MiB/s | 1.36 MiB/s | 5.657 | 4.205 | 523.9 MiB | 315.0 MiB | 1.16 MiB/s | 0.91 MiB/s | 0.084 | 0.071 | 202.4 MiB | 200.9 MiB | 0.03 MiB/s | 0.02 MiB/s | 935.5 | 915.0 | 1256.0 | 1387.0 |
| 200 | 8.8* | 0.202 | 0.186 | 128.1 MiB | 123.1 MiB | 1.70 MiB/s | 1.60 MiB/s | 5.530 | 5.020 | 945.7 MiB | 510.6 MiB | 1.05 MiB/s | 0.99 MiB/s | 0.104 | 0.092 | 203.8 MiB | 201.0 MiB | 0.05 MiB/s | 0.05 MiB/s | 1877.5 | 1819.0 | 2423.0 | 2578.0 |
| 300 | 8.6* | 0.215 | 0.183 | 130.1 MiB | 128.5 MiB | 1.81 MiB/s | 1.55 MiB/s | 5.949 | 5.264 | 1535.1 MiB | 758.5 MiB | 1.15 MiB/s | 1.02 MiB/s | 0.120 | 0.112 | 205.0 MiB | 202.8 MiB | 0.05 MiB/s | 0.05 MiB/s | 2950.9 | 2941.0 | 4342.0 | 4798.0 |
| 400 | 8.2* | 0.188 | 0.180 | 132.5 MiB | 131.3 MiB | 1.59 MiB/s | 1.53 MiB/s | 5.626 | 5.237 | 1816.3 MiB | 967.1 MiB | 1.06 MiB/s | 0.97 MiB/s | 0.084 | 0.069 | 206.3 MiB | 204.6 MiB | 0.05 MiB/s | 0.04 MiB/s | 4092.4 | 3979.0 | 5965.0 | 6554.0 |
| 500 | 8.6* | 0.195 | 0.167 | 131.5 MiB | 130.9 MiB | 1.68 MiB/s | 1.39 MiB/s | 5.904 | 4.933 | 2240.9 MiB | 1322.0 MiB | 1.10 MiB/s | 0.95 MiB/s | 0.096 | 0.088 | 204.3 MiB | 202.5 MiB | 0.06 MiB/s | 0.05 MiB/s | 4905.7 | 4775.0 | 8236.0 | 9514.0 |
| 1000 | 8.2* | 0.217 | 0.188 | 132.3 MiB | 130.8 MiB | 1.91 MiB/s | 1.61 MiB/s | 5.512 | 5.465 | 4399.8 MiB | 2059.1 MiB | 1.14 MiB/s | 0.96 MiB/s | 0.070 | 0.061 | 203.7 MiB | 202.3 MiB | 0.05 MiB/s | 0.05 MiB/s | 9958.4 | 11081.0 | 14751.0 | 15079.0 |

### `rls-condition-1-expression`

_Group_: RLS-condition. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 93.8 | 0.125 | 0.087 | 133.1 MiB | 132.1 MiB | 0.99 MiB/s | 0.66 MiB/s | 4.331 | 2.268 | 73.6 MiB | 54.5 MiB | 0.73 MiB/s | 0.53 MiB/s | 0.059 | 0.039 | 197.2 MiB | 196.2 MiB | 0.05 MiB/s | 0.03 MiB/s | 5.5 | 5.0 | 9.0 | 20.0 |
| 200 | 186.0 | 0.114 | 0.085 | 133.9 MiB | 132.8 MiB | 0.80 MiB/s | 0.59 MiB/s | 0.664 | 0.441 | 82.7 MiB | 68.0 MiB | 0.59 MiB/s | 0.42 MiB/s | 0.029 | 0.025 | 199.5 MiB | 197.4 MiB | 0.01 MiB/s | 0.01 MiB/s | 7.6 | 5.0 | 13.0 | 71.0 |
| 300 | 273.0 | 0.178 | 0.138 | 134.0 MiB | 132.5 MiB | 1.22 MiB/s | 0.96 MiB/s | 1.203 | 0.818 | 114.4 MiB | 76.8 MiB | 0.87 MiB/s | 0.66 MiB/s | 0.038 | 0.032 | 197.8 MiB | 197.2 MiB | 0.02 MiB/s | 0.01 MiB/s | 11.4 | 8.0 | 27.0 | 82.0 |
| 400 | 363.0 | 0.245 | 0.201 | 134.6 MiB | 132.9 MiB | 1.53 MiB/s | 1.32 MiB/s | 1.869 | 1.404 | 138.7 MiB | 88.4 MiB | 1.17 MiB/s | 0.95 MiB/s | 0.041 | 0.038 | 200.1 MiB | 197.7 MiB | 0.02 MiB/s | 0.02 MiB/s | 23.2 | 19.0 | 51.0 | 124.0 |
| 500 | 449.1* | 0.312 | 0.274 | 135.1 MiB | 133.3 MiB | 1.89 MiB/s | 1.70 MiB/s | 2.213 | 1.903 | 134.5 MiB | 80.1 MiB | 1.37 MiB/s | 1.18 MiB/s | 0.064 | 0.050 | 201.2 MiB | 200.6 MiB | 0.04 MiB/s | 0.03 MiB/s | 27.5 | 17.0 | 88.0 | 191.0 |
| 1000 | 673.1* | 0.456 | 0.372 | 135.2 MiB | 133.4 MiB | 2.54 MiB/s | 2.16 MiB/s | 3.553 | 2.675 | 212.6 MiB | 151.7 MiB | 1.96 MiB/s | 1.57 MiB/s | 0.097 | 0.077 | 198.8 MiB | 197.5 MiB | 0.04 MiB/s | 0.03 MiB/s | 108.0 | 96.0 | 237.0 | 315.0 |

### `rls-condition-2-expression`

_Group_: RLS-condition. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 93.4 | 0.405 | 0.209 | 133.6 MiB | 132.9 MiB | 2.22 MiB/s | 1.19 MiB/s | 3.980 | 2.028 | 120.8 MiB | 77.3 MiB | 2.17 MiB/s | 1.15 MiB/s | 0.128 | 0.079 | 202.2 MiB | 200.0 MiB | 0.05 MiB/s | 0.03 MiB/s | 6.3 | 5.0 | 10.0 | 24.0 |
| 200 | 186.2 | 0.106 | 0.086 | 134.5 MiB | 133.3 MiB | 0.73 MiB/s | 0.60 MiB/s | 0.654 | 0.483 | 86.1 MiB | 70.7 MiB | 0.54 MiB/s | 0.42 MiB/s | 0.024 | 0.021 | 202.1 MiB | 200.5 MiB | 0.01 MiB/s | 0.01 MiB/s | 8.2 | 6.0 | 17.0 | 46.0 |
| 300 | 278.0 | 0.185 | 0.148 | 134.0 MiB | 132.4 MiB | 1.28 MiB/s | 1.04 MiB/s | 1.433 | 0.969 | 129.3 MiB | 85.7 MiB | 0.94 MiB/s | 0.73 MiB/s | 0.050 | 0.043 | 199.6 MiB | 199.3 MiB | 0.02 MiB/s | 0.02 MiB/s | 17.6 | 13.0 | 49.0 | 76.0 |
| 400 | 361.9 | 0.258 | 0.210 | 134.2 MiB | 132.4 MiB | 1.63 MiB/s | 1.37 MiB/s | 2.043 | 1.613 | 127.4 MiB | 84.1 MiB | 1.20 MiB/s | 0.98 MiB/s | 0.041 | 0.041 | 201.4 MiB | 199.8 MiB | 0.02 MiB/s | 0.02 MiB/s | 25.5 | 19.0 | 66.0 | 123.0 |
| 500 | 456.9 | 0.313 | 0.277 | 134.4 MiB | 133.0 MiB | 2.09 MiB/s | 1.82 MiB/s | 2.411 | 2.015 | 142.4 MiB | 82.7 MiB | 1.45 MiB/s | 1.21 MiB/s | 0.076 | 0.057 | 200.3 MiB | 199.6 MiB | 0.05 MiB/s | 0.03 MiB/s | 23.5 | 19.0 | 63.0 | 98.0 |
| 1000 | 726.9* | 0.538 | 0.402 | 135.1 MiB | 132.9 MiB | 3.28 MiB/s | 2.55 MiB/s | 4.184 | 3.069 | 212.0 MiB | 125.9 MiB | 2.32 MiB/s | 1.77 MiB/s | 0.091 | 0.070 | 201.8 MiB | 200.5 MiB | 0.04 MiB/s | 0.03 MiB/s | 91.0 | 76.0 | 219.0 | 281.0 |

### `rls-condition-3-expression`

_Group_: RLS-condition. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 93.5 | 0.547 | 0.251 | 134.3 MiB | 132.8 MiB | 3.30 MiB/s | 1.55 MiB/s | 3.911 | 1.884 | 75.7 MiB | 53.1 MiB | 2.19 MiB/s | 1.12 MiB/s | 0.108 | 0.060 | 204.5 MiB | 204.1 MiB | 0.06 MiB/s | 0.04 MiB/s | 6.2 | 5.0 | 10.0 | 19.0 |
| 200 | 186.8 | 0.115 | 0.084 | 133.9 MiB | 132.4 MiB | 0.89 MiB/s | 0.64 MiB/s | 0.842 | 0.528 | 93.3 MiB | 60.4 MiB | 0.66 MiB/s | 0.45 MiB/s | 0.031 | 0.023 | 202.6 MiB | 201.2 MiB | 0.02 MiB/s | 0.01 MiB/s | 9.0 | 7.0 | 18.0 | 81.0 |
| 300 | 272.9 | 0.180 | 0.141 | 134.7 MiB | 132.3 MiB | 1.30 MiB/s | 1.05 MiB/s | 1.389 | 1.025 | 108.6 MiB | 68.5 MiB | 0.92 MiB/s | 0.74 MiB/s | 0.034 | 0.030 | 201.8 MiB | 201.5 MiB | 0.02 MiB/s | 0.01 MiB/s | 13.5 | 10.0 | 38.0 | 88.0 |
| 400 | 369.9 | 0.246 | 0.207 | 134.2 MiB | 133.0 MiB | 1.74 MiB/s | 1.50 MiB/s | 1.983 | 1.551 | 112.6 MiB | 83.0 MiB | 1.23 MiB/s | 0.99 MiB/s | 0.060 | 0.042 | 204.2 MiB | 202.5 MiB | 0.03 MiB/s | 0.02 MiB/s | 19.6 | 14.0 | 56.0 | 108.0 |
| 500 | 460.2 | 0.317 | 0.279 | 134.6 MiB | 132.3 MiB | 2.12 MiB/s | 1.91 MiB/s | 2.616 | 2.229 | 147.5 MiB | 86.9 MiB | 1.56 MiB/s | 1.35 MiB/s | 0.064 | 0.058 | 205.5 MiB | 203.2 MiB | 0.03 MiB/s | 0.03 MiB/s | 26.2 | 16.0 | 85.0 | 143.0 |
| 1000 | 499.0* | 0.408 | 0.352 | 135.1 MiB | 133.2 MiB | 2.30 MiB/s | 2.16 MiB/s | 3.558 | 2.868 | 195.9 MiB | 118.7 MiB | 1.71 MiB/s | 1.54 MiB/s | 0.099 | 0.070 | 205.1 MiB | 204.8 MiB | 0.04 MiB/s | 0.03 MiB/s | 155.3 | 146.0 | 334.0 | 434.0 |

### `rls-condition-5-expression`

_Group_: RLS-condition. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 91.4 | 0.422 | 0.205 | 132.9 MiB | 132.2 MiB | 2.33 MiB/s | 1.17 MiB/s | 3.242 | 1.606 | 76.5 MiB | 55.3 MiB | 1.55 MiB/s | 0.82 MiB/s | 0.099 | 0.069 | 205.7 MiB | 205.0 MiB | 0.04 MiB/s | 0.03 MiB/s | 8.0 | 7.0 | 13.0 | 19.0 |
| 200 | 185.9 | 0.122 | 0.088 | 133.4 MiB | 132.3 MiB | 0.91 MiB/s | 0.63 MiB/s | 0.926 | 0.600 | 81.2 MiB | 57.2 MiB | 0.64 MiB/s | 0.43 MiB/s | 0.028 | 0.023 | 204.3 MiB | 203.7 MiB | 0.01 MiB/s | 0.01 MiB/s | 9.4 | 8.0 | 17.0 | 48.0 |
| 300 | 276.8 | 0.183 | 0.147 | 134.2 MiB | 132.8 MiB | 1.25 MiB/s | 1.07 MiB/s | 1.550 | 1.127 | 110.3 MiB | 80.5 MiB | 0.93 MiB/s | 0.75 MiB/s | 0.052 | 0.038 | 207.2 MiB | 206.4 MiB | 0.02 MiB/s | 0.01 MiB/s | 18.4 | 12.0 | 57.0 | 123.0 |
| 400 | 368.9 | 0.287 | 0.226 | 134.2 MiB | 132.8 MiB | 1.87 MiB/s | 1.51 MiB/s | 2.116 | 1.834 | 104.1 MiB | 85.0 MiB | 1.20 MiB/s | 1.04 MiB/s | 0.066 | 0.057 | 208.3 MiB | 206.3 MiB | 0.02 MiB/s | 0.02 MiB/s | 18.8 | 11.0 | 60.0 | 109.0 |
| 500 | 439.4* | 0.335 | 0.303 | 135.1 MiB | 133.3 MiB | 2.09 MiB/s | 1.89 MiB/s | 3.068 | 2.465 | 127.7 MiB | 81.7 MiB | 1.52 MiB/s | 1.28 MiB/s | 0.102 | 0.078 | 206.7 MiB | 206.0 MiB | 0.04 MiB/s | 0.03 MiB/s | 43.4 | 29.0 | 122.0 | 214.0 |
| 1000 | 528.6* | 0.441 | 0.382 | 134.4 MiB | 132.5 MiB | 2.57 MiB/s | 2.29 MiB/s | 4.517 | 3.507 | 206.3 MiB | 129.7 MiB | 1.99 MiB/s | 1.63 MiB/s | 0.099 | 0.089 | 208.9 MiB | 206.9 MiB | 0.04 MiB/s | 0.03 MiB/s | 151.3 | 141.0 | 325.0 | 417.0 |

### `rls-predicate`

_Group_: RLS-predicate. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 93.3 | 0.464 | 0.204 | 137.0 MiB | 134.5 MiB | 2.67 MiB/s | 1.18 MiB/s | 3.961 | 1.747 | 73.3 MiB | 53.9 MiB | 1.75 MiB/s | 0.85 MiB/s | 0.118 | 0.062 | 209.2 MiB | 207.9 MiB | 0.04 MiB/s | 0.02 MiB/s | 4.8 | 4.0 | 7.0 | 12.0 |
| 200 | 184.9 | 0.121 | 0.087 | 141.1 MiB | 139.2 MiB | 0.82 MiB/s | 0.57 MiB/s | 0.568 | 0.363 | 83.3 MiB | 56.3 MiB | 0.54 MiB/s | 0.38 MiB/s | 0.032 | 0.023 | 209.4 MiB | 208.7 MiB | 0.01 MiB/s | 0.01 MiB/s | 7.0 | 5.0 | 13.0 | 55.0 |
| 300 | 270.9 | 0.196 | 0.147 | 144.3 MiB | 142.2 MiB | 1.17 MiB/s | 0.95 MiB/s | 1.093 | 0.733 | 105.0 MiB | 68.2 MiB | 0.79 MiB/s | 0.62 MiB/s | 0.035 | 0.033 | 210.0 MiB | 208.9 MiB | 0.02 MiB/s | 0.01 MiB/s | 14.0 | 9.0 | 39.0 | 101.0 |
| 400 | 365.5 | 0.259 | 0.215 | 145.4 MiB | 143.7 MiB | 1.46 MiB/s | 1.24 MiB/s | 1.609 | 1.299 | 113.4 MiB | 87.6 MiB | 1.04 MiB/s | 0.89 MiB/s | 0.048 | 0.043 | 211.1 MiB | 209.2 MiB | 0.02 MiB/s | 0.02 MiB/s | 20.7 | 14.0 | 57.0 | 153.0 |
| 500 | 460.1 | 0.316 | 0.284 | 147.1 MiB | 145.9 MiB | 1.82 MiB/s | 1.65 MiB/s | 1.849 | 1.692 | 128.0 MiB | 95.8 MiB | 1.21 MiB/s | 1.10 MiB/s | 0.058 | 0.051 | 209.7 MiB | 209.0 MiB | 0.03 MiB/s | 0.03 MiB/s | 24.0 | 16.0 | 71.0 | 121.0 |
| 1000 | 714.2* | 0.580 | 0.385 | 148.0 MiB | 146.2 MiB | 3.10 MiB/s | 2.14 MiB/s | 3.930 | 2.711 | 177.7 MiB | 119.1 MiB | 2.26 MiB/s | 1.65 MiB/s | 0.107 | 0.079 | 212.4 MiB | 211.7 MiB | 0.04 MiB/s | 0.03 MiB/s | 93.8 | 79.0 | 230.0 | 342.0 |

### `rls-predicate-summary-2-predicates`

_Group_: RLS-predicate. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 93.4 | 0.588 | 0.255 | 147.1 MiB | 145.4 MiB | 3.12 MiB/s | 1.41 MiB/s | 3.505 | 1.571 | 74.2 MiB | 52.9 MiB | 2.01 MiB/s | 0.98 MiB/s | 0.122 | 0.074 | 212.3 MiB | 210.8 MiB | 0.05 MiB/s | 0.03 MiB/s | 5.7 | 5.0 | 10.0 | 23.0 |
| 200 | 185.9 | 0.132 | 0.095 | 147.4 MiB | 146.1 MiB | 0.98 MiB/s | 0.69 MiB/s | 0.729 | 0.457 | 83.8 MiB | 59.9 MiB | 0.69 MiB/s | 0.48 MiB/s | 0.027 | 0.022 | 212.5 MiB | 211.0 MiB | 0.01 MiB/s | 0.01 MiB/s | 8.5 | 6.0 | 17.0 | 65.0 |
| 300 | 276.2 | 0.205 | 0.157 | 146.5 MiB | 145.2 MiB | 1.40 MiB/s | 1.12 MiB/s | 1.291 | 0.883 | 121.6 MiB | 74.3 MiB | 1.01 MiB/s | 0.78 MiB/s | 0.043 | 0.035 | 212.1 MiB | 211.7 MiB | 0.02 MiB/s | 0.02 MiB/s | 16.5 | 12.0 | 43.0 | 96.0 |
| 400 | 364.5 | 0.278 | 0.238 | 148.1 MiB | 146.5 MiB | 1.76 MiB/s | 1.57 MiB/s | 1.852 | 1.478 | 115.8 MiB | 72.6 MiB | 1.29 MiB/s | 1.09 MiB/s | 0.060 | 0.044 | 211.8 MiB | 211.2 MiB | 0.03 MiB/s | 0.02 MiB/s | 20.4 | 15.0 | 61.0 | 111.0 |
| 500 | 448.9* | 0.355 | 0.312 | 147.4 MiB | 146.2 MiB | 2.24 MiB/s | 1.95 MiB/s | 2.209 | 1.936 | 143.2 MiB | 104.1 MiB | 1.54 MiB/s | 1.34 MiB/s | 0.075 | 0.070 | 213.1 MiB | 212.5 MiB | 0.03 MiB/s | 0.03 MiB/s | 25.3 | 18.0 | 78.0 | 140.0 |
| 1000 | 646.8* | 0.527 | 0.415 | 148.1 MiB | 146.5 MiB | 2.95 MiB/s | 2.50 MiB/s | 3.282 | 2.662 | 211.8 MiB | 152.1 MiB | 2.06 MiB/s | 1.78 MiB/s | 0.128 | 0.076 | 215.8 MiB | 213.7 MiB | 0.05 MiB/s | 0.03 MiB/s | 114.1 | 102.0 | 262.0 | 335.0 |

### `rls-predicate-summary-3-predicates`

_Group_: RLS-predicate. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 93.4 | 0.498 | 0.242 | 145.8 MiB | 145.4 MiB | 2.75 MiB/s | 1.37 MiB/s | 3.213 | 1.614 | 71.8 MiB | 57.8 MiB | 1.99 MiB/s | 1.07 MiB/s | 0.128 | 0.083 | 214.7 MiB | 214.1 MiB | 0.05 MiB/s | 0.03 MiB/s | 5.3 | 5.0 | 9.0 | 14.0 |
| 200 | 186.5 | 0.137 | 0.096 | 146.8 MiB | 145.9 MiB | 1.00 MiB/s | 0.70 MiB/s | 0.764 | 0.470 | 89.4 MiB | 67.4 MiB | 0.73 MiB/s | 0.49 MiB/s | 0.029 | 0.024 | 215.1 MiB | 213.6 MiB | 0.01 MiB/s | 0.01 MiB/s | 7.9 | 6.0 | 15.0 | 29.0 |
| 300 | 277.9 | 0.200 | 0.161 | 147.4 MiB | 145.7 MiB | 1.48 MiB/s | 1.20 MiB/s | 1.128 | 0.863 | 86.4 MiB | 59.0 MiB | 1.06 MiB/s | 0.82 MiB/s | 0.048 | 0.033 | 214.1 MiB | 212.6 MiB | 0.02 MiB/s | 0.01 MiB/s | 8.3 | 6.0 | 20.0 | 43.0 |
| 400 | 362.6 | 0.270 | 0.232 | 147.7 MiB | 146.0 MiB | 1.91 MiB/s | 1.64 MiB/s | 1.477 | 1.255 | 89.4 MiB | 60.6 MiB | 1.36 MiB/s | 1.14 MiB/s | 0.066 | 0.057 | 218.7 MiB | 214.7 MiB | 0.03 MiB/s | 0.02 MiB/s | 11.4 | 6.0 | 41.0 | 104.0 |
| 500 | 456.9 | 0.369 | 0.298 | 148.0 MiB | 146.4 MiB | 2.40 MiB/s | 2.06 MiB/s | 2.082 | 1.636 | 110.7 MiB | 68.4 MiB | 1.66 MiB/s | 1.43 MiB/s | 0.084 | 0.064 | 218.2 MiB | 215.7 MiB | 0.03 MiB/s | 0.03 MiB/s | 17.7 | 9.0 | 66.0 | 129.0 |
| 1000 | 686.9* | 0.607 | 0.469 | 148.3 MiB | 146.9 MiB | 3.31 MiB/s | 2.80 MiB/s | 3.485 | 2.436 | 228.8 MiB | 136.2 MiB | 2.26 MiB/s | 1.76 MiB/s | 0.125 | 0.093 | 217.5 MiB | 217.5 MiB | 0.04 MiB/s | 0.03 MiB/s | 99.0 | 80.0 | 249.0 | 387.0 |

### `rls-predicate-summary-4-predicates`

_Group_: RLS-predicate. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 93.1 | 0.660 | 0.335 | 147.1 MiB | 146.0 MiB | 3.56 MiB/s | 1.84 MiB/s | 3.812 | 2.021 | 190.0 MiB | 89.4 MiB | 2.48 MiB/s | 1.37 MiB/s | 0.135 | 0.098 | 219.3 MiB | 217.8 MiB | 0.05 MiB/s | 0.04 MiB/s | 6.9 | 6.0 | 13.0 | 21.0 |
| 200 | 186.6 | 0.127 | 0.092 | 148.7 MiB | 146.9 MiB | 0.91 MiB/s | 0.62 MiB/s | 0.672 | 0.443 | 82.4 MiB | 69.4 MiB | 0.64 MiB/s | 0.44 MiB/s | 0.028 | 0.025 | 219.6 MiB | 219.4 MiB | 0.01 MiB/s | 0.01 MiB/s | 8.2 | 7.0 | 16.0 | 32.0 |
| 300 | 280.6 | 0.214 | 0.160 | 147.7 MiB | 146.4 MiB | 1.58 MiB/s | 1.17 MiB/s | 1.155 | 0.852 | 87.8 MiB | 69.9 MiB | 1.11 MiB/s | 0.80 MiB/s | 0.052 | 0.039 | 220.4 MiB | 219.0 MiB | 0.02 MiB/s | 0.02 MiB/s | 7.9 | 6.0 | 16.0 | 44.0 |
| 400 | 371.2 | 0.263 | 0.224 | 148.2 MiB | 146.6 MiB | 2.04 MiB/s | 1.71 MiB/s | 1.471 | 1.205 | 91.7 MiB | 72.9 MiB | 1.45 MiB/s | 1.18 MiB/s | 0.053 | 0.049 | 217.5 MiB | 217.1 MiB | 0.03 MiB/s | 0.02 MiB/s | 8.6 | 6.0 | 21.0 | 55.0 |
| 500 | 459.7 | 0.355 | 0.297 | 147.8 MiB | 146.5 MiB | 2.53 MiB/s | 2.23 MiB/s | 2.114 | 1.637 | 93.6 MiB | 61.5 MiB | 1.85 MiB/s | 1.54 MiB/s | 0.089 | 0.058 | 220.5 MiB | 218.7 MiB | 0.04 MiB/s | 0.03 MiB/s | 14.6 | 8.0 | 47.0 | 125.0 |
| 1000 | 731.3* | 0.690 | 0.479 | 149.0 MiB | 146.5 MiB | 4.06 MiB/s | 3.07 MiB/s | 4.251 | 2.771 | 233.9 MiB | 142.2 MiB | 2.95 MiB/s | 2.12 MiB/s | 0.129 | 0.100 | 222.8 MiB | 219.6 MiB | 0.04 MiB/s | 0.04 MiB/s | 81.0 | 59.0 | 225.0 | 355.0 |

### `rls-predicate-summary-5-predicates`

_Group_: RLS-predicate. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 92.9 | 0.706 | 0.315 | 147.4 MiB | 146.1 MiB | 4.12 MiB/s | 1.89 MiB/s | 3.772 | 1.805 | 78.8 MiB | 55.2 MiB | 2.62 MiB/s | 1.32 MiB/s | 0.151 | 0.091 | 221.0 MiB | 220.1 MiB | 0.06 MiB/s | 0.04 MiB/s | 6.5 | 5.0 | 11.0 | 22.0 |
| 200 | 186.5 | 0.134 | 0.098 | 147.7 MiB | 146.3 MiB | 1.08 MiB/s | 0.78 MiB/s | 0.793 | 0.502 | 85.8 MiB | 58.7 MiB | 0.79 MiB/s | 0.53 MiB/s | 0.032 | 0.025 | 221.6 MiB | 220.4 MiB | 0.01 MiB/s | 0.01 MiB/s | 7.4 | 6.0 | 13.0 | 20.0 |
| 300 | 278.2 | 0.205 | 0.161 | 147.2 MiB | 145.9 MiB | 1.62 MiB/s | 1.30 MiB/s | 1.111 | 0.861 | 83.8 MiB | 57.1 MiB | 1.09 MiB/s | 0.86 MiB/s | 0.034 | 0.032 | 221.5 MiB | 220.7 MiB | 0.02 MiB/s | 0.01 MiB/s | 8.3 | 6.0 | 19.0 | 37.0 |
| 400 | 368.5 | 0.279 | 0.238 | 148.1 MiB | 146.1 MiB | 2.10 MiB/s | 1.80 MiB/s | 1.629 | 1.292 | 99.7 MiB | 65.4 MiB | 1.46 MiB/s | 1.19 MiB/s | 0.077 | 0.052 | 222.6 MiB | 221.6 MiB | 0.04 MiB/s | 0.03 MiB/s | 10.4 | 8.0 | 28.0 | 58.0 |
| 500 | 459.8 | 0.395 | 0.325 | 148.4 MiB | 146.5 MiB | 2.61 MiB/s | 2.30 MiB/s | 2.304 | 1.877 | 114.4 MiB | 67.9 MiB | 1.79 MiB/s | 1.56 MiB/s | 0.073 | 0.064 | 223.7 MiB | 222.4 MiB | 0.03 MiB/s | 0.03 MiB/s | 17.3 | 11.0 | 53.0 | 100.0 |
| 1000 | 588.3* | 0.580 | 0.453 | 150.4 MiB | 147.6 MiB | 3.29 MiB/s | 2.83 MiB/s | 3.399 | 2.551 | 208.4 MiB | 131.5 MiB | 2.22 MiB/s | 1.86 MiB/s | 0.102 | 0.074 | 225.3 MiB | 223.4 MiB | 0.04 MiB/s | 0.03 MiB/s | 129.0 | 110.0 | 304.0 | 426.0 |

### `rls-predicate-summary-10-predicates`

_Group_: RLS-predicate. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 92.9 | 0.620 | 0.312 | 146.7 MiB | 145.9 MiB | 3.49 MiB/s | 1.79 MiB/s | 3.508 | 1.815 | 152.5 MiB | 82.8 MiB | 2.31 MiB/s | 1.25 MiB/s | 0.100 | 0.067 | 225.1 MiB | 224.5 MiB | 0.05 MiB/s | 0.03 MiB/s | 7.7 | 6.0 | 14.0 | 27.0 |
| 200 | 179.9* | 0.200 | 0.130 | 146.6 MiB | 145.5 MiB | 1.25 MiB/s | 0.86 MiB/s | 1.110 | 0.616 | 110.4 MiB | 67.3 MiB | 0.80 MiB/s | 0.53 MiB/s | 0.042 | 0.029 | 224.6 MiB | 223.7 MiB | 0.01 MiB/s | 0.01 MiB/s | 18.4 | 14.0 | 36.0 | 89.0 |
| 300 | 265.2* | 0.294 | 0.232 | 147.4 MiB | 145.9 MiB | 1.81 MiB/s | 1.44 MiB/s | 1.983 | 1.440 | 137.5 MiB | 80.3 MiB | 1.29 MiB/s | 0.97 MiB/s | 0.065 | 0.047 | 227.7 MiB | 226.3 MiB | 0.02 MiB/s | 0.01 MiB/s | 29.7 | 26.0 | 62.0 | 128.0 |
| 400 | 354.1* | 0.379 | 0.320 | 148.5 MiB | 146.5 MiB | 2.17 MiB/s | 1.92 MiB/s | 2.440 | 2.115 | 110.9 MiB | 85.5 MiB | 1.56 MiB/s | 1.36 MiB/s | 0.079 | 0.071 | 229.2 MiB | 225.7 MiB | 0.02 MiB/s | 0.02 MiB/s | 33.3 | 21.0 | 97.0 | 189.0 |
| 500 | 419.2* | 0.496 | 0.427 | 148.4 MiB | 146.9 MiB | 2.89 MiB/s | 2.46 MiB/s | 3.140 | 2.578 | 186.0 MiB | 96.3 MiB | 1.98 MiB/s | 1.64 MiB/s | 0.098 | 0.088 | 227.2 MiB | 226.4 MiB | 0.03 MiB/s | 0.02 MiB/s | 48.6 | 32.0 | 154.0 | 254.0 |
| 1000 | 456.4* | 0.530 | 0.499 | 149.2 MiB | 147.1 MiB | 2.92 MiB/s | 2.85 MiB/s | 3.394 | 2.990 | 243.5 MiB | 142.5 MiB | 2.00 MiB/s | 1.85 MiB/s | 0.112 | 0.105 | 231.3 MiB | 228.4 MiB | 0.04 MiB/s | 0.04 MiB/s | 180.2 | 161.0 | 391.0 | 516.0 |

### `rls-predicate-pips-1-token-pip`

_Group_: RLS-predicate-pips. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 92.9 | 0.608 | 0.271 | 146.7 MiB | 146.1 MiB | 3.31 MiB/s | 1.48 MiB/s | 3.754 | 1.863 | 213.1 MiB | 97.9 MiB | 2.22 MiB/s | 1.15 MiB/s | 0.123 | 0.053 | 227.2 MiB | 227.0 MiB | 0.05 MiB/s | 0.02 MiB/s | 5.2 | 5.0 | 8.0 | 13.0 |
| 200 | 184.0 | 0.136 | 0.095 | 147.2 MiB | 146.3 MiB | 0.89 MiB/s | 0.61 MiB/s | 0.664 | 0.402 | 79.9 MiB | 61.4 MiB | 0.63 MiB/s | 0.43 MiB/s | 0.029 | 0.025 | 229.9 MiB | 228.5 MiB | 0.01 MiB/s | 0.01 MiB/s | 7.9 | 5.0 | 15.0 | 81.0 |
| 300 | 266.2* | 0.201 | 0.155 | 147.8 MiB | 146.4 MiB | 1.17 MiB/s | 0.96 MiB/s | 1.174 | 0.800 | 112.2 MiB | 68.7 MiB | 0.85 MiB/s | 0.67 MiB/s | 0.044 | 0.034 | 228.5 MiB | 227.5 MiB | 0.02 MiB/s | 0.01 MiB/s | 20.8 | 12.0 | 57.0 | 117.0 |
| 400 | 363.3 | 0.258 | 0.233 | 148.3 MiB | 146.7 MiB | 1.55 MiB/s | 1.36 MiB/s | 1.610 | 1.338 | 122.7 MiB | 91.4 MiB | 1.12 MiB/s | 0.94 MiB/s | 0.058 | 0.050 | 227.2 MiB | 227.2 MiB | 0.02 MiB/s | 0.02 MiB/s | 21.2 | 16.0 | 58.0 | 164.0 |
| 500 | 434.9* | 0.321 | 0.291 | 147.9 MiB | 147.0 MiB | 1.73 MiB/s | 1.65 MiB/s | 2.458 | 1.766 | 139.3 MiB | 89.3 MiB | 1.50 MiB/s | 1.17 MiB/s | 0.075 | 0.059 | 230.7 MiB | 228.6 MiB | 0.03 MiB/s | 0.03 MiB/s | 41.8 | 29.0 | 126.0 | 196.0 |
| 1000 | 507.8* | 0.442 | 0.394 | 148.0 MiB | 146.3 MiB | 2.27 MiB/s | 2.02 MiB/s | 2.594 | 2.324 | 206.8 MiB | 120.2 MiB | 1.51 MiB/s | 1.39 MiB/s | 0.108 | 0.085 | 229.3 MiB | 228.0 MiB | 0.04 MiB/s | 0.03 MiB/s | 153.4 | 137.0 | 355.0 | 457.0 |

### `rls-predicate-pips-2-token-pip`

_Group_: RLS-predicate-pips. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 91.3 | 0.404 | 0.187 | 147.1 MiB | 146.2 MiB | 2.03 MiB/s | 0.94 MiB/s | 2.721 | 1.126 | 123.6 MiB | 74.9 MiB | 1.59 MiB/s | 0.71 MiB/s | 0.097 | 0.059 | 229.6 MiB | 228.8 MiB | 0.03 MiB/s | 0.02 MiB/s | 6.4 | 5.0 | 12.0 | 18.0 |
| 200 | 181.4 | 0.150 | 0.104 | 147.7 MiB | 146.2 MiB | 0.87 MiB/s | 0.61 MiB/s | 0.861 | 0.482 | 100.4 MiB | 64.8 MiB | 0.64 MiB/s | 0.43 MiB/s | 0.028 | 0.026 | 231.2 MiB | 229.6 MiB | 0.01 MiB/s | 0.01 MiB/s | 14.8 | 9.0 | 40.0 | 103.0 |
| 300 | 268.0* | 0.202 | 0.167 | 148.5 MiB | 146.3 MiB | 1.19 MiB/s | 0.97 MiB/s | 1.114 | 0.934 | 119.5 MiB | 88.1 MiB | 0.82 MiB/s | 0.69 MiB/s | 0.053 | 0.040 | 231.3 MiB | 230.1 MiB | 0.02 MiB/s | 0.02 MiB/s | 19.6 | 14.0 | 51.0 | 127.0 |
| 400 | 346.5* | 0.318 | 0.254 | 148.1 MiB | 146.3 MiB | 1.74 MiB/s | 1.42 MiB/s | 1.897 | 1.444 | 123.0 MiB | 82.3 MiB | 1.25 MiB/s | 0.98 MiB/s | 0.070 | 0.049 | 232.2 MiB | 231.2 MiB | 0.03 MiB/s | 0.02 MiB/s | 34.7 | 22.0 | 106.0 | 197.0 |
| 500 | 432.4* | 0.371 | 0.323 | 148.4 MiB | 146.3 MiB | 1.97 MiB/s | 1.75 MiB/s | 2.247 | 1.911 | 169.7 MiB | 97.5 MiB | 1.39 MiB/s | 1.23 MiB/s | 0.070 | 0.057 | 232.1 MiB | 231.5 MiB | 0.03 MiB/s | 0.02 MiB/s | 37.3 | 22.0 | 118.0 | 215.0 |
| 1000 | 527.6* | 0.426 | 0.352 | 148.1 MiB | 146.7 MiB | 2.22 MiB/s | 1.85 MiB/s | 2.918 | 2.562 | 212.0 MiB | 152.7 MiB | 1.77 MiB/s | 1.59 MiB/s | 0.103 | 0.094 | 234.2 MiB | 232.7 MiB | 0.04 MiB/s | 0.04 MiB/s | 148.0 | 138.0 | 318.0 | 425.0 |

### `rls-predicate-pips-3-token-pip`

_Group_: RLS-predicate-pips. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 91.7 | 0.480 | 0.216 | 147.6 MiB | 146.1 MiB | 2.49 MiB/s | 1.13 MiB/s | 2.874 | 1.266 | 90.8 MiB | 58.5 MiB | 1.73 MiB/s | 0.81 MiB/s | 0.097 | 0.055 | 232.8 MiB | 231.8 MiB | 0.04 MiB/s | 0.02 MiB/s | 7.4 | 6.0 | 13.0 | 24.0 |
| 200 | 183.7 | 0.131 | 0.099 | 147.7 MiB | 146.5 MiB | 0.85 MiB/s | 0.62 MiB/s | 0.679 | 0.451 | 85.2 MiB | 72.9 MiB | 0.62 MiB/s | 0.43 MiB/s | 0.031 | 0.025 | 232.0 MiB | 231.1 MiB | 0.01 MiB/s | 0.01 MiB/s | 9.5 | 7.0 | 20.0 | 79.0 |
| 300 | 270.8 | 0.234 | 0.166 | 147.8 MiB | 146.2 MiB | 1.41 MiB/s | 1.03 MiB/s | 1.298 | 0.912 | 119.7 MiB | 78.7 MiB | 0.93 MiB/s | 0.73 MiB/s | 0.041 | 0.033 | 235.2 MiB | 233.6 MiB | 0.02 MiB/s | 0.01 MiB/s | 22.6 | 17.0 | 60.0 | 104.0 |
| 400 | 349.1* | 0.299 | 0.250 | 147.8 MiB | 146.6 MiB | 1.70 MiB/s | 1.45 MiB/s | 1.777 | 1.470 | 144.4 MiB | 79.3 MiB | 1.20 MiB/s | 1.02 MiB/s | 0.050 | 0.046 | 234.5 MiB | 233.7 MiB | 0.02 MiB/s | 0.02 MiB/s | 30.7 | 24.0 | 75.0 | 149.0 |
| 500 | 428.1* | 0.356 | 0.318 | 148.7 MiB | 146.9 MiB | 1.94 MiB/s | 1.79 MiB/s | 2.027 | 1.884 | 138.8 MiB | 102.9 MiB | 1.35 MiB/s | 1.27 MiB/s | 0.084 | 0.070 | 234.5 MiB | 234.0 MiB | 0.03 MiB/s | 0.03 MiB/s | 39.7 | 25.0 | 120.0 | 193.0 |
| 1000 | 548.3* | 0.483 | 0.415 | 148.5 MiB | 146.8 MiB | 2.59 MiB/s | 2.24 MiB/s | 3.224 | 2.447 | 228.4 MiB | 125.8 MiB | 1.97 MiB/s | 1.56 MiB/s | 0.110 | 0.087 | 236.8 MiB | 235.8 MiB | 0.04 MiB/s | 0.03 MiB/s | 140.3 | 132.0 | 296.0 | 373.0 |

### `rls-predicate-pips-1-header-pip`

_Group_: RLS-predicate-pips. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 92.5 | 0.509 | 0.263 | 146.7 MiB | 146.0 MiB | 2.69 MiB/s | 1.40 MiB/s | 3.148 | 1.579 | 186.8 MiB | 87.3 MiB | 1.93 MiB/s | 1.01 MiB/s | 0.104 | 0.068 | 234.9 MiB | 234.7 MiB | 0.04 MiB/s | 0.03 MiB/s | 6.1 | 5.0 | 10.0 | 15.0 |
| 200 | 181.4 | 0.142 | 0.098 | 146.7 MiB | 146.0 MiB | 0.82 MiB/s | 0.55 MiB/s | 0.705 | 0.471 | 93.4 MiB | 61.7 MiB | 0.58 MiB/s | 0.42 MiB/s | 0.038 | 0.028 | 235.5 MiB | 234.7 MiB | 0.01 MiB/s | 0.01 MiB/s | 13.1 | 8.0 | 28.0 | 151.0 |
| 300 | 270.0 | 0.224 | 0.170 | 147.6 MiB | 145.9 MiB | 1.30 MiB/s | 0.99 MiB/s | 1.318 | 0.941 | 132.2 MiB | 87.4 MiB | 0.92 MiB/s | 0.69 MiB/s | 0.044 | 0.036 | 237.3 MiB | 235.1 MiB | 0.02 MiB/s | 0.01 MiB/s | 18.7 | 13.0 | 47.0 | 125.0 |
| 400 | 353.9* | 0.240 | 0.223 | 148.4 MiB | 146.6 MiB | 1.36 MiB/s | 1.26 MiB/s | 1.358 | 1.197 | 132.2 MiB | 99.3 MiB | 0.94 MiB/s | 0.83 MiB/s | 0.049 | 0.044 | 237.4 MiB | 235.7 MiB | 0.02 MiB/s | 0.02 MiB/s | 21.2 | 12.0 | 68.0 | 207.0 |
| 500 | 437.0* | 0.367 | 0.311 | 148.6 MiB | 146.4 MiB | 2.01 MiB/s | 1.71 MiB/s | 2.288 | 1.847 | 134.3 MiB | 85.9 MiB | 1.47 MiB/s | 1.23 MiB/s | 0.082 | 0.062 | 237.9 MiB | 236.9 MiB | 0.04 MiB/s | 0.03 MiB/s | 32.5 | 21.0 | 96.0 | 205.0 |
| 1000 | 513.0* | 0.428 | 0.384 | 148.3 MiB | 146.6 MiB | 2.20 MiB/s | 2.07 MiB/s | 2.686 | 2.331 | 203.9 MiB | 128.1 MiB | 1.58 MiB/s | 1.45 MiB/s | 0.093 | 0.076 | 240.3 MiB | 237.9 MiB | 0.03 MiB/s | 0.03 MiB/s | 152.6 | 142.0 | 333.0 | 430.0 |

### `rls-predicate-pips-2-header-pip`

_Group_: RLS-predicate-pips. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 92.2 | 0.406 | 0.223 | 147.2 MiB | 146.5 MiB | 2.06 MiB/s | 1.14 MiB/s | 2.350 | 1.375 | 68.3 MiB | 50.5 MiB | 1.35 MiB/s | 0.83 MiB/s | 0.097 | 0.056 | 240.3 MiB | 239.0 MiB | 0.03 MiB/s | 0.02 MiB/s | 6.3 | 6.0 | 11.0 | 17.0 |
| 200 | 181.7 | 0.152 | 0.103 | 147.2 MiB | 145.8 MiB | 0.90 MiB/s | 0.60 MiB/s | 0.797 | 0.476 | 85.6 MiB | 59.3 MiB | 0.63 MiB/s | 0.43 MiB/s | 0.029 | 0.025 | 237.5 MiB | 237.2 MiB | 0.01 MiB/s | 0.01 MiB/s | 12.2 | 8.0 | 31.0 | 104.0 |
| 300 | 274.2 | 0.209 | 0.172 | 147.6 MiB | 146.3 MiB | 1.19 MiB/s | 1.00 MiB/s | 1.154 | 0.884 | 104.7 MiB | 66.1 MiB | 0.81 MiB/s | 0.66 MiB/s | 0.047 | 0.041 | 239.1 MiB | 238.4 MiB | 0.02 MiB/s | 0.01 MiB/s | 17.3 | 12.0 | 47.0 | 98.0 |
| 400 | 358.9* | 0.268 | 0.232 | 147.6 MiB | 146.6 MiB | 1.51 MiB/s | 1.33 MiB/s | 1.696 | 1.354 | 116.8 MiB | 85.0 MiB | 1.15 MiB/s | 0.94 MiB/s | 0.048 | 0.046 | 240.2 MiB | 239.1 MiB | 0.02 MiB/s | 0.02 MiB/s | 23.1 | 14.0 | 76.0 | 146.0 |
| 500 | 410.8* | 0.351 | 0.299 | 148.2 MiB | 146.6 MiB | 1.90 MiB/s | 1.63 MiB/s | 2.120 | 1.784 | 171.2 MiB | 87.8 MiB | 1.33 MiB/s | 1.16 MiB/s | 0.063 | 0.058 | 240.2 MiB | 238.7 MiB | 0.03 MiB/s | 0.02 MiB/s | 41.0 | 25.0 | 127.0 | 218.0 |
| 1000 | 553.2* | 0.435 | 0.369 | 148.5 MiB | 146.8 MiB | 2.22 MiB/s | 1.94 MiB/s | 2.720 | 2.270 | 207.4 MiB | 148.7 MiB | 1.61 MiB/s | 1.41 MiB/s | 0.123 | 0.092 | 241.1 MiB | 239.6 MiB | 0.04 MiB/s | 0.03 MiB/s | 139.2 | 132.0 | 298.0 | 395.0 |

### `rls-predicate-pips-3-header-pip`

_Group_: RLS-predicate-pips. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 90.7 | 0.515 | 0.230 | 145.9 MiB | 145.5 MiB | 2.64 MiB/s | 1.16 MiB/s | 3.006 | 1.309 | 70.1 MiB | 49.7 MiB | 1.75 MiB/s | 0.81 MiB/s | 0.099 | 0.060 | 240.9 MiB | 240.1 MiB | 0.04 MiB/s | 0.02 MiB/s | 7.6 | 6.0 | 13.0 | 39.0 |
| 200 | 181.8 | 0.142 | 0.113 | 148.0 MiB | 146.5 MiB | 0.75 MiB/s | 0.58 MiB/s | 0.742 | 0.462 | 85.8 MiB | 71.1 MiB | 0.54 MiB/s | 0.39 MiB/s | 0.027 | 0.025 | 240.6 MiB | 240.2 MiB | 0.01 MiB/s | 0.01 MiB/s | 15.4 | 11.0 | 35.0 | 86.0 |
| 300 | 268.8* | 0.247 | 0.183 | 148.0 MiB | 146.5 MiB | 1.31 MiB/s | 0.98 MiB/s | 1.378 | 0.981 | 127.8 MiB | 72.8 MiB | 0.90 MiB/s | 0.67 MiB/s | 0.059 | 0.047 | 243.8 MiB | 242.9 MiB | 0.02 MiB/s | 0.02 MiB/s | 23.6 | 15.0 | 67.0 | 132.0 |
| 400 | 355.2* | 0.285 | 0.256 | 148.2 MiB | 147.0 MiB | 1.46 MiB/s | 1.34 MiB/s | 1.671 | 1.463 | 136.5 MiB | 96.1 MiB | 1.06 MiB/s | 0.95 MiB/s | 0.070 | 0.058 | 243.5 MiB | 242.5 MiB | 0.02 MiB/s | 0.02 MiB/s | 29.7 | 21.0 | 81.0 | 156.0 |
| 500 | 421.5* | 0.397 | 0.335 | 148.2 MiB | 146.7 MiB | 2.00 MiB/s | 1.71 MiB/s | 2.408 | 1.933 | 127.6 MiB | 78.3 MiB | 1.45 MiB/s | 1.19 MiB/s | 0.072 | 0.060 | 243.5 MiB | 242.2 MiB | 0.03 MiB/s | 0.02 MiB/s | 42.6 | 27.0 | 140.0 | 225.0 |
| 1000 | 507.2* | 0.423 | 0.391 | 148.6 MiB | 147.0 MiB | 2.12 MiB/s | 1.96 MiB/s | 2.576 | 2.337 | 192.4 MiB | 144.9 MiB | 1.50 MiB/s | 1.40 MiB/s | 0.092 | 0.073 | 244.4 MiB | 242.3 MiB | 0.04 MiB/s | 0.03 MiB/s | 150.3 | 140.0 | 329.0 | 444.0 |

### `rls-predicate-summary-10-predicates-3-token-pip`

_Group_: RLS-predicate-pips. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 89.8* | 0.473 | 0.227 | 147.8 MiB | 146.6 MiB | 2.35 MiB/s | 1.19 MiB/s | 2.888 | 1.318 | 77.5 MiB | 54.2 MiB | 1.64 MiB/s | 0.83 MiB/s | 0.106 | 0.067 | 245.7 MiB | 244.5 MiB | 0.04 MiB/s | 0.02 MiB/s | 11.0 | 10.0 | 17.0 | 40.0 |
| 200 | 172.2* | 0.248 | 0.158 | 149.4 MiB | 147.6 MiB | 1.26 MiB/s | 0.90 MiB/s | 1.133 | 0.692 | 112.4 MiB | 82.0 MiB | 0.75 MiB/s | 0.57 MiB/s | 0.040 | 0.031 | 248.0 MiB | 245.5 MiB | 0.01 MiB/s | 0.01 MiB/s | 26.1 | 21.0 | 60.0 | 126.0 |
| 300 | 262.8* | 0.461 | 0.344 | 149.0 MiB | 147.4 MiB | 2.24 MiB/s | 1.70 MiB/s | 2.251 | 1.665 | 140.0 MiB | 78.8 MiB | 1.41 MiB/s | 1.07 MiB/s | 0.065 | 0.055 | 247.9 MiB | 246.3 MiB | 0.02 MiB/s | 0.02 MiB/s | 37.4 | 27.0 | 106.0 | 187.0 |
| 400 | 312.2* | 0.484 | 0.446 | 149.1 MiB | 147.9 MiB | 2.35 MiB/s | 2.12 MiB/s | 2.344 | 2.171 | 147.9 MiB | 107.4 MiB | 1.44 MiB/s | 1.34 MiB/s | 0.079 | 0.072 | 246.2 MiB | 245.6 MiB | 0.03 MiB/s | 0.02 MiB/s | 73.4 | 54.0 | 195.0 | 318.0 |
| 500 | 343.9* | 0.653 | 0.571 | 149.5 MiB | 148.3 MiB | 2.94 MiB/s | 2.60 MiB/s | 3.300 | 2.784 | 169.1 MiB | 92.6 MiB | 1.89 MiB/s | 1.63 MiB/s | 0.097 | 0.084 | 249.4 MiB | 248.6 MiB | 0.03 MiB/s | 0.03 MiB/s | 104.6 | 88.0 | 233.0 | 319.0 |
| 1000 | 346.7* | 0.695 | 0.585 | 149.8 MiB | 148.3 MiB | 3.14 MiB/s | 2.64 MiB/s | 3.280 | 2.922 | 206.6 MiB | 123.2 MiB | 1.88 MiB/s | 1.66 MiB/s | 0.111 | 0.098 | 251.8 MiB | 248.9 MiB | 0.03 MiB/s | 0.03 MiB/s | 241.5 | 237.0 | 455.0 | 548.0 |

### `wildcard-all-single`

_Group_: Wildcard. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 91.1 | 0.645 | 0.286 | 148.1 MiB | 147.2 MiB | 2.89 MiB/s | 1.31 MiB/s | 3.035 | 1.325 | 64.1 MiB | 53.3 MiB | 1.70 MiB/s | 0.80 MiB/s | 0.103 | 0.058 | 249.2 MiB | 247.9 MiB | 0.03 MiB/s | 0.02 MiB/s | 5.8 | 5.0 | 11.0 | 20.0 |
| 200 | 182.4 | 0.122 | 0.089 | 149.2 MiB | 147.6 MiB | 0.69 MiB/s | 0.49 MiB/s | 0.485 | 0.326 | 81.1 MiB | 53.4 MiB | 0.46 MiB/s | 0.33 MiB/s | 0.029 | 0.024 | 249.1 MiB | 248.3 MiB | 0.01 MiB/s | 0.01 MiB/s | 8.5 | 6.0 | 16.0 | 76.0 |
| 300 | 271.4 | 0.198 | 0.156 | 149.0 MiB | 148.0 MiB | 1.09 MiB/s | 0.86 MiB/s | 0.759 | 0.661 | 81.2 MiB | 70.8 MiB | 0.68 MiB/s | 0.60 MiB/s | 0.042 | 0.035 | 249.1 MiB | 248.8 MiB | 0.02 MiB/s | 0.01 MiB/s | 12.5 | 7.0 | 41.0 | 114.0 |
| 400 | 357.8* | 0.255 | 0.222 | 149.6 MiB | 148.2 MiB | 1.40 MiB/s | 1.20 MiB/s | 1.354 | 1.081 | 114.6 MiB | 69.7 MiB | 1.02 MiB/s | 0.84 MiB/s | 0.059 | 0.043 | 250.9 MiB | 249.6 MiB | 0.03 MiB/s | 0.02 MiB/s | 23.0 | 18.0 | 54.0 | 119.0 |
| 500 | 443.9* | 0.300 | 0.272 | 149.4 MiB | 148.0 MiB | 1.55 MiB/s | 1.44 MiB/s | 1.622 | 1.434 | 108.1 MiB | 86.1 MiB | 1.19 MiB/s | 1.07 MiB/s | 0.075 | 0.060 | 251.2 MiB | 250.2 MiB | 0.03 MiB/s | 0.03 MiB/s | 26.9 | 15.0 | 85.0 | 162.0 |
| 1000 | 649.1* | 0.503 | 0.390 | 149.9 MiB | 148.6 MiB | 2.54 MiB/s | 1.99 MiB/s | 2.638 | 1.941 | 157.7 MiB | 96.4 MiB | 1.76 MiB/s | 1.36 MiB/s | 0.082 | 0.072 | 250.0 MiB | 249.9 MiB | 0.03 MiB/s | 0.03 MiB/s | 107.4 | 91.0 | 253.0 | 329.0 |

### `wildcard-mixed-bulk`

_Group_: Wildcard. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource/bulk`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 82.0* | 0.478 | 0.286 | 148.1 MiB | 147.2 MiB | 2.41 MiB/s | 1.49 MiB/s | 2.542 | 1.890 | 79.5 MiB | 58.1 MiB | 1.70 MiB/s | 0.98 MiB/s | 0.111 | 0.073 | 254.7 MiB | 252.1 MiB | 0.05 MiB/s | 0.03 MiB/s | 70.9 | 63.0 | 140.0 | 195.0 |
| 200 | 113.6* | 0.256 | 0.191 | 144.9 MiB | 144.2 MiB | 1.57 MiB/s | 1.19 MiB/s | 3.688 | 2.692 | 144.1 MiB | 92.1 MiB | 0.99 MiB/s | 0.77 MiB/s | 0.083 | 0.066 | 259.4 MiB | 256.9 MiB | 0.01 MiB/s | 0.01 MiB/s | 145.1 | 135.0 | 240.0 | 304.0 |
| 300 | 111.3* | 0.272 | 0.237 | 142.1 MiB | 141.3 MiB | 1.68 MiB/s | 1.45 MiB/s | 3.772 | 3.570 | 168.8 MiB | 101.5 MiB | 1.00 MiB/s | 0.95 MiB/s | 0.101 | 0.091 | 257.8 MiB | 257.1 MiB | 0.02 MiB/s | 0.02 MiB/s | 227.6 | 209.0 | 413.0 | 558.0 |
| 400 | 115.2* | 0.256 | 0.224 | 140.6 MiB | 139.6 MiB | 1.55 MiB/s | 1.36 MiB/s | 3.716 | 3.468 | 197.8 MiB | 124.7 MiB | 0.97 MiB/s | 0.91 MiB/s | 0.090 | 0.076 | 261.7 MiB | 257.5 MiB | 0.02 MiB/s | 0.01 MiB/s | 292.4 | 265.0 | 579.0 | 766.0 |
| 500 | 103.3* | 0.283 | 0.224 | 141.2 MiB | 139.3 MiB | 1.71 MiB/s | 1.35 MiB/s | 3.698 | 3.334 | 219.0 MiB | 143.9 MiB | 0.97 MiB/s | 0.88 MiB/s | 0.083 | 0.079 | 264.2 MiB | 260.6 MiB | 0.02 MiB/s | 0.02 MiB/s | 406.5 | 369.0 | 810.0 | 1068.0 |
| 1000 | 99.5* | 0.223 | 0.209 | 138.9 MiB | 138.0 MiB | 1.36 MiB/s | 1.25 MiB/s | 3.556 | 3.163 | 279.3 MiB | 175.7 MiB | 0.92 MiB/s | 0.82 MiB/s | 0.087 | 0.070 | 259.4 MiB | 256.4 MiB | 0.02 MiB/s | 0.01 MiB/s | 809.9 | 786.0 | 1459.0 | 1742.0 |

## Notes

- The following (scenario, RPS) rows under-delivered (`achieved_rps < 0.9 × target_rps`) and are marked with `*` in the tables above (D-18). The promote-gate still applies to these rows — saturation shows up as a stable high p95 rather than dropped rows:
  - `ols-single` at 200 RPS — achieved 179.1/s
  - `ols-single` at 1000 RPS — achieved 750.2/s
  - `ols-single-10roles` at 500 RPS — achieved 447.7/s
  - `ols-single-10roles` at 1000 RPS — achieved 724.2/s
  - `ols-single-20roles` at 400 RPS — achieved 357.9/s
  - `ols-single-20roles` at 500 RPS — achieved 433.6/s
  - `ols-single-20roles` at 1000 RPS — achieved 688.4/s
  - `ols-single-30roles` at 500 RPS — achieved 446.5/s
  - `ols-single-30roles` at 1000 RPS — achieved 614.4/s
  - `ols-single-50roles` at 200 RPS — achieved 177.2/s
  - `ols-single-50roles` at 400 RPS — achieved 348.7/s
  - `ols-single-50roles` at 500 RPS — achieved 440.0/s
  - `ols-single-50roles` at 1000 RPS — achieved 492.7/s
  - `ols-single-100roles` at 300 RPS — achieved 265.9/s
  - `ols-single-100roles` at 400 RPS — achieved 347.9/s
  - `ols-single-100roles` at 500 RPS — achieved 374.7/s
  - `ols-single-100roles` at 1000 RPS — achieved 395.0/s
  - `ols-bulk-50` at 100 RPS — achieved 87.9/s
  - `ols-bulk-50` at 200 RPS — achieved 140.5/s
  - `ols-bulk-50` at 300 RPS — achieved 146.9/s
  - `ols-bulk-50` at 400 RPS — achieved 120.6/s
  - `ols-bulk-50` at 500 RPS — achieved 128.0/s
  - `ols-bulk-50` at 1000 RPS — achieved 129.2/s
  - `ols-bulk-100` at 100 RPS — achieved 80.7/s
  - `ols-bulk-100` at 200 RPS — achieved 81.3/s
  - `ols-bulk-100` at 300 RPS — achieved 77.3/s
  - `ols-bulk-100` at 400 RPS — achieved 81.2/s
  - `ols-bulk-100` at 500 RPS — achieved 80.7/s
  - `ols-bulk-100` at 1000 RPS — achieved 83.9/s
  - `ols-bulk-1000` at 100 RPS — achieved 9.0/s
  - `ols-bulk-1000` at 200 RPS — achieved 8.8/s
  - `ols-bulk-1000` at 300 RPS — achieved 8.6/s
  - `ols-bulk-1000` at 400 RPS — achieved 8.2/s
  - `ols-bulk-1000` at 500 RPS — achieved 8.6/s
  - `ols-bulk-1000` at 1000 RPS — achieved 8.2/s
  - `rls-condition-1-expression` at 500 RPS — achieved 449.1/s
  - `rls-condition-1-expression` at 1000 RPS — achieved 673.1/s
  - `rls-condition-2-expression` at 1000 RPS — achieved 726.9/s
  - `rls-condition-3-expression` at 1000 RPS — achieved 499.0/s
  - `rls-condition-5-expression` at 500 RPS — achieved 439.4/s
  - `rls-condition-5-expression` at 1000 RPS — achieved 528.6/s
  - `rls-predicate` at 1000 RPS — achieved 714.2/s
  - `rls-predicate-summary-2-predicates` at 500 RPS — achieved 448.9/s
  - `rls-predicate-summary-2-predicates` at 1000 RPS — achieved 646.8/s
  - `rls-predicate-summary-3-predicates` at 1000 RPS — achieved 686.9/s
  - `rls-predicate-summary-4-predicates` at 1000 RPS — achieved 731.3/s
  - `rls-predicate-summary-5-predicates` at 1000 RPS — achieved 588.3/s
  - `rls-predicate-summary-10-predicates` at 200 RPS — achieved 179.9/s
  - `rls-predicate-summary-10-predicates` at 300 RPS — achieved 265.2/s
  - `rls-predicate-summary-10-predicates` at 400 RPS — achieved 354.1/s
  - `rls-predicate-summary-10-predicates` at 500 RPS — achieved 419.2/s
  - `rls-predicate-summary-10-predicates` at 1000 RPS — achieved 456.4/s
  - `rls-predicate-pips-1-token-pip` at 300 RPS — achieved 266.2/s
  - `rls-predicate-pips-1-token-pip` at 500 RPS — achieved 434.9/s
  - `rls-predicate-pips-1-token-pip` at 1000 RPS — achieved 507.8/s
  - `rls-predicate-pips-2-token-pip` at 300 RPS — achieved 268.0/s
  - `rls-predicate-pips-2-token-pip` at 400 RPS — achieved 346.5/s
  - `rls-predicate-pips-2-token-pip` at 500 RPS — achieved 432.4/s
  - `rls-predicate-pips-2-token-pip` at 1000 RPS — achieved 527.6/s
  - `rls-predicate-pips-3-token-pip` at 400 RPS — achieved 349.1/s
  - `rls-predicate-pips-3-token-pip` at 500 RPS — achieved 428.1/s
  - `rls-predicate-pips-3-token-pip` at 1000 RPS — achieved 548.3/s
  - `rls-predicate-pips-1-header-pip` at 400 RPS — achieved 353.9/s
  - `rls-predicate-pips-1-header-pip` at 500 RPS — achieved 437.0/s
  - `rls-predicate-pips-1-header-pip` at 1000 RPS — achieved 513.0/s
  - `rls-predicate-pips-2-header-pip` at 400 RPS — achieved 358.9/s
  - `rls-predicate-pips-2-header-pip` at 500 RPS — achieved 410.8/s
  - `rls-predicate-pips-2-header-pip` at 1000 RPS — achieved 553.2/s
  - `rls-predicate-pips-3-header-pip` at 300 RPS — achieved 268.8/s
  - `rls-predicate-pips-3-header-pip` at 400 RPS — achieved 355.2/s
  - `rls-predicate-pips-3-header-pip` at 500 RPS — achieved 421.5/s
  - `rls-predicate-pips-3-header-pip` at 1000 RPS — achieved 507.2/s
  - `rls-predicate-summary-10-predicates-3-token-pip` at 100 RPS — achieved 89.8/s
  - `rls-predicate-summary-10-predicates-3-token-pip` at 200 RPS — achieved 172.2/s
  - `rls-predicate-summary-10-predicates-3-token-pip` at 300 RPS — achieved 262.8/s
  - `rls-predicate-summary-10-predicates-3-token-pip` at 400 RPS — achieved 312.2/s
  - `rls-predicate-summary-10-predicates-3-token-pip` at 500 RPS — achieved 343.9/s
  - `rls-predicate-summary-10-predicates-3-token-pip` at 1000 RPS — achieved 346.7/s
  - `wildcard-all-single` at 400 RPS — achieved 357.8/s
  - `wildcard-all-single` at 500 RPS — achieved 443.9/s
  - `wildcard-all-single` at 1000 RPS — achieved 649.1/s
  - `wildcard-mixed-bulk` at 100 RPS — achieved 82.0/s
  - `wildcard-mixed-bulk` at 200 RPS — achieved 113.6/s
  - `wildcard-mixed-bulk` at 300 RPS — achieved 111.3/s
  - `wildcard-mixed-bulk` at 400 RPS — achieved 115.2/s
  - `wildcard-mixed-bulk` at 500 RPS — achieved 103.3/s
  - `wildcard-mixed-bulk` at 1000 RPS — achieved 99.5/s
