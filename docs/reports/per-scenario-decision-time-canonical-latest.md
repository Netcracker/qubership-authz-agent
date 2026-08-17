# Per-Scenario Decision-Time Report — canonical

Generated: 2026-05-20 12:04:20 UTC
Sweep timestamp: canonical-20260519-155138 (last merged: `ols-bulk-50`)

## Methodology

- **Mode**: `canonical` — requests traverse Envoy → OPA → decision-log-collector via `POST /access/v1/authorize`.
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
- **Other-mode report**: see [per-scenario-decision-time-legacy-latest.md](per-scenario-decision-time-legacy-latest.md) (independent baseline, no cross-mode gating per D-15).
- **Companion xlsx**: [per-scenario-decision-time.xlsx](per-scenario-decision-time.xlsx), `canonical` sheet (168 rows × 25 cols, header row sortable).

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
| 100 | 96.2 | 0.026 | 0.016 | 52.0 MiB | 49.5 MiB | 0.31 MiB/s | 0.14 MiB/s | 0.083 | 0.038 | 138.1 MiB | 125.9 MiB | 0.19 MiB/s | 0.08 MiB/s | 0.010 | 0.008 | 53.8 MiB | 52.9 MiB | 0.00 MiB/s | 0.00 MiB/s | 2.5 | 2.0 | 3.0 | 4.0 |
| 200 | 192.0 | 0.058 | 0.046 | 53.4 MiB | 52.3 MiB | 0.92 MiB/s | 0.67 MiB/s | 0.222 | 0.161 | 142.7 MiB | 132.3 MiB | 0.56 MiB/s | 0.40 MiB/s | 0.015 | 0.013 | 53.1 MiB | 51.8 MiB | 0.01 MiB/s | 0.01 MiB/s | 2.3 | 2.0 | 3.0 | 4.0 |
| 300 | 287.5 | 0.087 | 0.069 | 55.1 MiB | 53.2 MiB | 1.49 MiB/s | 1.14 MiB/s | 0.322 | 0.282 | 141.5 MiB | 139.1 MiB | 0.82 MiB/s | 0.71 MiB/s | 0.021 | 0.018 | 54.1 MiB | 52.2 MiB | 0.02 MiB/s | 0.02 MiB/s | 2.5 | 2.0 | 3.0 | 20.0 |
| 400 | 383.8 | 0.106 | 0.093 | 55.6 MiB | 54.5 MiB | 1.88 MiB/s | 1.62 MiB/s | 0.436 | 0.361 | 142.9 MiB | 124.7 MiB | 1.11 MiB/s | 0.92 MiB/s | 0.023 | 0.021 | 53.9 MiB | 53.1 MiB | 0.02 MiB/s | 0.02 MiB/s | 2.5 | 2.0 | 3.0 | 21.0 |
| 500 | 479.2 | 0.132 | 0.120 | 56.0 MiB | 55.2 MiB | 2.50 MiB/s | 2.21 MiB/s | 0.562 | 0.480 | 150.4 MiB | 136.1 MiB | 1.47 MiB/s | 1.25 MiB/s | 0.030 | 0.027 | 54.6 MiB | 53.5 MiB | 0.03 MiB/s | 0.03 MiB/s | 2.6 | 2.0 | 4.0 | 19.0 |
| 1000 | 956.4 | 0.219 | 0.156 | 57.7 MiB | 55.7 MiB | 4.49 MiB/s | 3.10 MiB/s | 0.919 | 0.648 | 144.3 MiB | 139.5 MiB | 2.42 MiB/s | 1.70 MiB/s | 0.038 | 0.033 | 55.8 MiB | 53.8 MiB | 0.04 MiB/s | 0.04 MiB/s | 3.5 | 2.0 | 16.0 | 25.0 |

### `ols-single-10roles`

_Group_: OLS. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 96.1 | 0.217 | 0.134 | 29.1 MiB | 27.7 MiB | 4.45 MiB/s | 2.74 MiB/s | 0.955 | 0.589 | 60.5 MiB | 44.1 MiB | 2.55 MiB/s | 1.61 MiB/s | 0.054 | 0.042 | 55.4 MiB | 54.7 MiB | 0.06 MiB/s | 0.05 MiB/s | 2.5 | 2.0 | 4.0 | 4.0 |
| 200 | 192.0 | 0.063 | 0.048 | 28.6 MiB | 28.2 MiB | 1.21 MiB/s | 0.84 MiB/s | 0.230 | 0.174 | 59.6 MiB | 49.7 MiB | 0.73 MiB/s | 0.53 MiB/s | 0.015 | 0.014 | 54.3 MiB | 54.1 MiB | 0.01 MiB/s | 0.01 MiB/s | 2.1 | 2.0 | 3.0 | 4.0 |
| 300 | 288.0 | 0.083 | 0.071 | 29.1 MiB | 28.1 MiB | 1.74 MiB/s | 1.44 MiB/s | 0.323 | 0.268 | 69.1 MiB | 61.2 MiB | 1.06 MiB/s | 0.87 MiB/s | 0.026 | 0.021 | 57.2 MiB | 55.3 MiB | 0.02 MiB/s | 0.02 MiB/s | 2.1 | 2.0 | 3.0 | 4.0 |
| 400 | 383.7 | 0.108 | 0.096 | 30.0 MiB | 29.2 MiB | 2.41 MiB/s | 2.09 MiB/s | 0.412 | 0.354 | 63.5 MiB | 53.7 MiB | 1.36 MiB/s | 1.15 MiB/s | 0.032 | 0.028 | 57.2 MiB | 54.8 MiB | 0.03 MiB/s | 0.03 MiB/s | 2.0 | 2.0 | 3.0 | 4.0 |
| 500 | 479.6 | 0.131 | 0.122 | 30.0 MiB | 28.8 MiB | 3.03 MiB/s | 2.79 MiB/s | 0.497 | 0.475 | 62.1 MiB | 61.2 MiB | 1.66 MiB/s | 1.57 MiB/s | 0.037 | 0.032 | 57.6 MiB | 55.5 MiB | 0.03 MiB/s | 0.03 MiB/s | 2.0 | 2.0 | 3.0 | 4.0 |
| 1000 | 959.0 | 0.218 | 0.163 | 29.4 MiB | 28.5 MiB | 5.25 MiB/s | 3.87 MiB/s | 0.854 | 0.630 | 68.5 MiB | 50.2 MiB | 2.94 MiB/s | 2.15 MiB/s | 0.054 | 0.045 | 58.3 MiB | 56.5 MiB | 0.05 MiB/s | 0.04 MiB/s | 2.0 | 2.0 | 3.0 | 5.0 |

### `ols-single-20roles`

_Group_: OLS. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 96.2 | 0.232 | 0.131 | 28.9 MiB | 28.4 MiB | 5.72 MiB/s | 3.16 MiB/s | 0.861 | 0.514 | 58.7 MiB | 49.6 MiB | 3.03 MiB/s | 1.83 MiB/s | 0.067 | 0.049 | 60.5 MiB | 58.7 MiB | 0.07 MiB/s | 0.05 MiB/s | 2.6 | 2.0 | 4.0 | 4.0 |
| 200 | 191.8 | 0.060 | 0.049 | 29.9 MiB | 28.9 MiB | 1.26 MiB/s | 0.95 MiB/s | 0.236 | 0.182 | 69.2 MiB | 61.3 MiB | 0.77 MiB/s | 0.59 MiB/s | 0.016 | 0.014 | 60.8 MiB | 60.4 MiB | 0.01 MiB/s | 0.01 MiB/s | 2.6 | 2.0 | 4.0 | 5.0 |
| 300 | 288.0 | 0.088 | 0.075 | 29.9 MiB | 29.2 MiB | 2.09 MiB/s | 1.73 MiB/s | 0.343 | 0.281 | 64.6 MiB | 48.0 MiB | 1.23 MiB/s | 0.97 MiB/s | 0.030 | 0.022 | 59.4 MiB | 58.3 MiB | 0.03 MiB/s | 0.02 MiB/s | 2.5 | 2.0 | 4.0 | 5.0 |
| 400 | 383.8 | 0.115 | 0.107 | 29.7 MiB | 29.3 MiB | 2.97 MiB/s | 2.68 MiB/s | 0.472 | 0.401 | 65.7 MiB | 61.2 MiB | 1.77 MiB/s | 1.46 MiB/s | 0.037 | 0.031 | 60.7 MiB | 59.8 MiB | 0.03 MiB/s | 0.03 MiB/s | 2.4 | 2.0 | 3.0 | 5.0 |
| 500 | 478.8 | 0.135 | 0.123 | 29.9 MiB | 28.9 MiB | 3.60 MiB/s | 3.23 MiB/s | 0.564 | 0.506 | 64.6 MiB | 60.2 MiB | 2.17 MiB/s | 1.90 MiB/s | 0.044 | 0.038 | 60.5 MiB | 60.3 MiB | 0.04 MiB/s | 0.03 MiB/s | 2.3 | 2.0 | 3.0 | 6.0 |
| 1000 | 958.1 | 0.240 | 0.178 | 30.9 MiB | 29.5 MiB | 6.49 MiB/s | 4.79 MiB/s | 1.045 | 0.742 | 81.5 MiB | 59.4 MiB | 3.75 MiB/s | 2.73 MiB/s | 0.049 | 0.042 | 62.7 MiB | 62.0 MiB | 0.04 MiB/s | 0.04 MiB/s | 3.4 | 2.0 | 7.0 | 17.0 |

### `ols-single-30roles`

_Group_: OLS. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 96.1 | 0.251 | 0.148 | 30.9 MiB | 29.2 MiB | 6.80 MiB/s | 3.97 MiB/s | 1.027 | 0.571 | 62.2 MiB | 52.2 MiB | 3.68 MiB/s | 2.10 MiB/s | 0.088 | 0.067 | 62.4 MiB | 62.1 MiB | 0.08 MiB/s | 0.06 MiB/s | 2.8 | 3.0 | 4.0 | 5.0 |
| 200 | 192.1 | 0.063 | 0.050 | 30.8 MiB | 29.7 MiB | 1.53 MiB/s | 1.14 MiB/s | 0.218 | 0.156 | 63.4 MiB | 45.0 MiB | 0.81 MiB/s | 0.58 MiB/s | 0.021 | 0.017 | 66.7 MiB | 64.3 MiB | 0.01 MiB/s | 0.01 MiB/s | 3.0 | 2.0 | 4.0 | 33.0 |
| 300 | 288.5 | 0.094 | 0.082 | 30.9 MiB | 30.0 MiB | 2.57 MiB/s | 2.12 MiB/s | 0.395 | 0.316 | 86.7 MiB | 61.3 MiB | 1.52 MiB/s | 1.20 MiB/s | 0.029 | 0.025 | 65.7 MiB | 64.3 MiB | 0.02 MiB/s | 0.02 MiB/s | 2.9 | 2.0 | 4.0 | 27.0 |
| 400 | 382.6 | 0.126 | 0.102 | 30.9 MiB | 30.2 MiB | 3.62 MiB/s | 2.86 MiB/s | 0.540 | 0.465 | 70.5 MiB | 67.5 MiB | 2.03 MiB/s | 1.77 MiB/s | 0.037 | 0.034 | 68.4 MiB | 64.4 MiB | 0.03 MiB/s | 0.03 MiB/s | 3.5 | 2.0 | 6.0 | 34.0 |
| 500 | 480.1 | 0.143 | 0.128 | 30.6 MiB | 29.8 MiB | 4.26 MiB/s | 3.69 MiB/s | 0.628 | 0.556 | 71.3 MiB | 48.3 MiB | 2.43 MiB/s | 2.08 MiB/s | 0.045 | 0.039 | 68.4 MiB | 66.4 MiB | 0.04 MiB/s | 0.03 MiB/s | 3.4 | 2.0 | 8.0 | 31.0 |
| 1000 | 954.3 | 0.259 | 0.195 | 31.3 MiB | 30.4 MiB | 7.83 MiB/s | 5.83 MiB/s | 1.278 | 0.908 | 83.4 MiB | 66.7 MiB | 4.67 MiB/s | 3.39 MiB/s | 0.073 | 0.056 | 69.9 MiB | 67.8 MiB | 0.06 MiB/s | 0.05 MiB/s | 6.2 | 3.0 | 24.0 | 45.0 |

### `ols-single-50roles`

_Group_: OLS. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 95.6 | 0.336 | 0.198 | 31.6 MiB | 30.6 MiB | 8.22 MiB/s | 4.82 MiB/s | 1.438 | 0.906 | 60.1 MiB | 44.9 MiB | 4.51 MiB/s | 2.91 MiB/s | 0.100 | 0.071 | 54.1 MiB | 52.1 MiB | 0.08 MiB/s | 0.05 MiB/s | 3.3 | 3.0 | 4.0 | 9.0 |
| 200 | 190.8 | 0.077 | 0.060 | 31.7 MiB | 31.0 MiB | 1.95 MiB/s | 1.45 MiB/s | 0.277 | 0.202 | 63.2 MiB | 51.6 MiB | 1.18 MiB/s | 0.83 MiB/s | 0.030 | 0.022 | 55.2 MiB | 54.4 MiB | 0.02 MiB/s | 0.01 MiB/s | 3.2 | 3.0 | 4.0 | 7.0 |
| 300 | 287.0 | 0.120 | 0.101 | 33.8 MiB | 31.5 MiB | 3.23 MiB/s | 2.68 MiB/s | 0.476 | 0.368 | 66.9 MiB | 61.7 MiB | 1.89 MiB/s | 1.51 MiB/s | 0.035 | 0.032 | 56.6 MiB | 53.6 MiB | 0.02 MiB/s | 0.02 MiB/s | 4.6 | 3.0 | 9.0 | 48.0 |
| 400 | 381.8 | 0.144 | 0.135 | 33.3 MiB | 31.4 MiB | 3.99 MiB/s | 3.66 MiB/s | 0.608 | 0.547 | 69.4 MiB | 65.8 MiB | 2.38 MiB/s | 2.13 MiB/s | 0.058 | 0.046 | 57.2 MiB | 55.5 MiB | 0.04 MiB/s | 0.03 MiB/s | 5.1 | 3.0 | 14.0 | 43.0 |
| 500 | 475.6 | 0.180 | 0.164 | 32.4 MiB | 31.0 MiB | 5.21 MiB/s | 4.68 MiB/s | 0.713 | 0.639 | 69.3 MiB | 46.7 MiB | 2.95 MiB/s | 2.55 MiB/s | 0.052 | 0.050 | 57.8 MiB | 57.5 MiB | 0.04 MiB/s | 0.03 MiB/s | 4.3 | 3.0 | 13.0 | 30.0 |
| 1000 | 945.4 | 0.327 | 0.240 | 33.0 MiB | 31.7 MiB | 9.40 MiB/s | 6.86 MiB/s | 1.431 | 0.984 | 79.9 MiB | 51.2 MiB | 5.37 MiB/s | 3.84 MiB/s | 0.091 | 0.076 | 61.3 MiB | 59.9 MiB | 0.06 MiB/s | 0.05 MiB/s | 11.2 | 4.0 | 37.0 | 80.0 |

### `ols-single-100roles`

_Group_: OLS. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 95.9 | 0.302 | 0.199 | 34.0 MiB | 32.2 MiB | 10.88 MiB/s | 7.20 MiB/s | 1.336 | 0.867 | 79.5 MiB | 65.9 MiB | 5.98 MiB/s | 3.93 MiB/s | 0.116 | 0.099 | 77.9 MiB | 76.6 MiB | 0.09 MiB/s | 0.08 MiB/s | 3.7 | 3.0 | 5.0 | 7.0 |
| 200 | 192.1 | 0.085 | 0.069 | 32.7 MiB | 31.9 MiB | 3.26 MiB/s | 2.46 MiB/s | 0.337 | 0.255 | 56.9 MiB | 49.1 MiB | 1.97 MiB/s | 1.41 MiB/s | 0.037 | 0.025 | 79.5 MiB | 77.0 MiB | 0.02 MiB/s | 0.01 MiB/s | 3.6 | 3.0 | 5.0 | 19.0 |
| 300 | 287.9 | 0.115 | 0.098 | 33.1 MiB | 32.1 MiB | 4.85 MiB/s | 3.99 MiB/s | 0.424 | 0.387 | 66.2 MiB | 60.9 MiB | 2.55 MiB/s | 2.30 MiB/s | 0.034 | 0.033 | 80.4 MiB | 80.0 MiB | 0.02 MiB/s | 0.02 MiB/s | 3.7 | 3.0 | 5.0 | 26.0 |
| 400 | 383.4 | 0.156 | 0.135 | 33.3 MiB | 31.8 MiB | 6.86 MiB/s | 5.89 MiB/s | 0.683 | 0.559 | 69.9 MiB | 50.5 MiB | 4.01 MiB/s | 3.30 MiB/s | 0.069 | 0.057 | 86.5 MiB | 81.1 MiB | 0.05 MiB/s | 0.04 MiB/s | 4.6 | 4.0 | 7.0 | 10.0 |
| 500 | 479.5 | 0.207 | 0.182 | 33.8 MiB | 33.1 MiB | 9.03 MiB/s | 7.96 MiB/s | 0.956 | 0.793 | 85.7 MiB | 63.8 MiB | 5.49 MiB/s | 4.53 MiB/s | 0.073 | 0.066 | 85.4 MiB | 81.7 MiB | 0.05 MiB/s | 0.05 MiB/s | 4.4 | 3.0 | 7.0 | 15.0 |
| 1000 | 953.3 | 0.342 | 0.248 | 34.3 MiB | 33.4 MiB | 14.27 MiB/s | 10.56 MiB/s | 1.497 | 1.137 | 85.5 MiB | 73.7 MiB | 8.24 MiB/s | 6.34 MiB/s | 0.152 | 0.094 | 89.5 MiB | 86.4 MiB | 0.10 MiB/s | 0.06 MiB/s | 5.9 | 5.0 | 12.0 | 27.0 |

### `ols-bulk-50`

_Group_: OLS-bulk. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource/bulk`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 95.1 | 0.401 | 0.245 | 33.9 MiB | 32.7 MiB | 16.92 MiB/s | 10.29 MiB/s | 1.711 | 1.144 | 69.4 MiB | 49.5 MiB | 9.31 MiB/s | 5.98 MiB/s | 0.170 | 0.118 | 89.9 MiB | 87.6 MiB | 0.11 MiB/s | 0.08 MiB/s | 7.4 | 5.0 | 8.0 | 72.0 |
| 200 | 190.5 | 0.076 | 0.062 | 34.6 MiB | 33.3 MiB | 2.77 MiB/s | 2.13 MiB/s | 0.847 | 0.586 | 88.8 MiB | 66.3 MiB | 1.53 MiB/s | 1.10 MiB/s | 0.041 | 0.029 | 90.0 MiB | 89.4 MiB | 0.03 MiB/s | 0.02 MiB/s | 11.4 | 8.0 | 41.0 | 70.0 |
| 300 | 284.5 | 0.111 | 0.093 | 33.8 MiB | 33.0 MiB | 4.19 MiB/s | 3.45 MiB/s | 1.320 | 1.029 | 97.3 MiB | 86.4 MiB | 2.22 MiB/s | 1.80 MiB/s | 0.057 | 0.052 | 95.8 MiB | 92.9 MiB | 0.04 MiB/s | 0.03 MiB/s | 18.4 | 13.0 | 48.0 | 96.0 |
| 400 | 377.3 | 0.156 | 0.134 | 34.3 MiB | 33.3 MiB | 5.96 MiB/s | 5.10 MiB/s | 1.779 | 1.509 | 115.9 MiB | 76.7 MiB | 2.90 MiB/s | 2.46 MiB/s | 0.090 | 0.078 | 100.3 MiB | 97.7 MiB | 0.06 MiB/s | 0.05 MiB/s | 17.8 | 14.0 | 49.0 | 85.0 |
| 500 | 469.9 | 0.195 | 0.174 | 34.3 MiB | 33.5 MiB | 7.53 MiB/s | 6.69 MiB/s | 2.533 | 2.123 | 100.2 MiB | 75.3 MiB | 4.17 MiB/s | 3.45 MiB/s | 0.152 | 0.111 | 99.1 MiB | 96.4 MiB | 0.10 MiB/s | 0.07 MiB/s | 18.1 | 11.0 | 50.0 | 80.0 |
| 1000 | 880.3* | 0.276 | 0.234 | 35.4 MiB | 34.6 MiB | 10.80 MiB/s | 9.10 MiB/s | 3.840 | 2.608 | 159.9 MiB | 84.1 MiB | 5.90 MiB/s | 4.16 MiB/s | 0.138 | 0.126 | 103.5 MiB | 101.4 MiB | 0.09 MiB/s | 0.08 MiB/s | 60.0 | 56.0 | 129.0 | 189.0 |

### `ols-bulk-100`

_Group_: OLS-bulk. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource/bulk`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 95.2 | 0.333 | 0.215 | 35.5 MiB | 34.4 MiB | 13.46 MiB/s | 8.81 MiB/s | 4.508 | 2.977 | 122.3 MiB | 83.1 MiB | 6.86 MiB/s | 4.69 MiB/s | 0.188 | 0.184 | 109.3 MiB | 105.7 MiB | 0.13 MiB/s | 0.13 MiB/s | 8.1 | 8.0 | 10.0 | 13.0 |
| 200 | 189.9 | 0.092 | 0.070 | 35.2 MiB | 34.2 MiB | 4.71 MiB/s | 3.48 MiB/s | 1.255 | 0.874 | 86.0 MiB | 58.9 MiB | 2.45 MiB/s | 1.80 MiB/s | 0.064 | 0.054 | 113.8 MiB | 106.0 MiB | 0.04 MiB/s | 0.03 MiB/s | 10.7 | 11.0 | 15.0 | 18.0 |
| 300 | 285.4 | 0.146 | 0.116 | 35.4 MiB | 35.1 MiB | 8.00 MiB/s | 6.13 MiB/s | 1.998 | 1.645 | 85.6 MiB | 82.0 MiB | 3.64 MiB/s | 3.01 MiB/s | 0.110 | 0.078 | 117.0 MiB | 108.3 MiB | 0.07 MiB/s | 0.05 MiB/s | 11.7 | 12.0 | 17.0 | 26.0 |
| 400 | 377.2 | 0.188 | 0.156 | 35.8 MiB | 34.4 MiB | 10.21 MiB/s | 8.53 MiB/s | 3.005 | 2.511 | 89.9 MiB | 75.1 MiB | 5.29 MiB/s | 4.47 MiB/s | 0.141 | 0.126 | 116.4 MiB | 114.2 MiB | 0.08 MiB/s | 0.08 MiB/s | 13.7 | 12.0 | 25.0 | 45.0 |
| 500 | 468.2 | 0.249 | 0.216 | 35.5 MiB | 34.6 MiB | 12.30 MiB/s | 11.07 MiB/s | 3.765 | 3.158 | 120.4 MiB | 85.4 MiB | 6.23 MiB/s | 5.39 MiB/s | 0.187 | 0.164 | 120.8 MiB | 117.5 MiB | 0.11 MiB/s | 0.09 MiB/s | 19.3 | 16.0 | 39.0 | 84.0 |
| 1000 | 653.5* | 0.357 | 0.296 | 37.2 MiB | 35.4 MiB | 16.42 MiB/s | 14.10 MiB/s | 5.576 | 4.456 | 200.3 MiB | 113.5 MiB | 8.25 MiB/s | 6.95 MiB/s | 0.234 | 0.194 | 122.7 MiB | 118.8 MiB | 0.13 MiB/s | 0.11 MiB/s | 122.4 | 115.0 | 232.0 | 293.0 |

### `ols-bulk-1000`

_Group_: OLS-bulk. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource/bulk`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 62.2* | 0.373 | 0.223 | 39.6 MiB | 37.9 MiB | 16.82 MiB/s | 12.37 MiB/s | 5.566 | 4.608 | 265.1 MiB | 159.0 MiB | 8.03 MiB/s | 6.55 MiB/s | 0.276 | 0.234 | 131.5 MiB | 124.8 MiB | 0.18 MiB/s | 0.15 MiB/s | 132.1 | 134.0 | 150.0 | 170.0 |
| 200 | 64.6* | 0.160 | 0.150 | 40.1 MiB | 39.4 MiB | 15.43 MiB/s | 14.55 MiB/s | 6.398 | 5.392 | 277.1 MiB | 193.0 MiB | 8.95 MiB/s | 7.56 MiB/s | 0.377 | 0.285 | 128.7 MiB | 125.7 MiB | 0.54 MiB/s | 0.41 MiB/s | 262.5 | 271.0 | 302.0 | 315.0 |
| 300 | 66.0* | 0.182 | 0.166 | 41.1 MiB | 40.8 MiB | 18.02 MiB/s | 16.18 MiB/s | 6.268 | 5.641 | 361.2 MiB | 225.3 MiB | 8.65 MiB/s | 7.83 MiB/s | 0.299 | 0.266 | 130.2 MiB | 128.7 MiB | 0.40 MiB/s | 0.35 MiB/s | 389.4 | 403.0 | 456.0 | 480.0 |
| 400 | 65.9* | 0.161 | 0.154 | 40.9 MiB | 40.6 MiB | 15.70 MiB/s | 14.92 MiB/s | 6.155 | 5.850 | 396.8 MiB | 228.2 MiB | 8.86 MiB/s | 8.30 MiB/s | 0.323 | 0.271 | 135.3 MiB | 133.8 MiB | 0.45 MiB/s | 0.38 MiB/s | 520.7 | 538.0 | 581.0 | 597.0 |
| 500 | 66.3* | 0.166 | 0.162 | 41.6 MiB | 40.2 MiB | 15.90 MiB/s | 15.45 MiB/s | 5.756 | 5.438 | 519.3 MiB | 393.0 MiB | 8.12 MiB/s | 7.66 MiB/s | 0.285 | 0.267 | 141.3 MiB | 139.8 MiB | 0.38 MiB/s | 0.35 MiB/s | 648.1 | 666.0 | 737.0 | 764.0 |
| 1000 | 66.9* | 0.175 | 0.169 | 42.9 MiB | 40.8 MiB | 16.81 MiB/s | 16.06 MiB/s | 5.877 | 5.494 | 686.2 MiB | 480.3 MiB | 8.13 MiB/s | 7.68 MiB/s | 0.312 | 0.272 | 148.8 MiB | 146.7 MiB | 0.45 MiB/s | 0.38 MiB/s | 1279.1 | 1307.0 | 1396.0 | 1421.0 |

### `rls-condition-1-expression`

_Group_: RLS-condition. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 95.9 | 0.171 | 0.109 | 39.8 MiB | 39.5 MiB | 16.26 MiB/s | 9.14 MiB/s | 5.267 | 2.924 | 113.5 MiB | 72.6 MiB | 7.88 MiB/s | 4.76 MiB/s | 0.250 | 0.211 | 152.3 MiB | 151.1 MiB | 0.38 MiB/s | 0.33 MiB/s | 3.5 | 3.0 | 5.0 | 6.0 |
| 200 | 191.8 | 0.063 | 0.051 | 39.7 MiB | 38.9 MiB | 1.01 MiB/s | 0.75 MiB/s | 0.358 | 0.260 | 70.3 MiB | 57.4 MiB | 0.59 MiB/s | 0.43 MiB/s | 0.038 | 0.018 | 151.6 MiB | 150.0 MiB | 0.06 MiB/s | 0.02 MiB/s | 3.6 | 3.0 | 5.0 | 20.0 |
| 300 | 288.1 | 0.078 | 0.069 | 39.3 MiB | 38.3 MiB | 1.33 MiB/s | 1.18 MiB/s | 0.462 | 0.398 | 75.8 MiB | 50.6 MiB | 0.76 MiB/s | 0.66 MiB/s | 0.021 | 0.018 | 153.9 MiB | 152.1 MiB | 0.02 MiB/s | 0.02 MiB/s | 3.6 | 3.0 | 5.0 | 22.0 |
| 400 | 383.5 | 0.110 | 0.098 | 39.7 MiB | 38.6 MiB | 2.06 MiB/s | 1.79 MiB/s | 0.697 | 0.581 | 98.6 MiB | 62.3 MiB | 1.13 MiB/s | 0.95 MiB/s | 0.024 | 0.023 | 153.2 MiB | 152.4 MiB | 0.02 MiB/s | 0.02 MiB/s | 3.7 | 3.0 | 6.0 | 21.0 |
| 500 | 478.5 | 0.138 | 0.124 | 39.7 MiB | 39.0 MiB | 2.68 MiB/s | 2.39 MiB/s | 1.019 | 0.847 | 77.5 MiB | 62.6 MiB | 1.65 MiB/s | 1.37 MiB/s | 0.033 | 0.031 | 152.6 MiB | 152.2 MiB | 0.03 MiB/s | 0.03 MiB/s | 3.8 | 3.0 | 6.0 | 27.0 |
| 1000 | 955.8 | 0.233 | 0.173 | 39.4 MiB | 38.8 MiB | 4.29 MiB/s | 3.27 MiB/s | 1.961 | 1.350 | 117.6 MiB | 95.3 MiB | 2.59 MiB/s | 1.96 MiB/s | 0.044 | 0.033 | 154.6 MiB | 152.9 MiB | 0.05 MiB/s | 0.03 MiB/s | 11.4 | 8.0 | 34.0 | 57.0 |

### `rls-condition-2-expression`

_Group_: RLS-condition. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 96.1 | 0.290 | 0.173 | 38.7 MiB | 37.8 MiB | 5.26 MiB/s | 3.12 MiB/s | 2.262 | 1.411 | 71.8 MiB | 51.5 MiB | 2.80 MiB/s | 1.79 MiB/s | 0.058 | 0.046 | 153.8 MiB | 153.6 MiB | 0.07 MiB/s | 0.05 MiB/s | 3.6 | 3.0 | 5.0 | 6.0 |
| 200 | 191.8 | 0.062 | 0.052 | 39.0 MiB | 38.5 MiB | 1.08 MiB/s | 0.83 MiB/s | 0.427 | 0.304 | 76.2 MiB | 66.8 MiB | 0.65 MiB/s | 0.47 MiB/s | 0.015 | 0.013 | 155.2 MiB | 153.7 MiB | 0.01 MiB/s | 0.01 MiB/s | 3.8 | 3.0 | 5.0 | 19.0 |
| 300 | 287.7 | 0.088 | 0.073 | 39.9 MiB | 38.1 MiB | 1.58 MiB/s | 1.29 MiB/s | 0.642 | 0.513 | 80.2 MiB | 70.9 MiB | 0.95 MiB/s | 0.78 MiB/s | 0.020 | 0.018 | 156.7 MiB | 155.3 MiB | 0.02 MiB/s | 0.02 MiB/s | 4.1 | 3.0 | 6.0 | 23.0 |
| 400 | 383.3 | 0.111 | 0.101 | 39.7 MiB | 38.8 MiB | 2.14 MiB/s | 1.89 MiB/s | 0.815 | 0.718 | 79.0 MiB | 58.3 MiB | 1.26 MiB/s | 1.09 MiB/s | 0.032 | 0.025 | 156.3 MiB | 155.8 MiB | 0.04 MiB/s | 0.02 MiB/s | 3.7 | 3.0 | 6.0 | 20.0 |
| 500 | 479.0 | 0.149 | 0.125 | 39.9 MiB | 38.3 MiB | 2.94 MiB/s | 2.45 MiB/s | 1.079 | 0.892 | 75.2 MiB | 63.2 MiB | 1.68 MiB/s | 1.38 MiB/s | 0.028 | 0.026 | 156.5 MiB | 155.7 MiB | 0.03 MiB/s | 0.03 MiB/s | 4.1 | 3.0 | 7.0 | 29.0 |
| 1000 | 954.6 | 0.258 | 0.182 | 39.5 MiB | 38.2 MiB | 4.76 MiB/s | 3.45 MiB/s | 2.128 | 1.367 | 122.1 MiB | 68.7 MiB | 2.56 MiB/s | 1.84 MiB/s | 0.043 | 0.035 | 157.7 MiB | 155.7 MiB | 0.05 MiB/s | 0.04 MiB/s | 12.8 | 8.0 | 36.0 | 62.0 |

### `rls-condition-3-expression`

_Group_: RLS-condition. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 95.9 | 0.286 | 0.156 | 38.9 MiB | 38.1 MiB | 5.19 MiB/s | 2.79 MiB/s | 2.497 | 1.425 | 74.0 MiB | 53.6 MiB | 2.90 MiB/s | 1.71 MiB/s | 0.068 | 0.050 | 158.8 MiB | 157.1 MiB | 0.07 MiB/s | 0.05 MiB/s | 3.8 | 4.0 | 5.0 | 6.0 |
| 200 | 192.0 | 0.060 | 0.049 | 38.5 MiB | 38.0 MiB | 0.98 MiB/s | 0.76 MiB/s | 0.408 | 0.295 | 74.7 MiB | 66.8 MiB | 0.58 MiB/s | 0.44 MiB/s | 0.018 | 0.014 | 158.8 MiB | 158.1 MiB | 0.02 MiB/s | 0.01 MiB/s | 4.4 | 4.0 | 6.0 | 21.0 |
| 300 | 287.6 | 0.087 | 0.075 | 39.3 MiB | 38.4 MiB | 1.62 MiB/s | 1.33 MiB/s | 0.652 | 0.517 | 76.1 MiB | 50.5 MiB | 0.93 MiB/s | 0.72 MiB/s | 0.023 | 0.020 | 158.9 MiB | 158.5 MiB | 0.02 MiB/s | 0.02 MiB/s | 4.1 | 3.0 | 6.0 | 21.0 |
| 400 | 383.5 | 0.120 | 0.105 | 38.9 MiB | 38.3 MiB | 2.31 MiB/s | 2.02 MiB/s | 1.033 | 0.816 | 83.2 MiB | 67.1 MiB | 1.39 MiB/s | 1.14 MiB/s | 0.029 | 0.024 | 158.8 MiB | 157.8 MiB | 0.03 MiB/s | 0.02 MiB/s | 4.9 | 4.0 | 9.0 | 24.0 |
| 500 | 478.8 | 0.143 | 0.129 | 38.8 MiB | 37.9 MiB | 2.77 MiB/s | 2.46 MiB/s | 1.330 | 1.146 | 82.5 MiB | 71.4 MiB | 1.72 MiB/s | 1.49 MiB/s | 0.038 | 0.031 | 162.1 MiB | 159.6 MiB | 0.04 MiB/s | 0.03 MiB/s | 5.4 | 4.0 | 10.0 | 25.0 |
| 1000 | 953.3 | 0.266 | 0.191 | 39.2 MiB | 38.2 MiB | 4.99 MiB/s | 3.65 MiB/s | 2.544 | 1.731 | 179.0 MiB | 105.4 MiB | 2.78 MiB/s | 2.02 MiB/s | 0.039 | 0.036 | 162.8 MiB | 160.1 MiB | 0.04 MiB/s | 0.04 MiB/s | 14.7 | 10.0 | 42.0 | 68.0 |

### `rls-condition-5-expression`

_Group_: RLS-condition. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 96.0 | 0.286 | 0.151 | 39.0 MiB | 38.1 MiB | 5.31 MiB/s | 2.77 MiB/s | 2.573 | 1.435 | 72.1 MiB | 58.4 MiB | 2.79 MiB/s | 1.60 MiB/s | 0.067 | 0.051 | 164.1 MiB | 162.2 MiB | 0.07 MiB/s | 0.05 MiB/s | 4.5 | 4.0 | 6.0 | 7.0 |
| 200 | 191.5 | 0.062 | 0.049 | 38.8 MiB | 37.7 MiB | 1.05 MiB/s | 0.81 MiB/s | 0.454 | 0.349 | 75.5 MiB | 66.8 MiB | 0.62 MiB/s | 0.48 MiB/s | 0.020 | 0.015 | 166.3 MiB | 161.5 MiB | 0.02 MiB/s | 0.01 MiB/s | 4.0 | 4.0 | 6.0 | 6.0 |
| 300 | 288.0 | 0.095 | 0.081 | 38.9 MiB | 38.3 MiB | 1.77 MiB/s | 1.46 MiB/s | 0.805 | 0.631 | 76.3 MiB | 63.2 MiB | 1.07 MiB/s | 0.86 MiB/s | 0.025 | 0.021 | 163.4 MiB | 162.6 MiB | 0.02 MiB/s | 0.02 MiB/s | 4.2 | 4.0 | 6.0 | 8.0 |
| 400 | 382.6 | 0.108 | 0.100 | 39.1 MiB | 38.7 MiB | 2.21 MiB/s | 1.97 MiB/s | 1.134 | 0.880 | 74.7 MiB | 67.7 MiB | 1.52 MiB/s | 1.17 MiB/s | 0.032 | 0.026 | 164.6 MiB | 163.0 MiB | 0.03 MiB/s | 0.02 MiB/s | 4.2 | 4.0 | 7.0 | 9.0 |
| 500 | 479.4 | 0.143 | 0.125 | 39.3 MiB | 37.9 MiB | 2.96 MiB/s | 2.59 MiB/s | 1.166 | 0.973 | 82.8 MiB | 53.4 MiB | 1.52 MiB/s | 1.29 MiB/s | 0.035 | 0.031 | 165.3 MiB | 163.8 MiB | 0.03 MiB/s | 0.03 MiB/s | 4.5 | 4.0 | 7.0 | 10.0 |
| 1000 | 956.0 | 0.278 | 0.202 | 39.6 MiB | 38.5 MiB | 5.53 MiB/s | 4.04 MiB/s | 2.737 | 1.905 | 110.8 MiB | 79.2 MiB | 3.16 MiB/s | 2.28 MiB/s | 0.052 | 0.045 | 164.6 MiB | 163.2 MiB | 0.05 MiB/s | 0.04 MiB/s | 5.7 | 5.0 | 10.0 | 19.0 |

### `rls-predicate`

_Group_: RLS-predicate. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 96.0 | 0.317 | 0.160 | 38.8 MiB | 38.3 MiB | 6.36 MiB/s | 3.14 MiB/s | 2.516 | 1.453 | 62.5 MiB | 58.9 MiB | 2.92 MiB/s | 1.74 MiB/s | 0.077 | 0.064 | 165.1 MiB | 164.9 MiB | 0.07 MiB/s | 0.06 MiB/s | 3.2 | 3.0 | 5.0 | 5.0 |
| 200 | 191.9 | 0.061 | 0.050 | 39.3 MiB | 37.9 MiB | 0.91 MiB/s | 0.69 MiB/s | 0.313 | 0.228 | 80.0 MiB | 55.5 MiB | 0.52 MiB/s | 0.38 MiB/s | 0.015 | 0.013 | 164.9 MiB | 164.2 MiB | 0.01 MiB/s | 0.01 MiB/s | 3.4 | 3.0 | 5.0 | 19.0 |
| 300 | 288.0 | 0.087 | 0.075 | 39.4 MiB | 39.0 MiB | 1.49 MiB/s | 1.23 MiB/s | 0.548 | 0.426 | 75.9 MiB | 60.1 MiB | 0.91 MiB/s | 0.71 MiB/s | 0.025 | 0.019 | 168.4 MiB | 165.9 MiB | 0.03 MiB/s | 0.02 MiB/s | 3.4 | 3.0 | 5.0 | 19.0 |
| 400 | 382.0 | 0.107 | 0.090 | 39.2 MiB | 38.1 MiB | 1.92 MiB/s | 1.59 MiB/s | 0.696 | 0.603 | 74.2 MiB | 69.3 MiB | 1.17 MiB/s | 1.00 MiB/s | 0.027 | 0.025 | 169.0 MiB | 166.8 MiB | 0.03 MiB/s | 0.02 MiB/s | 3.4 | 3.0 | 5.0 | 22.0 |
| 500 | 479.4 | 0.136 | 0.121 | 39.2 MiB | 38.2 MiB | 2.54 MiB/s | 2.21 MiB/s | 0.920 | 0.753 | 86.9 MiB | 62.7 MiB | 1.46 MiB/s | 1.25 MiB/s | 0.029 | 0.028 | 168.3 MiB | 167.2 MiB | 0.03 MiB/s | 0.03 MiB/s | 4.0 | 3.0 | 7.0 | 24.0 |
| 1000 | 953.8 | 0.249 | 0.176 | 39.9 MiB | 39.0 MiB | 4.58 MiB/s | 3.23 MiB/s | 2.054 | 1.345 | 93.4 MiB | 85.7 MiB | 2.83 MiB/s | 1.94 MiB/s | 0.061 | 0.041 | 170.3 MiB | 169.2 MiB | 0.07 MiB/s | 0.04 MiB/s | 7.4 | 4.0 | 24.0 | 43.0 |

### `rls-predicate-summary-2-predicates`

_Group_: RLS-predicate. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 95.9 | 0.258 | 0.169 | 38.3 MiB | 37.5 MiB | 4.69 MiB/s | 3.06 MiB/s | 2.016 | 1.293 | 101.3 MiB | 74.7 MiB | 2.73 MiB/s | 1.81 MiB/s | 0.059 | 0.048 | 171.4 MiB | 168.8 MiB | 0.06 MiB/s | 0.05 MiB/s | 3.4 | 3.0 | 5.0 | 6.0 |
| 200 | 191.8 | 0.063 | 0.052 | 39.0 MiB | 38.2 MiB | 1.11 MiB/s | 0.83 MiB/s | 0.361 | 0.259 | 69.7 MiB | 51.1 MiB | 0.65 MiB/s | 0.48 MiB/s | 0.017 | 0.013 | 170.5 MiB | 168.2 MiB | 0.01 MiB/s | 0.01 MiB/s | 3.6 | 3.0 | 5.0 | 20.0 |
| 300 | 287.6 | 0.095 | 0.074 | 39.7 MiB | 38.8 MiB | 1.78 MiB/s | 1.35 MiB/s | 0.526 | 0.433 | 79.3 MiB | 71.9 MiB | 0.92 MiB/s | 0.78 MiB/s | 0.021 | 0.019 | 170.9 MiB | 169.2 MiB | 0.02 MiB/s | 0.02 MiB/s | 3.8 | 3.0 | 6.0 | 21.0 |
| 400 | 383.0 | 0.114 | 0.100 | 39.4 MiB | 38.0 MiB | 2.28 MiB/s | 1.93 MiB/s | 0.712 | 0.599 | 71.7 MiB | 49.5 MiB | 1.26 MiB/s | 1.05 MiB/s | 0.030 | 0.024 | 172.4 MiB | 170.3 MiB | 0.03 MiB/s | 0.02 MiB/s | 3.9 | 3.0 | 7.0 | 22.0 |
| 500 | 479.2 | 0.145 | 0.129 | 39.8 MiB | 38.6 MiB | 2.98 MiB/s | 2.63 MiB/s | 1.042 | 0.855 | 82.7 MiB | 66.2 MiB | 1.77 MiB/s | 1.49 MiB/s | 0.037 | 0.031 | 170.8 MiB | 169.8 MiB | 0.04 MiB/s | 0.03 MiB/s | 4.2 | 3.0 | 8.0 | 25.0 |
| 1000 | 954.8 | 0.263 | 0.177 | 39.2 MiB | 38.9 MiB | 5.36 MiB/s | 3.63 MiB/s | 1.679 | 1.257 | 96.4 MiB | 76.3 MiB | 2.47 MiB/s | 2.01 MiB/s | 0.043 | 0.038 | 170.6 MiB | 170.4 MiB | 0.04 MiB/s | 0.04 MiB/s | 7.3 | 4.0 | 23.0 | 44.0 |

### `rls-predicate-summary-3-predicates`

_Group_: RLS-predicate. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 96.0 | 0.270 | 0.172 | 37.9 MiB | 37.6 MiB | 5.40 MiB/s | 3.44 MiB/s | 2.087 | 1.344 | 61.7 MiB | 44.5 MiB | 3.06 MiB/s | 2.03 MiB/s | 0.064 | 0.050 | 170.9 MiB | 170.9 MiB | 0.07 MiB/s | 0.06 MiB/s | 3.5 | 3.0 | 5.0 | 6.0 |
| 200 | 191.7 | 0.065 | 0.053 | 38.7 MiB | 38.3 MiB | 1.18 MiB/s | 0.89 MiB/s | 0.375 | 0.270 | 74.0 MiB | 60.7 MiB | 0.69 MiB/s | 0.50 MiB/s | 0.018 | 0.015 | 174.7 MiB | 172.4 MiB | 0.01 MiB/s | 0.01 MiB/s | 3.4 | 3.0 | 5.0 | 6.0 |
| 300 | 287.4 | 0.089 | 0.075 | 39.0 MiB | 37.9 MiB | 1.74 MiB/s | 1.44 MiB/s | 0.546 | 0.457 | 73.1 MiB | 67.2 MiB | 1.00 MiB/s | 0.84 MiB/s | 0.026 | 0.021 | 175.8 MiB | 172.7 MiB | 0.02 MiB/s | 0.02 MiB/s | 3.2 | 3.0 | 5.0 | 6.0 |
| 400 | 383.3 | 0.118 | 0.102 | 39.0 MiB | 37.8 MiB | 2.44 MiB/s | 2.07 MiB/s | 0.832 | 0.676 | 75.4 MiB | 51.8 MiB | 1.46 MiB/s | 1.21 MiB/s | 0.031 | 0.028 | 172.7 MiB | 172.2 MiB | 0.03 MiB/s | 0.02 MiB/s | 3.6 | 3.0 | 6.0 | 8.0 |
| 500 | 479.0 | 0.147 | 0.124 | 39.3 MiB | 37.9 MiB | 3.08 MiB/s | 2.57 MiB/s | 1.026 | 0.855 | 81.1 MiB | 65.5 MiB | 1.75 MiB/s | 1.45 MiB/s | 0.038 | 0.031 | 176.6 MiB | 173.4 MiB | 0.03 MiB/s | 0.03 MiB/s | 3.7 | 3.0 | 7.0 | 8.0 |
| 1000 | 956.4 | 0.244 | 0.178 | 39.7 MiB | 38.4 MiB | 5.21 MiB/s | 3.76 MiB/s | 1.795 | 1.338 | 77.8 MiB | 70.3 MiB | 3.03 MiB/s | 2.28 MiB/s | 0.057 | 0.045 | 175.5 MiB | 173.3 MiB | 0.05 MiB/s | 0.04 MiB/s | 3.8 | 3.0 | 7.0 | 16.0 |

### `rls-predicate-summary-4-predicates`

_Group_: RLS-predicate. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 91.1 | 0.467 | 0.270 | 37.4 MiB | 36.9 MiB | 4.51 MiB/s | 2.63 MiB/s | 3.770 | 2.243 | 69.7 MiB | 48.1 MiB | 2.57 MiB/s | 1.58 MiB/s | 0.142 | 0.095 | 144.5 MiB | 144.0 MiB | 0.05 MiB/s | 0.04 MiB/s | 5.3 | 4.0 | 8.0 | 11.0 |
| 200 | 185.0 | 0.082 | 0.063 | 37.5 MiB | 36.8 MiB | 0.98 MiB/s | 0.77 MiB/s | 0.540 | 0.347 | 82.4 MiB | 54.1 MiB | 0.56 MiB/s | 0.40 MiB/s | 0.031 | 0.023 | 144.7 MiB | 143.2 MiB | 0.01 MiB/s | 0.01 MiB/s | 7.3 | 6.0 | 14.0 | 29.0 |
| 300 | 278.9 | 0.137 | 0.114 | 38.7 MiB | 37.4 MiB | 1.70 MiB/s | 1.41 MiB/s | 0.843 | 0.730 | 73.2 MiB | 55.7 MiB | 0.97 MiB/s | 0.79 MiB/s | 0.043 | 0.039 | 145.4 MiB | 144.0 MiB | 0.02 MiB/s | 0.02 MiB/s | 7.1 | 5.0 | 16.0 | 61.0 |
| 400 | 365.6 | 0.178 | 0.157 | 39.8 MiB | 37.9 MiB | 2.28 MiB/s | 1.97 MiB/s | 1.252 | 1.038 | 76.8 MiB | 68.9 MiB | 1.33 MiB/s | 1.15 MiB/s | 0.046 | 0.041 | 145.4 MiB | 143.6 MiB | 0.02 MiB/s | 0.02 MiB/s | 10.3 | 6.0 | 18.0 | 161.0 |
| 500 | 457.7 | 0.249 | 0.196 | 39.0 MiB | 38.2 MiB | 2.79 MiB/s | 2.34 MiB/s | 2.007 | 1.585 | 140.0 MiB | 84.3 MiB | 1.71 MiB/s | 1.52 MiB/s | 0.061 | 0.054 | 144.2 MiB | 143.8 MiB | 0.03 MiB/s | 0.03 MiB/s | 18.7 | 9.0 | 77.0 | 141.0 |
| 1000 | 752.6* | 0.480 | 0.322 | 39.5 MiB | 38.7 MiB | 4.85 MiB/s | 3.36 MiB/s | 3.493 | 2.551 | 185.5 MiB | 139.1 MiB | 2.47 MiB/s | 1.92 MiB/s | 0.144 | 0.100 | 146.2 MiB | 144.6 MiB | 0.05 MiB/s | 0.04 MiB/s | 74.8 | 50.0 | 214.0 | 351.0 |

### `rls-predicate-summary-5-predicates`

_Group_: RLS-predicate. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 93.8 | 0.428 | 0.219 | 38.5 MiB | 37.3 MiB | 4.33 MiB/s | 2.24 MiB/s | 3.624 | 1.857 | 68.3 MiB | 56.0 MiB | 2.48 MiB/s | 1.34 MiB/s | 0.144 | 0.085 | 146.8 MiB | 145.8 MiB | 0.06 MiB/s | 0.03 MiB/s | 5.7 | 5.0 | 10.0 | 28.0 |
| 200 | 187.2 | 0.085 | 0.069 | 38.7 MiB | 37.5 MiB | 1.07 MiB/s | 0.84 MiB/s | 0.593 | 0.415 | 74.3 MiB | 54.7 MiB | 0.65 MiB/s | 0.48 MiB/s | 0.033 | 0.023 | 148.6 MiB | 147.4 MiB | 0.02 MiB/s | 0.01 MiB/s | 6.8 | 6.0 | 12.0 | 31.0 |
| 300 | 280.1 | 0.136 | 0.114 | 38.3 MiB | 37.1 MiB | 1.75 MiB/s | 1.43 MiB/s | 0.922 | 0.779 | 76.1 MiB | 56.2 MiB | 1.02 MiB/s | 0.82 MiB/s | 0.041 | 0.033 | 148.5 MiB | 147.6 MiB | 0.02 MiB/s | 0.02 MiB/s | 6.6 | 5.0 | 14.0 | 48.0 |
| 400 | 372.5 | 0.187 | 0.158 | 38.7 MiB | 37.5 MiB | 2.26 MiB/s | 2.04 MiB/s | 1.451 | 1.096 | 85.8 MiB | 52.8 MiB | 1.33 MiB/s | 1.17 MiB/s | 0.049 | 0.046 | 147.3 MiB | 146.9 MiB | 0.02 MiB/s | 0.02 MiB/s | 10.8 | 8.0 | 27.0 | 56.0 |
| 500 | 453.2 | 0.262 | 0.229 | 39.0 MiB | 37.6 MiB | 2.99 MiB/s | 2.69 MiB/s | 2.035 | 1.708 | 107.9 MiB | 70.5 MiB | 1.73 MiB/s | 1.49 MiB/s | 0.087 | 0.066 | 147.7 MiB | 146.5 MiB | 0.03 MiB/s | 0.03 MiB/s | 18.5 | 8.0 | 77.0 | 169.0 |
| 1000 | 674.2* | 0.423 | 0.320 | 39.8 MiB | 38.0 MiB | 4.35 MiB/s | 3.43 MiB/s | 3.792 | 2.575 | 214.5 MiB | 137.6 MiB | 2.52 MiB/s | 1.93 MiB/s | 0.126 | 0.095 | 151.1 MiB | 148.0 MiB | 0.04 MiB/s | 0.03 MiB/s | 102.7 | 88.0 | 239.0 | 327.0 |

### `rls-predicate-summary-10-predicates`

_Group_: RLS-predicate. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 92.3 | 0.430 | 0.216 | 38.2 MiB | 37.3 MiB | 4.38 MiB/s | 2.25 MiB/s | 3.801 | 1.939 | 188.5 MiB | 85.9 MiB | 2.53 MiB/s | 1.37 MiB/s | 0.137 | 0.090 | 151.4 MiB | 150.4 MiB | 0.05 MiB/s | 0.04 MiB/s | 7.4 | 6.0 | 12.0 | 39.0 |
| 200 | 186.5 | 0.093 | 0.073 | 38.7 MiB | 38.0 MiB | 1.35 MiB/s | 1.02 MiB/s | 0.681 | 0.455 | 99.8 MiB | 71.8 MiB | 0.61 MiB/s | 0.48 MiB/s | 0.025 | 0.023 | 150.0 MiB | 149.3 MiB | 0.01 MiB/s | 0.01 MiB/s | 11.8 | 11.0 | 21.0 | 60.0 |
| 300 | 277.7 | 0.181 | 0.125 | 39.4 MiB | 38.0 MiB | 2.33 MiB/s | 1.68 MiB/s | 1.637 | 1.273 | 111.6 MiB | 77.3 MiB | 1.29 MiB/s | 1.05 MiB/s | 0.050 | 0.041 | 152.4 MiB | 150.6 MiB | 0.02 MiB/s | 0.02 MiB/s | 15.4 | 12.0 | 34.0 | 79.0 |
| 400 | 369.7 | 0.240 | 0.197 | 39.6 MiB | 37.3 MiB | 3.07 MiB/s | 2.55 MiB/s | 2.732 | 1.983 | 125.6 MiB | 89.8 MiB | 1.93 MiB/s | 1.49 MiB/s | 0.071 | 0.055 | 152.8 MiB | 151.1 MiB | 0.03 MiB/s | 0.02 MiB/s | 29.9 | 27.0 | 62.0 | 98.0 |
| 500 | 439.8* | 0.288 | 0.255 | 38.4 MiB | 37.4 MiB | 3.63 MiB/s | 3.23 MiB/s | 3.046 | 2.637 | 170.4 MiB | 102.2 MiB | 2.10 MiB/s | 1.83 MiB/s | 0.123 | 0.086 | 153.5 MiB | 152.6 MiB | 0.04 MiB/s | 0.03 MiB/s | 42.8 | 35.0 | 112.0 | 171.0 |
| 1000 | 576.8* | 0.382 | 0.328 | 39.3 MiB | 38.0 MiB | 4.50 MiB/s | 3.97 MiB/s | 4.009 | 3.363 | 270.4 MiB | 145.2 MiB | 2.63 MiB/s | 2.27 MiB/s | 0.124 | 0.113 | 153.8 MiB | 153.1 MiB | 0.04 MiB/s | 0.04 MiB/s | 134.9 | 117.0 | 308.0 | 438.0 |

### `rls-predicate-pips-1-token-pip`

_Group_: RLS-predicate-pips. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 93.1 | 0.388 | 0.228 | 38.2 MiB | 37.2 MiB | 4.57 MiB/s | 2.66 MiB/s | 3.960 | 2.331 | 65.2 MiB | 45.5 MiB | 2.58 MiB/s | 1.56 MiB/s | 0.141 | 0.108 | 155.1 MiB | 153.8 MiB | 0.05 MiB/s | 0.04 MiB/s | 5.1 | 4.0 | 8.0 | 18.0 |
| 200 | 186.0 | 0.075 | 0.058 | 38.5 MiB | 37.2 MiB | 0.84 MiB/s | 0.63 MiB/s | 0.426 | 0.314 | 75.1 MiB | 50.4 MiB | 0.48 MiB/s | 0.37 MiB/s | 0.029 | 0.022 | 156.1 MiB | 154.9 MiB | 0.01 MiB/s | 0.01 MiB/s | 7.0 | 5.0 | 12.0 | 68.0 |
| 300 | 275.0 | 0.126 | 0.105 | 38.3 MiB | 37.2 MiB | 1.43 MiB/s | 1.19 MiB/s | 0.910 | 0.652 | 106.8 MiB | 83.3 MiB | 0.82 MiB/s | 0.65 MiB/s | 0.033 | 0.032 | 157.1 MiB | 155.4 MiB | 0.01 MiB/s | 0.01 MiB/s | 10.6 | 7.0 | 30.0 | 77.0 |
| 400 | 370.5 | 0.179 | 0.149 | 38.7 MiB | 37.6 MiB | 1.91 MiB/s | 1.64 MiB/s | 1.507 | 1.180 | 105.4 MiB | 90.3 MiB | 1.21 MiB/s | 0.99 MiB/s | 0.066 | 0.049 | 157.5 MiB | 154.6 MiB | 0.04 MiB/s | 0.02 MiB/s | 16.2 | 11.0 | 52.0 | 104.0 |
| 500 | 461.4 | 0.251 | 0.194 | 39.0 MiB | 38.7 MiB | 2.58 MiB/s | 2.02 MiB/s | 1.844 | 1.631 | 136.5 MiB | 94.0 MiB | 1.40 MiB/s | 1.25 MiB/s | 0.060 | 0.051 | 154.5 MiB | 154.4 MiB | 0.03 MiB/s | 0.03 MiB/s | 22.4 | 15.0 | 63.0 | 139.0 |
| 1000 | 770.1* | 0.413 | 0.311 | 38.9 MiB | 37.8 MiB | 4.13 MiB/s | 3.11 MiB/s | 3.676 | 2.600 | 192.7 MiB | 144.0 MiB | 2.43 MiB/s | 1.80 MiB/s | 0.129 | 0.078 | 158.9 MiB | 156.7 MiB | 0.05 MiB/s | 0.04 MiB/s | 80.6 | 69.0 | 196.0 | 272.0 |

### `rls-predicate-pips-2-token-pip`

_Group_: RLS-predicate-pips. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 93.7 | 0.417 | 0.214 | 38.2 MiB | 37.7 MiB | 4.15 MiB/s | 2.13 MiB/s | 3.544 | 1.844 | 70.4 MiB | 48.8 MiB | 2.34 MiB/s | 1.27 MiB/s | 0.131 | 0.099 | 159.4 MiB | 157.5 MiB | 0.05 MiB/s | 0.04 MiB/s | 5.0 | 4.0 | 8.0 | 11.0 |
| 200 | 185.6 | 0.081 | 0.064 | 38.4 MiB | 37.1 MiB | 0.90 MiB/s | 0.70 MiB/s | 0.490 | 0.347 | 79.6 MiB | 51.1 MiB | 0.53 MiB/s | 0.41 MiB/s | 0.027 | 0.021 | 157.9 MiB | 157.3 MiB | 0.01 MiB/s | 0.01 MiB/s | 8.0 | 5.0 | 14.0 | 88.0 |
| 300 | 275.9 | 0.126 | 0.108 | 38.1 MiB | 37.2 MiB | 1.43 MiB/s | 1.24 MiB/s | 1.016 | 0.774 | 105.4 MiB | 62.6 MiB | 0.86 MiB/s | 0.72 MiB/s | 0.033 | 0.029 | 157.2 MiB | 157.0 MiB | 0.02 MiB/s | 0.01 MiB/s | 13.4 | 10.0 | 35.0 | 95.0 |
| 400 | 368.8 | 0.160 | 0.143 | 39.2 MiB | 37.5 MiB | 1.91 MiB/s | 1.69 MiB/s | 1.320 | 1.176 | 107.5 MiB | 59.5 MiB | 1.11 MiB/s | 0.99 MiB/s | 0.051 | 0.043 | 158.8 MiB | 158.2 MiB | 0.03 MiB/s | 0.02 MiB/s | 15.8 | 10.0 | 52.0 | 94.0 |
| 500 | 452.6 | 0.235 | 0.201 | 39.0 MiB | 37.8 MiB | 2.48 MiB/s | 2.23 MiB/s | 1.979 | 1.595 | 137.1 MiB | 83.5 MiB | 1.44 MiB/s | 1.26 MiB/s | 0.065 | 0.052 | 160.5 MiB | 159.1 MiB | 0.04 MiB/s | 0.03 MiB/s | 27.2 | 21.0 | 69.0 | 94.0 |
| 1000 | 754.0* | 0.380 | 0.296 | 39.8 MiB | 37.9 MiB | 3.91 MiB/s | 3.06 MiB/s | 3.351 | 2.443 | 205.3 MiB | 149.7 MiB | 2.26 MiB/s | 1.71 MiB/s | 0.077 | 0.066 | 159.4 MiB | 158.7 MiB | 0.04 MiB/s | 0.03 MiB/s | 82.0 | 65.0 | 218.0 | 325.0 |

### `rls-predicate-pips-3-token-pip`

_Group_: RLS-predicate-pips. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 93.7 | 0.420 | 0.249 | 38.4 MiB | 37.3 MiB | 4.33 MiB/s | 2.60 MiB/s | 3.241 | 2.196 | 73.5 MiB | 60.2 MiB | 2.23 MiB/s | 1.55 MiB/s | 0.104 | 0.073 | 163.0 MiB | 161.5 MiB | 0.06 MiB/s | 0.04 MiB/s | 5.4 | 4.0 | 10.0 | 13.0 |
| 200 | 186.5 | 0.087 | 0.067 | 38.8 MiB | 37.8 MiB | 1.02 MiB/s | 0.76 MiB/s | 0.600 | 0.401 | 82.9 MiB | 53.3 MiB | 0.59 MiB/s | 0.43 MiB/s | 0.026 | 0.021 | 162.8 MiB | 160.5 MiB | 0.01 MiB/s | 0.01 MiB/s | 9.8 | 7.0 | 20.0 | 59.0 |
| 300 | 279.2 | 0.147 | 0.115 | 38.4 MiB | 37.4 MiB | 1.75 MiB/s | 1.37 MiB/s | 1.123 | 0.851 | 84.9 MiB | 69.3 MiB | 1.04 MiB/s | 0.79 MiB/s | 0.033 | 0.030 | 162.0 MiB | 160.7 MiB | 0.02 MiB/s | 0.01 MiB/s | 10.1 | 6.0 | 30.0 | 71.0 |
| 400 | 369.2 | 0.200 | 0.167 | 39.0 MiB | 37.8 MiB | 2.23 MiB/s | 1.89 MiB/s | 1.730 | 1.302 | 123.3 MiB | 84.9 MiB | 1.36 MiB/s | 1.10 MiB/s | 0.069 | 0.045 | 162.1 MiB | 161.2 MiB | 0.04 MiB/s | 0.02 MiB/s | 18.3 | 13.0 | 50.0 | 119.0 |
| 500 | 461.0 | 0.246 | 0.216 | 39.3 MiB | 37.5 MiB | 2.71 MiB/s | 2.39 MiB/s | 1.966 | 1.732 | 121.2 MiB | 77.4 MiB | 1.60 MiB/s | 1.38 MiB/s | 0.063 | 0.061 | 162.6 MiB | 162.1 MiB | 0.03 MiB/s | 0.03 MiB/s | 19.1 | 11.0 | 66.0 | 131.0 |
| 1000 | 727.2* | 0.382 | 0.300 | 39.6 MiB | 38.1 MiB | 4.07 MiB/s | 3.25 MiB/s | 3.728 | 2.538 | 190.4 MiB | 118.9 MiB | 2.54 MiB/s | 1.90 MiB/s | 0.093 | 0.072 | 163.0 MiB | 162.1 MiB | 0.04 MiB/s | 0.03 MiB/s | 90.1 | 76.0 | 217.0 | 313.0 |

### `rls-predicate-pips-1-header-pip`

_Group_: RLS-predicate-pips. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 93.3 | 0.401 | 0.239 | 38.8 MiB | 37.3 MiB | 4.26 MiB/s | 2.55 MiB/s | 3.518 | 2.114 | 69.3 MiB | 47.6 MiB | 2.42 MiB/s | 1.50 MiB/s | 0.109 | 0.082 | 164.2 MiB | 163.8 MiB | 0.06 MiB/s | 0.05 MiB/s | 5.6 | 4.0 | 9.0 | 22.0 |
| 200 | 183.8 | 0.077 | 0.062 | 37.6 MiB | 36.9 MiB | 0.81 MiB/s | 0.65 MiB/s | 0.415 | 0.302 | 73.2 MiB | 65.3 MiB | 0.47 MiB/s | 0.35 MiB/s | 0.023 | 0.021 | 165.3 MiB | 163.8 MiB | 0.01 MiB/s | 0.01 MiB/s | 7.2 | 5.0 | 14.0 | 63.0 |
| 300 | 278.6 | 0.127 | 0.104 | 38.4 MiB | 37.2 MiB | 1.31 MiB/s | 1.11 MiB/s | 0.865 | 0.675 | 107.9 MiB | 77.1 MiB | 0.76 MiB/s | 0.67 MiB/s | 0.030 | 0.029 | 164.1 MiB | 163.7 MiB | 0.02 MiB/s | 0.01 MiB/s | 15.9 | 11.0 | 42.0 | 115.0 |
| 400 | 368.5 | 0.175 | 0.156 | 39.7 MiB | 38.2 MiB | 1.88 MiB/s | 1.65 MiB/s | 1.442 | 1.176 | 112.7 MiB | 78.7 MiB | 1.17 MiB/s | 0.95 MiB/s | 0.053 | 0.041 | 164.6 MiB | 163.7 MiB | 0.03 MiB/s | 0.02 MiB/s | 14.7 | 9.0 | 46.0 | 122.0 |
| 500 | 460.6 | 0.236 | 0.208 | 37.9 MiB | 37.2 MiB | 2.49 MiB/s | 2.19 MiB/s | 1.831 | 1.579 | 157.0 MiB | 102.4 MiB | 1.34 MiB/s | 1.21 MiB/s | 0.063 | 0.050 | 165.2 MiB | 164.7 MiB | 0.03 MiB/s | 0.03 MiB/s | 28.2 | 23.0 | 67.0 | 161.0 |
| 1000 | 753.3* | 0.411 | 0.302 | 39.9 MiB | 38.0 MiB | 4.06 MiB/s | 3.01 MiB/s | 3.815 | 2.645 | 203.6 MiB | 123.0 MiB | 2.51 MiB/s | 1.80 MiB/s | 0.100 | 0.077 | 167.7 MiB | 166.3 MiB | 0.04 MiB/s | 0.04 MiB/s | 81.8 | 65.0 | 212.0 | 318.0 |

### `rls-predicate-pips-2-header-pip`

_Group_: RLS-predicate-pips. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 94.0 | 0.405 | 0.223 | 38.1 MiB | 37.3 MiB | 3.97 MiB/s | 2.20 MiB/s | 3.465 | 1.871 | 69.1 MiB | 45.6 MiB | 2.31 MiB/s | 1.30 MiB/s | 0.113 | 0.072 | 166.5 MiB | 165.9 MiB | 0.05 MiB/s | 0.04 MiB/s | 5.0 | 4.0 | 8.0 | 19.0 |
| 200 | 185.7 | 0.080 | 0.064 | 39.3 MiB | 37.7 MiB | 0.84 MiB/s | 0.66 MiB/s | 0.473 | 0.322 | 76.3 MiB | 51.0 MiB | 0.49 MiB/s | 0.37 MiB/s | 0.028 | 0.023 | 168.0 MiB | 166.3 MiB | 0.01 MiB/s | 0.01 MiB/s | 7.9 | 6.0 | 15.0 | 63.0 |
| 300 | 277.6 | 0.123 | 0.107 | 38.9 MiB | 37.4 MiB | 1.38 MiB/s | 1.18 MiB/s | 0.834 | 0.703 | 100.3 MiB | 58.6 MiB | 0.78 MiB/s | 0.67 MiB/s | 0.031 | 0.028 | 167.0 MiB | 166.6 MiB | 0.01 MiB/s | 0.01 MiB/s | 9.1 | 6.0 | 22.0 | 68.0 |
| 400 | 365.4 | 0.168 | 0.144 | 38.8 MiB | 37.6 MiB | 1.83 MiB/s | 1.63 MiB/s | 1.187 | 0.950 | 121.6 MiB | 64.3 MiB | 0.99 MiB/s | 0.85 MiB/s | 0.051 | 0.041 | 168.8 MiB | 166.9 MiB | 0.03 MiB/s | 0.02 MiB/s | 16.1 | 11.0 | 48.0 | 95.0 |
| 500 | 461.7 | 0.248 | 0.211 | 39.2 MiB | 37.8 MiB | 2.43 MiB/s | 2.18 MiB/s | 1.979 | 1.489 | 133.1 MiB | 109.3 MiB | 1.46 MiB/s | 1.16 MiB/s | 0.070 | 0.053 | 169.8 MiB | 167.8 MiB | 0.03 MiB/s | 0.03 MiB/s | 23.9 | 16.0 | 72.0 | 126.0 |
| 1000 | 757.0* | 0.395 | 0.292 | 39.4 MiB | 38.4 MiB | 3.88 MiB/s | 2.84 MiB/s | 3.354 | 2.634 | 190.0 MiB | 126.8 MiB | 2.19 MiB/s | 1.83 MiB/s | 0.104 | 0.077 | 169.7 MiB | 168.6 MiB | 0.04 MiB/s | 0.03 MiB/s | 84.4 | 71.0 | 200.0 | 279.0 |

### `rls-predicate-pips-3-header-pip`

_Group_: RLS-predicate-pips. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 94.0 | 0.376 | 0.189 | 39.5 MiB | 38.2 MiB | 3.73 MiB/s | 1.84 MiB/s | 3.360 | 1.665 | 72.8 MiB | 54.9 MiB | 2.21 MiB/s | 1.16 MiB/s | 0.121 | 0.081 | 169.9 MiB | 169.4 MiB | 0.06 MiB/s | 0.04 MiB/s | 4.8 | 4.0 | 8.0 | 11.0 |
| 200 | 186.2 | 0.101 | 0.076 | 38.3 MiB | 37.6 MiB | 1.11 MiB/s | 0.79 MiB/s | 0.690 | 0.424 | 84.1 MiB | 68.6 MiB | 0.67 MiB/s | 0.45 MiB/s | 0.027 | 0.022 | 172.0 MiB | 169.7 MiB | 0.01 MiB/s | 0.01 MiB/s | 8.1 | 6.0 | 14.0 | 73.0 |
| 300 | 278.3 | 0.133 | 0.111 | 39.1 MiB | 37.4 MiB | 1.40 MiB/s | 1.18 MiB/s | 1.069 | 0.798 | 99.6 MiB | 69.3 MiB | 0.85 MiB/s | 0.70 MiB/s | 0.034 | 0.032 | 170.3 MiB | 170.0 MiB | 0.01 MiB/s | 0.01 MiB/s | 15.8 | 13.0 | 34.0 | 128.0 |
| 400 | 370.4 | 0.176 | 0.154 | 39.0 MiB | 37.9 MiB | 1.93 MiB/s | 1.71 MiB/s | 1.486 | 1.261 | 121.2 MiB | 77.0 MiB | 1.17 MiB/s | 0.99 MiB/s | 0.049 | 0.041 | 170.7 MiB | 170.4 MiB | 0.03 MiB/s | 0.02 MiB/s | 17.6 | 12.0 | 54.0 | 108.0 |
| 500 | 455.9 | 0.248 | 0.218 | 39.7 MiB | 38.1 MiB | 2.51 MiB/s | 2.27 MiB/s | 2.118 | 1.757 | 146.0 MiB | 87.1 MiB | 1.54 MiB/s | 1.32 MiB/s | 0.063 | 0.057 | 171.1 MiB | 170.2 MiB | 0.03 MiB/s | 0.03 MiB/s | 26.3 | 20.0 | 69.0 | 147.0 |
| 1000 | 747.6* | 0.415 | 0.305 | 39.1 MiB | 37.9 MiB | 4.03 MiB/s | 2.99 MiB/s | 3.565 | 2.588 | 194.4 MiB | 125.0 MiB | 2.33 MiB/s | 1.78 MiB/s | 0.088 | 0.072 | 173.8 MiB | 171.8 MiB | 0.04 MiB/s | 0.03 MiB/s | 84.2 | 73.0 | 195.0 | 258.0 |

### `rls-predicate-summary-10-predicates-3-token-pip`

_Group_: RLS-predicate-pips. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/filter`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 92.6 | 0.425 | 0.264 | 38.2 MiB | 37.6 MiB | 4.12 MiB/s | 2.64 MiB/s | 3.606 | 2.265 | 149.7 MiB | 82.3 MiB | 2.39 MiB/s | 1.57 MiB/s | 0.102 | 0.081 | 173.0 MiB | 172.6 MiB | 0.06 MiB/s | 0.05 MiB/s | 6.8 | 6.0 | 10.0 | 13.0 |
| 200 | 185.9 | 0.104 | 0.074 | 39.1 MiB | 37.9 MiB | 1.53 MiB/s | 1.09 MiB/s | 0.908 | 0.609 | 121.8 MiB | 86.6 MiB | 0.83 MiB/s | 0.63 MiB/s | 0.035 | 0.029 | 174.6 MiB | 173.6 MiB | 0.01 MiB/s | 0.01 MiB/s | 17.7 | 14.0 | 37.0 | 119.0 |
| 300 | 274.6 | 0.152 | 0.131 | 39.5 MiB | 38.1 MiB | 2.26 MiB/s | 1.97 MiB/s | 1.810 | 1.411 | 137.0 MiB | 85.3 MiB | 1.34 MiB/s | 1.09 MiB/s | 0.046 | 0.039 | 175.2 MiB | 173.9 MiB | 0.02 MiB/s | 0.02 MiB/s | 27.4 | 21.0 | 63.0 | 171.0 |
| 400 | 363.0 | 0.246 | 0.202 | 39.3 MiB | 37.7 MiB | 3.46 MiB/s | 2.90 MiB/s | 2.834 | 2.272 | 138.1 MiB | 95.9 MiB | 1.97 MiB/s | 1.61 MiB/s | 0.090 | 0.067 | 177.3 MiB | 174.2 MiB | 0.03 MiB/s | 0.03 MiB/s | 37.1 | 28.0 | 98.0 | 171.0 |
| 500 | 436.4* | 0.297 | 0.262 | 41.0 MiB | 38.2 MiB | 4.13 MiB/s | 3.64 MiB/s | 3.326 | 2.903 | 141.3 MiB | 91.5 MiB | 2.28 MiB/s | 2.00 MiB/s | 0.114 | 0.095 | 178.1 MiB | 175.7 MiB | 0.04 MiB/s | 0.04 MiB/s | 47.5 | 35.0 | 132.0 | 198.0 |
| 1000 | 505.3* | 0.322 | 0.312 | 39.7 MiB | 38.5 MiB | 4.49 MiB/s | 4.34 MiB/s | 4.060 | 3.570 | 211.1 MiB | 134.0 MiB | 2.64 MiB/s | 2.40 MiB/s | 0.122 | 0.111 | 179.0 MiB | 176.3 MiB | 0.04 MiB/s | 0.04 MiB/s | 160.9 | 160.0 | 305.0 | 403.0 |

### `wildcard-all-single`

_Group_: Wildcard. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 93.6 | 0.331 | 0.204 | 38.9 MiB | 37.7 MiB | 4.61 MiB/s | 2.81 MiB/s | 4.013 | 2.378 | 128.8 MiB | 77.7 MiB | 2.61 MiB/s | 1.58 MiB/s | 0.128 | 0.090 | 180.6 MiB | 179.5 MiB | 0.05 MiB/s | 0.03 MiB/s | 3.7 | 3.0 | 6.0 | 10.0 |
| 200 | 187.0 | 0.072 | 0.060 | 39.2 MiB | 37.9 MiB | 0.72 MiB/s | 0.58 MiB/s | 0.342 | 0.257 | 73.2 MiB | 62.9 MiB | 0.44 MiB/s | 0.35 MiB/s | 0.023 | 0.020 | 179.3 MiB | 178.1 MiB | 0.01 MiB/s | 0.01 MiB/s | 7.0 | 4.0 | 12.0 | 78.0 |
| 300 | 275.5 | 0.129 | 0.102 | 39.3 MiB | 38.2 MiB | 1.32 MiB/s | 1.05 MiB/s | 0.833 | 0.637 | 105.2 MiB | 80.4 MiB | 0.81 MiB/s | 0.66 MiB/s | 0.035 | 0.029 | 179.7 MiB | 179.3 MiB | 0.02 MiB/s | 0.02 MiB/s | 11.5 | 7.0 | 32.0 | 94.0 |
| 400 | 370.5 | 0.173 | 0.153 | 39.0 MiB | 38.4 MiB | 1.77 MiB/s | 1.57 MiB/s | 1.182 | 0.913 | 111.7 MiB | 86.5 MiB | 1.08 MiB/s | 0.86 MiB/s | 0.041 | 0.037 | 180.2 MiB | 178.7 MiB | 0.02 MiB/s | 0.02 MiB/s | 17.3 | 13.0 | 44.0 | 121.0 |
| 500 | 465.8 | 0.206 | 0.191 | 39.7 MiB | 38.8 MiB | 2.15 MiB/s | 1.97 MiB/s | 1.338 | 1.208 | 84.5 MiB | 65.4 MiB | 1.29 MiB/s | 1.14 MiB/s | 0.052 | 0.039 | 179.0 MiB | 178.8 MiB | 0.03 MiB/s | 0.02 MiB/s | 12.0 | 7.0 | 42.0 | 79.0 |
| 1000 | 862.9* | 0.456 | 0.306 | 40.1 MiB | 38.7 MiB | 4.46 MiB/s | 3.03 MiB/s | 3.126 | 2.027 | 122.6 MiB | 77.6 MiB | 2.55 MiB/s | 1.77 MiB/s | 0.106 | 0.084 | 181.8 MiB | 180.9 MiB | 0.04 MiB/s | 0.04 MiB/s | 46.8 | 32.0 | 137.0 | 188.0 |

### `wildcard-mixed-bulk`

_Group_: Wildcard. _Canonical endpoint_: `/access/v1/authorize`. _Legacy endpoint_: `/access/v1/check/resource/bulk`.

| RPS | achieved | envoy CPU peak | envoy CPU avg | envoy RAM peak | envoy RAM avg | envoy IO peak | envoy IO avg | opa CPU peak | opa CPU avg | opa RAM peak | opa RAM avg | opa IO peak | opa IO avg | dlc CPU peak | dlc CPU avg | dlc RAM peak | dlc RAM avg | dlc IO peak | dlc IO avg | rt avg | rt median | rt p95 | rt p99 |
| ----: | ---------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: | -------: |
| 100 | 91.2 | 0.425 | 0.245 | 38.7 MiB | 37.9 MiB | 4.12 MiB/s | 2.55 MiB/s | 2.981 | 2.092 | 102.1 MiB | 58.7 MiB | 2.45 MiB/s | 1.55 MiB/s | 0.123 | 0.094 | 186.5 MiB | 182.2 MiB | 0.06 MiB/s | 0.05 MiB/s | 37.4 | 36.0 | 56.0 | 110.0 |
| 200 | 162.2* | 0.155 | 0.102 | 39.1 MiB | 38.0 MiB | 2.71 MiB/s | 1.96 MiB/s | 4.301 | 2.702 | 142.9 MiB | 88.3 MiB | 1.37 MiB/s | 0.94 MiB/s | 0.088 | 0.058 | 186.3 MiB | 184.4 MiB | 0.02 MiB/s | 0.02 MiB/s | 79.9 | 73.0 | 149.0 | 196.0 |
| 300 | 169.4* | 0.163 | 0.150 | 39.6 MiB | 38.3 MiB | 2.82 MiB/s | 2.57 MiB/s | 4.711 | 4.490 | 167.7 MiB | 132.7 MiB | 1.46 MiB/s | 1.43 MiB/s | 0.111 | 0.091 | 183.1 MiB | 181.4 MiB | 0.03 MiB/s | 0.02 MiB/s | 148.3 | 135.0 | 270.0 | 352.0 |
| 400 | 161.7* | 0.179 | 0.174 | 39.7 MiB | 38.2 MiB | 3.07 MiB/s | 2.96 MiB/s | 5.178 | 4.811 | 195.7 MiB | 163.7 MiB | 1.62 MiB/s | 1.51 MiB/s | 0.092 | 0.086 | 190.8 MiB | 186.9 MiB | 0.03 MiB/s | 0.03 MiB/s | 211.5 | 188.0 | 422.0 | 580.0 |
| 500 | 158.2* | 0.174 | 0.156 | 38.9 MiB | 38.6 MiB | 2.96 MiB/s | 2.64 MiB/s | 4.732 | 4.379 | 209.2 MiB | 161.5 MiB | 1.45 MiB/s | 1.35 MiB/s | 0.128 | 0.095 | 192.7 MiB | 187.5 MiB | 0.04 MiB/s | 0.03 MiB/s | 271.1 | 246.0 | 537.0 | 746.0 |
| 1000 | 164.4* | 0.170 | 0.163 | 39.6 MiB | 38.4 MiB | 3.01 MiB/s | 2.79 MiB/s | 5.034 | 4.646 | 264.6 MiB | 170.3 MiB | 1.54 MiB/s | 1.43 MiB/s | 0.105 | 0.090 | 190.5 MiB | 185.8 MiB | 0.03 MiB/s | 0.02 MiB/s | 524.7 | 484.0 | 981.0 | 1292.0 |

## Notes

- The following (scenario, RPS) rows under-delivered (`achieved_rps < 0.9 × target_rps`) and are marked with `*` in the tables above (D-18). The promote-gate still applies to these rows — saturation shows up as a stable high p95 rather than dropped rows:
  - `rls-predicate-summary-4-predicates` at 1000 RPS — achieved 752.6/s
  - `rls-predicate-summary-5-predicates` at 1000 RPS — achieved 674.2/s
  - `rls-predicate-summary-10-predicates` at 500 RPS — achieved 439.8/s
  - `rls-predicate-summary-10-predicates` at 1000 RPS — achieved 576.8/s
  - `rls-predicate-pips-1-token-pip` at 1000 RPS — achieved 770.1/s
  - `rls-predicate-pips-2-token-pip` at 1000 RPS — achieved 754.0/s
  - `rls-predicate-pips-3-token-pip` at 1000 RPS — achieved 727.2/s
  - `rls-predicate-pips-1-header-pip` at 1000 RPS — achieved 753.3/s
  - `rls-predicate-pips-2-header-pip` at 1000 RPS — achieved 757.0/s
  - `rls-predicate-pips-3-header-pip` at 1000 RPS — achieved 747.6/s
  - `rls-predicate-summary-10-predicates-3-token-pip` at 500 RPS — achieved 436.4/s
  - `rls-predicate-summary-10-predicates-3-token-pip` at 1000 RPS — achieved 505.3/s
  - `wildcard-all-single` at 1000 RPS — achieved 862.9/s
  - `wildcard-mixed-bulk` at 200 RPS — achieved 162.2/s
  - `wildcard-mixed-bulk` at 300 RPS — achieved 169.4/s
  - `wildcard-mixed-bulk` at 400 RPS — achieved 161.7/s
  - `wildcard-mixed-bulk` at 500 RPS — achieved 158.2/s
  - `wildcard-mixed-bulk` at 1000 RPS — achieved 164.4/s

  - `ols-bulk-1000` at 100 RPS — achieved 62.2/s
  - `ols-bulk-1000` at 200 RPS — achieved 64.6/s
  - `ols-bulk-1000` at 300 RPS — achieved 66.0/s
  - `ols-bulk-1000` at 400 RPS — achieved 65.9/s
  - `ols-bulk-1000` at 500 RPS — achieved 66.3/s
  - `ols-bulk-1000` at 1000 RPS — achieved 66.9/s

  - `ols-bulk-100` at 1000 RPS — achieved 653.5/s

  - `ols-bulk-50` at 1000 RPS — achieved 880.3/s
