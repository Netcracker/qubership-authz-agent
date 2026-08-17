# SVT Assets

This directory is the single repository root for all load-testing and service-validation-testing
assets.

Use `tests/svt/` for everything related to the local load-testing stack introduced by ADR-0030:

- Docker Compose files and helper assets for the SVT environment
- `JMeter` test plans, data files, and result artifacts
- `Prometheus` scrape configuration
- `Grafana` dashboards and provisioning
- supporting documentation for local SVT execution

Keep functional integration assets under `test/integration/` and policy/unit assets under
`tests/unit/`. Do not scatter load-testing files across those directories.

## Layout

```text
tests/svt/
├── README.md
├── common/                            # shared assets used by all tests
│   ├── compose/
│   │   ├── docker-compose.yml         # SVT stack (envoy, opa, decision-log-collector, keycloak, cadvisor, prometheus, grafana, jmeter)
│   │   ├── keycloak/
│   │   │   ├── svt-realm.json
│   │   │   └── trusted-providers.json
│   │   └── seed/
│   │       └── svt-policies.json
│   ├── grafana/
│   │   ├── dashboards/
│   │   │   └── authz-agent-resources.json
│   │   └── provisioning/
│   │       ├── dashboards/
│   │       │   └── dashboards.yml
│   │       └── datasources/
│   │           └── prometheus.yml
│   ├── jmeter/
│   │   └── data/
│   │       ├── users.csv
│   │       ├── requests.csv
│   │       ├── requests-filter.csv
│   │       └── requests-bulk.csv
│   ├── prometheus/
│   │   └── prometheus.yml
│   ├── scripts/
│   │   └── lib/
│   │       └── svt-lib.sh             # shared runner functions
│   └── tools/
│       ├── opa_direct_matrix.py
│       └── svt_individual_matrix.py   # per-mode scenario matrix + workbook orchestration
├── profiler/                          # static OPA profiler assets
│   ├── README.md
│   ├── rls-condition/
│   ├── rls-predicate/
│   ├── rls-predicate-pips/
│   ├── ols-single/
│   ├── ols-bulk-50/
│   ├── identity-verify-token/
│   ├── identity-validate-jwt/
│   ├── wildcard-all-single/
│   └── wildcard-mixed-bulk/
├── load-tests/                        # per-test load scenarios
│   ├── run                            # suite-level runner (all full, then all opa-direct)
│   ├── full/                          # Envoy-boundary tests (canonical + legacy pairs)
│   │   ├── mixed/
│   │   │   ├── 100rps/
│   │   │   ├── 200rps/
│   │   │   ├── 300rps/
│   │   │   ├── 400rps/
│   │   │   ├── 500rps/
│   │   │   └── 1000rps/
│   │   ├── single/
│   │   │   └── 100rps/
│   │   ├── filter/
│   │   │   └── 100rps/
│   │   └── bulk/
│   │       └── 100rps/
│   ├── opa-direct/                    # backend-isolated diagnostic tests
│       ├── mixed/
│       │   ├── 100rps/
│       │   ├── 200rps/
│       │   ├── 300rps/
│       │   ├── 400rps/
│       │   ├── 500rps/
│       │   └── 1000rps/
│       ├── single/
│       │   └── 100rps/
│       ├── filter/
│       │   └── 100rps/
│       └── bulk/
│           └── 100rps/
│   └── individual/                    # additive per-mode scenario matrix assets
│       ├── envoy-canonical/
│       ├── envoy-legacy/
│       ├── opa-direct/
│       └── artifacts/
├── jmeter/                            # legacy JMX templates (kept for backward compatibility)
│   ├── plans/
│   │   ├── baseline-authz.jmx
│   │   ├── baseline-authz.md
│   │   ├── opa-direct-authz.jmx
│   │   ├── opa-direct-authz.md
│   │   ├── opa-direct-scenario.jmx
│   │   └── opa-direct-scenario.md
│   └── data/                          # legacy data location (use common/jmeter/data/ for new tests)
│       ├── users.csv
│       ├── requests.csv
│       ├── requests-filter.csv
│       └── requests-bulk.csv
├── compose/                           # legacy compose location (use common/compose/ for new tests)
│   └── ...
├── scripts/                           # environment management scripts
│   ├── up
│   ├── down
│   ├── run                            # legacy Envoy-boundary runner
│   ├── run-opa-direct                 # legacy OPA-direct runner
│   ├── run-opa-direct-matrix
│   ├── run-individual-svt-matrix
│   ├── run-opa-direct-decision-analysis
│   ├── run-opa-direct-decision-bench
│   └── run-opa-direct-decision-profile
└── artifacts/                         # legacy shared artifacts (new tests use per-test artifacts/)
    └── .gitkeep
```

Each individual load-test directory follows this structure:

```text
tests/svt/load-tests/<format>/<family>/<rps>/
├── scenario.md
├── test.jmx
├── config.env
├── run
└── artifacts/
    └── .gitkeep
```

Each profiler directory follows this structure:

```text
tests/svt/profiler/<scenario>/
├── data.json
├── input.json
├── profile.sh
├── bench.sh
└── profile-trace.sh
```

Authorize-result profiler directories (`ols-*`, `rls-*`, `wildcard-*`) may also include:

```text
├── data-real-token.json
├── input-real-token.json
├── profile-real-token.sh
└── bench-real-token.sh
```

Those additive files keep the same semantic scenario but swap the cached synthetic token for a
fixed signed JWT plus committed public JWKS data in the same canonical authn runtime shape used by
bootstrap (`trustedProviders.byId` plus the `jwksByKid` candidate index, authz-agent-ADR-0075).

## Quick Start

```bash
# 1. Start the environment (builds image, starts services, seeds policies, runs smoke check)
tests/svt/scripts/up

# 2. Run all load tests sequentially (all full first, then all opa-direct)
tests/svt/load-tests/run

# 3. Run a specific test
tests/svt/load-tests/full/mixed/100rps/run

# 4. Run selected tests via environment variable
TESTS_CSV=full/mixed/100rps,opa-direct/mixed/100rps tests/svt/load-tests/run

# 5. Legacy runners still work for backward compatibility
tests/svt/scripts/run
tests/svt/scripts/run-opa-direct

# 6. Profiler wrappers
tests/svt/profiler/ols-single/profile.sh          # opa eval --profile
tests/svt/profiler/ols-single/bench.sh             # opa bench (5 runs)
tests/svt/profiler/ols-single/profile-trace.sh     # opa eval --explain=full
tests/svt/profiler/ols-single/profile-real-token.sh
tests/svt/profiler/ols-single/bench-real-token.sh
tests/svt/profiler/identity-validate-jwt/profile.sh
TOKEN_KIND=service tests/svt/profiler/identity-validate-jwt/profile.sh
tests/svt/profiler/rls-predicate-pips/profile-real-token.sh
tests/svt/profiler/rls-predicate-pips/bench-real-token.sh
tests/svt/profiler/wildcard-mixed-bulk/profile-real-token.sh
tests/svt/profiler/wildcard-mixed-bulk/bench-real-token.sh

# 7. Individual per-mode scenario matrix
tests/svt/scripts/run-individual-svt-matrix
tests/svt/scripts/run-individual-svt-matrix --transport-modes envoy-canonical,envoy-legacy,opa-direct --scenarios ols-single,rls-filter --target-rps 500,1000 --output-dir tests/svt/load-tests/individual/artifacts/example
tests/svt/scripts/run-individual-svt-matrix --transport-modes envoy-legacy --scenarios rls-filter --target-rps 25 --threads 1 --ramp-seconds 1 --duration-seconds 6 --output-dir tests/svt/load-tests/individual/artifacts/smoke

# 8. Stop the environment when you are done
tests/svt/scripts/down

# 9. Optional: remove Compose volumes as well
REMOVE_VOLUMES=1 tests/svt/scripts/down
```

If an older local SVT volume was created before the bootstrap authn-cleanup follow-up and
`tests/svt/scripts/up` fails its smoke check with `HTTP 401`, run
`REMOVE_VOLUMES=1 tests/svt/scripts/down` once and start the environment again. Current builds also
remove legacy `authn/internal.json` and stale `authn/jwks/*` artifacts during bootstrap.

## Load Test Matrix

### Full (Envoy-boundary) — canonical + legacy pairs

| Family | RPS  | Path                             |
| ------ | ---- | -------------------------------- |
| mixed  | 100  | `load-tests/full/mixed/100rps/`  |
| mixed  | 200  | `load-tests/full/mixed/200rps/`  |
| mixed  | 300  | `load-tests/full/mixed/300rps/`  |
| mixed  | 400  | `load-tests/full/mixed/400rps/`  |
| mixed  | 500  | `load-tests/full/mixed/500rps/`  |
| mixed  | 1000 | `load-tests/full/mixed/1000rps/` |
| single | 100  | `load-tests/full/single/100rps/` |
| filter | 100  | `load-tests/full/filter/100rps/` |
| bulk   | 100  | `load-tests/full/bulk/100rps/`   |

### OPA-direct — backend-isolated diagnostics

| Family | RPS  | Path                                   |
| ------ | ---- | -------------------------------------- |
| mixed  | 100  | `load-tests/opa-direct/mixed/100rps/`  |
| mixed  | 200  | `load-tests/opa-direct/mixed/200rps/`  |
| mixed  | 300  | `load-tests/opa-direct/mixed/300rps/`  |
| mixed  | 400  | `load-tests/opa-direct/mixed/400rps/`  |
| mixed  | 500  | `load-tests/opa-direct/mixed/500rps/`  |
| mixed  | 1000 | `load-tests/opa-direct/mixed/1000rps/` |
| single | 100  | `load-tests/opa-direct/single/100rps/` |
| filter | 100  | `load-tests/opa-direct/filter/100rps/` |
| bulk   | 100  | `load-tests/opa-direct/bulk/100rps/`   |

Mixed tests split throughput `1/3 : 1/3 : 1/3` across single, filter, and bulk request families.
Full tests execute as canonical-vs-legacy pairs with an OPA restart between phases.

## Individual Matrix

`tests/svt/scripts/run-individual-svt-matrix` drives the additive individual-run matrix requested
on `2026-04-10`.

- Transport modes: `envoy-canonical`, `envoy-legacy`, `opa-direct`
- Scenarios: `ols-single`, `ols-bulk`, `rls-filter`, `rls-condition-1`, `rls-condition-2`, `rls-condition-3`
- Default target RPS: `500`, `1000`
- Decision mix: `90% ALLOW / 10% DENY` for every logical run
- Non-bulk cardinality: `100` users / `100` resourceType-operation pairs / `1` resource per request
- Bulk cardinality: `500` total resourceType-operation pairs / `50` resources per request

Full requested workbook run with default benchmark settings (`500` + `1000 RPS`, `60s` duration):

```bash
tests/svt/scripts/run-individual-svt-matrix --output-dir tests/svt/load-tests/individual/artifacts/full-$(date +%Y%m%d-%H%M%S)
```

Per run, the orchestrator:

- provisions/reuses the deterministic `100` Keycloak users and fresh bearer tokens;
- generates concrete `policies.json`, `policies-ref-index.json`, `pips.json`, `authn.json`, and
  `requests.csv`;
- uploads the run-specific data, executes the selected transport runner, and preserves JMeter raw
  output plus dashboard files;
- queries Prometheus/cAdvisor for OPA and Envoy CPU/memory samples over the exact measured JTL
  time window;
- writes one workbook `individual-svt-matrix.xlsx` with one summary row per
  `{transport_mode, scenario, target_rps}` run.

Validated example on `2026-04-10`:

```bash
tests/svt/scripts/run-individual-svt-matrix --ramp-seconds 1 --duration-seconds 6 --output-dir tests/svt/load-tests/individual/artifacts/final-20260410-full
```

That end-to-end run completed all `36` rows with `0` JMeter errors and wrote the workbook to
`tests/svt/load-tests/individual/artifacts/final-20260410-full/individual-svt-matrix.xlsx`.

Artifact layout for one matrix output:

```text
tests/svt/load-tests/individual/artifacts/<run-id>/
├── individual-svt-matrix.xlsx
├── matrix-summary.json
└── runs/
    └── <transport>__<scenario>__<rps>rps/
        ├── generated/
        │   ├── authn.json
        │   ├── pips.json
        │   ├── policies.json
        │   ├── policies-ref-index.json
        │   ├── requests.csv
        │   └── scenario.json
        ├── jmeter/
        │   ├── results.jtl
        │   ├── dashboard/
        │   └── ...
        ├── prometheus/
        │   └── *.json
        └── run-metadata.json
```

## Mixed-flow reports

Consolidated CPU / memory / IO report for the eight-scenario composite mix at six RPS
levels (`100`, `200`, `300`, `400`, `500`, `1000`). Shipped by handover
[20260518-mixed-load-report-task.md](../../docs/handovers/done/20260518-mixed-load-report-task.md).

| Mode                                    | Latest canonical file                                                                                            | Runner                                                 |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| canonical (`POST /access/v1/authorize`) | [`docs/reports/mixed-load-report-canonical-latest.md`](../../docs/reports/mixed-load-report-canonical-latest.md) | `tests/svt/scripts/mixed-load-report --mode canonical` |
| legacy (`/access/v1/check/*`)           | [`docs/reports/mixed-load-report-legacy-latest.md`](../../docs/reports/mixed-load-report-legacy-latest.md)       | `tests/svt/scripts/mixed-load-report --mode legacy`    |

Layout under `tests/svt/load-tests/mixed-flow/`:

```text
load-tests/mixed-flow/
├── test.jmx                   # shared JMX, 8 thread groups, ${MODE} switch
├── 100rps/                    # one per RPS level
│   ├── scenario.md
│   ├── config.env
│   ├── run                    # standalone runner; sources svt-lib
│   └── artifacts/.gitkeep
├── 200rps/ ... 1000rps/
└── artifacts/                 # per-sweep timestamped output dirs
    └── <mode>-<timestamp>/
        ├── idle-before/{window.json,prometheus/...}
        ├── 100rps/{tokens.properties,jmeter.log,results.jtl,window.json,prometheus/...}
        ├── ...
        ├── idle-after/...
        └── mixed-load-report-<mode>-<timestamp>.md
```

The 8-scenario mix is composed from the existing profiler set (same fixtures as
`tests/svt/scripts/bench-report`). Per-thread-group share: `20% ols-single-10roles
/ 5% rls-predicate / 5% rls-condition / 5% ols-bulk-100 / 25% rls-condition-2-expression
/ 25% rls-predicate-summary-2-predicates / 10% rls-predicate-pips-2-token-pip
/ 5% wildcard-all-single`. `ols-bulk-100` follows D-4 (1 HTTP request = 1 RPS slot,
100 resources per body). OPA is cold-restarted before every RPS level (decision D-2),
and a single idle-before / idle-after pair brackets each sweep (D-5).

Promotion gate: `±5%` on every peak CPU and peak memory cell vs the existing
canonical file (D-6). IO columns (network + filesystem byte rates) are rendered
for visibility but are not gated. On a first run with no baseline the report
is promoted unconditionally.

Eight extra Keycloak users (`svt-mixed-001` … `svt-mixed-008`) are seeded into
[`svt-realm.json`](common/compose/keycloak/svt-realm.json) so each thread group
authorizes with a per-scenario claim profile (roles + optional `department`
claim). The `authz-agent` Keycloak client carries an `oidc-usermodel-attribute-mapper`
that exposes the `department` user attribute as a token claim — required by the
three `dept-01` scenarios. The additive simplified-policy and PIP entries that
back the eight scenarios are generated by
[`tests/svt/scripts/build-mixed-flow-seeds.py`](scripts/build-mixed-flow-seeds.py)
and committed as `tests/svt/common/compose/seed/svt-mixed-flow-{policies,pips}.json`.
Bootstrap (`tests/svt/scripts/up`) and `svt_restart_opa` merge base seed +
mixed-flow seed via `jq` before seeding to the authz-policy-admin control surface
(ADR-0071; the pull loop delivers the merged set to OPA).

## Per-scenario decision-time reports

Per-scenario end-to-end decision-time and runtime-resource report across
**every benchmark in
[docs/reports/bench-report-latest.md](../../docs/reports/bench-report-latest.md)**
(28 scenarios at task draft time) swept at six RPS levels (`100`, `200`,
`300`, `400`, `500`, `1000`). Shipped by handover
[20260518-per-scenario-decision-time-task.md](../../docs/handovers/done/20260518-per-scenario-decision-time-task.md).

| Mode                                    | Latest canonical file                                                                                                              | Runner                                                          |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| canonical (`POST /access/v1/authorize`) | [`docs/reports/per-scenario-decision-time-canonical-latest.md`](../../docs/reports/per-scenario-decision-time-canonical-latest.md) | `tests/svt/scripts/per-scenario-decision-time --mode canonical` |
| legacy (`/access/v1/check/*`)           | [`docs/reports/per-scenario-decision-time-legacy-latest.md`](../../docs/reports/per-scenario-decision-time-legacy-latest.md)       | `tests/svt/scripts/per-scenario-decision-time --mode legacy`    |

Both modes share a single companion workbook at
[`docs/reports/per-scenario-decision-time.xlsx`](../../docs/reports/per-scenario-decision-time.xlsx),
with two flat mega-sheets (`canonical`, `legacy`) — one row per
`(scenario, RPS)` tuple, 168 rows × 25 columns each. Sortable filter
on the header row.

Layout under `tests/svt/load-tests/per-scenario/`:

```text
load-tests/per-scenario/
├── <scenario>/                # one folder per bench-report scenario
│   ├── test.jmx               # single thread group, ${MODE} switch
│   ├── 100rps/                # one per RPS level
│   │   ├── scenario.md
│   │   ├── config.env
│   │   ├── run                # standalone runner; sources svt-lib
│   │   └── artifacts/.gitkeep
│   ├── 200rps/ ... 1000rps/
│   └── artifacts/.gitkeep
└── artifacts/                 # per-sweep timestamped output dirs
    └── <mode>-<timestamp>/
        ├── <scenario>/<rps>rps/{tokens.properties,jmeter.log,results.jtl,window.json,prometheus/...,summary.json}
        ├── ...
        ├── per-scenario-decision-time-<mode>-<timestamp>.md
        └── per-scenario-decision-time-<mode>-<timestamp>.xlsx
```

The per-scenario JMX set, per-RPS configs, and runners are generated by
[`tests/svt/scripts/build-per-scenario-jmx.py`](scripts/build-per-scenario-jmx.py)
from the shared inventory in
[`tests/svt/scripts/build-per-scenario-seeds.py`](scripts/build-per-scenario-seeds.py).
Re-running both scripts after changing the inventory yields a
byte-for-byte identical regeneration.

Iteration shape: scenario-major outer loop (28 scenarios in
bench-report order), RPS-ascending inner loop (`100 → 200 → 300 → 400
→ 500 → 1000`). OPA is cold-restarted before every `(scenario, RPS)`
tuple, the JMeter plan runs for 60 s with a 5 s ramp-in, and there are
**no idle baselines** (handover D-10 — `mixed-load-report` already
publishes the canonical idle baseline for the three services).

Promotion gate: `±5%` on every per-(scenario, RPS) **response-time
p95** cell vs the existing canonical file (D-12). CPU / memory / IO-net
columns are rendered for visibility but are **not** gated (cAdvisor
filesystem sampling is noisy on cgroup v2 — IO-fs columns are skipped
in this report).

Each scenario is backed by:

- A dedicated Keycloak user `svt-bench-<scenario>` (one per inventory
  entry, role list + attribute map matched to the scenario shape;
  seeded into [`svt-realm.json`](common/compose/keycloak/svt-realm.json)).
- A scenario-isolated component namespace `PS_<scenario_upper>` in the
  per-scenario policy seed
  ([`tests/svt/common/compose/seed/svt-per-scenario-policies.json`](common/compose/seed/svt-per-scenario-policies.json),
  generated by `build-per-scenario-seeds.py`).
- New token-claim PIPs (`region`, `country`, `division`,
  `field06..field10`) and header PIPs (`x-svt-region`, `x-svt-country`,
  `x-svt-division`) supplied through
  [`tests/svt/common/compose/seed/svt-per-scenario-pips.json`](common/compose/seed/svt-per-scenario-pips.json).

Bootstrap (`tests/svt/scripts/up`) and `svt_restart_opa` merge the
per-scenario seeds alongside the base + mixed-flow seeds via `jq`
before seeding to the authz-policy-admin control surface; the pull loop delivers
the merged set to OPA (ADR-0071).

Bulk-slot accounting follows D-13: **1 HTTP request = 1 RPS**. At 1000
RPS the `ols-bulk-1000` thread group fires 1000 req/s × 1000 resources
≈ 10⁶ decisions/s and is expected to saturate the reference host. Rows
that under-deliver (`achieved_rps < 0.9 × target_rps`) are flagged with
a `*` suffix on the `achieved_rps` cell in both markdown and xlsx and
listed in the Notes section (D-18).

## Environment Services

| Service                  | Internal Port | Default Host Port | Purpose                                                                             |
| ------------------------ | ------------- | ----------------- | ----------------------------------------------------------------------------------- |
| `envoy`                  | 8080 / 9901   | 28080 / 29901     | Public compatibility facade and primary benchmark target                            |
| `opa`                    | 8181 / 8182   | —                 | Internal backend authz runtime; direct OPA profile targets `8181` from Compose only |
| `decision-log-collector` | 8183          | —                 | Internal decision-log ingest/download service                                       |
| `keycloak`               | 8080          | 25556             | Identity provider (svt-test realm)                                                  |
| `cadvisor`               | 8080          | 28888             | Container resource metrics                                                          |
| `prometheus`             | 9090          | 29090             | Metrics scraping and storage                                                        |
| `grafana`                | 3000          | 23000             | Metrics visualization (admin/admin)                                                 |
| `jmeter`                 | —             | —                 | Load generator (run via `docker compose run`)                                       |

## Host Baseline (First Stage)

| Parameter          | Value                                        |
| ------------------ | -------------------------------------------- |
| OS                 | Ubuntu 24.04.4 LTS                           |
| Kernel             | `6.18.7-76061807-generic`                    |
| CPU                | AMD Ryzen 9 8945HS (16 logical / 8 physical) |
| RAM                | 92 GiB                                       |
| Swap               | 8 GiB                                        |
| Docker Engine      | 29.3.1                                       |
| Docker Compose     | v5.1.1                                       |
| authz-agent limits | 8 CPU, 8G RAM                                |

## References

- [ADR-0030](../../docs/decisions/20260330-authz-agent-adr-0030-local-compose-jmeter-load-testing-stack.md)
- [ADR-0031](../../docs/decisions/20260331-authz-agent-adr-0031-compose-topology-split-for-load-tracking.md)
- [ADR-0034](../../docs/decisions/superseeded/20260403-authz-agent-adr-0034-opa-direct-svt-profile.md) *(superseded by ADR-0061; see ADR header)*
- [Load Testing Plan](../../docs/plans/20260330-load-testing-preparation-plan.md)
- [SVT Layout Expansion Handover](../../docs/handovers/done/20260409-svt-load-suite-expansion-and-layout-reorganization-task.md)

## Why this harness is not in CI

The load harness needs Docker Compose and sustained load generation; it measures
performance, not correctness, and its numbers are only meaningful on dedicated hardware.
It is run locally (`test/svt/scripts/up`) — the smoke request documented there doubles as
its correctness check. See `.github/workflows/go-build.yaml` for the CI scope rationale.
