# Task: 20260518-per-scenario-decision-time — Per-Scenario E2E Decision-Time Report

*Archived internal engineering document, restored for reference. Component names and paths reflect the tree at the time of writing and may differ from the current layout.*

## Filename

`20260518-per-scenario-decision-time-task.md`

## Plan

[20260330-load-testing-preparation-plan.md](../../plans/20260330-load-testing-preparation-plan.md)

## Status

Done

Implementation pass + Phase 6 (canonical baseline) + Phase 7 (legacy
baseline) all landed on branch `svt-fixes` on `2026-05-18`. Both
canonical and legacy `latest.md` reports and the two-sheet xlsx are
under `docs/reports/per-scenario-decision-time-*`. Promote-gate
fired in unconditional mode (no prior baselines) for both modes.
Sweep totals: Phase 6 = 74 min 42 s, Phase 7 = 76 min, full
canonical-then-legacy budget = 2 h 31 min wall-clock — well within
the ~2–3 h envelope predicted by D-20.

## Goal

Produce two consolidated per-scenario load-test reports that measure end-to-end
decision time and runtime resource consumption (CPU, memory, network IO) of
`envoy`, `opa`, and `decision-log-collector` for **every benchmark scenario
listed in [docs/reports/bench-report-latest.md](../../reports/bench-report-latest.md)**,
swept across six target RPS levels: `100`, `200`, `300`, `400`, `500`, `1000`.

Canonical first:

- [docs/reports/per-scenario-decision-time-canonical-latest.md](../../reports/per-scenario-decision-time-canonical-latest.md)
  exercises every scenario through `POST /access/v1/authorize` (Envoy →
  OPA → decision-log-collector).

Legacy second (separate sweep, same harness, `--mode legacy`):

- [docs/reports/per-scenario-decision-time-legacy-latest.md](../../reports/per-scenario-decision-time-legacy-latest.md)
  exercises the same scenario set through the legacy compatibility
  endpoints — `/access/v1/check/resource`, `/access/v1/check/resource/bulk`,
  `/access/v1/check/filter` — so the Envoy Lua mapping cost is included.

A single companion Excel workbook
[docs/reports/per-scenario-decision-time.xlsx](../../reports/per-scenario-decision-time.xlsx)
ships alongside, with two sheets (`canonical`, `legacy`), each a flat
one-row-per-(scenario, RPS) mega-table for filtering and pivot work.

Request bodies, JWT claims, and policy/PIP fixtures are taken verbatim
from the existing profiler scenario directories under
`tests/svt/profiler/`. The previous mixed-flow harness already wired up
8 of these scenarios; this task extends that to all `bench-report` scenarios.

---

## Execution Prompt

<!-- folded from 20260518-per-scenario-decision-time-task.prompt.md by migrate_handovers_layout (security-ADR-0023) -->

### Prompt: Per-Scenario E2E Decision-Time Report

#### Context

You are implementing a task in the Authz Agent repository. The task is defined in
`docs/handovers/20260518-per-scenario-decision-time-task.md` — read it fully before
starting. It is the single source of truth for what needs to be built and how.

The task ships two consolidated SVT load-test reports (canonical first, legacy
second) that measure end-to-end decision time and runtime resource consumption
of `envoy`, `opa`, and `decision-log-collector` for **every benchmark scenario
listed in `docs/reports/bench-report-latest.md`** (28 at draft time), swept
across six RPS levels (100/200/300/400/500/1000). A single Excel workbook
ships alongside with two flat mega-sheets (`canonical`, `legacy`).

This task builds on the mixed-flow harness already on disk:
`tests/svt/scripts/mixed-load-report`, `svt_restart_opa` with merged-seed
upload, `svt_run_jmeter_mixed_flow`, and the
`tests/svt/common/compose/seed/svt-mixed-flow-{policies,pips}.json` files.
Read those first — most of the new code is structural reuse, not rewrite.

#### Pre-read (mandatory)

Read these files in this order before writing any code:

1. `AGENTS.md` — sector-wide rules (commit hygiene, ADR/handover formats,
   no-LLM-attribution rule, `commit-msg` hook).
2. `docs/conventions.md` — coding and testing conventions.
3. `docs/handovers/20260518-per-scenario-decision-time-task.md` — **the task
   itself** (goal, decisions D-9…D-19, scenario inventory, methodology,
   mega-sheet column layout, two resolved OQs).
4. `docs/reports/bench-report-latest.md` — **the canonical scenario list**.
   The 28 scenarios documented in that file are the inventory; re-derive at
   execution time in case bench-report drifted between draft and run.
5. `docs/handovers/20260518-mixed-load-report-task.md` — predecessor task.
   Read the Execution Report sub-section under Done to understand exactly
   how `mixed-load-report` was implemented; this task reuses most of that
   scaffolding.
6. `docs/reports/mixed-load-report-{canonical,legacy}-latest.md` and
   `docs/reports/mixed-load-report.xlsx` — output shapes to model
   structure on. The new markdown is more verbose (28 H3 sections × 6 RPS
   tables) and the new xlsx is flat mega-sheet, not a 7-row block.
7. `tests/svt/scripts/mixed-load-report` — Python 3 stdlib orchestrator
   that the new `tests/svt/scripts/per-scenario-decision-time` should
   mirror in shape (CLI flags, two-stage promotion, Prometheus range
   queries, markdown rendering, openpyxl xlsx writer).
8. `tests/svt/scripts/build-mixed-flow-seeds.py` — deterministic
   generator that emits the additive mixed-flow seed files from the
   eight profiler scenarios. Extend (or fork as
   `build-per-scenario-seeds.py`) for all 28 scenarios.
9. `tests/svt/common/scripts/lib/svt-lib.sh` — the harness library.
   `svt_restart_opa` already merges base + mixed-flow seeds; teach it to
   also merge the new per-scenario seed. `svt_run_jmeter_mixed_flow` is
   the JMeter wrapper; a per-scenario sibling
   (`svt_run_jmeter_per_scenario`) may be cleaner than parameterising.
10. `tests/svt/load-tests/full/mixed/100rps/test.jmx` and
    `tests/svt/load-tests/mixed-flow/test.jmx` — JMX boilerplate. The new
    per-scenario plans have a single thread group each, with the
    `${MODE}` switch already wired the same way.
11. `tests/svt/common/compose/keycloak/svt-realm.json` — realm seed.
    Extend with 28 new `svt-bench-<scenario-name>` users (one per
    scenario, per the OQ-5 resolution; do not collapse profiles).
12. The 28 profiler directories under `tests/svt/profiler/` (one
    per scenario in the inventory). Each `input.json` is the request
    shape you copy into the new per-scenario JMX verbatim.

#### Working branch

Start from the current tip of `svt-fixes` (commit `6c8e904` or later).
That branch carries:

- `ed33c54` SVT fix — `svt-pips.json` + `requests-filter.csv` correction +
  `svt_restart_opa` re-seed.
- `6c8e904` mixed-flow harness — all the scaffolding this task extends.

Branch off `svt-fixes` for the new work (or stay on `svt-fixes` if the
owner agrees). Do not start from `master` — the harness this task depends
on has not landed there yet.

#### Execution order

Follow the phases defined in the task's `Done` checklist:

1. **Phase 1** — extend `build-mixed-flow-seeds.py` (or fork it) to emit
   `svt-per-scenario-{policies,pips}.json`; teach `svt-lib.sh` to merge
   the third seed file alongside base + mixed-flow.
2. **Phase 2** — add 28 `svt-bench-<scenario>` users to
   `svt-realm.json`; extend `svt_acquire_all_tokens` /
   `svt_write_tokens_file` for the new tokens.
3. **Phase 3** — 28 JMX files at
   `tests/svt/load-tests/per-scenario/<scenario>/test.jmx`, six per-RPS
   sub-directories per scenario (`config.env` + `run` +
   `artifacts/.gitkeep`).
4. **Phase 4** — sweep harness
   `tests/svt/scripts/per-scenario-decision-time` (`--mode`,
   `--scenarios`, `--rps`, `--skip-promote`). Scenario-major iteration
   (D-16).
5. **Phase 5** — markdown + xlsx renderer. Full-render markdown (D-19),
   mega-sheet xlsx (D-11), `±5%` promote-gate on response-time p95
   (D-12).
6. **Phase 6** — first canonical baseline sweep.
7. **Phase 7** — legacy baseline sweep (re-use the same stack; do not
   tear down between modes).

Work phase by phase. After each phase, tick the matching item in the
handover's `Done` checklist.

#### Rules

- **Do not modify Rego policy files**
  (`image/deployments/opa/policies/*.rego`). This task is additive:
  new seed JSON, new SVT users, new JMX, new Python orchestrator, new
  report files.
- **Do not modify existing profiler directories.** The 28 profiler
  scenarios are the source of truth for request shapes and policy
  fixtures — copy `input.json` payloads verbatim into the new JMX files.
- **Do not touch the parity / integration test suites or any unrelated
  SVT files** (mixed-flow harness stays as-is — extend, do not rewrite).
- **Python stdlib only.** No `pip install`. Prometheus range queries go
  through `urllib.request`, the xlsx writer is `openpyxl` (already a
  dependency on the host because `mixed-load-report.xlsx` was rendered
  with it; the new task may safely use it the same way via a small
  helper script, or skip openpyxl and emit a `.xlsx` zip by hand —
  prefer openpyxl).
- **Follow existing SVT boilerplate exactly.** Per-scenario directories
  mirror `tests/svt/load-tests/full/mixed/100rps/`: same five files
  (`scenario.md`, `config.env`, `test.jmx`, `run`, `artifacts/.gitkeep`).
- **Tokens come from Keycloak, not profiler JWKS** (D-3 carryover from
  mixed-flow). Profiler `tests/svt/profiler/keys/` stays scoped to
  `opa bench`.
- **OPA restart before every (scenario, RPS) run** (D-2 carryover). The
  existing `svt_restart_opa` already re-seeds policies + PIPs; extend
  it once to include the third seed file, not per-call.
- **No idle baselines** (D-10). Skip the idle-before / idle-after
  windows entirely — they are not part of this sweep.
- **Load window is 15 s, ramp 3 s** (D-20). Overrides the
  mixed-flow default of 60 s / 5 s. Every per-RPS `config.env`
  pins `DURATION_SECONDS=15` and `RAMP_SECONDS=3`. If you find a
  `60` or `5` in those files during this task, fix it.
- **5 s wall-clock break between scenario blocks** (D-21). After
  the last RPS run of scenario N completes (Prometheus collection
  - JTL parse + row appended), `time.sleep(5)` before the first
  `svt_restart_opa` of scenario N+1. Skip after the final scenario
  in the inventory. The break runs 27 times per sweep.
- **Best-effort saturation** (D-18). Every run records its
  `achieved_rps`. Rows with `achieved_rps < 0.9 * target_rps` are
  flagged with a `*` suffix in markdown and xlsx, listed in Notes. Do
  **not** drop rows pre-flight; do **not** cap RPS for bulk scenarios.
- **Scenario-major iteration** (D-16). Outer loop = scenarios in
  inventory order; inner loop = `[100,200,300,400,500,1000]`. Per
  scenario all six RPS rows are contiguous in time.
- **Auto-promote with `±5%` gate on response-time p95 only** (D-12).
  CPU/MEM/IO rendered for visibility but not gated. cAdvisor
  filesystem sampling is noisy on cgroup v2 — do not gate against it.
- **Two canonical files + one xlsx** (D-15, D-11):
  `docs/reports/per-scenario-decision-time-canonical-latest.md`,
  `docs/reports/per-scenario-decision-time-legacy-latest.md`,
  `docs/reports/per-scenario-decision-time.xlsx` (sheets `canonical`,
  `legacy`). Independent promote-gate per mode.
- **Bulk slot math: 1 HTTP request = 1 RPS** (D-13). At 1000 RPS the
  `ols-bulk-1000` thread group fires 1000 req/s × 1000 resources;
  expected to saturate. Record honestly.
- **No commits without explicit owner approval.** Land all work on
  the feature branch; the owner reviews and merges.
- **No LLM attribution in commits, branches, or PR bodies** (sector
  rule; the `commit-msg` hook enforces — do not use `--no-verify`).

#### Validation

Before declaring Phase 6 complete:

1. `tests/svt/scripts/up` smoke check passes (`environment ready` line).
2. All 28 new Keycloak users acquire valid tokens (probe each one
   against `/realms/svt-test/protocol/openid-connect/token`).
3. A dry-run smoke at `--scenarios ols-single,wildcard-all-single`
   `--rps 100` with `DURATION_SECONDS=10` finishes with **zero JMeter
   errors** in both canonical and legacy modes.
4. `tests/svt/scripts/per-scenario-decision-time --mode canonical`
   produces:
   - a timestamped Markdown report under
     `tests/svt/load-tests/per-scenario/artifacts/canonical-<ts>/`;
   - a timestamped xlsx under the same directory;
   - promotion to
     `docs/reports/per-scenario-decision-time-canonical-latest.md`
     and to the `canonical` sheet of
     `docs/reports/per-scenario-decision-time.xlsx` on a first run
     (no existing baseline).
5. The canonical markdown contains: methodology section, inventory
   table, 28 H3 sub-sections (one per scenario), each with a six-row
   RPS table. Total `28 × 6 = 168` data rows. Final ≈ 1700 lines.
6. The canonical xlsx sheet is a flat mega-sheet, 168 data rows × 25
   data columns, openpyxl-rendered with header row + sortable
   columns.
7. Re-running `--mode canonical` with no source changes promotes
   again (p95 within `±5%` of itself by construction).
8. `bash tests/scripts/test-opa.sh` still passes — sanity (this task
   should not touch Rego, but verify).
9. `bash tests/svt/scripts/down` cleans the stack.

#### Delivery format

- Update the handover file
  (`...-per-scenario-decision-time-task.md`) with a brief Execution
  Report — implemented changes, validation performed, remaining gaps.
  Do not prepare PR/MR output unless asked.
- Update `tests/svt/README.md` with a new "Per-scenario decision-time
  reports" subsection pointing at the two canonical files, the
  workbook, and the runner script.
- Update the parent plan
  `docs/plans/20260330-load-testing-preparation-plan.md` with a row
  for this task.
- Land commits on the working branch only; the owner promotes to
  `master`. With D-20 (15 s load window) and D-21 (5 s
  inter-scenario gap), the full sweep (canonical + legacy, 336
  runs total) takes ≈ **2–3 hours** wall-clock per mode on the
  reference host — fits inside a single afternoon. Earlier draft
  budget figures of ~10–12 h reflect the pre-D-20 default and are
  obsolete.

## Done

- [ ] Phase 1 — Scenario inventory and per-scenario seeds
  - [ ] Confirm the canonical scenario list directly from
        [docs/reports/bench-report-latest.md](../../reports/bench-report-latest.md)
        (28 scenarios at task draft time; see the table below). Drift in
        the canonical bench-report between draft and execution is allowed
        — re-derive at execution time.
  - [ ] Extend
        [tests/svt/scripts/build-mixed-flow-seeds.py](../../../test/svt/scripts/build-mixed-flow-seeds.py)
        (or fork it as `build-per-scenario-seeds.py` if scope makes
        reuse messy) so it emits policies + PIPs for every scenario in
        the inventory. Output files:
        - `tests/svt/common/compose/seed/svt-per-scenario-policies.json`
        - `tests/svt/common/compose/seed/svt-per-scenario-pips.json`
  - [ ] Both files are merged with the hand-authored
        `svt-policies.json` and `svt-pips.json` on every
        `tests/svt/scripts/up` and `svt_restart_opa` (extend the
        existing merge-via-`jq` block; no logic rewrite).
- [ ] Phase 2 — Keycloak users (one per scenario, 28 new)
  - [ ] Extend
        [tests/svt/common/compose/keycloak/svt-realm.json](../../../test/svt/common/compose/keycloak/svt-realm.json)
        with **one distinct user per scenario** in the inventory (28
        new users beyond the 8 `svt-mixed-NNN` added by the
        mixed-flow handover). Per OQ-5 resolution, identical claim
        profiles are **not** collapsed — every scenario gets its own
        dedicated user so a `--scenarios <comma>` subset run never
        depends on another scenario's user being seeded. Naming
        convention: `svt-bench-<scenario-name>`, hyphenated, e.g.
        `svt-bench-ols-single-30roles`,
        `svt-bench-rls-predicate-pips-3-header-pip`.
  - [ ] Reuse the existing `oidc-usermodel-attribute-mapper` for any
        new attribute claims; do not add a second realm.
  - [ ] `svt_acquire_all_tokens` / `svt_write_tokens_file` extended
        so JMeter properties carry tokens for all 28 new users.
        Property keys follow the existing pattern:
        `token_svt_bench_<scenario_name_underscored>` (e.g.
        `token_svt_bench_ols_single_30roles`).
- [ ] Phase 3 — Per-scenario JMX
  - [ ] One JMX plan per scenario at
        `tests/svt/load-tests/per-scenario/<scenario>/test.jmx`. Each
        plan has a single thread group that fires the scenario's
        request body verbatim from the profiler `input.json`, with a
        `${MODE}` switch (`canonical` → `/access/v1/authorize`,
        `legacy` → the scenario-appropriate compatibility endpoint;
        mapping table below).
  - [ ] Bulk slot accounting: `ols-bulk-{50,100,1000}` and
        `wildcard-mixed-bulk` are rated as **1 HTTP request = 1 RPS**.
        At 1000 RPS, `ols-bulk-1000` fires 1000 req/s × 1000 resources
        ≈ 10⁶ decisions/s — this is expected to saturate the reference
        host; record the achieved-RPS figure honestly and let the
        Notes section flag it.
  - [ ] Per-scenario `config.env` files under
        `tests/svt/load-tests/per-scenario/<scenario>/<rps>rps/` for
        the six RPS levels.
- [ ] Phase 4 — Sweep harness
  - [ ] Add `tests/svt/scripts/per-scenario-decision-time` (Python 3
        stdlib only; structurally mirrors `mixed-load-report`).
  - [ ] CLI: `--mode canonical|legacy`,
        `--scenarios <comma>` (default: all from `bench-report-latest.md`),
        `--rps <comma>` (default: 100,200,300,400,500,1000),
        `--skip-promote`.
  - [ ] Per-(scenario, RPS) sequence (D-2 carries over from mixed-flow):
        1. `svt_restart_opa` (merged base + per-scenario seed),
        2. run JMeter for **15 s** at target RPS (refined 2026-05-18 from 60 s — see D-20),
        3. record JMeter `start_ms` / `end_ms`,
        4. query Prometheus range for the (svc, resource) cells listed
           below over `[start_ms, end_ms]`,
        5. parse `results.jtl` for response-time stats.
  - [ ] **No idle-baseline windows.** Per owner decision on
        `2026-05-18`, this sweep skips idle measurements entirely —
        the per-scenario sweep is too long (168 runs × 2 modes) for
        idle windows to be useful, and `mixed-load-report` already
        owns the canonical idle baseline.
- [ ] Phase 5 — Report renderer
  - [ ] Markdown:
        `docs/reports/per-scenario-decision-time-<mode>-latest.md`
        with a methodology section, the scenario inventory, and one
        per-scenario sub-section that contains a six-row RPS table
        with peak/avg CPU/MEM/IO-net per service plus response-time
        avg/median/p95/p99. Total: `1 + 1 + 28 = 30` H2/H3 sections,
        `28 × 6 = 168` data rows.
  - [ ] Xlsx: `docs/reports/per-scenario-decision-time.xlsx` with two
        sheets (`canonical`, `legacy`), each a single flat
        mega-sheet — one row per `(scenario, RPS)` tuple, 168 data
        rows × 17 data columns (`scenario`, `RPS`, 12 resource cells
        for 3 services × 4 cells each, plus 4 response-time cells).
        See "Mega-sheet column layout" below.
  - [ ] Auto-promote gate (same shape as `bench-report` and
        `mixed-load-report`): regression = any
        **response-time p95 cell** exceeds the existing baseline by
        more than `5%`. CPU/MEM/IO are rendered for visibility but
        **not** gated.
- [ ] Phase 6 — First canonical baseline sweep
  - [ ] Run `tests/svt/scripts/per-scenario-decision-time --mode canonical`
        on the host baseline (see
        [tests/svt/README.md §Host Baseline](../../../test/svt/README.md#host-baseline-first-stage)).
  - [ ] Commit the first
        `docs/reports/per-scenario-decision-time-canonical-latest.md`
        and the xlsx canonical sheet.
- [ ] Phase 7 — Legacy baseline sweep
  - [ ] Re-use the harness with `--mode legacy`; same scenarios, same
        six RPS levels, scenario-appropriate legacy endpoint mapping.
  - [ ] Commit the first
        `docs/reports/per-scenario-decision-time-legacy-latest.md`
        and the xlsx legacy sheet.

### Scenario inventory (28 from `bench-report-latest.md`)

The inventory below is the snapshot at task draft time; the executor
should re-derive it from the live `bench-report-latest.md` at run
time. If a scenario has been added or removed in the bench-report,
update this table and the per-scenario JMX set accordingly.

| Scenario                                          | Group              | Canonical endpoint     | Legacy endpoint mapping                              |
| ------------------------------------------------- | ------------------ | ---------------------- | ---------------------------------------------------- |
| `ols-single`                                      | OLS                | `/access/v1/authorize` | `/access/v1/check/resource`                          |
| `ols-single-10roles`                              | OLS                | `/access/v1/authorize` | `/access/v1/check/resource`                          |
| `ols-single-20roles`                              | OLS                | `/access/v1/authorize` | `/access/v1/check/resource`                          |
| `ols-single-30roles`                              | OLS                | `/access/v1/authorize` | `/access/v1/check/resource`                          |
| `ols-single-50roles`                              | OLS                | `/access/v1/authorize` | `/access/v1/check/resource`                          |
| `ols-single-100roles`                             | OLS                | `/access/v1/authorize` | `/access/v1/check/resource`                          |
| `ols-bulk-50`                                     | OLS-bulk           | `/access/v1/authorize` | `/access/v1/check/resource/bulk`                     |
| `ols-bulk-100`                                    | OLS-bulk           | `/access/v1/authorize` | `/access/v1/check/resource/bulk`                     |
| `ols-bulk-1000`                                   | OLS-bulk           | `/access/v1/authorize` | `/access/v1/check/resource/bulk`                     |
| `rls-condition-1-expression`                      | RLS-condition      | `/access/v1/authorize` | `/access/v1/check/resource`                          |
| `rls-condition-2-expression`                      | RLS-condition      | `/access/v1/authorize` | `/access/v1/check/resource`                          |
| `rls-condition-3-expression`                      | RLS-condition      | `/access/v1/authorize` | `/access/v1/check/resource`                          |
| `rls-condition-5-expression`                      | RLS-condition      | `/access/v1/authorize` | `/access/v1/check/resource`                          |
| `rls-predicate`                                   | RLS-predicate      | `/access/v1/authorize` | `/access/v1/check/filter?resourceType=…&operation=…` |
| `rls-predicate-summary-2-predicates`              | RLS-predicate      | `/access/v1/authorize` | `/access/v1/check/filter?…`                          |
| `rls-predicate-summary-3-predicates`              | RLS-predicate      | `/access/v1/authorize` | `/access/v1/check/filter?…`                          |
| `rls-predicate-summary-4-predicates`              | RLS-predicate      | `/access/v1/authorize` | `/access/v1/check/filter?…`                          |
| `rls-predicate-summary-5-predicates`              | RLS-predicate      | `/access/v1/authorize` | `/access/v1/check/filter?…`                          |
| `rls-predicate-summary-10-predicates`             | RLS-predicate      | `/access/v1/authorize` | `/access/v1/check/filter?…`                          |
| `rls-predicate-pips-1-token-pip`                  | RLS-predicate-pips | `/access/v1/authorize` | `/access/v1/check/filter?…`                          |
| `rls-predicate-pips-2-token-pip`                  | RLS-predicate-pips | `/access/v1/authorize` | `/access/v1/check/filter?…`                          |
| `rls-predicate-pips-3-token-pip`                  | RLS-predicate-pips | `/access/v1/authorize` | `/access/v1/check/filter?…`                          |
| `rls-predicate-pips-1-header-pip`                 | RLS-predicate-pips | `/access/v1/authorize` | `/access/v1/check/filter?…`                          |
| `rls-predicate-pips-2-header-pip`                 | RLS-predicate-pips | `/access/v1/authorize` | `/access/v1/check/filter?…`                          |
| `rls-predicate-pips-3-header-pip`                 | RLS-predicate-pips | `/access/v1/authorize` | `/access/v1/check/filter?…`                          |
| `rls-predicate-summary-10-predicates-3-token-pip` | RLS-predicate-pips | `/access/v1/authorize` | `/access/v1/check/filter?…`                          |
| `wildcard-all-single`                             | Wildcard           | `/access/v1/authorize` | `/access/v1/check/resource`                          |
| `wildcard-mixed-bulk`                             | Wildcard           | `/access/v1/authorize` | `/access/v1/check/resource/bulk`                     |

### Measured resources

Per (scenario, RPS) the report captures, for each of the three
services (`envoy`, `opa`, `decision-log-collector`):

1. **CPU** — fractional cores, `sum(rate(container_cpu_usage_seconds_total{name=~".*<svc>.*"}[30s]))`.
2. **Memory** — bytes (working set),
   `sum(container_memory_working_set_bytes{name=~".*<svc>.*"})`.
3. **IO (net)** — receive + transmit byte rate,
   `sum(rate(container_network_receive_bytes_total{name=~".*<svc>.*"}[30s]))`
   `+ sum(rate(container_network_transmit_bytes_total{name=~".*<svc>.*"}[30s]))`.

Per (scenario, RPS) the report also captures, from `results.jtl`:

- **Response time avg** — arithmetic mean of the `elapsed` column.
- **Response time median** — 50th percentile of `elapsed`.
- **Response time p95** — 95th percentile of `elapsed`.
- **Response time p99** — 99th percentile of `elapsed`.

For every (scenario, RPS, service, resource) cell the report records
**load-peak** and **load-avg** during the 15 s load window. No idle
baseline is captured.

### Mega-sheet column layout (xlsx)

Each sheet (`canonical`, `legacy`) is a flat table:

| Col | Header                        | Source                      |
| --- | ----------------------------- | --------------------------- |
| A   | `scenario`                    | inventory                   |
| B   | `RPS`                         | 100/200/.../1000            |
| C   | `achieved_rps`                | JMeter Summariser tail line |
| D   | `envoy CPU peak`              | Prometheus range            |
| E   | `envoy CPU avg`               | Prometheus range            |
| F   | `envoy RAM peak`              | Prometheus range            |
| G   | `envoy RAM avg`               | Prometheus range            |
| H   | `envoy IO-net peak`           | Prometheus range            |
| I   | `envoy IO-net avg`            | Prometheus range            |
| J–O | `opa CPU/RAM/IO-net peak,avg` | Prometheus range            |
| P–U | `dlc CPU/RAM/IO-net peak,avg` | Prometheus range            |
| V   | `rt avg (ms)`                 | results.jtl elapsed         |
| W   | `rt median (ms)`              | results.jtl elapsed         |
| X   | `rt p95 (ms)`                 | results.jtl elapsed         |
| Y   | `rt p99 (ms)`                 | results.jtl elapsed         |

Total: 25 columns, 168 data rows per sheet (28 scenarios × 6 RPS).
Row 1 is the header. Filter / sort applied by openpyxl.

### Run methodology

For each mode ∈ {canonical, legacy}, **scenario-major iteration**: outer
loop iterates the 28 scenarios in inventory order; inner loop iterates
the six RPS levels in ascending order (`100 → 200 → 300 → 400 → 500
→ 1000`). Equivalent pseudocode:

```python
for i, scenario in enumerate(inventory):      # outer (D-16)
    if i > 0:
        sleep 5 s                              # inter-scenario gap (D-21)
    for rps in [100,200,...,1000]:             # inner
        svt_restart_opa
        run JMeter 15 s at <rps>               # D-20: load window
        record metrics
```

Per (scenario, RPS) tuple:

1. `svt_restart_opa` — cold-OPA per run, re-seed merged base + per-scenario
   policies + PIPs (D-2 carryover from mixed-flow).
2. Run JMeter against the per-scenario JMX at the target RPS for **15 s**
   (3 s ramp in, no cooldown inside the plan; per D-20 the load window
   shortens from the mixed-flow default of 60 s so the full
   28 × 6 × 2 = 336-run sweep fits in a single afternoon rather than
   overnight).
3. Record `start_ms` / `end_ms` of the JMeter run from the Summariser
   tail.
4. Query Prometheus range for the 12 (service, resource) cells over
   `[start_ms, end_ms]`. Reduce each range to (`peak` = max,
   `load-avg` = arithmetic mean of the samples).
5. Parse `results.jtl` for response-time stats (avg, median, p95, p99
   of `elapsed`). Use the same parser path
   `mixed-load-report` already has for `summarize_jtl_payload` —
   extend it to emit the four percentiles.
6. Append one row to the xlsx mega-sheet and one block to the markdown
   per-scenario section.

After the **last** RPS of every scenario except the final one in the
inventory, sleep **5 s** (D-21 inter-scenario gap) before kicking off
the next scenario's `svt_restart_opa`. This wall-clock break gives
Prometheus/cAdvisor a clean boundary between adjacent scenario blocks
in the time-series and makes manual visualisation in Grafana easier.

The sweep does **not** capture idle-before / idle-after windows.

### Execution Report (2026-05-18)

#### Design pass

- Full read of the 12 mandatory pre-read sources listed in the prompt:
  `AGENTS.md`, `project_rules.md`, `docs/conventions.md`, this
  handover, `docs/reports/bench-report-latest.md`, predecessor
  handover `20260518-mixed-load-report-task.md`,
  `mixed-load-report-canonical-latest.md` (output shape),
  `tests/svt/scripts/mixed-load-report`, `build-mixed-flow-seeds.py`,
  `svt-lib.sh`, the existing mixed-flow JMX + per-RPS layout,
  `svt-realm.json`, and a representative subset of profiler scenarios
  (`ols-single`, `ols-single-30roles`, `ols-bulk-{50,100,1000}`,
  `rls-condition-{1,2,3,5}-expression`, every `rls-predicate-*`
  variant, `wildcard-{all-single,mixed-bulk}`) to lock down the
  per-scenario request shapes, role lists, and policy fixtures.
- Decoded the 28 profiler `data.json` files into the simplified-policy
  - PIP + claim-mapper inventory that the seed / realm / JMX builders
  share.
- Confirmed scenario inventory matches `bench-report-latest.md` (28
  scenarios at draft time; the sweep harness re-derives the inventory
  from the live bench-report at runtime per D-9).
- Owner decisions D-9 … D-19 already documented in the original draft
  of this handover; OQ-4 and OQ-5 already resolved. No new owner gates
  hit during implementation.

#### Implementation pass (Phases 1-5)

Landed on branch `svt-fixes`, uncommitted. All five Phase-1-to-5
deliverables are on disk and pass static gates listed below.

**Modified files:**

- [tests/svt/common/scripts/lib/svt-lib.sh](../../../test/svt/common/scripts/lib/svt-lib.sh)
  — `svt_merged_seed_policies` and `svt_merged_seed_pips` extended to
  merge a third optional source
  (`svt-per-scenario-{policies,pips}.json`) alongside base +
  mixed-flow. New helpers `SVT_BENCH_SCENARIOS` array (28 entries),
  `svt_bench_scenario_underscored`, plus an extended
  `svt_acquire_all_tokens` / `svt_write_tokens_file` that iterate the
  array to acquire and emit the 28 `token_svt_bench_<scenario>` JMeter
  properties without enumerating each scenario by hand.
- [tests/svt/scripts/up](../../../test/svt/scripts/up) — seed-upload
  step now merges base + mixed-flow + per-scenario JSON via `jq`
  before the `PUT /internal/v1/policies` / `/internal/v1/pips` calls.
  Same three-tier merge added for the PIP upload. New Admin-API
  fallback block that detects missing `svt-bench-*` users in a stale
  Keycloak volume and re-provisions them by reading the role list,
  protocol mappers, and user definitions directly from
  `svt-realm.json` (so the fallback never drifts from the realm
  import).
- [tests/svt/common/compose/keycloak/svt-realm.json](../../../test/svt/common/compose/keycloak/svt-realm.json)
  — extended idempotently by the new
  `tests/svt/scripts/build-per-scenario-realm.py` patcher: 233 new
  `PS_<scenario>_ROLE_NN` realm roles, 8 new
  `oidc-usermodel-attribute-mapper` entries on the `authz-agent`
  client (`region`, `country`, `division`, `field06..field10`), and
  28 new `svt-bench-<scenario>` users (one per inventory entry) with
  scenario-specific role lists + attribute maps. The patcher leaves
  the existing 14 users (`svt-admin`, `svt-manager`, …,
  `svt-mixed-NNN`) untouched and is fully idempotent (re-run yields
  0/0/0 additions).

**New files:**

- [tests/svt/scripts/build-per-scenario-seeds.py](../../../test/svt/scripts/build-per-scenario-seeds.py)
  — deterministic generator that emits the additive simplified-policy
  and PIP files from the 28-scenario inventory. Re-running yields
  byte-for-byte identical output. The inventory is the single source
  of truth — `build-per-scenario-jmx.py` and
  `build-per-scenario-realm.py` import it via
  `importlib.machinery.SourceFileLoader` so the seed namespace
  (`PS_<scenario>_RT/OP/ROLE_NN`) stays in sync with the realm users
  and the JMX request bodies.
- [tests/svt/scripts/build-per-scenario-realm.py](../../../test/svt/scripts/build-per-scenario-realm.py)
  — idempotent realm.json patcher.
- [tests/svt/scripts/build-per-scenario-jmx.py](../../../test/svt/scripts/build-per-scenario-jmx.py)
  — generator for the 28 JMX plans + 168 per-RPS directories
  (`config.env` / `run` / `scenario.md` / `artifacts/.gitkeep`).
  Single-thread-group plans with the `${MODE}` switch wired into a
  `JSR223PreProcessor` that builds the request body verbatim from the
  scenario's profiler shape. Bulk variants build the cartesian
  product of `bulk_rt_count` × `bulk_op_count`; header-PIP scenarios
  add `x-svt-region` / `x-svt-country` / `x-svt-division` headers.
  Thread count scales as `RPS / 10` (10/20/30/40/50/100) so the plan
  has enough parallelism for high-latency bulk scenarios.
- [tests/svt/common/compose/seed/svt-per-scenario-policies.json](../../../test/svt/common/compose/seed/svt-per-scenario-policies.json)
  — 1309 simplified-policy entries spanning 28 components
  (`PS_<scenario>` namespace). No overlap with the base `SVT`
  component or the mixed-flow `SVT_MIXED_FLOW` component.
- [tests/svt/common/compose/seed/svt-per-scenario-pips.json](../../../test/svt/common/compose/seed/svt-per-scenario-pips.json)
  — 13 PIP entries (10 TOKEN PIPs + 3 HEADER PIPs). Merged with the
  base + mixed-flow PIPs the runtime sees 13 unique entries
  (deduplicated by `name`).
- `tests/svt/load-tests/per-scenario/<scenario>/test.jmx`
  — 28 single-thread-group JMX plans, each with the `${MODE}` switch
  and the scenario-specific request shape.
- `tests/svt/load-tests/per-scenario/<scenario>/<rps>rps/`
  — 168 directories (28 × 6 RPS), each with `config.env`,
  `scenario.md`, `run` (standalone wrapper that sources `svt-lib.sh`,
  restarts OPA, runs the per-scenario JMX), and `artifacts/.gitkeep`.
- [tests/svt/scripts/per-scenario-decision-time](../../../test/svt/scripts/per-scenario-decision-time)
  — Python 3 stdlib + openpyxl orchestrator. CLI flags: `--mode
  canonical|legacy`, `--scenarios <comma>` (defaults to live
  bench-report order), `--rps <comma>` (defaults to
  `100,200,300,400,500,1000`), `--skip-promote`. Scenario-major
  iteration (D-16). Per `(scenario, RPS)`: invokes the per-RPS
  `run` script (which restarts OPA + runs JMeter for 15 s per D-20), reads
  `window.json`, queries Prometheus range over the load window,
  parses `results.jtl` for `elapsed` percentiles and `jmeter.log` for
  the cumulative Summariser tail (achieved RPS). Renders a Markdown
  file with methodology + inventory table + 28 H3 sub-sections (six
  RPS rows each, 25 cells per row) plus a Notes section that lists
  flagged rows (`achieved_rps < 0.9 × target_rps`, D-18). Also writes
  a two-sheet xlsx (`canonical` + `legacy`) with the flat 168 × 25
  mega-sheet — current run overwrites only its own sheet; the other
  is preserved. Promote-gate is `±5%` on response-time p95 per
  `(scenario, RPS)` cell (D-12).
- [tests/svt/README.md](../../../test/svt/README.md) — new
  "Per-scenario decision-time reports" subsection pointing at the
  two canonical files, the workbook, the runner, the layout, and the
  Keycloak / seed / PIP extension story.
- [docs/plans/20260330-load-testing-preparation-plan.md](../../plans/20260330-load-testing-preparation-plan.md)
  — new Handovers row for this task.

#### Static-gate validation (2026-05-18)

All run on the host that owns the working tree; no docker stack
required.

- `python3 -c py_compile` on all four new Python scripts
  (`build-per-scenario-seeds.py`, `build-per-scenario-realm.py`,
  `build-per-scenario-jmx.py`, `per-scenario-decision-time`) — all
  pass.
- `bash -n` on `up`, `svt-lib.sh`, and all 168 per-RPS `run` scripts —
  168/168 pass.
- `python3 -c "json.load(...)"` on `svt-realm.json`,
  `svt-per-scenario-policies.json`, `svt-per-scenario-pips.json` —
  all valid JSON.
- `xml.etree.ElementTree.parse` on the 28 per-scenario JMX files —
  28/28 well-formed XML.
- `jq -s 'add | length'` on base + mixed-flow + per-scenario policies
  → 2345 (66 base + 970 mixed-flow + 1309 per-scenario). PIPs after
  dedup-by-name → 13.
- `tests/svt/scripts/per-scenario-decision-time --help` returns the
  expected `--mode`, `--scenarios`, `--rps`, `--skip-promote` flags.
- Inventory derivation smoke-test in-process: `select_scenarios` with
  `--scenarios=None` produces 28 entries in the live bench-report
  order; with `--scenarios=ols-single,wildcard-all-single` filters
  to those two.
- Markdown round-trip in-process: rendered a 4-row mock report, fed
  it back through `parse_p95_cells_from_report`, recovered all four
  `(scenario, RPS) → p95` entries.
- Idempotency of `build-per-scenario-realm.py`: second run reports
  `added: roles=0, mappers=0, users=0` (the patcher always rebuilds
  the bench-user block so attribute changes are picked up, but the
  rest of the realm is preserved byte-for-byte).
- xlsx round-trip in-process: wrote a 4-row workbook to `/tmp`, both
  `canonical` and `legacy` sheets present with 25 columns + header
  row + auto-filter applied.

#### D-20 / D-21 refresh (2026-05-18, follow-up)

Applied after the spec refinement landed mid-implementation:

- `tests/svt/scripts/build-per-scenario-jmx.py` — `RAMP_SECONDS`
  default lowered from `5` to `3`, `DURATION_SECONDS` from `60` to
  `15`. The generator re-emits all 168 per-RPS `config.env` files
  with the new defaults (sample: `RAMP_SECONDS="${RAMP_SECONDS:-3}"`,
  `DURATION_SECONDS="${DURATION_SECONDS:-15}"`).
- `tests/svt/scripts/per-scenario-decision-time` — methodology text
  updated, `LOAD_DURATION_SECONDS`/`RAMP_SECONDS` constants now
  reflect the new D-20 values, new `INTER_SCENARIO_GAP_SECONDS = 5`
  constant + `time.sleep` between adjacent scenario iterations
  (skipped before scenario 1; runs 27 times across the 28-scenario
  inventory). Methodology now lists the D-21 inter-scenario gap.
- Re-validated: `python3 -c py_compile` on the orchestrator,
  `bash -n` on all 168 per-RPS run scripts (168/168 pass), 28/28
  JMX files parse as well-formed XML after regeneration.

#### Dry-run smoke (2026-05-18)

Two-scenario × 100 RPS × 10 s smoke run against the live SVT stack:

- `tests/svt/scripts/up` re-applied the merged base + mixed-flow +
  per-scenario seeds (2345 policies, 13 PIPs) and verified all 28
  `svt-bench-*` users acquire valid tokens (28/28 OK).
- One-shot canonical authorize hit (`PS_OLS_SINGLE_RT_01` /
  `PS_OLS_SINGLE_OP_01`) returned `ALLOW`; legacy
  `/access/v1/check/resource` returned HTTP 200. Token-PIP /
  header-PIP predicate scenarios returned the expected
  `predicates[]` payload with substituted PIP values.
- `DURATION_SECONDS=10 tests/svt/scripts/per-scenario-decision-time
  --mode canonical --scenarios ols-single,wildcard-all-single
  --rps 100 --skip-promote` finished with zero JMeter errors
  (`summary = 951 in 00:00:10 = 93.7/s` for ols-single,
  `summary = 948 in 00:00:10 = 93.5/s` for wildcard-all-single).
  Markdown + xlsx artefacts emitted under
  `tests/svt/load-tests/per-scenario/artifacts/canonical-<ts>/`.
- Same invocation with `--mode legacy` also finished cleanly
  (0 errors, ~93/s achieved on both scenarios).

#### Phase 6 — canonical baseline sweep (2026-05-18)

- Launched via `tests/svt/scripts/per-scenario-decision-time --mode
  canonical` on the running SVT stack.
- **Wall-clock**: started `12:58:38+03:00`, finished
  `14:13:20+03:00` — **74 min 42 s** for 168 (scenario, RPS) runs
  (≈ 26.7 s per tuple including the per-RPS OPA restart, JMeter
  ramp + load, Prometheus range queries, and results.jtl parse).
- **Errors**: zero JMeter assertion failures, zero subprocess
  non-zero exits.
- **Flagged rows (D-18, `achieved_rps < 0.9 × target_rps`)**:
  **70 / 168 (42 %)**. Distribution by target RPS:
  100 → 5 rows, 200 → 4, 300 → 9, 400 → 11, 500 → 14,
  1000 → 27. Only `ols-single` cleared all six RPS levels.
- **Worst saturation**: `ols-bulk-1000` flagged at every RPS
  (achieved 21–23 r/s regardless of target, as predicted by D-13).
- **Resource peaks across the canonical sweep**:
  envoy CPU 0.76 cores / RAM 93.3 MiB; opa CPU 5.50 cores
  (limit 8) / RAM 1 697 MiB (limit 8 G); dlc CPU 0.32 cores /
  RAM 173.0 MiB. OPA never reached its CPU/RAM limit — the
  bottleneck under saturation was Envoy ↔ JMeter keepalive
  concurrency, not OPA itself.
- **Latency surface (p95 in ms)** — `min / median / p75 / max`
  by RPS: 100 RPS → 4 / 10 / 12 / 629;
  200 → 4 / 17 / 30 / 1 086;
  300 → 4 / 40 / 54 / 1 470;
  400 → 5 / 54 / 82 / 2 204;
  500 → 13 / 91 / 118 / 2 476;
  1000 → 47 / 235 / 332 / 6 472.
- **Promotion**: no prior baseline at
  `docs/reports/per-scenario-decision-time-canonical-latest.md`,
  promoted unconditionally; `canonical` sheet of
  `docs/reports/per-scenario-decision-time.xlsx` populated with
  168 × 25 cells + auto-filter + freeze-pane.

#### Phase 7 — legacy baseline sweep (2026-05-18)

- Launched immediately after Phase 6 on the warm SVT stack (no
  tear-down between modes per the task's Next Steps).
- **Wall-clock**: `14:13:20+03:00` → `15:29:15+03:00` — **76 min**
  for 168 runs (≈ 27.1 s per tuple). Full canonical-then-legacy
  cycle = 2 h 30 min 37 s.
- **Errors**: zero JMeter assertion failures.
- **Flagged rows**: **87 / 168 (52 %)**, +17 over canonical. Extra
  flagged surface concentrated at 400–500 RPS, where the Envoy Lua
  mapping cost pushes mid-RPS sweet-spot scenarios into saturation
  (e.g. `ols-single-100roles @ 500 RPS`: canonical 450 → legacy
  375 r/s, −16.7 %).
- **Worst row**: `ols-bulk-1000 @ 1000 RPS` legacy p95 = 14 751 ms
  vs canonical 6 472 ms — Lua transform for the 1000-resource
  bulk payload doubles the wall-clock cost. OPA RAM peak under
  this row = 4 400 MiB (still under the 8 G limit).
- **Resource peaks across the legacy sweep**:
  envoy CPU 0.71 cores / RAM 150 MiB; opa CPU 5.95 cores /
  RAM 4 400 MiB; dlc CPU 0.21 cores / RAM 264 MiB.
- **Latency surface (p95 in ms)** — `min / median / p75 / max`
  by RPS: 100 RPS → 7 / 12 / 14 / 1 256;
  200 → 13 / 25 / 38 / 2 423;
  300 → 16 / 51 / 63 / 4 342;
  400 → 19 / 68 / 106 / 5 965;
  500 → 47 / 118 / 140 / 8 236;
  1000 → 207 / 318 / 355 / 14 751.
- **Promotion**: no prior baseline at
  `docs/reports/per-scenario-decision-time-legacy-latest.md`,
  promoted unconditionally; `legacy` sheet of
  `docs/reports/per-scenario-decision-time.xlsx` populated.

#### Canonical-vs-Legacy delta (cross-mode, informational)

The two modes have independent baselines (D-15); the comparison
below is informational only — it is **not** part of the
promote-gate.

- **Median Δp95 (legacy − canonical) by RPS**: 100 → +3 ms
  (+30 %); 200 → +8 ms (+47 %); 300 → +15 ms (+38 %);
  400 → +13 ms (+24 %); 500 → +27 ms (+30 %); 1000 → +94 ms
  (+40 %). Legacy carries ~30 % p95 overhead across the sweep on
  average.
- **Top legacy overhead cells @ 100 RPS** (light-load isolation
  of the Lua mapping cost): `ols-bulk-1000` +627 ms,
  `ols-bulk-100` +100 ms, `wildcard-mixed-bulk` +52 ms,
  `ols-bulk-50` +24 ms, `ols-single-100roles` +7 ms — every
  top-5 entry is a bulk or large-role-list scenario.
- **Four RLS scenarios are actually faster under legacy at
  100 RPS** by 1–3 ms (`rls-predicate`,
  `rls-condition-2-expression`,
  `rls-predicate-summary-3-predicates`,
  `rls-predicate-pips-2-token-pip`). The legacy
  `/access/v1/check/filter` carries no request body (only
  `?resourceType=&operation=` query string), so the JSON-parse
  savings on the wire outweigh the Lua-transform cost for the
  RLS-thin shapes.

## Decisions

- *D-9.* **Scenario inventory mirrors `bench-report-latest.md` exactly.**
  Identity-only profiler scenarios (`identity-verify-token`,
  `identity-validate-jwt`) are already absent from that report and are
  therefore out of scope here. If `bench-report` later re-adds or
  drops a scenario, this sweep follows.
- *D-10.* **No idle baselines.** The per-scenario sweep is too long
  (168 runs × 2 modes) for the idle windows to pay back the runtime.
  `mixed-load-report` already publishes the canonical idle baseline
  for the three services and that baseline is referenced from here.
- *D-11.* **Mega-sheet xlsx layout, one row per `(scenario, RPS)`.**
  Lets the consumer apply Excel filter/sort/pivot rather than
  switching tabs. Two sheets total — canonical and legacy.
- *D-12.* **Promote-gate is `±5%` on response-time p95.** The
  primary deliverable is decision-time, not resource consumption, so
  the gate shifts from peak CPU / peak MEM (used by `bench-report` and
  `mixed-load-report`) to p95 latency per `(scenario, RPS)` cell. CPU
  / MEM / IO are rendered without gating.
- *D-13.* **Carry over `D-2` (per-run OPA restart) and `D-4`
  (1 HTTP req = 1 RPS for bulk).** `D-5` and `D-8` (idle-baseline
  rules) do not apply — there are no idle windows in this sweep.
- *D-14.* **JMeter response time is the latency source.** Wall-clock
  end-to-end client-side measurement, single-hop from JMeter through
  Envoy → OPA → JMeter. OPA-internal histograms remain visible via
  the existing Prometheus surface but are not folded into this
  report; the bench-report continues to own that view.
- *D-15.* **Canonical first, legacy second.** Same staging order as
  `mixed-load-report` (D-1 carryover). Each mode has its own canonical
  markdown file and its own xlsx sheet; baselines are independent.
- *D-16.* **Scenario-major iteration order.** Outer loop iterates the
  28 scenarios in inventory order; inner loop iterates the six RPS
  levels. This keeps every scenario's six rows contiguous in time and
  surfaces per-scenario regressions early (the first failing scenario
  is visible before the sweep continues). The alternative — RPS-major
  — would expose host saturation patterns earlier but disperses
  per-scenario error surfaces across the run; not chosen.
- *D-17.* **28 JMX files + 168 per-RPS sub-directories.** Layout
  mirrors the existing `tests/svt/load-tests/full/mixed/100rps/`
  pattern: one JMX per scenario at
  `tests/svt/load-tests/per-scenario/<scenario>/test.jmx`, six
  per-RPS sub-directories per scenario carrying `config.env` + `run`
  - `artifacts/.gitkeep`. The alternative mega-JMX with thread groups
  gated by `${SCENARIO}` would centralise logic but breaks the
  existing SVT convention; not chosen.
- *D-18.* **Best-effort saturation handling.** Every run records its
  `achieved_rps` from the JMeter Summariser tail line, irrespective
  of how far below `target_rps` the run lands. Rows where
  `achieved_rps < 0.9 * target_rps` are flagged with a `*` suffix on
  the `achieved_rps` cell in both markdown and xlsx, and the markdown
  Notes section lists every flagged row. The promote-gate (`±5%` on
  p95) still runs against flagged rows — saturation surfaces as a
  high but stable p95 vs the previous baseline. No row is dropped
  pre-flight.
- *D-19.* **Full markdown render.** The canonical markdown file
  carries one H3 sub-section per scenario, each with a six-row RPS
  table containing every resource + response-time cell. Final size
  is ≈ 1700 lines per mode; the xlsx mega-sheet is the recommended
  view for filtering. The condensed-pivot alternative was
  considered and not chosen — promote-gate logic is simpler against
  a fully-rendered file (parser already exists in `bench-report` /
  `mixed-load-report`).
- *D-20 (2026-05-18 refinement).* **Load window is 15 s, not 60 s.**
  The default carried from mixed-flow (D-7, 60 s) is overridden here:
  the per-scenario sweep is 336 individual runs (28 × 6 × 2), and a
  60 s window would push the wall-clock to ~10–12 h per sweep. A
  15 s window keeps statistically useful percentile samples
  (≈ 1 500 hits at 100 RPS, ≈ 15 000 at 1000 RPS) while compressing
  the full canonical + legacy budget down to ~2–3 h. Ramp-in
  shortens from 5 s to 3 s in step with the shorter window so the
  steady-state portion stays ≥ 12 s per run.
- *D-21 (2026-05-18 refinement).* **5 s wall-clock break between
  scenario blocks.** After the last RPS run of scenario N completes
  (Prometheus collection done, results.jtl parsed, row appended),
  sleep 5 s before `svt_restart_opa` for the first RPS of scenario
  N+1. The break gives Prometheus/cAdvisor a clean boundary between
  adjacent scenario blocks in the time-series so manual Grafana
  inspection can tell scenarios apart by sight rather than by
  scenario-tag overlay. The break runs 27 times per sweep (between
  scenario 1→2 through 27→28), adds ≈ 2 min wall-clock total — a
  rounding error against the 2–3 h sweep budget. Skipped after the
  final scenario in the inventory.

## Open Questions

- *OQ-4 (resolved 2026-05-18).* Legacy mapping for
  `rls-predicate-summary-10-predicates-3-token-pip` goes through
  `/access/v1/check/filter`. Confirmed by owner; the inventory
  table above reflects this. The scenario carries predicates, so
  filter is the semantically correct legacy endpoint.
- *OQ-5 (resolved 2026-05-18).* Do **not** collapse Keycloak users
  by shared claim profile — extend `svt-realm.json` with **one
  distinct user per scenario** in the inventory (28 new users
  beyond the 8 `svt-mixed-NNN` added by the mixed-flow handover).
  Confirmed by owner. One user per scenario keeps the mapping
  explicit and avoids ambiguity when re-running a subset via
  `--scenarios <comma>`. Naming convention: `svt-bench-<scenario>`
  with hyphenated scenario name (e.g. `svt-bench-ols-single-30roles`,
  `svt-bench-rls-predicate-pips-3-header-pip`).

## Next Steps

- After Phase 6 (canonical baseline) lands, run Phase 7 (legacy
  baseline) on the same stack; do **not** tear down between modes
  (the realm is warm, Keycloak admin-API provisioning happens once).
- After both baselines and the xlsx ship, link them from
  [tests/svt/README.md](../../../test/svt/README.md) under the existing
  "Mixed-flow reports" subsection (the per-scenario report sits
  alongside, not nested).
- Consider a follow-up task to surface the `bench-report` vs
  per-scenario `decision-time` deltas (per scenario, per RPS): the
  former is `opa bench` (no network), the latter is JMeter through
  Envoy. The deltas characterise the Envoy + network overhead per
  scenario shape.
