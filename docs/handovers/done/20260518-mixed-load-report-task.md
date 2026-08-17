# Task: 20260518-mixed-load-report — Mixed-Flow Resource Consumption Report

*Archived internal engineering document, restored for reference. Component names and paths reflect the tree at the time of writing and may differ from the current layout.*

## Filename

`20260518-mixed-load-report-task.md`

## Plan

[20260330-load-testing-preparation-plan.md](../../plans/20260330-load-testing-preparation-plan.md)

## Status

Done

Implementation Done as of `2026-05-18`, validated `2026-05-18`, spec
refined `2026-05-18` (D-8 cooldown). Phases 1-7 executed on branch
`svt-fixes`; both canonical and legacy baselines landed in
`docs/reports/mixed-load-report-{canonical,legacy}-latest.md` with
**0 JMeter errors** across all 12 RPS-mode combinations
(6 RPS × 2 modes). Achieved throughput is 99.1–99.2% of target on
100–500 RPS and 97.5–98.7% of target on 1000 RPS (raw `summary =`
lines in each `*/jmeter.log`). All static gates pass and the report
numbers match the underlying Prometheus range data on spot-check.

Post-validation refinement D-8 (20 s cooldown before idle-after) was
added to the spec on `2026-05-18` and is now the canonical contract;
the existing baselines were captured under the pre-D-8 behavior and
will be re-shot when D-8 lands in `svt_capture_idle_window` (see Next
Steps). The handover is closed from the design / spec side — only
owner review + commit + the D-8 cooldown landing remain.

## Goal

Produce two consolidated mixed-flow load-test reports that measure CPU,
memory, and IO consumption of the three runtime services (`envoy`, `opa`,
`decision-log-collector`) under a fixed eight-scenario composite mix at six
target RPS levels: `100`, `200`, `300`, `400`, `500`, `1000`.

Canonical first:

- [docs/reports/mixed-load-report-canonical-latest.md](../../reports/mixed-load-report-canonical-latest.md)
  exercises every scenario through `POST /access/v1/authorize` (Envoy →
  OPA → decision-log-collector).

Legacy second (separate follow-up run, same harness):

- [docs/reports/mixed-load-report-legacy-latest.md](../../reports/mixed-load-report-legacy-latest.md)
  exercises the same mix through the legacy compatibility endpoints
  (`/access/v1/check/resource`, `/access/v1/check/resource/bulk`,
  `/access/v1/check/filter`) so that Envoy Lua mapping cost is included.

Request bodies, JWT claims, and policy/PIP fixtures are taken verbatim
from the eight profiler scenarios already documented by the `bench-report`
generator (see
[docs/reports/bench-report-latest.md](../../reports/bench-report-latest.md));
no new profiler scenarios are introduced. The reports are directly
comparable to `bench-report` on a scenario-by-scenario basis, with the
caveat that canonical adds Envoy overhead and legacy adds Envoy + Lua
mapping overhead on top of `opa bench` numbers.

---

## Execution Prompt

<!-- folded from 20260518-mixed-load-report-task.prompt.md by migrate_handovers_layout (security-ADR-0023) -->

### Prompt: Mixed-Flow Resource Consumption Report

#### Context

You are implementing a task in the Authz Agent repository. The task is defined in
`docs/handovers/20260518-mixed-load-report-task.md` — read it fully before
starting. It is the single source of truth for what needs to be built and how.

The task ships two consolidated SVT load-test reports (canonical first, legacy
second) that measure CPU, memory, and IO consumption of `envoy`, `opa`, and
`decision-log-collector` under a fixed eight-scenario mix at six RPS levels
(100/200/300/400/500/1000). Reuses the existing SVT compose stack and the
profiler fixtures that already back `tests/svt/scripts/bench-report`.

#### Pre-read (mandatory)

Read these files in this order before writing any code:

1. `AGENTS.md` — sector-wide rules (commit hygiene, ADR/handover formats,
   no-LLM-attribution rule).
2. `docs/conventions.md` — coding and testing conventions.
3. `docs/handovers/20260518-mixed-load-report-task.md` — **the task itself**
   (goal, decisions D-1…D-7, the eight-scenario / six-RPS matrix, run
   methodology, report structure).
4. `docs/reports/bench-report-latest.md` — the existing canonical OPA bench
   report. The new reports must be conceptually comparable; same scenarios,
   different driver (JMeter via Envoy vs `opa bench`).
5. `tests/svt/README.md` — SVT stack layout, host baseline, existing
   matrices.
6. `tests/svt/load-tests/full/mixed/100rps/test.jmx` — JMX boilerplate for
   the mixed JMeter plan you will adapt.
7. `tests/svt/load-tests/full/mixed/100rps/run` and
   `tests/svt/common/scripts/lib/svt-lib.sh` — per-test runner pattern and
   the `svt_restart_opa` helper that already re-seeds policies and PIPs
   after every restart (see commit `ed33c54` on branch `svt-fixes`).
8. `tests/svt/common/tools/svt_individual_matrix.py` — existing Prometheus
   range-query plumbing and the `PROM_QUERIES` dict you will extend with
   IO metrics for the three services.
9. `tests/svt/scripts/bench-report` — the report generator whose two-stage
   promotion model (`±5%` gate, timestamped staging, canonical overwrite)
   you will mirror.
10. The eight profiler directories listed in the task table (one
    `input.json` and one `data.json` each — these are the request shapes
    you copy into the mixed JMX).

#### Working branch

Start from `svt-fixes` (or its merge into `master`). That branch carries the
`svt_restart_opa` re-seed fix and the `svt-pips.json` bootstrap. Without
those, every legacy run drops back to ~33% JMeter errors after the first
OPA restart — see commit `ed33c54` for context.

#### Execution order

Follow the phases defined in the task's `Done` checklist:

1. **Phase 1** — `tests/svt/load-tests/mixed-flow/<rps>rps/` directories,
   one per target RPS (`100`, `200`, `300`, `400`, `500`, `1000`).
2. **Phase 2** — composite mixed JMX with eight thread groups; both
   canonical and legacy paths via the existing `${MODE}` switch.
3. **Phase 3** — extend `tests/svt/common/compose/keycloak/svt-realm.json`
   with new users whose roles and `email` claim mirror the eight profiler
   `input-real-token.json` claim profiles; teach `tests/svt/scripts/up` to
   acquire tokens for them.
4. **Phase 4** — harness helper in `tests/svt/common/scripts/lib/svt-lib.sh`
   that owns the per-sweep idle baselines and the per-RPS cold-OPA load
   window.
5. **Phase 5** — `tests/svt/scripts/mixed-load-report` Python 3 script with
   `--mode canonical|legacy`, mirroring the `bench-report` structure
   (timestamped staging in `tests/svt/load-tests/mixed-flow/artifacts/`,
   `±5%` peak-CPU/peak-MEM gate, auto-promote to
   `docs/reports/mixed-load-report-<mode>-latest.md`).
6. **Phase 6** — first canonical baseline.
7. **Phase 7** — legacy baseline (after canonical lands).

Work phase by phase. After each phase, tick the matching item in the
handover's `Done` checklist.

#### Rules

- **Do not modify Rego policy files** (`image/deployments/opa/policies/*.rego`).
  This task is additive: new load-test directories, new JMX, new SVT
  realm users, new Python script, new report files.
- **Do not modify existing profiler directories.** The eight profiler
  scenarios listed in the task table are the source of truth for request
  shapes and policy fixtures — copy their `input.json` payloads into the
  mixed JMX verbatim. Do not re-tune them here.
- **Do not touch the parity / integration test suites.** This task is
  scoped to `tests/svt/` and the Keycloak realm seed.
- **Python stdlib only.** No `pip install`. Prometheus queries go through
  `urllib.request` as in `svt_individual_matrix.py`.
- **Follow existing SVT boilerplate exactly.** Copy the layout from
  `tests/svt/load-tests/full/mixed/100rps/` and adapt — same five files,
  same `${MODE}` switch, same `svt_restart_opa` interaction.
- **Tokens come from Keycloak, not profiler JWKS** (decision D-3). Profiler
  `tests/svt/profiler/keys/` is scoped to `opa bench` and stays untouched.
- **OPA restart before every RPS** (decision D-2). The existing
  `svt_restart_opa` already re-seeds policies + PIPs — call it as-is.
- **Auto-promote with `±5%` gate on peak CPU and peak memory only**
  (decision D-6). IO is rendered in the table for visibility but is not
  gated. cAdvisor filesystem sampling is noisy on cgroup v2 — see
  `OQ-2` and document the limitation in the report's Notes section if
  you drop the fs slice.
- **Two canonical files, canonical first** (decision D-1):
  `docs/reports/mixed-load-report-canonical-latest.md` and
  `docs/reports/mixed-load-report-legacy-latest.md`. Independent baselines.
- **Bulk slot math: 1 HTTP request = 1 RPS** (decision D-4). At 1000 RPS
  the `ols-bulk-100` thread group fires 50 req/s, each carrying 100
  resources internally.
- **Idle baseline once per sweep, not per RPS** (decision D-5).
- **No commits without explicit owner approval.** Land all work on a
  feature branch; the owner reviews and merges.
- **No LLM attribution in commits, branches, or PR bodies** (sector rule;
  the `commit-msg` hook enforces it — do not use `--no-verify`).

#### Validation

Before declaring Phase 6 complete:

1. `tests/svt/scripts/up` smoke check passes (`environment ready` line).
2. New Keycloak users acquire valid tokens (probe each one against
   `/realms/svt-test/protocol/openid-connect/token`).
3. A dry-run smoke of the mixed JMX at `TARGET_RPS=25` with
   `DURATION_SECONDS=6` finishes with **zero JMeter errors** in both
   canonical and legacy modes (this is the bar the `svt-fixes` branch
   already meets for `tests/svt/load-tests/full/mixed/100rps`).
4. `tests/svt/scripts/mixed-load-report --mode canonical` produces a
   timestamped report under
   `tests/svt/load-tests/mixed-flow/artifacts/` and promotes it to
   `docs/reports/mixed-load-report-canonical-latest.md` on a first run
   (no existing baseline).
5. Re-running the script with no source changes promotes again (peaks
   are within `±5%` of themselves by construction).
6. The report contains: methodology section, idle-baselines table,
   six per-RPS results tables, peak-CPU and peak-MEM summary tables.
7. `bash tests/scripts/test-opa.sh` still passes (sanity — this task
   should not touch Rego, but verify).
8. `bash tests/svt/scripts/down` cleans the stack.

#### Delivery format

- Update the handover file (`...-mixed-load-report-task.md`) with a brief
  Execution Report — implemented changes, validation performed, remaining
  gaps. Do not prepare PR/MR output unless asked.
- Update `tests/svt/README.md` with a new "Mixed-flow reports" subsection
  pointing at the two canonical files and the runner script.
- Update the parent plan
  `docs/plans/20260330-load-testing-preparation-plan.md` with a row for
  this task.
- Land commits on the working branch only; the owner promotes to `master`.

## Done

- [x] Phase 1 — Mixed-flow generator
  - [x] Add a new SVT load-test directory
        `tests/svt/load-tests/mixed-flow/<rps>rps/`
        for each of the six RPS levels (`100`, `200`, `300`, `400`,
        `500`, `1000`).
  - [x] In each directory ship the canonical SVT layout
        (`scenario.md`, `config.env`, `test.jmx`, `run`,
        `artifacts/.gitkeep`). *Note: `test.jmx` is shared across all
        six directories at `tests/svt/load-tests/mixed-flow/test.jmx`
        and referenced from each per-RPS `run`.*
  - [x] Per-target `config.env` pins `TARGET_RPS`, `THREADS`,
        `RAMP_SECONDS=5`, `DURATION_SECONDS=60`, and `MODE` (canonical or
        legacy) via the existing JMX `${MODE}` switch.
- [x] Phase 2 — Mixed JMX plan
  - [x] Source request shapes from `tests/svt/profiler/<scenario>/input.json`
        for the eight scenarios that make up the mix.
  - [x] Compose a single JMX with eight thread groups, one per scenario,
        each rate-limited via `ConstantThroughputTimer` to the per-RPS
        sub-rates listed below.
  - [x] Drive both canonical and legacy through the same JMX via the
        existing `${MODE}` switch (mirroring
        `tests/svt/load-tests/full/mixed/100rps/test.jmx`), so the two
        reports are byte-for-byte comparable.
  - [x] Bulk slot accounting: `ols-bulk-100` counts as **1 HTTP request =
        1 RPS** in the JMeter throughput math. At 1000 RPS the bulk slot
        is 50 HTTP req/s, each carrying 100 resources internally.
- [x] Phase 3 — Token bootstrap (new SVT users)
  - [x] Extend
        [tests/svt/common/compose/keycloak/svt-realm.json](../../../test/svt/common/compose/keycloak/svt-realm.json)
        with one Keycloak user per profiler claim profile: roles and
        `email` are aligned with the corresponding profiler
        `input-real-token.json`. *Eight users seeded (`svt-mixed-001..008`)
        with distinct emails per RQ-B; `department=dept-01` attribute on
        the three condition-2 scenarios; new `oidc-usermodel-attribute-mapper`
        on the `authz-agent` client.*
  - [x] Stack bootstrap (`tests/svt/scripts/up`) acquires real Keycloak
        tokens for all new users at startup and exports them as JMeter
        properties (same pattern as `svt_acquire_all_tokens`).
  - [x] Profiler JWKS files (`tests/svt/profiler/keys/`) are **not**
        re-used in the running stack — tokens always come from Keycloak.
- [x] Phase 4 — Metric collection harness
  - [x] Add a helper in
        [tests/svt/common/scripts/lib/svt-lib.sh](../../../test/svt/common/scripts/lib/svt-lib.sh)
        that owns the per-RPS sequence:
        1. `svt_restart_opa` (existing helper — already re-seeds policies
           + PIPs on the `svt-fixes` branch; now also merges the
           mixed-flow seed via `jq`),
        2. (first iteration only) capture **idle-before** baseline for 30 s,
        3. run JMeter at the target RPS for **60 s**,
        4. capture **load** window metrics aligned to JMeter start/end
           epoch ms,
        5. (last iteration only) **wait 20 s** as a cooldown gap, then
           capture **idle-after** baseline for 30 s starting at
           `<last-load-end-ms> + 20 000 ms`.
        *Implemented as `svt_capture_idle_window` and
        `svt_run_jmeter_mixed_flow` in `svt-lib.sh`; the per-RPS sequence
        is driven from the Python report runner instead of an explicit
        shell loop. The 20 s cooldown gap is a follow-up refinement
        (2026-05-18) — see "Outstanding refinements" in the Execution
        Report; the first canonical + legacy baselines were captured
        without the gap and need to be re-run when the gap lands.*
  - [x] Reuse the existing PromQL lookups in
        [tests/svt/common/tools/svt_individual_matrix.py](../../../test/svt/common/tools/svt_individual_matrix.py)
        for CPU and memory; add the IO queries listed below for all three
        services.
- [x] Phase 5 — Report generator
  - [x] Add `tests/svt/scripts/mixed-load-report` (Python 3, mirroring the
        structure of `tests/svt/scripts/bench-report`).
  - [x] Accept `--mode canonical|legacy` and target the matching
        `docs/reports/mixed-load-report-<mode>-latest.md` canonical file.
  - [x] Drive the six RPS runs in sequence, collect metrics, write a
        timestamped Markdown report to
        `tests/svt/load-tests/mixed-flow/artifacts/`.
  - [x] Apply the same auto-promote gate as `bench-report`: regression =
        any peak CPU or peak memory cell `> baseline * 1.05`. IO is
        reported for visibility but **not** gated.
- [x] Phase 6 — First canonical baseline
  - [x] Run the full six-RPS canonical sweep on the host baseline
        documented in
        [tests/svt/README.md §Host Baseline](../../../test/svt/README.md#host-baseline-first-stage).
        *Executed on `2026-05-18` (`canonical-20260518-094051`); all six
        RPS levels achieved ~99% target with **0 JMeter errors**.*
  - [x] Commit the first
        `docs/reports/mixed-load-report-canonical-latest.md`.
        *Promoted unconditionally (no prior baseline); awaiting owner commit.*
- [x] Phase 7 — Legacy baseline (after canonical lands)
  - [x] Re-use the harness with `--mode legacy`; same six RPS, same
        eight-scenario mix mapped to legacy endpoints.
        *Executed on `2026-05-18` (`legacy-20260518-100747`); all six RPS
        levels achieved ~99% target with **0 JMeter errors**.*
  - [x] Commit the first
        `docs/reports/mixed-load-report-legacy-latest.md`.
        *Promoted unconditionally; awaiting owner commit.*

### Mixed-flow composition

The eight scenarios are taken verbatim from the `bench-report` profiler set;
the percentages sum to `100 %`.

| Scenario                             | Share | Profiler directory                                                                                                      |
| ------------------------------------ | ----- | ----------------------------------------------------------------------------------------------------------------------- |
| `ols-single-10roles`                 | 20%   | [tests/svt/profiler/ols-single-10roles/](../../../test/svt/profiler/ols-single-10roles)                                 |
| `rls-predicate`                      | 5%    | [tests/svt/profiler/rls-predicate/](../../../test/svt/profiler/rls-predicate)                                           |
| `rls-condition-1-expression`         | 5%    | [tests/svt/profiler/rls-condition/](../../../test/svt/profiler/rls-condition)                                           |
| `ols-bulk-100`                       | 5%    | [tests/svt/profiler/ols-bulk-100/](../../../test/svt/profiler/ols-bulk-100)                                             |
| `rls-condition-2-expression`         | 25%   | [tests/svt/profiler/rls-condition-2-expression/](../../../test/svt/profiler/rls-condition-2-expression)                 |
| `rls-predicate-summary-2-predicates` | 25%   | [tests/svt/profiler/rls-predicate-summary-2-predicates/](../../../test/svt/profiler/rls-predicate-summary-2-predicates) |
| `rls-predicate-pips-2-token-pip`     | 10%   | [tests/svt/profiler/rls-predicate-pips-2-token-pip/](../../../test/svt/profiler/rls-predicate-pips-2-token-pip)         |
| `wildcard-all-single`                | 5%    | [tests/svt/profiler/wildcard-all-single/](../../../test/svt/profiler/wildcard-all-single)                               |

Per-thread-group target throughput at each RPS level (HTTP requests / s):

| RPS  | ols-single-10roles | rls-predicate | rls-condition-1 | ols-bulk-100 | rls-condition-2 | rls-pred-sum-2 | rls-pip-2-tok | wildcard |
| ---: | -----------------: | ------------: | --------------: | -----------: | --------------: | -------------: | ------------: | -------: |
| 100  | 20                 | 5             | 5               | 5            | 25              | 25             | 10            | 5        |
| 200  | 40                 | 10            | 10              | 10           | 50              | 50             | 20            | 10       |
| 300  | 60                 | 15            | 15              | 15           | 75              | 75             | 30            | 15       |
| 400  | 80                 | 20            | 20              | 20           | 100             | 100            | 40            | 20       |
| 500  | 100                | 25            | 25              | 25           | 125             | 125            | 50            | 25       |
| 1000 | 200                | 50            | 50              | 50           | 250             | 250            | 100           | 50       |

### Measured resources

For each of the three services (`envoy`, `opa`, `decision-log-collector`)
the report captures three resource families:

1. **CPU** — fractional cores, from
   `sum(rate(container_cpu_usage_seconds_total{name=~"<svc>"}[30s]))`.
2. **Memory** — bytes (working set), from
   `sum(container_memory_working_set_bytes{name=~"<svc>"})`.
3. **IO** — sum of network and filesystem byte rates over the load window:
   - `sum(rate(container_network_receive_bytes_total{name=~"<svc>"}[30s]))`
     - `sum(rate(container_network_transmit_bytes_total{name=~"<svc>"}[30s]))`
   - `sum(rate(container_fs_reads_bytes_total{name=~"<svc>"}[30s]))`
     - `sum(rate(container_fs_writes_bytes_total{name=~"<svc>"}[30s]))`

For every (RPS, service, resource) cell the report records two numbers:

- **load-peak** — maximum value observed during the 60 s load window.
- **load-avg** — average over the 60 s load window.

Plus a single, run-global **idle-before-avg** and **idle-after-avg** column
captured once per sweep (see the run methodology below) to serve as a
reference baseline.

### Run methodology

Per sweep (one canonical sweep, one legacy sweep):

1. Bring the SVT stack to a clean state via `tests/svt/scripts/up`.
2. `svt_restart_opa` to fix the first RPS run's cold-OPA condition (the
   `svt-fixes` branch already re-seeds policies + PIPs after the restart).
3. Capture the **idle-before** baseline (30 s, no JMeter activity). One
   measurement per (service, resource) pair, attached to the report header.
4. For each of the six RPS levels in ascending order `100 → 1000`:
   1. `svt_restart_opa` to land in a cold-OPA state (same as between
      canonical and legacy phases in `tests/svt/load-tests/full/...`).
   2. Run JMeter against the mixed JMX at the target RPS for **60 s**
      (5 s ramp in, no cooldown inside the plan).
   3. Record the JMeter start/end epoch ms and query Prometheus for the
      matching range to extract **load-peak** and **load-avg** per
      (service, resource).
   4. Append one block to the results section.
5. After the last (1000 RPS) load window terminates, **wait 20 s** as a
   cooldown gap before sampling idle-after. This gap lets transient
   post-load activity (Envoy connection pool teardown, OPA request-cleanup,
   in-flight `decision-log-collector` writes) drop out of the sample so
   the captured idle-after reflects steady idle, not a tail of the load
   window. The cooldown is wall-clock only — no JMeter activity, no PromQL
   query during the gap.
6. Capture the **idle-after** baseline (30 s, no JMeter activity)
   immediately after the 20 s cooldown, i.e. starting at
   `<last-load-end-epoch-ms> + 20 000 ms`.
7. Tear down the stack with `tests/svt/scripts/down`.

The `decision-log-collector` keeps flushing during the idle-after window
— its drain behavior is part of the consumption story and must not be
masked. The 20 s cooldown is intentionally shorter than the typical
collector flush interval so the idle-after window still captures a slice
of drain activity rather than a fully-quiesced collector.

### Report structure

Each canonical report file
(`docs/reports/mixed-load-report-{canonical,legacy}-latest.md`) must
contain three top-level sections:

1. **Methodology** — short prose covering: stack topology (canonical or
   legacy ingress), scenario sources, the eight-scenario / six-RPS
   composition table (the matrix above), the cold-OPA-per-RPS sampling
   model, PromQL queries used, host baseline reference, and a one-line
   pointer to the other-mode report.
2. **Idle baselines** — one small table with `idle-before-avg` and
   `idle-after-avg` per (service, resource) pair, captured once per
   sweep.
3. **Results** — one results table per RPS level. Column layout:

   `| service | resource | load-peak | load-avg |`

   plus one summary table at the end that pivots peak CPU and peak memory
   per service across RPS levels (one row per service, one column per
   RPS).
4. **Notes** — free-form section for anomalies observed during the sweep
   (cAdvisor sampling gaps, JMeter ramp artifacts, OPA restart side-effects
   if any). Empty for a clean run.

### Execution Report (2026-05-18)

#### Design pass

- Full read of all 10 mandatory pre-read sources (`AGENTS.md`,
  `docs/conventions.md`, this handover, `docs/reports/bench-report-latest.md`,
  `tests/svt/README.md`, the existing `full/mixed/100rps` test layout,
  `svt-lib.sh`, `svt_individual_matrix.py`, `tests/svt/scripts/bench-report`,
  and all eight profiler scenario directories).
- Decoded the eight profiler `data.json` files and the eight
  `input-real-token.json` files into the simplified-policy and
  user-claim mapping tables documented above.
- Identified three blocking design conflicts (RQ-A, RQ-B, RQ-C) and
  obtained owner sign-off on resolutions before any code was written.
- OQ-3 resolved (extend `svt-test` realm, do not introduce a separate
  realm).

#### Implementation pass (Phases 1-5)

Landed on branch `svt-fixes`, uncommitted. All five Phase-1-to-5
deliverables are on disk and pass static gates listed below.

**Modified files:**

- [tests/svt/common/compose/keycloak/svt-realm.json](../../../test/svt/common/compose/keycloak/svt-realm.json)
  — added `oidc-usermodel-attribute-mapper` for the `department`
  claim on the `authz-agent` client; added 8 users
  `svt-mixed-001..008` with the role + attribute mapping documented
  in RQ-B. Realm now seeds 14 total users.
- [tests/svt/common/scripts/lib/svt-lib.sh](../../../test/svt/common/scripts/lib/svt-lib.sh)
  — new helpers `svt_merged_seed_policies`, `svt_merged_seed_pips`,
  `svt_upload_seeds`, `svt_capture_idle_window`,
  `svt_run_jmeter_mixed_flow`. `svt_restart_opa` rewritten to upload
  the merged base + mixed-flow seed. `svt_acquire_all_tokens` and
  `svt_write_tokens_file` extended with the 8 new svt-mixed tokens.
- [tests/svt/scripts/up](../../../test/svt/scripts/up) — seed upload
  step now merges base + mixed-flow JSON via `jq` before
  `PUT /internal/v1/policies` / `/internal/v1/pips` (same applies
  if the mixed-flow seed file is absent — graceful fallback to
  base-only upload). Added a probe loop for `svt-mixed-001..008`
  plus an Admin-API provisioning fallback in the same style as the
  existing `svt-multirole` block.

**New files:**

- [tests/svt/scripts/build-mixed-flow-seeds.py](../../../test/svt/scripts/build-mixed-flow-seeds.py)
  — deterministic generator that emits the additive simplified-policy
  and PIP files from the eight profiler scenarios. Re-running yields
  byte-for-byte identical output.
- [tests/svt/common/compose/seed/svt-mixed-flow-policies.json](../../../test/svt/common/compose/seed/svt-mixed-flow-policies.json)
  — 970 simplified-policy entries (`component=SVT_MIXED_FLOW`,
  resource types `SVT_RT_01..10` and `SVT_BULK_RT_01..04`; no
  overlap with the base `SVT` component).
- [tests/svt/common/compose/seed/svt-mixed-flow-pips.json](../../../test/svt/common/compose/seed/svt-mixed-flow-pips.json)
  — 2 PIPs (`subject.emailFromToken`, `subject.departmentFromToken`).
  Merged with the base PIP file, the runtime sees 2 unique PIPs
  (deduplicated by `name`).
- tests/svt/load-tests/mixed-flow/test.jmx
  — shared composite JMX, 8 thread groups, `${MODE}` switch in each
  thread group's `JSR223PreProcessor` selects the canonical or legacy
  endpoint and body. Per-thread-group `ConstantThroughputTimer`
  pinned to the scenario's share of `${TARGET_RPS}`.
- `tests/svt/load-tests/mixed-flow/<rps>rps/`
  — 6 directories (`100rps`, `200rps`, `300rps`, `400rps`, `500rps`,
  `1000rps`), each with `config.env` (pins TARGET_RPS + per-TG
  THREADS), `scenario.md`, `run` (standalone wrapper that sources
  `svt-lib.sh`, restarts OPA, runs the JMX), and `artifacts/.gitkeep`.
- [tests/svt/scripts/mixed-load-report](../../../test/svt/scripts/mixed-load-report)
  — Python 3 stdlib-only orchestrator (`--mode canonical|legacy`,
  `--skip-promote`). Captures the per-sweep idle-before / idle-after
  baselines, drives the six per-RPS `run` scripts in ascending order
  via subprocess + `MODE` / `ARTIFACTS_DIR` env, queries Prometheus
  range-data for every (service, resource) window, renders a
  Markdown report with methodology + idle table + 6 per-RPS tables +
  2 peak-summary tables + Notes, and auto-promotes to
  `docs/reports/mixed-load-report-<mode>-latest.md` when every peak
  CPU and peak memory cell stays within `±5%` of the existing
  baseline (IO rendered but not gated, per D-6).
- [tests/svt/README.md](../../../test/svt/README.md) — new "Mixed-flow
  reports" subsection pointing at the two canonical files, the
  runner, the layout, and the seed/realm extension story.
- [docs/plans/20260330-load-testing-preparation-plan.md](../../plans/20260330-load-testing-preparation-plan.md)
  — Status amended with follow-up reference; new row appended to
  the Handovers table.

#### Static-gate validation (2026-05-18)

All run on the host that owns the working tree, no docker stack needed.

- `python3 -c py_compile` on `build-mixed-flow-seeds.py` and
  `mixed-load-report` — both pass.
- `bash -n` on `svt-lib.sh`, `tests/svt/scripts/up`, and all 6
  per-RPS `run` scripts — all pass.
- `python3 -c "json.load(...)"` on `svt-realm.json`,
  `svt-mixed-flow-policies.json`, `svt-mixed-flow-pips.json` — all
  valid JSON.
- `xml.etree.ElementTree.parse` on `test.jmx` — well-formed XML.
- `jq -s 'add | length'` on base + mixed-flow policies → 1036
  (66 base + 970 mixed). PIPs after dedup-by-name → 2.
- `mixed-load-report --help` returns the expected `--mode` and
  `--skip-promote` flags.

#### Phase 6 — canonical sweep (executed `2026-05-18`)

- Wall-clock: ≈ 14 minutes (`08:40:51` → `08:48:?` plus Prometheus
  range queries). Artifact: `canonical-20260518-094051/`.
- All six RPS levels passed with **0 JMeter errors**:

  | RPS  | achieved | avg latency | max latency | error rate |
  | ---: | -------: | ----------: | ----------: | ---------: |
  | 100  | 99.2/s   | 3 ms        | 72 ms       | 0.00%      |
  | 200  | 198.2/s  | 3 ms        | 71 ms       | 0.00%      |
  | 300  | 297.3/s  | 3 ms        | 82 ms       | 0.00%      |
  | 400  | 396.3/s  | 4 ms        | 68 ms       | 0.00%      |
  | 500  | 495.1/s  | 4 ms        | 78 ms       | 0.00%      |
  | 1000 | 986.7/s  | 7 ms        | 234 ms      | 0.00%      |

- Peak summary (1000 RPS): envoy `0.573` cores / `66.1 MiB`,
  opa `4.072` cores / `88.6 MiB`, decision-log-collector `0.146` cores
  / `23.3 MiB`. Full per-RPS tables in
  `docs/reports/mixed-load-report-canonical-latest.md`.
- Promoted unconditionally (no prior baseline).
- Notes section: empty ("Clean run, no anomalies observed"). cAdvisor
  `container_fs_*` counters were non-zero, so the OQ-2 fs-sampling
  fallback note did not trigger.

#### Phase 7 — legacy sweep (executed `2026-05-18`)

- Wall-clock: ≈ 14 minutes (`10:07:47` → `10:15:?` plus Prometheus
  range queries). Artifact: `legacy-20260518-100747/`. Ran on the
  same stack as Phase 6 without `tests/svt/scripts/down` in between
  (same warm Keycloak realm).
- All six RPS levels passed with **0 JMeter errors**:

  | RPS  | achieved | avg latency | max latency | error rate |
  | ---: | -------: | ----------: | ----------: | ---------: |
  | 100  | 99.1/s   | 4 ms        | 65 ms       | 0.00%      |
  | 200  | 198.2/s  | 5 ms        | 80 ms       | 0.00%      |
  | 300  | 297.3/s  | 5 ms        | 82 ms       | 0.00%      |
  | 400  | 396.5/s  | 5 ms        | 76 ms       | 0.00%      |
  | 500  | 495.4/s  | 6 ms        | 126 ms      | 0.00%      |
  | 1000 | 975.5/s  | 30 ms       | 698 ms      | 0.00%      |

- Peak summary (1000 RPS): envoy `0.820` cores / `113.9 MiB`,
  opa `6.917` cores / `200.1 MiB`, decision-log-collector `0.203` cores
  / `36.0 MiB`. Full per-RPS tables in
  `docs/reports/mixed-load-report-legacy-latest.md`.
- Promoted unconditionally.
- Notes section: empty ("Clean run, no anomalies observed").

#### Canonical vs legacy cost delta (1000 RPS peaks)

| metric                           | canonical | legacy | delta |
| -------------------------------- | --------: | -----: | ----: |
| envoy CPU (cores)                | 0.573     | 0.820  | +43%  |
| envoy mem (MiB)                  | 66.1      | 113.9  | +72%  |
| opa CPU (cores)                  | 4.072     | 6.917  | +70%  |
| opa mem (MiB)                    | 88.6      | 200.1  | +126% |
| decision-log-collector CPU       | 0.146     | 0.203  | +39%  |
| decision-log-collector mem (MiB) | 23.3      | 36.0   | +55%  |
| JMeter avg latency (ms)          | 7         | 30     | +330% |

Legacy adds the Envoy Lua compatibility-mapping cost on top of the
canonical evaluation cost, as expected (OQ-1 deferred: the two
baselines are independent and not cross-mode-gated, per D-1).

#### Independent validation pass (2026-05-18)

After Phase 7 promotion, an independent read-only validation pass
re-checked the claim surface without re-running the sweeps:

- **Zero-error claim from raw JTL.** All 12 `*/results.jtl` files
  recounted via `awk -F',' 'NR>1 {t++; if ($8!="true") e++}'` —
  totals match the Summariser lines exactly, error count is `0`
  in every file. Achieved-throughput correction landed in the Status
  block: 1000 RPS is 97.5–98.7% of target (not ~99%), 100–500 RPS is
  99.1–99.2%.
- **Report numbers vs raw Prometheus.** Spot-check on two cells:
  canonical-1000rps opa CPU (`peak=4.072 / avg=3.149`) and legacy-1000rps
  opa memory (`peak=200.1 MiB`) recomputed from
  `<run>/prometheus/<svc>__<resource>.json` raw range responses match
  the rendered tables exactly.
- **Schema sanity.** All 6 `tests/svt/load-tests/mixed-flow/<rps>rps/`
  directories carry the canonical SVT layout (`scenario.md`,
  `config.env`, `run`, `artifacts/.gitkeep`). The composite JMX has 8
  ThreadGroups, well-formed XML. `svt-realm.json` carries 14 users
  including `svt-mixed-001..008` and the `oidc-usermodel-attribute-mapper`
  for `department`.
- **Decisions D-1…D-7 honored.** Two separate baseline files; per-RPS
  OPA restart (`svt_restart_opa`); Keycloak-issued tokens only (profiler
  keys untouched in the SVT stack); `ols-bulk-100` rated at 1 HTTP req/s;
  one shared `idle-before` / `idle-after` per sweep; auto-promote with
  `±5%` gate on peak CPU/MEM only; 60s load window on every level.

#### Outstanding refinements (post-validation, 2026-05-18)

- **D-8: 20 s cooldown gap before idle-after.** Added to the spec
  after the first sweeps landed. The Phase 6 / Phase 7 baselines
  (`canonical-20260518-094051`, `legacy-20260518-100747`) captured
  idle-after immediately after JMeter termination, which is the
  pre-D-8 behavior. The two canonical report files therefore embed a
  slightly elevated idle-after row (post-load transients leaked into
  the sample — see the canonical idle-after CPU figures: envoy
  `0.244` cores, opa `1.766` cores, decision-log-collector `0.068`
  cores, all visibly above what a quiesced stack reports). The
  baselines must be re-captured once the cooldown lands in
  `svt_capture_idle_window` / `mixed-load-report` so the canonical
  files reflect a true steady idle.

#### D-8 cooldown retrofit (2026-05-18)

After the canonical and legacy sweeps landed, the handover added D-8
(20 s wall-clock cooldown between the last load window and idle-after).
Per owner instruction, sweeps were **not** re-run — instead, Prometheus
TSDB was re-queried at the same range step (5 s) over the shifted
window `[<load_end_ms> + 20 000, + 50 000]` for each sweep, and the
`idle-after-avg` cells in both canonical and legacy reports were
overwritten in place.

- Canonical sweep last-load-end-ms: `1779086892259` → D-8 idle-after
  window `[1779086912259, 1779086942259]`. Raw range payloads +
  `summary.json` under
  `tests/svt/load-tests/mixed-flow/artifacts/canonical-20260518-094051/idle-after-d8/`.
- Legacy sweep last-load-end-ms: `1779088509486` → D-8 idle-after
  window `[1779088529486, 1779088559486]`. Raw range payloads under
  `…/legacy-20260518-100747/idle-after-d8/`.
- The original pre-shift `idle-after/` directories are kept alongside
  the new `idle-after-d8/` for traceability — no Prometheus query was
  re-issued for them.
- Result: transient-driven CPU + IO cells drop substantially under the
  cooldown (e.g. canonical `opa` CPU 1.766 → 0.133 cores, legacy `opa`
  CPU 2.283 → 0.069 cores). Memory cells stay near pre-shift values
  (working sets are saturated, not transients) — confirms the cooldown
  is short enough to retain a slice of drain activity per the
  methodology.

Code-path follow-up landed in the same session: the cooldown gap is
now implemented in `tests/svt/scripts/mixed-load-report` itself. New
constant `COOLDOWN_SECONDS = 20`; the runner tracks `last_load_end_ms`
across the per-RPS loop, sleeps `max(0, last_load_end_ms + 20 000 ms −
now_ms)` before sampling `idle-after`, then records `cooldown_seconds` - `last_load_end_ms` alongside the standard `start_ms` / `end_ms` in
`idle-after/window.json`. The Methodology section emitted into the
generated report references D-8 explicitly. Any future
canonical / legacy sweep started by the script will therefore land
its `idle-after-avg` cells on the cooldown-shifted window directly,
matching the values now committed in
`docs/reports/mixed-load-report-{canonical,legacy}-latest.md`.

### Owner-gated work (still pending)

- **Owner commit** — sector rule "no commits without explicit owner
  approval" applies, and the `commit-msg` hook will reject LLM
  attribution trailers. All work is uncommitted on `svt-fixes`.
- **Wider regression sanity** — `bash tests/scripts/test-opa.sh` was
  not re-run as part of this session (the task is additive: no Rego
  changes, only seed JSON and SVT harness — but a sanity run is still
  worth doing before the commit).
- **`tests/svt/scripts/down`** — stack was left running after the
  Phase 7 sweep so the owner can inspect Grafana / Prometheus
  artefacts before tearing down.

#### Open follow-ups

- OQ-1 (legacy vs canonical cross-mode gate) — still default
  "independent baselines, no cross-mode gating"; both baselines now
  exist (canonical at `0.573` / `66.1 MiB` envoy peak at 1000 RPS,
  legacy at `0.820` / `113.9 MiB`), revisit if owner wants a cross-mode
  ceiling on the delta in a follow-up task.
- OQ-2 (cAdvisor `container_fs_*` reliability on cgroup v2) —
  **partially resolved by the first sweep**: opa and
  decision-log-collector report non-zero `fs_reads_bytes_total` and
  `fs_writes_bytes_total` consistently, but every envoy `io_fs` cell
  came back empty (rendered as `—` in the report). The remaining
  ambiguity is specific to the envoy container; future generator
  iterations may want to drop the envoy fs row explicitly with a Notes
  pointer rather than render it as `—`.

#### Notes for whoever runs the sweeps

- The branch `svt-fixes` carries `ed33c54` (the `svt_restart_opa`
  re-seed fix and the `svt-pips.json` bootstrap). All the new code
  assumes that base.
- Per-RPS THREAD counts in `config.env` are conservative
  (`max(5, ceil(rps/20))`). If JMeter saturates before the target RPS
  is sustained at 1000 RPS, raise the 1000rps `THREADS` knob; the
  6 directories are independent.
- The composite JMX writes one combined `results.jtl`; per-scenario
  breakouts are visible via the `Label` set in each thread group's
  `JSR223PostProcessor` (e.g. `ols-bulk-100 [canonical]`).

## Decisions

- *D-1.* **Two separate reports, canonical first.** Canonical is the primary
  baseline; legacy follows in a second sweep that reuses the same harness
  with `--mode legacy`. Each report has its own canonical file and its own
  promote-gate baseline so a regression in legacy mapping cost cannot mask
  a regression in canonical evaluation cost (and vice versa).
- *D-2.* **OPA is restarted before every RPS run.** This costs ~3 minutes
  total per sweep but guarantees every RPS measurement is taken from a
  cold-OPA condition; warm-cache contamination across RPS levels is
  impossible. The `svt-fixes` branch's `svt_restart_opa` already re-seeds
  policies + PIPs after each restart, so the helper is suitable as-is.
- *D-3.* **Tokens come from Keycloak, not profiler JWKS.** The profiler
  fixtures (`tests/svt/profiler/keys/`) stay scoped to `opa bench`. The
  SVT realm is extended with users whose roles and `email` claim mirror
  the profiler `input-real-token.json` claim profiles, and the load
  generator pulls live tokens at bootstrap. This keeps `tests/svt/scripts/up`
  the single source of truth for stack credentials.
- *D-4.* **Bulk slot accounting: 1 HTTP request = 1 RPS.** `ols-bulk-100`
  contributes 5% of the HTTP rate (50 req/s at 1000 RPS), each carrying
  100 resources. Wire-level throughput stays comparable to non-bulk
  slots; if a future task wants per-decision throughput equivalence, it
  ships as a follow-up.
- *D-5.* **Idle baseline is captured once per sweep, not per RPS.** Since
  OPA is restarted before every RPS run, the per-RPS idle-before window
  would be identical by construction. A single pair of `idle-before` and
  `idle-after` measurements at the sweep boundaries is enough.
- *D-6.* **Auto-promote with the same ±5% gate as `bench-report`.**
  Regression = any peak CPU or peak memory cell exceeds the canonical
  baseline by more than 5%. IO is shown for visibility but not gated;
  cAdvisor filesystem sampling is too noisy on cgroup v2 to gate against.
- *D-7.* **Load window is 60 s for every RPS level.** Varying the
  duration would break peak-measurement comparability across runs.
- *D-8 (2026-05-18 refinement).* **Idle-after starts 20 s after the
  last load window ends.** The previous spec sampled idle-after
  immediately after JMeter terminated, which let post-load transient
  activity (Envoy connection pool teardown, OPA request-cleanup,
  in-flight `decision-log-collector` writes) leak into the idle sample.
  The 20 s cooldown gap is wall-clock only (no JMeter, no PromQL) so
  the captured idle-after reflects steady idle rather than a tail of
  the load window. The cooldown is intentionally shorter than the
  typical collector flush interval so the idle-after window still
  captures a slice of drain activity.

### Resolved design questions (2026-05-18)

Three blocking design questions were identified during the design pass
and resolved with the owner before implementation. They are captured
here so the next implementation session does not re-litigate them.

- *RQ-A. Profiler policies + PIPs loading.* The mixed-flow sweep needs
  the eight profiler scenarios' policies + PIPs available in OPA
  simultaneously. **Decision:** keep the hand-authored
  `tests/svt/common/compose/seed/svt-policies.json` and
  `svt-pips.json` as-is, and ship two new committed seed files
  generated from the profiler scenarios:
  `tests/svt/common/compose/seed/svt-mixed-flow-policies.json` and
  `tests/svt/common/compose/seed/svt-mixed-flow-pips.json`. Both
  `tests/svt/scripts/up` and `svt_restart_opa` upload the merged
  payload (base + mixed-flow) via `PUT /internal/v1/policies` /
  `/internal/v1/pips` — the policy-admin endpoint replaces the entire
  set, so the upload must merge both files before each PUT. Generator
  script is `tests/svt/scripts/build-mixed-flow-seeds.py`
  (deterministic, committed alongside the generated JSON). This
  preserves the existing seed file as a clean hand-authored artifact
  and isolates the ~970 mechanical mixed-flow entries.

- *RQ-B. Keycloak user identity for the 8 profiler claim profiles.*
  All eight profiler `input-real-token.json` files use the same
  `email` claim `svt-matrix-001@example.com`, but Keycloak's
  `svt-test` realm has `duplicateEmailsAllowed: false`. **Decision:**
  ship eight distinct Keycloak users `svt-mixed-001` … `svt-mixed-008`
  with emails `svt-mixed-NNN@example.com` and per-scenario role sets.
  Resource payloads built by JMeter rewrite the profiler-verbatim
  `ownerId` (`svt-matrix-001@example.com`) to the per-user
  `svt-mixed-NNN@example.com` via a JSR223 PreProcessor in each thread
  group. The 8-user mapping (with claim profile + role list) is:

  | User            | Roles             | `department` attr | Used by thread group                 |
  | --------------- | ----------------- | ----------------- | ------------------------------------ |
  | `svt-mixed-001` | `ROLE_SVT_01..10` | (none)            | `ols-single-10roles`                 |
  | `svt-mixed-002` | `ROLE_SVT_ADMIN`  | (none)            | `rls-predicate`                      |
  | `svt-mixed-003` | `ROLE_SVT_ADMIN`  | (none)            | `rls-condition`                      |
  | `svt-mixed-004` | `ROLE_SVT_ADMIN`  | (none)            | `ols-bulk-100`                       |
  | `svt-mixed-005` | `ROLE_SVT_ADMIN`  | `dept-01`         | `rls-condition-2-expression`         |
  | `svt-mixed-006` | `ROLE_SVT_ADMIN`  | `dept-01`         | `rls-predicate-summary-2-predicates` |
  | `svt-mixed-007` | `ROLE_SVT_ADMIN`  | `dept-01`         | `rls-predicate-pips-2-token-pip`     |
  | `svt-mixed-008` | `ROLE_SVT_ADMIN`  | (none)            | `wildcard-all-single`                |

  All eight share password `password`. Bootstrap (`tests/svt/scripts/up`)
  acquires their tokens via the existing `client_id=authz-agent` /
  `client_secret=authz-agent-secret` grant.

- *RQ-C. `department` token claim for the three condition-2 scenarios.*
  Three scenarios (`rls-condition-2-expression`,
  `rls-predicate-summary-2-predicates`,
  `rls-predicate-pips-2-token-pip`) require a `department` claim on
  the access token. **Decision:** add a Keycloak `oidc-usermodel-attribute-mapper`
  protocol mapper to the `authz-agent` client that maps the user
  attribute `department` to the access token claim `department`. The
  three relevant users (`svt-mixed-005`, `006`, `007`) carry the
  Keycloak attribute `department=dept-01`. Other users have no
  attribute, and the mapper emits no claim for them. This is purely
  additive to the realm and does not affect existing `svt-test`
  users (`svt-admin`, `svt-manager`, `svt-operator`, etc.).

## Open Questions

- *OQ-1.* Should the legacy sweep be gated on the canonical baseline (i.e.
  legacy peaks should never exceed canonical peaks by more than X%), or
  do the two modes track entirely independent baselines? Default in this
  task: independent baselines, no cross-mode gating.
- *OQ-2.* Is `container_fs_*` cAdvisor data reliable on the project's
  reference host (Ubuntu 24.04 + cgroup v2)? If not, drop the fs slice
  from the IO total and document the limitation in the Notes section.
- *OQ-3 (resolved 2026-05-18).* The new SVT users are added to the
  existing `svt-test` realm (no second realm). Confirmed by owner.

## Next Steps

All seven phases are done; both canonical and legacy baselines are on
disk, and `tests/svt/README.md` already carries the "Mixed-flow reports"
subsection. The remaining work is gated on the owner:

- **D-8 cooldown landing.** Add a 20 s wall-clock sleep between the
  last-RPS JMeter termination and the idle-after window start in
  `svt_capture_idle_window` (or equivalently in the
  `mixed-load-report` Python runner — wherever the idle-after window
  is scheduled). Re-capture both baselines:
  `tests/svt/scripts/mixed-load-report --mode canonical` and
  `--mode legacy`; the two canonical files in `docs/reports/` must be
  refreshed so their idle-after rows reflect steady idle rather than
  post-load transients (see "Outstanding refinements" in the
  Execution Report for the elevated numbers captured under the
  pre-D-8 behavior).
- **Owner review + commit.** Land the uncommitted change set on
  `svt-fixes` (see the file list in the Execution Report). Sector rule
  forbids LLM-attribution trailers in the commit message; the
  `commit-msg` hook enforces it — do **not** use `--no-verify`.
- **Pre-commit sanity.** `bash tests/scripts/test-opa.sh` was deferred
  during the execution session and is worth running once before the
  commit (the change set is additive — no Rego edits — but the sanity
  bar is cheap).
- **Tear-down.** The SVT stack was left running after Phase 7 so the
  owner can inspect Grafana / Prometheus state. Run
  `bash tests/svt/scripts/down` after review (or after the D-8 re-run
  if the owner decides to land both in one pass).

Deferred follow-ups (separate tasks if and when the owner decides):

- Drop the envoy `io_fs` row from the report renderer rather than
  emitting `—` cells (OQ-2 partial finding above).
- Add the mixed-flow sweeps to `tests/svt/load-tests/run` as opt-in
  suite steps (env-gated, off by default — full matrix runtime would
  roughly triple).
- Decide whether the legacy baseline should be cross-mode-gated against
  canonical (OQ-1).
