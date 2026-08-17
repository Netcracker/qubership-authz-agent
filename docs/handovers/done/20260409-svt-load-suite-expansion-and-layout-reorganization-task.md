# Task: 20260409-svt-load-suite-expansion-and-layout-reorganization — Expand SVT Load Suite and Reorganize `tests/svt/`

*Archived internal engineering document, restored for reference. Component names and paths reflect the tree at the time of writing and may differ from the current layout.*

## Filename

`20260409-svt-load-suite-expansion-and-layout-reorganization-task.md`

## Plan

[20260330-load-testing-preparation-plan.md](../../plans/20260330-load-testing-preparation-plan.md)

## Jira dev task

*TBD.*

## Status

*TBD.*

## Goal

Prepare the next SVT implementation wave: add the requested mixed-load and per-request-family
benchmark profiles in both `full` and `opa-direct` formats, and reorganize `tests/svt/` so shared
configs, profilers, and load-test definitions are separated cleanly while each test keeps its own
report artifacts next to the test definition. The top-level compatibility wrapper
`tests/svt/scripts/run` must act as the suite entrypoint and execute the whole load-test set in the
same deterministic order as the common suite runner: all `full` tests first, then all
`opa-direct` tests.

## Done

- [x] Linked the new task to the active load-testing preparation plan.
- [x] Fixed the requested scope to cover both benchmark formats for every test:
  - `full` for the client-visible Envoy-boundary flow; and
  - `opa-direct` for the backend-isolated flow.
- [x] Fixed the interpretation of "same ratio as in the current mixed test" as the current
  stage-level `1/3 : 1/3 : 1/3` split across:
  - single-resource authorization/check;
  - filter-style authorization/check; and
  - bulk authorization/check.
- [x] Fixed the compatibility rule for every new `full` profile: each profile still runs as a
  canonical-vs-legacy pair with semantically identical request composition.
- [x] Fixed the requested new profile matrix:
  - mixed `100 RPS`;
  - mixed `200 RPS`;
  - mixed `300 RPS`;
  - mixed `400 RPS`;
  - mixed `500 RPS`;
  - single-only `100 RPS`;
  - filter-only `100 RPS`; and
  - bulk-only `100 RPS`.
- [x] Fixed the artifact-location requirement: generated reports must be stored under the
  corresponding test directory rather than under one shared top-level artifacts sink.
- [x] Fixed the runner rule:
  - the suite-level `run` must execute all test types sequentially; and
  - each individual test must also have its own dedicated run script.
- [x] Fixed the suite-level execution order:
  - all `full` tests run first; and
  - all `opa-direct` tests run after that.
- [x] Align the compatibility wrapper `tests/svt/scripts/run` with the suite contract so it
  launches the whole load-test set in the same deterministic order:
  - all `full` tests first; and
  - all `opa-direct` tests after that.
- [x] Fixed the scenario-definition rule: every individual test keeps its own specific `JMX` file;
  shared JMeter templates must not replace per-test `JMX` ownership.
- [x] Fixed the `opa-direct` mixed-scenario rule: there is no separate baseline-style
  `opa-direct matrix` family in the target suite; the mixed `opa-direct` tests replace that role
  and are executed by the same suite-level `run`.
- [x] Fixed the profiler-extension rule: every profiler directory under `tests/svt/profiler/`
  must also gain:
  - `bench.sh` for `opa bench` with `5` runs; and
  - `profile-trace.sh` for a full explain trace (`--explain=full`).
- [x] Reorganize `tests/svt/` into clearly separated areas for shared configs, profilers, and
  load-test definitions.
- [x] Extract shared Compose, Grafana, Prometheus, dataset, helper-script, and utility assets into
  a new `tests/svt/common/` area.
- [x] Move the current baseline Envoy-boundary load test into the new load-test directory layout.
- [x] Move the current additive OPA-direct load tests into the same load-test directory layout
  without changing their diagnostic-only status.
- [x] Add five mixed `full` profiles at `100/200/300/400/500 RPS`, each preserving the current
  `1/3 : 1/3 : 1/3` throughput split across single/filter/bulk families.
- [x] Add five matching mixed `opa-direct` profiles at `100/200/300/400/500 RPS`.
- [x] Add three dedicated `full` `100 RPS` profiles:
  - single only;
  - filter only; and
  - bulk only.
- [x] Add three matching dedicated `opa-direct` `100 RPS` profiles:
  - single only;
  - filter only; and
  - bulk only.
- [x] Ensure each test directory owns:
  - one dedicated `run` script;
  - one dedicated scenario description; and
  - one dedicated specific `JMX` file.
- [x] Extend every profiler directory under `tests/svt/profiler/` so it owns:
  - `profile.sh`;
  - `bench.sh` with `5` runs; and
  - `profile-trace.sh` with full explain output.
- [x] Add a suite-level `run` entrypoint that executes all `full` and `opa-direct` tests
  sequentially in a deterministic order.
- [x] Update runners so each load test writes artifacts into its own neighboring `artifacts/`
  directory.
- [x] Update `tests/svt/README.md`, scenario docs, and wrapper usage examples to match the new
  layout and profile set.
- [x] Fix the new shared Compose/runtime paths so `tests/svt/scripts/up` and the new per-test
  runners are actually runnable from the repository root.
- [x] Remove active runtime usage of the legacy shared artifact sink `tests/svt/artifacts/`.
- [x] Finish runtime smoke validation for representative `full` and `opa-direct` tests after the
  Compose/runtime blockers are fixed (see validation section below).
- [x] Fix the suite-level `tests/svt/load-tests/run` wrapper so it executes the full selected
  sequence instead of exiting after the first successful test under `set -e`.
- [x] Re-run the suite-level `tests/svt/load-tests/run` end to end after the wrapper fix and
  record the final orchestration validation in this handover.

### Target Layout

```text
tests/svt/
├── README.md
├── common/
│   ├── compose/
│   ├── grafana/
│   ├── prometheus/
│   ├── jmeter/
│   │   └── data/
│   ├── scripts/
│   │   └── lib/
│   └── tools/
├── profiler/
│   ├── README.md
│   └── ...
└── load-tests/
    ├── run
    ├── full/
    │   ├── mixed/
    │   │   ├── 100rps/
    │   │   ├── 200rps/
    │   │   ├── 300rps/
    │   │   ├── 400rps/
    │   │   ├── 500rps/
    │   │   └── 1000rps/
    │   ├── single/
    │   │   └── 100rps/
    │   ├── filter/
    │   │   └── 100rps/
    │   └── bulk/
    │       └── 100rps/
    └── opa-direct/
        ├── mixed/
        │   ├── 100rps/
        │   ├── 200rps/
        │   ├── 300rps/
        │   ├── 400rps/
        │   ├── 500rps/
        │   └── 1000rps/
        ├── single/
        │   └── 100rps/
        ├── filter/
        │   └── 100rps/
        └── bulk/
            └── 100rps/
```

Each load-test directory must contain only test-specific assets and neighboring output storage, for
example:

```text
tests/svt/load-tests/full/mixed/100rps/
├── scenario.md
├── test.jmx
├── config.env
├── run
└── artifacts/
```

The shared CSV datasets, Compose stack configs, Grafana dashboards, Prometheus scrape config,
shared runner functions, and helper tools should move under `tests/svt/common/` so the per-test
directories stay small and explicit. `JMX` ownership stays local to each test directory.

Each profiler directory must also follow one consistent wrapper contract:

```text
tests/svt/profiler/<scenario>/
├── data.json
├── input.json
├── profile.sh
├── bench.sh
└── profile-trace.sh
```

### Acceptance Criteria

1. The current baseline mixed `full` scenario remains available after the reorganization, but it
   lives in the new per-test structure as the `1000rps` mixed profile.
2. The five new mixed profiles preserve the current stage-level `1/3 : 1/3 : 1/3` split across
   single/filter/bulk request families in both `full` and `opa-direct` formats.
3. The three dedicated `100 RPS` profiles isolate one request family per profile in both `full`
   and `opa-direct` formats.
4. Every individual test directory owns its own `run` script and its own specific `JMX` file.
5. The suite-level `run` executes all test directories sequentially in a documented deterministic
   order: all `full` tests first, then all `opa-direct` tests.
6. The compatibility wrapper `tests/svt/scripts/run` delegates to the suite-level execution flow
   and therefore launches the whole load-test set in the same documented order: all `full` tests
   first, then all `opa-direct` tests.
7. Each profile stores generated artifacts under its own directory, for example
   `tests/svt/load-tests/full/mixed/100rps/artifacts/<timestamp>/...`.
8. `full` artifact sets keep canonical and legacy results separated inside the corresponding run
   artifact tree.
9. The shared top-level `tests/svt/artifacts/` sink is removed from active runner usage once the
   new per-test artifact directories are in place.
10. `tests/svt/README.md` documents the new structure and the entrypoints for running the added
   profiles.
11. Static validation passes for the moved markdown/config/shell assets, and short smoke
    executions pass for at least one representative test from each request family in both formats.
12. The reorganized suite does not keep a separate baseline-style `opa-direct matrix` branch; its
    mixed `opa-direct` coverage is provided by the ordinary `opa-direct/mixed/*` tests invoked by
    the same suite-level `run`.
13. Every profiler directory provides:
    - `profile.sh` for `opa eval --profile`;
    - `bench.sh` for `opa bench` with `5` runs; and
    - `profile-trace.sh` for `opa eval --explain=full`.

### Validation

Validated on `2026-04-09`:

- Static checks passed:
  - `git diff --check`
  - `bash -n` for changed/new SVT shell scripts
  - `docker compose -f tests/svt/common/compose/docker-compose.yml config`
- Structure checks passed:
  - `18` load-test directories under `tests/svt/load-tests/*/*/*rps`
  - each contains `run`, `scenario.md`, `test.jmx`, `config.env`, and `artifacts/`
  - `8` profiler directories under `tests/svt/profiler/*` at the time of this handover
  - each contains `data.json`, `input.json`, `profile.sh`, `bench.sh`, and `profile-trace.sh`
- Wrapper checks passed:
  - all `profile-trace.sh` wrappers completed successfully
  - dedicated `single/filter/bulk` `JMX` files are distinct and not simple copies of the mixed
    profile

Runtime blockers resolved on `2026-04-09`:

1. Fixed `tests/svt/common/compose/docker-compose.yml` relative paths: build contexts and
   volume mounts now correctly reference `../../../../image/` from the relocated
   `tests/svt/common/compose/` location (was `../../../image/` from old `tests/svt/compose/`).
   Removed stale default JMeter plans volume mount since JMX ownership is now per-test.
2. Converted legacy wrappers to the new layout:
   - `tests/svt/scripts/run` now delegates to `tests/svt/load-tests/run`, which executes the
     full suite in deterministic `full` then `opa-direct` order
   - `tests/svt/scripts/run-opa-direct` remains a targeted direct wrapper for the corresponding
     `opa-direct` per-test runners
   - env var overrides (`TARGET_RPS`, `THREADS`, `TESTS_CSV`, etc.) are passed through; per-test
     `config.env` uses `${VAR:-default}` syntax so env vars take precedence
3. Full runtime smoke validation completed with `0` errors on each representative profile:
   - `full/mixed/100rps` (canonical + legacy, OPA restart between phases)
   - `full/single/100rps` (canonical + legacy, single-family only)
   - `full/filter/100rps` (canonical + legacy, filter-family only)
   - `full/bulk/100rps` (canonical + legacy, bulk-family only)
   - `opa-direct/mixed/100rps` (OPA-direct, 3 thread groups)
   - `opa-direct/single/100rps` (OPA-direct, single-family only)
   - `opa-direct/filter/100rps` (OPA-direct, filter-family only)
   - `opa-direct/bulk/100rps` (OPA-direct, bulk-family only)
   - legacy wrapper `scripts/run` with `TARGET_RPS=100` (delegated to `full/mixed/100rps`)
4. Full profiler `bench.sh` validation completed successfully after reducing the wrapper baseline
   to `opa bench --count 5`:
   - all `8` `tests/svt/profiler/*/bench.sh` scripts completed successfully
   - the reduced count was chosen explicitly to keep routine validation bounded in wall-clock time
5. Suite-level `tests/svt/load-tests/run` arithmetic-increment bug fixed (`((PASSED++)) || true`
   guards for `set -e` safety). End-to-end suite smoke completed successfully with
   `TESTS_CSV=full/mixed/100rps,opa-direct/mixed/100rps`: 2 passed, 0 failed, 0 skipped.
6. Compatibility wrapper `tests/svt/scripts/run` updated to delegate to `tests/svt/load-tests/run`
   (the suite-level orchestrator) instead of targeting one mixed `full` profile. Smoke validated
   with `TESTS_CSV=full/mixed/100rps,opa-direct/mixed/100rps`: 2 passed, 0 failed, 0 skipped —
   both `full` and `opa-direct` sections executed sequentially through the legacy entrypoint.

## Decisions

1. This task expands the SVT suite in both required benchmark formats:
   - `full` for the client-visible Envoy boundary; and
   - `opa-direct` for backend-isolated diagnostics.
2. "Same ratio as the current mixed test" is fixed as the current `1/3 : 1/3 : 1/3`
   stage-throughput split across single, filter, and bulk families, not as a new dataset-level
   row weighting rule.
3. Each new `full` profile remains a canonical-vs-legacy pair because ADR-0030 keeps paired
   measurements as the comparability rule for Envoy-boundary SVT.
4. The repository-layout change stays inside the existing `tests/svt/` ownership boundary from
   ADR-0011 and ADR-0030, so this handover records the implementation target without opening a new
   architecture ADR at task-definition time.
5. Per-test artifact colocation is part of the task outcome; reports must sit next to the test that
   generated them instead of being mixed in one shared global artifact directory.
6. The suite must provide one top-level sequential `run` entrypoint plus one dedicated run script
   per individual test.
7. Shared data and helper logic may move into `tests/svt/common/`, but `JMX` ownership stays local
   to each test directory.
8. The suite-level execution order is fixed: run all `full` tests first, then all `opa-direct`
   tests.
9. The target suite does not preserve a separate baseline-style `opa-direct matrix` family; the
   mixed `opa-direct` tests replace that role and are executed through the same suite-level `run`.
10. Profiler wrappers are standardized across all profiler directories: `profile.sh`, `bench.sh`
    with `5` runs, and `profile-trace.sh` with `--explain=full`.
11. `tests/svt/scripts/run` is the compatibility top-level SVT entrypoint and must delegate to the
    shared suite runner so it executes all load tests in `full` then `opa-direct` order; it must
    not remain pinned to a single mixed `full` profile.
12. `tests/svt/scripts/run-opa-direct` may remain a targeted direct wrapper, but it does not
    replace the whole-suite responsibility of `tests/svt/scripts/run`.

## Open Questions

No open questions.

## Next Steps

No further implementation steps remain. The task is closed.
