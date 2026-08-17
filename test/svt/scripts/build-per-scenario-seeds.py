#!/usr/bin/env python3

# Copyright 2024-2026 Netcracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Generate the additive per-scenario simplified-policy and PIP seed files.

The per-scenario decision-time report (handover 20260518-per-scenario)
measures end-to-end decision time across all 28 scenarios listed in
`docs/reports/bench-report-latest.md`. Each scenario gets its own
isolated namespace so per-scenario policies cannot collide with one
another or with the eight mixed-flow scenarios already seeded by
`build-mixed-flow-seeds.py`.

Outputs:
  - tests/svt/common/compose/seed/svt-per-scenario-policies.json
  - tests/svt/common/compose/seed/svt-per-scenario-pips.json

Naming convention (per-scenario isolation):
  - Resource types : `PS_<SCENARIO_UPPER>_RT_NN`
  - Operations    : `PS_<SCENARIO_UPPER>_OP_NN`
  - Roles         : `PS_<SCENARIO_UPPER>_ROLE_NN` (single role NN=01,
                     except `ols-single-Nroles` where NN spans 01..N)
  - Component     : `PS_<SCENARIO_UPPER>`

This separation guarantees a `--scenarios <subset>` sweep run can rely
on its scenario's policies + user being present without depending on
any other scenario's seed.

Run from the authz-agent repo root:

    tests/svt/scripts/build-per-scenario-seeds.py

The generator is deterministic — re-running yields a byte-for-byte
identical output. The same inventory drives `build-per-scenario-jmx.py`
(JMX + per-RPS directory generation), so the seed namespace and the
JMX request bodies stay in sync.
"""

from __future__ import annotations

import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SVT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
SEED_DIR = os.path.join(SVT_DIR, "common", "compose", "seed")


# ── shared inventory ───────────────────────────────────────────────────────
# The 28 scenarios from docs/reports/bench-report-latest.md. Each entry
# is consumed by both the seed generator (this file) and the JMX
# generator (`build-per-scenario-jmx.py`).
#
# Per-scenario shape:
#   `scenario`         : kebab-case scenario name (from bench-report)
#   `group`            : grouping bucket for the methodology table
#   `legacy_endpoint`  : legacy-mode HTTP path template; canonical mode
#                        always uses `/access/v1/authorize`
#   `kind`             : driver hint for the seed builder
#   `bulk_count`       : for bulk scenarios — number of resources/req
#   `bulk_rt_count`    : for bulk scenarios — number of distinct RTs in
#                        the request payload (resources spread evenly)
#   `bulk_op_count`    : for bulk scenarios — distinct ops per RT
#   `role_count`       : number of roles allowed for the request RT/OP
#                        (subject also carries exactly these roles)
#   `predicates`       : list of `(field, claim, source)` triples for
#                        RLS-predicate scenarios; `source` ∈ {"token",
#                        "header"}. The simplified-policy entry combines
#                        them via the RSQL `;` (AND) operator when
#                        `combine` is True.
#   `combine`          : whether multiple predicates compress into one
#                        compound RSQL string vs. emit N separate rules
#   `conditions`       : list of `(field, claim, source)` triples for
#                        RLS-condition scenarios — emitted as N
#                        independent `condition` strings on the RT/OP.

SCENARIOS: list[dict] = [
    # ── OLS-single family ────────────────────────────────────────────────
    {"scenario": "ols-single", "group": "OLS",
     "legacy_endpoint": "/access/v1/check/resource",
     "kind": "ols_single", "role_count": 1},
    {"scenario": "ols-single-10roles", "group": "OLS",
     "legacy_endpoint": "/access/v1/check/resource",
     "kind": "ols_single", "role_count": 10},
    {"scenario": "ols-single-20roles", "group": "OLS",
     "legacy_endpoint": "/access/v1/check/resource",
     "kind": "ols_single", "role_count": 20},
    {"scenario": "ols-single-30roles", "group": "OLS",
     "legacy_endpoint": "/access/v1/check/resource",
     "kind": "ols_single", "role_count": 30},
    {"scenario": "ols-single-50roles", "group": "OLS",
     "legacy_endpoint": "/access/v1/check/resource",
     "kind": "ols_single", "role_count": 50},
    {"scenario": "ols-single-100roles", "group": "OLS",
     "legacy_endpoint": "/access/v1/check/resource",
     "kind": "ols_single", "role_count": 100},

    # ── OLS-bulk family ──────────────────────────────────────────────────
    # bulk_count = total resources/request; rt_count × op_count = bulk_count.
    {"scenario": "ols-bulk-50", "group": "OLS-bulk",
     "legacy_endpoint": "/access/v1/check/resource/bulk",
     "kind": "ols_bulk", "bulk_count": 50, "bulk_rt_count": 2,
     "bulk_op_count": 25, "role_count": 1},
    {"scenario": "ols-bulk-100", "group": "OLS-bulk",
     "legacy_endpoint": "/access/v1/check/resource/bulk",
     "kind": "ols_bulk", "bulk_count": 100, "bulk_rt_count": 4,
     "bulk_op_count": 25, "role_count": 1},
    {"scenario": "ols-bulk-1000", "group": "OLS-bulk",
     "legacy_endpoint": "/access/v1/check/resource/bulk",
     "kind": "ols_bulk", "bulk_count": 1000, "bulk_rt_count": 40,
     "bulk_op_count": 25, "role_count": 1},

    # ── RLS-condition family ─────────────────────────────────────────────
    {"scenario": "rls-condition-1-expression", "group": "RLS-condition",
     "legacy_endpoint": "/access/v1/check/resource",
     "kind": "rls_condition", "role_count": 1,
     "conditions": [("ownerId", "emailFromToken", "token")]},
    {"scenario": "rls-condition-2-expression", "group": "RLS-condition",
     "legacy_endpoint": "/access/v1/check/resource",
     "kind": "rls_condition", "role_count": 1,
     "conditions": [
         ("ownerId", "emailFromToken", "token"),
         ("departmentId", "departmentFromToken", "token"),
     ]},
    {"scenario": "rls-condition-3-expression", "group": "RLS-condition",
     "legacy_endpoint": "/access/v1/check/resource",
     "kind": "rls_condition", "role_count": 1,
     "conditions": [
         ("ownerId", "emailFromToken", "token"),
         ("departmentId", "departmentFromToken", "token"),
         ("regionId", "regionFromToken", "token"),
     ]},
    {"scenario": "rls-condition-5-expression", "group": "RLS-condition",
     "legacy_endpoint": "/access/v1/check/resource",
     "kind": "rls_condition", "role_count": 1,
     "conditions": [
         ("ownerId", "emailFromToken", "token"),
         ("departmentId", "departmentFromToken", "token"),
         ("regionId", "regionFromToken", "token"),
         ("countryId", "countryFromToken", "token"),
         ("divisionId", "divisionFromToken", "token"),
     ]},

    # ── RLS-predicate (single rsql predicate) ────────────────────────────
    {"scenario": "rls-predicate", "group": "RLS-predicate",
     "legacy_endpoint": "/access/v1/check/filter",
     "kind": "rls_predicate", "role_count": 1, "combine": False,
     "predicates": [("ownerId", "emailFromToken", "token")]},

    # ── RLS-predicate-summary-N-predicates (independent rules) ───────────
    {"scenario": "rls-predicate-summary-2-predicates",
     "group": "RLS-predicate",
     "legacy_endpoint": "/access/v1/check/filter",
     "kind": "rls_predicate", "role_count": 1, "combine": False,
     "predicates": [
         ("ownerId", "emailFromToken", "token"),
         ("departmentId", "departmentFromToken", "token"),
     ]},
    {"scenario": "rls-predicate-summary-3-predicates",
     "group": "RLS-predicate",
     "legacy_endpoint": "/access/v1/check/filter",
     "kind": "rls_predicate", "role_count": 1, "combine": False,
     "predicates": [
         ("ownerId", "emailFromToken", "token"),
         ("departmentId", "departmentFromToken", "token"),
         ("regionId", "regionFromToken", "token"),
     ]},
    {"scenario": "rls-predicate-summary-4-predicates",
     "group": "RLS-predicate",
     "legacy_endpoint": "/access/v1/check/filter",
     "kind": "rls_predicate", "role_count": 1, "combine": False,
     "predicates": [
         ("ownerId", "emailFromToken", "token"),
         ("departmentId", "departmentFromToken", "token"),
         ("regionId", "regionFromToken", "token"),
         ("countryId", "countryFromToken", "token"),
     ]},
    {"scenario": "rls-predicate-summary-5-predicates",
     "group": "RLS-predicate",
     "legacy_endpoint": "/access/v1/check/filter",
     "kind": "rls_predicate", "role_count": 1, "combine": False,
     "predicates": [
         ("ownerId", "emailFromToken", "token"),
         ("departmentId", "departmentFromToken", "token"),
         ("regionId", "regionFromToken", "token"),
         ("countryId", "countryFromToken", "token"),
         ("divisionId", "divisionFromToken", "token"),
     ]},
    {"scenario": "rls-predicate-summary-10-predicates",
     "group": "RLS-predicate",
     "legacy_endpoint": "/access/v1/check/filter",
     "kind": "rls_predicate", "role_count": 1, "combine": False,
     "predicates": [
         ("ownerId", "emailFromToken", "token"),
         ("departmentId", "departmentFromToken", "token"),
         ("regionId", "regionFromToken", "token"),
         ("countryId", "countryFromToken", "token"),
         ("divisionId", "divisionFromToken", "token"),
         ("field06Id", "field06FromToken", "token"),
         ("field07Id", "field07FromToken", "token"),
         ("field08Id", "field08FromToken", "token"),
         ("field09Id", "field09FromToken", "token"),
         ("field10Id", "field10FromToken", "token"),
     ]},

    # ── RLS-predicate-pips-N-token-pip (single compound predicate) ───────
    {"scenario": "rls-predicate-pips-1-token-pip",
     "group": "RLS-predicate-pips",
     "legacy_endpoint": "/access/v1/check/filter",
     "kind": "rls_predicate", "role_count": 1, "combine": True,
     "predicates": [("ownerId", "emailFromToken", "token")]},
    {"scenario": "rls-predicate-pips-2-token-pip",
     "group": "RLS-predicate-pips",
     "legacy_endpoint": "/access/v1/check/filter",
     "kind": "rls_predicate", "role_count": 1, "combine": True,
     "predicates": [
         ("ownerId", "emailFromToken", "token"),
         ("departmentId", "departmentFromToken", "token"),
     ]},
    {"scenario": "rls-predicate-pips-3-token-pip",
     "group": "RLS-predicate-pips",
     "legacy_endpoint": "/access/v1/check/filter",
     "kind": "rls_predicate", "role_count": 1, "combine": True,
     "predicates": [
         ("ownerId", "emailFromToken", "token"),
         ("departmentId", "departmentFromToken", "token"),
         ("regionId", "regionFromToken", "token"),
     ]},
    {"scenario": "rls-predicate-pips-1-header-pip",
     "group": "RLS-predicate-pips",
     "legacy_endpoint": "/access/v1/check/filter",
     "kind": "rls_predicate", "role_count": 1, "combine": True,
     "predicates": [("regionId", "regionFromHeader", "header")]},
    {"scenario": "rls-predicate-pips-2-header-pip",
     "group": "RLS-predicate-pips",
     "legacy_endpoint": "/access/v1/check/filter",
     "kind": "rls_predicate", "role_count": 1, "combine": True,
     "predicates": [
         ("regionId", "regionFromHeader", "header"),
         ("countryId", "countryFromHeader", "header"),
     ]},
    {"scenario": "rls-predicate-pips-3-header-pip",
     "group": "RLS-predicate-pips",
     "legacy_endpoint": "/access/v1/check/filter",
     "kind": "rls_predicate", "role_count": 1, "combine": True,
     "predicates": [
         ("regionId", "regionFromHeader", "header"),
         ("countryId", "countryFromHeader", "header"),
         ("divisionId", "divisionFromHeader", "header"),
     ]},

    # ── Combined stress: 10 predicates × 3 token PIPs ────────────────────
    {"scenario": "rls-predicate-summary-10-predicates-3-token-pip",
     "group": "RLS-predicate-pips",
     "legacy_endpoint": "/access/v1/check/filter",
     "kind": "rls_predicate_summary_compound", "role_count": 1,
     "combine": False, "summary_count": 10, "pips_per_summary": 3,
     "pip_claims": [
         ("emailFromToken", "token"),
         ("departmentFromToken", "token"),
         ("regionFromToken", "token"),
     ]},

    # ── Wildcard family ──────────────────────────────────────────────────
    # wildcard-all-single: single resource, predicate "true" (always allows).
    {"scenario": "wildcard-all-single", "group": "Wildcard",
     "legacy_endpoint": "/access/v1/check/resource",
     "kind": "wildcard_single", "role_count": 1},
    # wildcard-mixed-bulk: 50 resources, mixed RT/OP — every (RT,OP)
    # carries both OLS (admin role) and a permissive RLS predicate
    # (`true`) so the bulk request short-circuits per resource.
    {"scenario": "wildcard-mixed-bulk", "group": "Wildcard",
     "legacy_endpoint": "/access/v1/check/resource/bulk",
     "kind": "wildcard_bulk", "bulk_count": 50, "bulk_rt_count": 10,
     "bulk_op_count": 5, "role_count": 1},
]


# ── helpers ────────────────────────────────────────────────────────────────
def scenario_tag(scenario: str) -> str:
    """Canonical SCENARIO_KEY: kebab-case → UPPER_UNDERSCORE."""
    return scenario.replace("-", "_").upper()


def rt_name(scenario: str, idx: int) -> str:
    return f"PS_{scenario_tag(scenario)}_RT_{idx:02d}"


def op_name(scenario: str, idx: int) -> str:
    return f"PS_{scenario_tag(scenario)}_OP_{idx:02d}"


def role_name(scenario: str, idx: int) -> str:
    return f"PS_{scenario_tag(scenario)}_ROLE_{idx:02d}"


def component_name(scenario: str) -> str:
    return f"PS_{scenario_tag(scenario)}"


def all_roles_for(spec: dict) -> list[str]:
    n = int(spec.get("role_count", 1))
    return [role_name(spec["scenario"], i) for i in range(1, n + 1)]


# ── PIP catalogue ──────────────────────────────────────────────────────────
# These PIPs are referenced by RLS-condition / RLS-predicate scenarios.
# We always emit the full set so a `--scenarios <subset>` run does not
# require a separate seed regeneration. Dedup by `name` happens in
# `svt_merged_seed_pips`.

def build_pips() -> list[dict]:
    pips: list[dict] = []
    # Token claims used by mixed-flow + per-scenario scenarios.
    token_claims = [
        "emailFromToken", "departmentFromToken",
        "regionFromToken", "countryFromToken", "divisionFromToken",
        # field06..field10 used by rls-predicate-summary-10-predicates.
        "field06FromToken", "field07FromToken", "field08FromToken",
        "field09FromToken", "field10FromToken",
    ]
    # Token PIP claim names mirror the simplified-policy field names —
    # `emailFromToken` reads the `email` claim, `regionFromToken` reads
    # `region`, etc. This matches the convention already in
    # `svt-mixed-flow-pips.json`.
    token_claim_to_token = {
        "emailFromToken": "email",
        "departmentFromToken": "department",
        "regionFromToken": "region",
        "countryFromToken": "country",
        "divisionFromToken": "division",
        "field06FromToken": "field06",
        "field07FromToken": "field07",
        "field08FromToken": "field08",
        "field09FromToken": "field09",
        "field10FromToken": "field10",
    }
    for name in token_claims:
        pips.append({
            "name": f"subject.{name}",
            "pipType": "TOKEN",
            "claim": token_claim_to_token[name],
        })
    # Header PIPs used by rls-predicate-pips-{1,2,3}-header-pip.
    header_claims = [
        ("regionFromHeader", "x-svt-region"),
        ("countryFromHeader", "x-svt-country"),
        ("divisionFromHeader", "x-svt-division"),
    ]
    for name, header in header_claims:
        pips.append({
            "name": f"subject.{name}",
            "pipType": "HEADER",
            "header": header,
        })
    return pips


# ── policy emitters ────────────────────────────────────────────────────────

def emit_ols_single(spec: dict, rules: list[dict]) -> None:
    """Single (RT_01, OP_01) entry allowing all role_count roles."""
    rules.append({
        "component": component_name(spec["scenario"]),
        "resourceType": rt_name(spec["scenario"], 1),
        "operation": op_name(spec["scenario"], 1),
        "roles": all_roles_for(spec),
    })


def emit_ols_bulk(spec: dict, rules: list[dict]) -> None:
    """For every (RT, OP) pair fired by the bulk request, emit one OLS
    entry. The JMX generator builds the same bulk_rt_count × bulk_op_count
    cartesian product so the request payload matches the policy. The
    `bulk_count` field is the explicit total used for validation."""
    n_rt = int(spec["bulk_rt_count"])
    n_op = int(spec["bulk_op_count"])
    expected = int(spec["bulk_count"])
    assert n_rt * n_op == expected, (
        f"{spec['scenario']}: bulk_rt_count*bulk_op_count={n_rt*n_op} "
        f"must equal bulk_count={expected}"
    )
    roles = all_roles_for(spec)
    comp = component_name(spec["scenario"])
    for ri in range(1, n_rt + 1):
        for oi in range(1, n_op + 1):
            rules.append({
                "component": comp,
                "resourceType": rt_name(spec["scenario"], ri),
                "operation": op_name(spec["scenario"], oi),
                "roles": list(roles),
            })


def emit_rls_condition(spec: dict, rules: list[dict]) -> None:
    """N independent simplified-policy entries — one per condition string —
    on the same (RT_01, OP_01) pair. Each entry carries a single
    `condition` field of the form `resource.<field> == subject.<claim>`."""
    comp = component_name(spec["scenario"])
    roles = all_roles_for(spec)
    rt = rt_name(spec["scenario"], 1)
    op = op_name(spec["scenario"], 1)
    for field, claim, _source in spec["conditions"]:
        rules.append({
            "component": comp,
            "resourceType": rt,
            "operation": op,
            "roles": list(roles),
            "condition": f"resource.{field} == subject.{claim}",
        })


def _rsql_predicate(field: str, claim: str) -> str:
    return f"{field}==${{subject.{claim}}}"


def emit_rls_predicate(spec: dict, rules: list[dict]) -> None:
    """Either N independent predicate entries (combine=False) or one
    compound predicate joining the N clauses via the RSQL `;` (AND)
    operator (combine=True). Mirrors the two profiler shapes:
    rls-predicate-summary-N-predicates (independent) vs.
    rls-predicate-pips-N-token-pip / N-header-pip (compound)."""
    comp = component_name(spec["scenario"])
    roles = all_roles_for(spec)
    rt = rt_name(spec["scenario"], 1)
    op = op_name(spec["scenario"], 1)
    if spec.get("combine"):
        clauses = [
            _rsql_predicate(field, claim)
            for field, claim, _source in spec["predicates"]
        ]
        rules.append({
            "component": comp,
            "resourceType": rt,
            "operation": op,
            "roles": list(roles),
            "rsqlPredicate": ";".join(clauses),
        })
    else:
        for field, claim, _source in spec["predicates"]:
            rules.append({
                "component": comp,
                "resourceType": rt,
                "operation": op,
                "roles": list(roles),
                "rsqlPredicate": _rsql_predicate(field, claim),
            })


def emit_rls_predicate_summary_compound(spec: dict, rules: list[dict]) -> None:
    """rls-predicate-summary-10-predicates-3-token-pip: 10 independent
    rsqlPredicate entries, each joining 3 PIPs via `;`. Field names are
    `field01_<claim>` so every entry exercises distinct field paths."""
    comp = component_name(spec["scenario"])
    roles = all_roles_for(spec)
    rt = rt_name(spec["scenario"], 1)
    op = op_name(spec["scenario"], 1)
    n_summary = int(spec["summary_count"])
    pip_claims = spec["pip_claims"]
    for i in range(1, n_summary + 1):
        prefix = f"field{i:02d}"
        clauses = [f"{prefix}_{claim}==${{subject.{claim}}}"
                   for claim, _source in pip_claims]
        rules.append({
            "component": comp,
            "resourceType": rt,
            "operation": op,
            "roles": list(roles),
            "rsqlPredicate": ";".join(clauses),
        })


def emit_wildcard_single(spec: dict, rules: list[dict]) -> None:
    """wildcard-all-single: a single role entry with a predicate of
    literal `true`. The profiler ships this as the short-circuit
    wildcard path."""
    rules.append({
        "component": component_name(spec["scenario"]),
        "resourceType": rt_name(spec["scenario"], 1),
        "operation": op_name(spec["scenario"], 1),
        "roles": all_roles_for(spec),
        "rsqlPredicate": "true",
    })


def emit_wildcard_bulk(spec: dict, rules: list[dict]) -> None:
    """wildcard-mixed-bulk: 50 resources × OLS + RLS `true` predicate
    per (RT, OP). Mirrors the profiler shape."""
    n_rt = int(spec["bulk_rt_count"])
    n_op = int(spec["bulk_op_count"])
    expected = int(spec["bulk_count"])
    assert n_rt * n_op == expected, (
        f"{spec['scenario']}: bulk_rt_count*bulk_op_count={n_rt*n_op} "
        f"must equal bulk_count={expected}"
    )
    roles = all_roles_for(spec)
    comp = component_name(spec["scenario"])
    for ri in range(1, n_rt + 1):
        for oi in range(1, n_op + 1):
            rt = rt_name(spec["scenario"], ri)
            op = op_name(spec["scenario"], oi)
            # OLS entry.
            rules.append({
                "component": comp,
                "resourceType": rt,
                "operation": op,
                "roles": list(roles),
            })
            # RLS `true` predicate entry on the same (RT, OP).
            rules.append({
                "component": comp,
                "resourceType": rt,
                "operation": op,
                "roles": list(roles),
                "rsqlPredicate": "true",
            })


EMITTERS = {
    "ols_single": emit_ols_single,
    "ols_bulk": emit_ols_bulk,
    "rls_condition": emit_rls_condition,
    "rls_predicate": emit_rls_predicate,
    "rls_predicate_summary_compound": emit_rls_predicate_summary_compound,
    "wildcard_single": emit_wildcard_single,
    "wildcard_bulk": emit_wildcard_bulk,
}


def build_policies() -> list[dict]:
    rules: list[dict] = []
    for spec in SCENARIOS:
        emitter = EMITTERS.get(spec["kind"])
        if emitter is None:
            raise SystemExit(f"unknown kind: {spec['kind']}")
        emitter(spec, rules)
    return rules


def main() -> int:
    os.makedirs(SEED_DIR, exist_ok=True)
    policies = build_policies()
    pips = build_pips()

    policies_path = os.path.join(SEED_DIR, "svt-per-scenario-policies.json")
    pips_path = os.path.join(SEED_DIR, "svt-per-scenario-pips.json")

    with open(policies_path, "w", encoding="utf-8") as f:
        json.dump(policies, f, indent=2, ensure_ascii=False)
        f.write("\n")
    with open(pips_path, "w", encoding="utf-8") as f:
        json.dump(pips, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"wrote {len(policies)} simplified-policy entries → {policies_path}",
          file=sys.stderr)
    print(f"wrote {len(pips)} PIP entries → {pips_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
