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

"""Generate the additive mixed-flow simplified-policy and PIP seed files.

The mixed-flow load-test report (handover 20260518) measures CPU/memory/IO
under the 8 profiler scenarios that back tests/svt/scripts/bench-report.
Profiler `data.json` files use the low-level OPA data document shape;
this generator converts each scenario into the simplified-policy shape
(`component`/`resourceType`/`operation`/`roles`/`condition`/`rsqlPredicate`)
that the policy-admin endpoint accepts, and emits two committed seed
files alongside the hand-authored base seed.

Outputs:
  - tests/svt/common/compose/seed/svt-mixed-flow-policies.json
  - tests/svt/common/compose/seed/svt-mixed-flow-pips.json

Both files are uploaded after the base svt-policies.json /
svt-pips.json by tests/svt/scripts/up and svt_restart_opa (merge via
jq before PUT).

Run from the authz-agent repo root:

    tests/svt/scripts/build-mixed-flow-seeds.py

The generator is deterministic — re-running yields a byte-for-byte
identical output.
"""

from __future__ import annotations

import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SVT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
SEED_DIR = os.path.join(SVT_DIR, "common", "compose", "seed")

COMPONENT = "SVT_MIXED_FLOW"

EMAIL_PREDICATE = "ownerId==${subject.emailFromToken}"
EMAIL_CONDITION = "resource.ownerId == subject.emailFromToken"
DEPT_PREDICATE = "departmentId==${subject.departmentFromToken}"
DEPT_CONDITION = "resource.departmentId == subject.departmentFromToken"
COMBINED_PREDICATE = (
    "ownerId==${subject.emailFromToken};"
    "departmentId==${subject.departmentFromToken}"
)


def rt_list(prefix: str, count: int) -> list[str]:
    return [f"{prefix}_{i:02d}" for i in range(1, count + 1)]


def op_list(prefix: str, count: int) -> list[str]:
    return [f"{prefix}_{i:02d}" for i in range(1, count + 1)]


def emit_ols(rules: list[dict], resource_types: list[str], operations: list[str], roles: list[str]) -> None:
    for rt in resource_types:
        for op in operations:
            rules.append({
                "component": COMPONENT,
                "resourceType": rt,
                "operation": op,
                "roles": list(roles),
            })


def emit_rls_predicate(
    rules: list[dict],
    resource_types: list[str],
    operations: list[str],
    roles: list[str],
    predicate: str,
    condition: str | None = None,
) -> None:
    for rt in resource_types:
        for op in operations:
            entry: dict = {
                "component": COMPONENT,
                "resourceType": rt,
                "operation": op,
                "roles": list(roles),
                "rsqlPredicate": predicate,
            }
            if condition is not None:
                entry["condition"] = condition
            rules.append(entry)


def emit_rls_condition(
    rules: list[dict],
    resource_types: list[str],
    operations: list[str],
    roles: list[str],
    condition: str,
) -> None:
    for rt in resource_types:
        for op in operations:
            rules.append({
                "component": COMPONENT,
                "resourceType": rt,
                "operation": op,
                "roles": list(roles),
                "condition": condition,
            })


def build_policies() -> list[dict]:
    """Return the merged simplified-policy list for all 8 scenarios."""
    rules: list[dict] = []

    # ── ols-single-10roles ────────────────────────────────────────────────
    # SVT_RT_01..10 × OP_01..10, roles = ROLE_SVT_01..10 (all 10 roles
    # allow each operation). 100 simplified-policy entries.
    emit_ols(
        rules,
        rt_list("SVT_RT", 10),
        op_list("OP", 10),
        [f"ROLE_SVT_{i:02d}" for i in range(1, 11)],
    )

    # ── rls-predicate ─────────────────────────────────────────────────────
    # SVT_RT_01..09 × OP_01..10, ROLE_SVT_ADMIN, single rsql predicate
    # on ownerId == subject.emailFromToken. No condition (rsqlPredicate
    # alone short-circuits to USE_FILTER_CONDITION at the legacy filter
    # endpoint and to a predicate response on canonical).
    emit_rls_predicate(
        rules,
        rt_list("SVT_RT", 9),
        op_list("OP", 10),
        ["ROLE_SVT_ADMIN"],
        EMAIL_PREDICATE,
    )

    # ── rls-condition ─────────────────────────────────────────────────────
    # SVT_RT_01..09 × OP_01..10, ROLE_SVT_ADMIN, condition only
    # (no rsqlPredicate). Profiler benches the conditionAst evaluation
    # cost without predicate substitution.
    emit_rls_condition(
        rules,
        rt_list("SVT_RT", 9),
        op_list("OP", 10),
        ["ROLE_SVT_ADMIN"],
        EMAIL_CONDITION,
    )

    # ── ols-bulk-100 ──────────────────────────────────────────────────────
    # SVT_BULK_RT_01..04 × BULK_OP_01..25, ROLE_SVT_ADMIN. 100 entries
    # for the 100-resource bulk path.
    emit_ols(
        rules,
        rt_list("SVT_BULK_RT", 4),
        op_list("BULK_OP", 25),
        ["ROLE_SVT_ADMIN"],
    )

    # ── rls-condition-2-expression ────────────────────────────────────────
    # SVT_RT_01..10 × OP_01..10, ROLE_SVT_ADMIN, two separate
    # conditionAst rules per (RT,OP): ownerId == email AND department ==
    # departmentFromToken. Emit as two simplified-policy entries per
    # (RT,OP) — the policy-admin compiler treats them as two RLS rules
    # to evaluate, mirroring the profiler.
    rt_10 = rt_list("SVT_RT", 10)
    op_10 = op_list("OP", 10)
    emit_rls_condition(
        rules,
        rt_10,
        op_10,
        ["ROLE_SVT_ADMIN"],
        EMAIL_CONDITION,
    )
    emit_rls_condition(
        rules,
        rt_10,
        op_10,
        ["ROLE_SVT_ADMIN"],
        DEPT_CONDITION,
    )

    # ── rls-predicate-summary-2-predicates ────────────────────────────────
    # SVT_RT_01..10 × OP_01..10, ROLE_SVT_ADMIN, two separate
    # rsqlPredicate rules per (RT,OP). Emitted as two entries per
    # (RT,OP); the compiler treats them as independent RLS rules.
    emit_rls_predicate(
        rules,
        rt_10,
        op_10,
        ["ROLE_SVT_ADMIN"],
        EMAIL_PREDICATE,
    )
    emit_rls_predicate(
        rules,
        rt_10,
        op_10,
        ["ROLE_SVT_ADMIN"],
        DEPT_PREDICATE,
    )

    # ── rls-predicate-pips-2-token-pip ────────────────────────────────────
    # SVT_RT_01..10 × OP_01..10, ROLE_SVT_ADMIN, single combined rsql
    # predicate that joins the two clauses via the RSQL `;` (AND)
    # operator. Profiler measures 2 PIP resolutions on one predicate.
    emit_rls_predicate(
        rules,
        rt_10,
        op_10,
        ["ROLE_SVT_ADMIN"],
        COMBINED_PREDICATE,
    )

    # ── wildcard-all-single ───────────────────────────────────────────────
    # SVT_RT_01..09 × OP_01..10, ROLE_SVT_ADMIN, predicate "true"
    # (constant — every resource passes). Profiler measures the
    # short-circuit wildcard path.
    emit_rls_predicate(
        rules,
        rt_list("SVT_RT", 9),
        op_list("OP", 10),
        ["ROLE_SVT_ADMIN"],
        "true",
    )

    return rules


def build_pips() -> list[dict]:
    """Return the additive PIP definitions needed by the 8 scenarios."""
    # The base svt-pips.json already declares subject.emailFromToken.
    # The mixed-flow scenarios additionally need subject.departmentFromToken
    # (token-claim PIP keyed off the access-token `department` claim,
    # supplied by the Keycloak protocol mapper added in svt-realm.json).
    return [
        {
            "name": "subject.emailFromToken",
            "pipType": "TOKEN",
            "claim": "email",
        },
        {
            "name": "subject.departmentFromToken",
            "pipType": "TOKEN",
            "claim": "department",
        },
    ]


def main() -> int:
    os.makedirs(SEED_DIR, exist_ok=True)
    policies = build_policies()
    pips = build_pips()

    policies_path = os.path.join(SEED_DIR, "svt-mixed-flow-policies.json")
    pips_path = os.path.join(SEED_DIR, "svt-mixed-flow-pips.json")

    with open(policies_path, "w", encoding="utf-8") as f:
        json.dump(policies, f, indent=2, ensure_ascii=False)
        f.write("\n")
    with open(pips_path, "w", encoding="utf-8") as f:
        json.dump(pips, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"wrote {len(policies)} simplified-policy entries → {policies_path}", file=sys.stderr)
    print(f"wrote {len(pips)} PIP entries → {pips_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
