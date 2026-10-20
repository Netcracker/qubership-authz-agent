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

import argparse
import csv
import json
import os
import math
from pathlib import Path


USER_COUNT = 100
ALLOW_COUNT = 90
DENY_COUNT = 10
USERS = [
    {
        "username": f"svt-matrix-{idx:03d}",
        "email": f"svt-matrix-{idx:03d}@example.com",
        "region": f"region-{((idx - 1) % 10) + 1:02d}",
    }
    for idx in range(1, USER_COUNT + 1)
]


def combo_grid(resource_type_count: int, operation_count: int, rt_prefix: str, op_prefix: str):
    resource_types = [f"{rt_prefix}_{idx:02d}" for idx in range(1, resource_type_count + 1)]
    operations = [f"{op_prefix}_{idx:02d}" for idx in range(1, operation_count + 1)]
    return [(rt, op) for rt in resource_types for op in operations]


COMBOS_100 = combo_grid(10, 10, "SVT_RT", "OP")
COMBOS_500 = combo_grid(20, 25, "SVT_BULK_RT", "BULK_OP")


SCENARIOS = {
    "rls-condition": {
        "title": "RLS condition",
        "request_class": "RLS_CONDITION",
        "total_pairs": 100,
        "pairs_per_request": 1,
        "ignore_rls": False,
        "policy_builder": "build_rls_condition_policies",
        "pip_builder": "build_email_token_pip",
        "request_builder": "build_rls_condition_requests",
    },
    "rls-predicate": {
        "title": "RLS predicate",
        "request_class": "RLS_PREDICATE",
        "total_pairs": 100,
        "pairs_per_request": 1,
        "ignore_rls": False,
        "policy_builder": "build_rls_predicate_policies",
        "pip_builder": "build_email_token_pip",
        "request_builder": "build_rls_predicate_requests",
    },
    "rls-predicate-pips": {
        "title": "RLS predicate + header/token PIP",
        "request_class": "RLS_PREDICATE_PIPS",
        "total_pairs": 100,
        "pairs_per_request": 1,
        "ignore_rls": False,
        "policy_builder": "build_rls_predicate_pips_policies",
        "pip_builder": "build_local_pips",
        "request_builder": "build_rls_predicate_pips_requests",
    },
    "ols-single": {
        "title": "OLS single-resource",
        "request_class": "OLS_SINGLE",
        "total_pairs": 100,
        "pairs_per_request": 1,
        "ignore_rls": True,
        "policy_builder": "build_ols_single_policies",
        "pip_builder": "build_empty_pips",
        "request_builder": "build_ols_single_requests",
    },
    "ols-bulk-50": {
        "title": "OLS bulk (50 resources/request)",
        "request_class": "OLS_BULK_50",
        "total_pairs": 500,
        "pairs_per_request": 50,
        "ignore_rls": True,
        "policy_builder": "build_ols_bulk_policies",
        "pip_builder": "build_empty_pips",
        "request_builder": "build_ols_bulk_requests",
    },
}


def policy(component, resource_type, operation, roles=None, condition=None, predicate=None):
    doc = {
        "component": component,
        "resourceType": resource_type,
        "operation": operation,
        "roles": roles or [],
    }
    if condition is not None:
        doc["condition"] = condition
    if predicate is not None:
        doc["rsqlPredicate"] = predicate
    return doc


def base_input(resources, ignore_rls, request_headers=None):
    return {
        "input": {
            "authorizationToken": "Bearer __TOKEN__",
            "authorizationType": "",
            "requestHeaders": request_headers or {},
            "decisionLogPipTrace": True,
            "resources": resources,
            "subject": "Bearer __TOKEN__",
            "ignoreRls": ignore_rls,
        }
    }


def build_rls_condition_policies():
    return [
        policy(
            "SVT_MATRIX",
            rt,
            op,
            roles=["ROLE_SVT_ADMIN"],
            condition="resource.ownerId == subject.emailFromToken",
        )
        for rt, op in COMBOS_100
    ]


def build_rls_predicate_policies():
    return [
        policy(
            "SVT_MATRIX",
            rt,
            op,
            roles=["ROLE_SVT_ADMIN"],
            predicate="ownerId==${subject.emailFromToken}",
        )
        for rt, op in COMBOS_100[:ALLOW_COUNT]
    ]


def build_rls_predicate_pips_policies():
    return [
        policy(
            "SVT_MATRIX",
            rt,
            op,
            roles=["ROLE_SVT_ADMIN"],
            predicate="ownerId==${subject.emailFromToken};regionId==${subject.regionFromHeader}",
        )
        for rt, op in COMBOS_100[:ALLOW_COUNT]
    ]


def build_ols_single_policies():
    return [
        policy("SVT_MATRIX", rt, op, roles=["ROLE_SVT_ADMIN"])
        for rt, op in COMBOS_100[:ALLOW_COUNT]
    ]


def build_ols_bulk_policies():
    return [
        policy("SVT_MATRIX", rt, op, roles=["ROLE_SVT_ADMIN"])
        for rt, op in COMBOS_500[:450]
    ]


def build_empty_pips():
    return []


def build_email_token_pip():
    return [
        {
            "name": "subject.emailFromToken",
            "pipType": "TOKEN",
            "claim": "email",
        },
    ]


def build_local_pips():
    return [
        {
            "name": "subject.emailFromToken",
            "pipType": "TOKEN",
            "claim": "email",
        },
        {
            "name": "subject.regionFromHeader",
            "pipType": "HEADER",
            "header": "X-SVT-Region",
        },
    ]


def build_rls_condition_requests(scenario_name, request_class):
    rows = []
    for idx, user in enumerate(USERS):
        resource_type, operation = COMBOS_100[idx]
        allow = idx < ALLOW_COUNT
        owner = user["email"] if allow else "deny-" + user["email"]
        body = base_input(
            [{"resourceType": resource_type, "operation": operation, "resource": {"ownerId": owner}}],
            True,
        )
        rows.append(
            {
                "username": user["username"],
                "scenarioLabel": scenario_name,
                "requestClass": request_class,
                "expectedDecision": "ALLOW" if allow else "DENY",
                "requestBodyTemplate": json.dumps(body, separators=(",", ":")),
            }
        )
    return rows


def build_rls_predicate_requests(scenario_name, request_class):
    rows = []
    for idx, user in enumerate(USERS):
        resource_type, operation = COMBOS_100[idx]
        body = base_input(
            [{"resourceType": resource_type, "operation": operation, "resource": {}}],
            True,
        )
        rows.append(
            {
                "username": user["username"],
                "scenarioLabel": scenario_name,
                "requestClass": request_class,
                "expectedDecision": "ALLOW" if idx < ALLOW_COUNT else "DENY",
                "requestBodyTemplate": json.dumps(body, separators=(",", ":")),
            }
        )
    return rows


def build_rls_predicate_pips_requests(scenario_name, request_class):
    rows = []
    for idx, user in enumerate(USERS):
        resource_type, operation = COMBOS_100[idx]
        body = base_input(
            [{"resourceType": resource_type, "operation": operation, "resource": {}}],
            True,
            request_headers={"x-svt-region": user["region"]},
        )
        rows.append(
            {
                "username": user["username"],
                "scenarioLabel": scenario_name,
                "requestClass": request_class,
                "expectedDecision": "ALLOW" if idx < ALLOW_COUNT else "DENY",
                "requestBodyTemplate": json.dumps(body, separators=(",", ":")),
            }
        )
    return rows


def build_ols_single_requests(scenario_name, request_class):
    rows = []
    for idx, user in enumerate(USERS):
        resource_type, operation = COMBOS_100[idx]
        body = base_input(
            [{"resourceType": resource_type, "operation": operation, "resource": {}}],
            False,
        )
        rows.append(
            {
                "username": user["username"],
                "scenarioLabel": scenario_name,
                "requestClass": request_class,
                "expectedDecision": "ALLOW" if idx < ALLOW_COUNT else "DENY",
                "requestBodyTemplate": json.dumps(body, separators=(",", ":")),
            }
        )
    return rows


def build_ols_bulk_requests(scenario_name, request_class):
    allow_batches = [COMBOS_500[idx : idx + 50] for idx in range(0, 450, 50)]
    deny_batch = COMBOS_500[450:500]
    rows = []
    for idx, user in enumerate(USERS):
        allow = idx < ALLOW_COUNT
        combos = allow_batches[idx % len(allow_batches)] if allow else deny_batch
        resources = [
            {"resourceType": resource_type, "operation": operation, "resource": {}}
            for resource_type, operation in combos
        ]
        body = base_input(resources, False)
        rows.append(
            {
                "username": user["username"],
                "scenarioLabel": scenario_name,
                "requestClass": request_class,
                "expectedDecision": "ALLOW" if allow else "DENY",
                "requestBodyTemplate": json.dumps(body, separators=(",", ":")),
            }
        )
    return rows


# tools/ -> common/ -> svt/: everything this tool writes belongs under the
# stand's own directory.
SVT_DIR = Path(__file__).resolve().parents[2]


def under_svt(path: Path) -> Path:
    """Canonicalise path and refuse one that leaves the SVT directory.

    Every destination comes from a `--output-dir` or `--output-file` on the
    command line, so a typo or a pasted absolute path would write wherever it
    said. `realpath` collapses any `..` the argument carried and follows the
    symlinks on the way, so the comparison is against the file that would
    actually be written rather than the string that was typed.
    """
    resolved = os.path.realpath(os.path.expanduser(str(path)))
    root = os.path.realpath(str(SVT_DIR))
    if resolved != root and not resolved.startswith(root + os.sep):
        raise SystemExit(f"refusing to write outside {root}: {resolved}")
    return Path(resolved)


def write_json(path: Path, payload):
    under_svt(path).write_text(json.dumps(payload, indent=2) + "\n", encoding="ascii")


def write_requests(path: Path, rows):
    with under_svt(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["username", "scenarioLabel", "requestClass", "expectedDecision", "requestBodyTemplate"],
        )
        writer.writeheader()
        writer.writerows(rows)


def generate(args):
    scenario = SCENARIOS[args.scenario]
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    policies = globals()[scenario["policy_builder"]]()
    pips = globals()[scenario["pip_builder"]]()
    rows = globals()[scenario["request_builder"]](args.scenario, scenario["request_class"])

    write_json(output_dir / "policies.json", policies)
    write_json(output_dir / "pips.json", pips)
    write_requests(output_dir / "requests.csv", rows)
    write_json(
        output_dir / "scenario.json",
        {
            "name": args.scenario,
            "title": scenario["title"],
            "users": USER_COUNT,
            "allow_ratio": 0.9,
            "deny_ratio": 0.1,
            "duration_seconds": 60,
            "target_rps": 500,
            "total_resource_type_operation": scenario["total_pairs"],
            "resource_type_operation_per_request": scenario["pairs_per_request"],
            "ignore_rls": scenario["ignore_rls"],
            "request_class": scenario["request_class"],
            "policy_count": len(policies),
            "pip_count": len(pips),
            "request_count": len(rows),
        },
    )


def summarize_jtl(args):
    elapsed = []
    with open(args.jtl, encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            try:
                elapsed.append(int(row["elapsed"]))
            except (KeyError, TypeError, ValueError):
                continue

    if not elapsed:
        payload = {"count": 0, "p95_ms": None}
    else:
        elapsed.sort()
        rank = max(0, math.ceil(len(elapsed) * 0.95) - 1)
        payload = {"count": len(elapsed), "p95_ms": elapsed[rank]}

    print(json.dumps(payload, separators=(",", ":")))


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    generate_parser = sub.add_parser("generate")
    generate_parser.add_argument("--scenario", choices=sorted(SCENARIOS.keys()), required=True)
    generate_parser.add_argument("--output-dir", required=True)
    generate_parser.set_defaults(func=generate)

    summarize_parser = sub.add_parser("summarize-jtl")
    summarize_parser.add_argument("--jtl", required=True)
    summarize_parser.set_defaults(func=summarize_jtl)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
