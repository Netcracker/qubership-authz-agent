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
import base64
import csv
import json
import math
import re
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

SUBJECT_PREDICATE_REF_RE = re.compile(r"\$\{subject\.([^}]+)\}")
SUBJECT_CONDITION_REF_RE = re.compile(r"subject\.([A-Za-z0-9_]+)")


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


def write_json(path: Path, payload):
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="ascii")


def write_requests(path: Path, rows):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["username", "scenarioLabel", "requestClass", "expectedDecision", "requestBodyTemplate"],
        )
        writer.writeheader()
        writer.writerows(rows)


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def load_tokens(path):
    tokens = {}
    with open(path, encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or "=" not in line:
                continue
            key, token = line.split("=", 1)
            username = key.removeprefix("token_").replace("_", "-")
            tokens[username] = token
    return tokens


def build_policy_ref_index(policies):
    subject_refs = {}
    for policy_doc in policies:
        resource_type = str(policy_doc.get("resourceType", "")).strip().upper()
        operation = str(policy_doc.get("operation", "")).strip().upper()
        if not resource_type or not operation:
            continue

        refs = set()
        condition = policy_doc.get("condition")
        if isinstance(condition, str):
            refs.update(SUBJECT_CONDITION_REF_RE.findall(condition))

        predicate = policy_doc.get("rsqlPredicate")
        if isinstance(predicate, str):
            refs.update(SUBJECT_PREDICATE_REF_RE.findall(predicate))

        subject_refs.setdefault(resource_type, {}).setdefault(operation, set()).update(refs)

    return {
        "subjectRefsByResourceTypeOperation": {
            resource_type: {
                operation: sorted(refs)
                for operation, refs in operations.items()
            }
            for resource_type, operations in subject_refs.items()
        }
    }


def decode_jwt_segment(segment: str):
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode((segment + padding).encode("ascii")))


def normalize_subject(payload):
    realm_access = payload.get("realm_access", {})
    realm_roles = realm_access.get("roles", []) if isinstance(realm_access, dict) else []
    roles = sorted({str(role).upper() for role in realm_roles if str(role).strip()})

    scopes = []
    raw_scope = payload.get("scope")
    if isinstance(raw_scope, str) and raw_scope.strip():
        scopes.extend(part.strip() for part in raw_scope.split(" ") if part.strip())

    raw_scp = payload.get("scp")
    if isinstance(raw_scp, list):
        scopes.extend(str(part).strip() for part in raw_scp if str(part).strip())
    elif isinstance(raw_scp, str) and raw_scp.strip():
        scopes.extend(part.strip() for part in raw_scp.split(" ") if part.strip())

    level = str(payload.get("level", "")).lower()
    subject = {
        "id": str(payload.get("sub", "")),
        "name": str(payload.get("preferred_username", "")),
        "type": "SERVICE" if level in {"m2m", "external"} else "USER",
        "roles": roles,
        "scopes": sorted(set(scopes)),
    }

    return subject


def build_authn_cache(args):
    tokens = {}
    for token in load_tokens(args.tokens_file).values():
        header_segment, payload_segment, _ = token.split(".", 2)
        header = decode_jwt_segment(header_segment)
        payload = decode_jwt_segment(payload_segment)
        tokens[token] = {
            "header": header,
            "payload": payload,
            "providerId": args.provider_id,
            "subject": normalize_subject(payload),
        }

    payload = {}
    if args.base_authn:
        payload = load_json(args.base_authn)

    payload["verifiedTokens"] = tokens
    write_json(Path(args.output_file), payload)


def materialize_requests(args):
    tokens = load_tokens(args.tokens_file)
    requests = []
    allow_count = 0
    deny_count = 0

    with open(args.requests_csv, encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            username = row["username"]
            token = tokens.get(username)
            if not token:
                raise ValueError(f"missing token for username: {username}")

            body = json.loads(row["requestBodyTemplate"].replace("__TOKEN__", token))
            requests.append(body["input"])

            if row.get("expectedDecision") == "ALLOW":
                allow_count += 1
            elif row.get("expectedDecision") == "DENY":
                deny_count += 1

    write_json(
        Path(args.output_file),
        {
            "requests": requests,
            "requestCount": len(requests),
            "allowCount": allow_count,
            "denyCount": deny_count,
        },
    )


def merge_analysis_data(args):
    requests_doc = load_json(args.requests_file)
    merged = {
        "authn": load_json(args.authn_file),
        "policies": load_json(args.policies_file),
        "pips": load_json(args.pips_file),
        "svt": {
            "requests": requests_doc.get("requests", []),
            "requestCount": requests_doc.get("requestCount", 0),
            "allowCount": requests_doc.get("allowCount", 0),
            "denyCount": requests_doc.get("denyCount", 0),
        },
    }
    write_json(Path(args.output_file), merged)


def summarize_bench(args):
    payload = load_json(args.bench_json)
    extra = payload.get("Extra", {})
    request_count = max(int(args.request_count), 1)

    query_eval_mean_ns = extra.get("histogram_timer_rego_query_eval_ns_mean")
    query_eval_p95_ns = extra.get("histogram_timer_rego_query_eval_ns_95%")

    per_request_mean_ms = None
    per_request_p95_ms = None
    if query_eval_mean_ns is not None:
        per_request_mean_ms = query_eval_mean_ns / request_count / 1_000_000
    if query_eval_p95_ns is not None:
        per_request_p95_ms = query_eval_p95_ns / request_count / 1_000_000

    print(
        json.dumps(
            {
                "requestCount": request_count,
                "benchmarkIterations": payload.get("N"),
                "queryEvalMeanNs": query_eval_mean_ns,
                "queryEvalP95Ns": query_eval_p95_ns,
                "perRequestMeanMs": per_request_mean_ms,
                "perRequestP95Ms": per_request_p95_ms,
            },
            separators=(",", ":"),
        )
    )


def summarize_profile(args):
    payload = load_json(args.profile_json)
    metrics = payload.get("metrics", {})
    profile_rows = payload.get("profile", [])
    request_count = max(int(args.request_count), 1)

    query_eval_ns = metrics.get("timer_rego_query_eval_ns")
    per_request_ms = None
    if query_eval_ns is not None:
        per_request_ms = query_eval_ns / request_count / 1_000_000

    hottest = profile_rows[0] if profile_rows else {}
    location = hottest.get("location", {})
    hottest_location = None
    if location:
        hottest_location = f"{location.get('file', '')}:{location.get('row', 0)}"

    print(
        json.dumps(
            {
                "requestCount": request_count,
                "queryEvalNs": query_eval_ns,
                "perRequestMeanMs": per_request_ms,
                "topHotspot": {
                    "location": hottest_location,
                    "totalTimeNs": hottest.get("total_time_ns"),
                    "numEval": hottest.get("num_eval"),
                },
            },
            separators=(",", ":"),
        )
    )


def generate(args):
    scenario = SCENARIOS[args.scenario]
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    policies = globals()[scenario["policy_builder"]]()
    pips = globals()[scenario["pip_builder"]]()
    rows = globals()[scenario["request_builder"]](args.scenario, scenario["request_class"])

    write_json(output_dir / "policies.json", policies)
    write_json(output_dir / "policies-ref-index.json", build_policy_ref_index(policies))
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

    authn_cache_parser = sub.add_parser("build-authn-cache")
    authn_cache_parser.add_argument("--tokens-file", required=True)
    authn_cache_parser.add_argument("--output-file", required=True)
    authn_cache_parser.add_argument("--provider-id", default="keycloak-svt")
    authn_cache_parser.add_argument("--base-authn")
    authn_cache_parser.set_defaults(func=build_authn_cache)

    materialize_parser = sub.add_parser("materialize-requests")
    materialize_parser.add_argument("--requests-csv", required=True)
    materialize_parser.add_argument("--tokens-file", required=True)
    materialize_parser.add_argument("--output-file", required=True)
    materialize_parser.set_defaults(func=materialize_requests)

    merge_analysis_parser = sub.add_parser("merge-analysis-data")
    merge_analysis_parser.add_argument("--authn-file", required=True)
    merge_analysis_parser.add_argument("--policies-file", required=True)
    merge_analysis_parser.add_argument("--pips-file", required=True)
    merge_analysis_parser.add_argument("--requests-file", required=True)
    merge_analysis_parser.add_argument("--output-file", required=True)
    merge_analysis_parser.set_defaults(func=merge_analysis_data)

    summarize_bench_parser = sub.add_parser("summarize-bench")
    summarize_bench_parser.add_argument("--bench-json", required=True)
    summarize_bench_parser.add_argument("--request-count", required=True, type=int)
    summarize_bench_parser.set_defaults(func=summarize_bench)

    summarize_profile_parser = sub.add_parser("summarize-profile")
    summarize_profile_parser.add_argument("--profile-json", required=True)
    summarize_profile_parser.add_argument("--request-count", required=True, type=int)
    summarize_profile_parser.set_defaults(func=summarize_profile)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
