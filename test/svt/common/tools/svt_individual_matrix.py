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

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from copy import deepcopy
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from opa_direct_matrix import (
    ALLOW_COUNT,
    COMBOS_100,
    COMBOS_500,
    USER_COUNT,
    USERS,
    base_input,
    build_policy_ref_index,
    decode_jwt_segment,
    load_tokens,
    normalize_subject,
    policy as simplified_policy,
)


REPO_ROOT = Path(__file__).resolve().parents[4]
SVT_DIR = REPO_ROOT / "tests" / "svt"
DEFAULT_OUTPUT_ROOT = SVT_DIR / "load-tests" / "individual" / "artifacts"
COMPOSE_FILE = SVT_DIR / "common" / "compose" / "docker-compose.yml"

PROJECT_NAME = os.environ.get("PROJECT_NAME", "authz-svt")
SVT_KC_PORT = int(os.environ.get("SVT_KC_PORT", "25556"))
SVT_AUTHZ_PORT = int(os.environ.get("SVT_AUTHZ_PORT", "28080"))
SVT_AUTHZ_POLICY_ADMIN_PORT = int(os.environ.get("SVT_AUTHZ_POLICY_ADMIN_PORT", "28093"))
# Must match the domain test/svt/scripts/up seeded under: the stub files
# policies per domain, so re-seeding a different one would leave the original
# set in place alongside it.
SVT_AUTHZ_POLICY_ADMIN_DOMAIN = os.environ.get("SVT_AUTHZ_POLICY_ADMIN_DOMAIN", "SVT")
# One full pull tick plus a margin, derived from the interval the stack runs
# with rather than hardcoded.
SVT_PAP_PULL_INTERVAL = int(os.environ.get("SVT_PAP_PULL_INTERVAL", "2"))
SVT_PULL_WAIT_SECONDS = SVT_PAP_PULL_INTERVAL + 2
SVT_AUTHZ_ADMIN_PORT = int(os.environ.get("SVT_AUTHZ_ADMIN_PORT", "29901"))
SVT_PROMETHEUS_PORT = int(os.environ.get("SVT_PROMETHEUS_PORT", "29090"))

KC_REALM = "svt-test"
KC_CLIENT_ID = "authz-agent"
KC_CLIENT_SECRET = "authz-agent-secret"
KC_ADMIN_USER = os.environ.get("KC_ADMIN_USER", "kcadmin")
KC_ADMIN_PASSWORD = os.environ.get("KC_ADMIN_PASSWORD", "kcadmin")
KC_ADMIN_REALM = os.environ.get("KC_ADMIN_REALM", "master")

COMPONENT = "SVT_INDIVIDUAL_MATRIX"
ALLOW_ROLE = "ROLE_SVT_ADMIN"
DENY_ROLE = "ROLE_SVT_MATRIX_DENY"
PROM_STEP_SECONDS = 5

TRANSPORT_MODE_ORDER = ("envoy-canonical", "envoy-legacy", "opa-direct")
SCENARIO_ORDER = (
    "ols-single",
    "ols-bulk",
    "rls-filter",
    "rls-condition-1",
    "rls-condition-2",
    "rls-condition-3",
)
DEFAULT_TARGET_RPS = (500, 1000)

REQUEST_FIELDS = [
    "username",
    "scenarioLabel",
    "requestClass",
    "requestPath",
    "requestBodyTemplate",
    "responseKind",
    "expectedDecision",
    "expectedAllowCount",
    "expectedPredicatePresent",
    "expectedFilterResult",
    "headerFilterMode",
]

PROM_QUERIES = {
    "opa_cpu": 'sum(rate(container_cpu_usage_seconds_total{name=~".*-opa-.*"}[30s]))',
    "opa_mem": 'sum(container_memory_working_set_bytes{name=~".*-opa-.*"})',
    "envoy_cpu": 'sum(rate(container_cpu_usage_seconds_total{name=~".*envoy.*"}[30s]))',
    "envoy_mem": 'sum(container_memory_working_set_bytes{name=~".*envoy.*"})',
}


def now_timestamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.localtime())


def run_command(
    command: list[str],
    *,
    input_text: str | None = None,
    capture_output: bool = False,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=True,
        cwd=str(REPO_ROOT),
        input=input_text,
        text=True,
        capture_output=capture_output,
        env=env,
    )


def compose_command(*extra: str) -> list[str]:
    return ["docker", "compose", "-p", PROJECT_NAME, "-f", str(COMPOSE_FILE), *extra]


def compose_exec(service: str, shell_command: str, *, input_text: str | None = None, capture_output: bool = False) -> str:
    completed = run_command(
        compose_command("exec", "-T", service, "sh", "-lc", shell_command),
        input_text=input_text,
        capture_output=capture_output,
    )
    return completed.stdout if capture_output else ""


def opa_helper_exec(
    shell_command: str,
    *,
    capture_output: bool = False,
    mounts: list[tuple[Path, str]] | None = None,
) -> str:
    command = compose_command("run", "--rm", "--no-deps", "--entrypoint", "sh")
    for host_path, container_path in mounts or []:
        command.extend(["-v", f"{host_path.resolve()}:{container_path}:ro"])
    command.extend(["jmeter", "-lc", shell_command])
    completed = run_command(command, capture_output=capture_output)
    return completed.stdout if capture_output else ""


def http_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_payload: Any | None = None,
    form_payload: dict[str, str] | None = None,
    raw_payload: bytes | None = None,
    timeout: int = 30,
) -> tuple[int, str]:
    final_headers = dict(headers or {})
    data: bytes | None = None
    if json_payload is not None:
        data = json.dumps(json_payload, separators=(",", ":")).encode("utf-8")
        final_headers.setdefault("Content-Type", "application/json")
    elif form_payload is not None:
        data = urllib.parse.urlencode(form_payload).encode("utf-8")
        final_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif raw_payload is not None:
        data = raw_payload

    request = urllib.request.Request(url, data=data, headers=final_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def http_request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_payload: Any | None = None,
    form_payload: dict[str, str] | None = None,
    timeout: int = 30,
) -> tuple[int, Any]:
    status, body = http_request(
        method,
        url,
        headers=headers,
        json_payload=json_payload,
        form_payload=form_payload,
        timeout=timeout,
    )
    if not body:
        return status, None
    return status, json.loads(body)


def wait_for_public_health(attempts: int = 90, delay_seconds: int = 2) -> None:
    url = f"http://localhost:{SVT_AUTHZ_PORT}/health"
    for _ in range(attempts):
        status, _ = http_request("GET", url, timeout=5)
        if status == 200:
            return
        time.sleep(delay_seconds)
    raise RuntimeError("SVT public health endpoint is not ready; run test/svt/scripts/up first")


def wait_for_backend_health(attempts: int = 90, delay_seconds: int = 2) -> None:
    for _ in range(attempts):
        try:
            run_command(compose_command("exec", "-T", "opa", "policy-admin", "healthcheck"))
            return
        except subprocess.CalledProcessError:
            time.sleep(delay_seconds)
    raise RuntimeError("SVT backend healthcheck is not ready; run test/svt/scripts/up first")


def restart_opa() -> None:
    run_command(compose_command("restart", "opa"))
    wait_for_backend_health()
    wait_for_public_health()


def json_deepcopy(payload: Any) -> Any:
    return json.loads(json.dumps(payload))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="ascii")


def write_requests(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=REQUEST_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def property_key(username: str) -> str:
    return f"token_{username.replace('-', '_')}"


def write_tokens_properties(path: Path, tokens: dict[str, str]) -> None:
    lines = [f"{property_key(username)}={token}" for username, token in sorted(tokens.items())]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def canonical_body(resources: list[dict[str, Any]], ignore_rls: bool) -> dict[str, Any]:
    return {
        "resources": resources,
        "subject": "Bearer __TOKEN__",
        "ignoreRls": ignore_rls,
    }


def direct_body(resources: list[dict[str, Any]], ignore_rls: bool, request_headers: dict[str, str] | None = None) -> dict[str, Any]:
    return base_input(resources, ignore_rls, request_headers=request_headers)


def make_row(
    *,
    username: str,
    scenario_label: str,
    request_class: str,
    request_path: str,
    request_body_template: str,
    response_kind: str,
    expected_decision: str,
    expected_allow_count: int,
    expected_predicate_present: bool,
    expected_filter_result: str = "",
    header_filter_mode: str = "",
) -> dict[str, str]:
    return {
        "username": username,
        "scenarioLabel": scenario_label,
        "requestClass": request_class,
        "requestPath": request_path,
        "requestBodyTemplate": request_body_template,
        "responseKind": response_kind,
        "expectedDecision": expected_decision,
        "expectedAllowCount": str(expected_allow_count),
        "expectedPredicatePresent": "true" if expected_predicate_present else "false",
        "expectedFilterResult": expected_filter_result,
        "headerFilterMode": header_filter_mode,
    }


def email_token_pip() -> list[dict[str, str]]:
    return [{"name": "subject.emailFromToken", "pipType": "TOKEN", "claim": "email"}]


def empty_pips() -> list[dict[str, str]]:
    return []


def role_for_index(index: int, allow_cutoff: int) -> list[str]:
    return [ALLOW_ROLE] if index < allow_cutoff else [DENY_ROLE]


def build_ols_single_assets(transport_mode: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, str]], dict[str, Any]]:
    policies = [
        simplified_policy(COMPONENT, resource_type, operation, roles=role_for_index(index, ALLOW_COUNT))
        for index, (resource_type, operation) in enumerate(COMBOS_100)
    ]
    rows: list[dict[str, str]] = []
    for index, user in enumerate(USERS):
        resource_type, operation = COMBOS_100[index]
        allow = index < ALLOW_COUNT
        resources = [{"resourceType": resource_type, "operation": operation, "resource": {}}]
        expected_decision = "ALLOW" if allow else "DENY"
        if transport_mode == "envoy-canonical":
            rows.append(
                make_row(
                    username=user["username"],
                    scenario_label="ols-single",
                    request_class="OLS_SINGLE",
                    request_path="/access/v1/authorize",
                    request_body_template=json.dumps(canonical_body(resources, False), separators=(",", ":")),
                    response_kind="single",
                    expected_decision=expected_decision,
                    expected_allow_count=1 if allow else 0,
                    expected_predicate_present=False,
                )
            )
        elif transport_mode == "envoy-legacy":
            rows.append(
                make_row(
                    username=user["username"],
                    scenario_label="ols-single",
                    request_class="OLS_SINGLE",
                    request_path="/access/v1/check/resource",
                    request_body_template=json.dumps(
                        {"type": resource_type, "operation": operation, "resource": {}},
                        separators=(",", ":"),
                    ),
                    response_kind="single",
                    expected_decision=expected_decision,
                    expected_allow_count=1 if allow else 0,
                    expected_predicate_present=False,
                )
            )
        else:
            rows.append(
                make_row(
                    username=user["username"],
                    scenario_label="ols-single",
                    request_class="OLS_SINGLE",
                    request_path="/v1/data/authorize",
                    request_body_template=json.dumps(direct_body(resources, False), separators=(",", ":")),
                    response_kind="single",
                    expected_decision=expected_decision,
                    expected_allow_count=1 if allow else 0,
                    expected_predicate_present=False,
                )
            )

    meta = {
        "name": "ols-single",
        "transport_mode": transport_mode,
        "request_count": len(rows),
        "allow_count": ALLOW_COUNT,
        "deny_count": USER_COUNT - ALLOW_COUNT,
        "policy_count": len(policies),
        "pip_count": 0,
        "total_resource_type_operation": 100,
        "resource_type_operation_per_request": 1,
        "ignore_rls": True,
    }
    return policies, empty_pips(), rows, meta


def build_ols_bulk_assets(transport_mode: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, str]], dict[str, Any]]:
    policies = [
        simplified_policy(COMPONENT, resource_type, operation, roles=role_for_index(index, 450))
        for index, (resource_type, operation) in enumerate(COMBOS_500)
    ]
    allow_batches = [COMBOS_500[index : index + 50] for index in range(0, 450, 50)]
    deny_batch = COMBOS_500[450:500]
    rows: list[dict[str, str]] = []

    for index, user in enumerate(USERS):
        allow = index < ALLOW_COUNT
        combos = allow_batches[index % len(allow_batches)] if allow else deny_batch
        expected_decision = "ALLOW" if allow else "DENY"
        if transport_mode == "envoy-legacy":
            payload = []
            for item_index, (resource_type, operation) in enumerate(combos, start=1):
                payload.append(
                    {
                        "type": resource_type,
                        "operation": operation,
                        "resource": {},
                        "id": f"bulk-{item_index:02d}",
                    }
                )
            rows.append(
                make_row(
                    username=user["username"],
                    scenario_label="ols-bulk",
                    request_class="OLS_BULK_50",
                    request_path="/access/v1/check/resource/bulk",
                    request_body_template=json.dumps(payload, separators=(",", ":")),
                    response_kind="bulk",
                    expected_decision=expected_decision,
                    expected_allow_count=50 if allow else 0,
                    expected_predicate_present=False,
                )
            )
            continue

        resources = [
            {"resourceType": resource_type, "operation": operation, "resource": {}}
            for resource_type, operation in combos
        ]
        request_path = "/access/v1/authorize" if transport_mode == "envoy-canonical" else "/v1/data/authorize"
        request_body = canonical_body(resources, False) if transport_mode == "envoy-canonical" else direct_body(resources, False)
        rows.append(
            make_row(
                username=user["username"],
                scenario_label="ols-bulk",
                request_class="OLS_BULK_50",
                request_path=request_path,
                request_body_template=json.dumps(request_body, separators=(",", ":")),
                response_kind="bulk",
                expected_decision=expected_decision,
                expected_allow_count=50 if allow else 0,
                expected_predicate_present=False,
            )
        )

    meta = {
        "name": "ols-bulk",
        "transport_mode": transport_mode,
        "request_count": len(rows),
        "allow_count": ALLOW_COUNT,
        "deny_count": USER_COUNT - ALLOW_COUNT,
        "policy_count": len(policies),
        "pip_count": 0,
        "total_resource_type_operation": 500,
        "resource_type_operation_per_request": 50,
        "ignore_rls": True,
    }
    return policies, empty_pips(), rows, meta


def build_rls_filter_assets(transport_mode: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, str]], dict[str, Any]]:
    policies = [
        simplified_policy(
            COMPONENT,
            resource_type,
            operation,
            roles=role_for_index(index, ALLOW_COUNT),
            predicate="ownerId==${subject.emailFromToken}",
        )
        for index, (resource_type, operation) in enumerate(COMBOS_100)
    ]
    rows: list[dict[str, str]] = []
    for index, user in enumerate(USERS):
        resource_type, operation = COMBOS_100[index]
        allow = index < ALLOW_COUNT
        expected_decision = "ALLOW" if allow else "DENY"
        if transport_mode == "envoy-canonical":
            rows.append(
                make_row(
                    username=user["username"],
                    scenario_label="rls-filter",
                    request_class="RLS_FILTER",
                    request_path="/access/v1/authorize",
                    request_body_template=json.dumps(
                        canonical_body([{"resourceType": resource_type, "operation": operation, "resource": {}}], False),
                        separators=(",", ":"),
                    ),
                    response_kind="filter",
                    expected_decision=expected_decision,
                    expected_allow_count=1 if allow else 0,
                    expected_predicate_present=allow,
                )
            )
        elif transport_mode == "envoy-legacy":
            rows.append(
                make_row(
                    username=user["username"],
                    scenario_label="rls-filter",
                    request_class="RLS_FILTER",
                    request_path=f"/access/v1/check/filter?resourceType={resource_type}&operation={operation}",
                    request_body_template="",
                    response_kind="filter",
                    expected_decision=expected_decision,
                    expected_allow_count=1 if allow else 0,
                    expected_predicate_present=False,
                    expected_filter_result="ALLOW" if allow else "DENY",
                )
            )
        else:
            rows.append(
                make_row(
                    username=user["username"],
                    scenario_label="rls-filter",
                    request_class="RLS_FILTER",
                    request_path="/v1/data/authorize",
                    request_body_template=json.dumps(
                        direct_body(
                            [{"resourceType": resource_type, "operation": operation, "resource": {}}],
                            False,
                        ),
                        separators=(",", ":"),
                    ),
                    response_kind="filter",
                    expected_decision=expected_decision,
                    expected_allow_count=1 if allow else 0,
                    expected_predicate_present=allow,
                )
            )

    meta = {
        "name": "rls-filter",
        "transport_mode": transport_mode,
        "request_count": len(rows),
        "allow_count": ALLOW_COUNT,
        "deny_count": USER_COUNT - ALLOW_COUNT,
        "policy_count": len(policies),
        "pip_count": 1,
        "total_resource_type_operation": 100,
        "resource_type_operation_per_request": 1,
        "ignore_rls": False,
    }
    return policies, email_token_pip(), rows, meta


def build_rls_condition_assets(
    transport_mode: str,
    clause_count: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, str]], dict[str, Any]]:
    condition_parts = [
        "resource.ownerId == subject.emailFromToken",
        "resource.department == 'svt'",
        "resource.status == 'active'",
    ]
    condition = " AND ".join(condition_parts[:clause_count])
    scenario_name = f"rls-condition-{clause_count}"
    request_class = f"RLS_CONDITION_{clause_count}"
    policies = [
        simplified_policy(
            COMPONENT,
            resource_type,
            operation,
            roles=[ALLOW_ROLE],
            condition=condition,
        )
        for resource_type, operation in COMBOS_100
    ]
    rows: list[dict[str, str]] = []
    for index, user in enumerate(USERS):
        resource_type, operation = COMBOS_100[index]
        allow = index < ALLOW_COUNT
        resource = {
            "ownerId": user["email"] if allow else f"deny-{user['email']}",
            "department": "svt",
            "status": "active",
        }
        expected_decision = "ALLOW" if allow else "DENY"
        if transport_mode == "envoy-canonical":
            rows.append(
                make_row(
                    username=user["username"],
                    scenario_label=scenario_name,
                    request_class=request_class,
                    request_path="/access/v1/authorize",
                    request_body_template=json.dumps(
                        canonical_body([{"resourceType": resource_type, "operation": operation, "resource": resource}], False),
                        separators=(",", ":"),
                    ),
                    response_kind="single",
                    expected_decision=expected_decision,
                    expected_allow_count=1 if allow else 0,
                    expected_predicate_present=False,
                )
            )
        elif transport_mode == "envoy-legacy":
            rows.append(
                make_row(
                    username=user["username"],
                    scenario_label=scenario_name,
                    request_class=request_class,
                    request_path="/access/v1/check/resource",
                    request_body_template=json.dumps(
                        {"type": resource_type, "operation": operation, "resource": resource},
                        separators=(",", ":"),
                    ),
                    response_kind="single",
                    expected_decision=expected_decision,
                    expected_allow_count=1 if allow else 0,
                    expected_predicate_present=False,
                )
            )
        else:
            rows.append(
                make_row(
                    username=user["username"],
                    scenario_label=scenario_name,
                    request_class=request_class,
                    request_path="/v1/data/authorize",
                    request_body_template=json.dumps(
                        direct_body([{"resourceType": resource_type, "operation": operation, "resource": resource}], False),
                        separators=(",", ":"),
                    ),
                    response_kind="single",
                    expected_decision=expected_decision,
                    expected_allow_count=1 if allow else 0,
                    expected_predicate_present=False,
                )
            )

    meta = {
        "name": scenario_name,
        "transport_mode": transport_mode,
        "request_count": len(rows),
        "allow_count": ALLOW_COUNT,
        "deny_count": USER_COUNT - ALLOW_COUNT,
        "policy_count": len(policies),
        "pip_count": 1,
        "total_resource_type_operation": 100,
        "resource_type_operation_per_request": 1,
        "ignore_rls": False,
        "condition_clause_count": clause_count,
    }
    return policies, email_token_pip(), rows, meta


def generate_run_assets(scenario: str, transport_mode: str, output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    if scenario == "ols-single":
        policies, pips, rows, meta = build_ols_single_assets(transport_mode)
    elif scenario == "ols-bulk":
        policies, pips, rows, meta = build_ols_bulk_assets(transport_mode)
    elif scenario == "rls-filter":
        policies, pips, rows, meta = build_rls_filter_assets(transport_mode)
    elif scenario.startswith("rls-condition-"):
        clause_count = int(scenario.rsplit("-", 1)[1])
        policies, pips, rows, meta = build_rls_condition_assets(transport_mode, clause_count)
    else:
        raise ValueError(f"unsupported scenario: {scenario}")

    write_json(output_dir / "policies.json", policies)
    write_json(output_dir / "policies-ref-index.json", build_policy_ref_index(policies))
    write_json(output_dir / "pips.json", pips)
    write_requests(output_dir / "requests.csv", rows)
    write_json(output_dir / "scenario.json", meta)
    return meta


def kc_admin_token() -> str:
    status, payload = http_request_json(
        "POST",
        f"http://localhost:{SVT_KC_PORT}/realms/{KC_ADMIN_REALM}/protocol/openid-connect/token",
        form_payload={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": KC_ADMIN_USER,
            "password": KC_ADMIN_PASSWORD,
        },
    )
    if status != 200 or not isinstance(payload, dict) or not payload.get("access_token"):
        raise RuntimeError("failed to acquire Keycloak admin token")
    return str(payload["access_token"])


def kc_request_json(
    admin_token: str,
    method: str,
    path: str,
    *,
    json_payload: Any | None = None,
) -> Any:
    status, payload = http_request_json(
        method,
        f"http://localhost:{SVT_KC_PORT}{path}",
        headers={"Authorization": f"Bearer {admin_token}"},
        json_payload=json_payload,
    )
    if status >= 400:
        raise RuntimeError(f"Keycloak request failed: {method} {path} -> HTTP {status}")
    return payload


def ensure_matrix_users() -> None:
    admin_token = kc_admin_token()
    role_rep = kc_request_json(admin_token, "GET", f"/admin/realms/{KC_REALM}/roles/{ALLOW_ROLE}")
    role_payload = [role_rep]
    for user in USERS:
        username = user["username"]
        email = user["email"]
        query_path = f"/admin/realms/{KC_REALM}/users?{urllib.parse.urlencode({'username': username, 'exact': 'true'})}"
        existing = kc_request_json(admin_token, "GET", query_path)
        if not existing:
            kc_request_json(
                admin_token,
                "POST",
                f"/admin/realms/{KC_REALM}/users",
                json_payload={
                    "username": username,
                    "email": email,
                    "enabled": True,
                    "emailVerified": True,
                    "firstName": "SVT",
                    "lastName": "Matrix",
                    "requiredActions": [],
                },
            )
            existing = kc_request_json(admin_token, "GET", query_path)
        user_id = str(existing[0]["id"])
        kc_request_json(
            admin_token,
            "PUT",
            f"/admin/realms/{KC_REALM}/users/{user_id}",
            json_payload={
                "id": user_id,
                "username": username,
                "email": email,
                "enabled": True,
                "emailVerified": True,
                "firstName": "SVT",
                "lastName": "Matrix",
                "requiredActions": [],
            },
        )
        kc_request_json(
            admin_token,
            "PUT",
            f"/admin/realms/{KC_REALM}/users/{user_id}/reset-password",
            json_payload={"type": "password", "value": "password", "temporary": False},
        )
        assigned_roles = kc_request_json(
            admin_token,
            "GET",
            f"/admin/realms/{KC_REALM}/users/{user_id}/role-mappings/realm/composite",
        )
        if not any(isinstance(role, dict) and role.get("name") == ALLOW_ROLE for role in assigned_roles):
            kc_request_json(
                admin_token,
                "POST",
                f"/admin/realms/{KC_REALM}/users/{user_id}/role-mappings/realm",
                json_payload=role_payload,
            )


def acquire_user_tokens() -> dict[str, str]:
    tokens: dict[str, str] = {}
    for user in USERS:
        status, payload = http_request_json(
            "POST",
            f"http://localhost:{SVT_KC_PORT}/realms/{KC_REALM}/protocol/openid-connect/token",
            form_payload={
                "grant_type": "password",
                "client_id": KC_CLIENT_ID,
                "client_secret": KC_CLIENT_SECRET,
                "username": user["username"],
                "password": "password",
                "scope": "openid",
            },
        )
        if status != 200 or not isinstance(payload, dict) or not payload.get("access_token"):
            raise RuntimeError(f"failed to acquire token for {user['username']}")
        tokens[user["username"]] = str(payload["access_token"])
    return tokens


def capture_authn_base() -> dict[str, Any]:
    output = opa_helper_exec("curl -sf http://opa:8181/v1/data/authn", capture_output=True)
    payload = json.loads(output)
    return payload["result"]


def build_authn_cache_payload(base_authn: dict[str, Any], tokens_file: Path) -> dict[str, Any]:
    verified_tokens: dict[str, Any] = {}
    for token in load_tokens(str(tokens_file)).values():
        header_segment, payload_segment, _ = token.split(".", 2)
        header = decode_jwt_segment(header_segment)
        payload = decode_jwt_segment(payload_segment)
        verified_tokens[token] = {
            "header": header,
            "payload": payload,
            "providerId": "keycloak-svt",
            "subject": normalize_subject(payload),
        }

    payload = json_deepcopy(base_authn)
    payload["verifiedTokens"] = verified_tokens
    return payload


def upload_authn_document(path: Path) -> None:
    opa_helper_exec(
        'curl -sf -X PUT http://opa:8181/v1/data/authn -H "Content-Type: application/json" --data @/payload/authn.json >/dev/null',
        mounts=[(path, "/payload/authn.json")],
    )


def upload_policy_ref_index(path: Path) -> None:
    opa_helper_exec(
        'curl -sf -X PUT http://opa:8181/v1/data/policies/refIndex -H "Content-Type: application/json" --data @/payload/policies-ref-index.json >/dev/null',
        mounts=[(path, "/payload/policies-ref-index.json")],
    )


def seed_via_authz_policy_admin(kind: str, payload_file: Path) -> None:
    """Seed simplified policies or PIPs into the authz-policy-admin.

    The stub serves access-control's own per-domain paths
    (authz-agent-ADR-0073); the OPA pull loop reads them back through the v3
    export. ``kind`` is ``domainPolicies`` or ``domainPIPs``.
    """
    path = f"/access/v1/simplifiedPolicies/{kind}/{SVT_AUTHZ_POLICY_ADMIN_DOMAIN}"
    status, body = http_request(
        "PUT",
        f"http://localhost:{SVT_AUTHZ_POLICY_ADMIN_PORT}{path}",
        headers={"Content-Type": "application/json"},
        raw_payload=payload_file.read_bytes(),
        timeout=60,
    )
    if status != 200:
        raise RuntimeError(f"seed failed for {path}: HTTP {status} {body}")


def summarize_jtl_payload(path: Path) -> dict[str, Any]:
    elapsed_values: list[int] = []
    timestamps: list[int] = []
    end_timestamps: list[int] = []
    error_count = 0
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            try:
                timestamp = int(row["timeStamp"])
                elapsed = int(row["elapsed"])
            except (KeyError, TypeError, ValueError):
                continue
            timestamps.append(timestamp)
            end_timestamps.append(timestamp + elapsed)
            elapsed_values.append(elapsed)
            if str(row.get("success", "")).lower() != "true":
                error_count += 1

    if not timestamps:
        return {
            "count": 0,
            "p95_ms": None,
            "error_count": 0,
            "window_start_epoch_s": None,
            "window_end_epoch_s": None,
            "window_duration_s": None,
            "achieved_rps": None,
        }

    elapsed_values.sort()
    rank = max(0, math.ceil(len(elapsed_values) * 0.95) - 1)
    window_start_ms = min(timestamps)
    window_end_ms = max(end_timestamps)
    duration_seconds = max((window_end_ms - window_start_ms) / 1000.0, 0.001)
    return {
        "count": len(elapsed_values),
        "p95_ms": elapsed_values[rank],
        "error_count": error_count,
        "window_start_epoch_s": window_start_ms / 1000.0,
        "window_end_epoch_s": window_end_ms / 1000.0,
        "window_duration_s": duration_seconds,
        "achieved_rps": len(elapsed_values) / duration_seconds,
    }


def prom_query_range(query: str, start: float, end: float, step_seconds: int = PROM_STEP_SECONDS) -> dict[str, Any]:
    params = urllib.parse.urlencode(
        {
            "query": query,
            "start": f"{start:.3f}",
            "end": f"{end:.3f}",
            "step": str(step_seconds),
        }
    )
    status, payload = http_request_json(
        "GET",
        f"http://localhost:{SVT_PROMETHEUS_PORT}/api/v1/query_range?{params}",
        timeout=60,
    )
    if status != 200:
        raise RuntimeError(f"Prometheus query failed: HTTP {status}")
    return {
        "query": query,
        "start": start,
        "end": end,
        "step_seconds": step_seconds,
        "response": payload,
    }


def summarize_prometheus_series(payload: dict[str, Any]) -> dict[str, float | None]:
    values: list[float] = []
    response = payload.get("response", {})
    data = response.get("data", {}) if isinstance(response, dict) else {}
    result = data.get("result", []) if isinstance(data, dict) else []
    for series in result:
        for sample in series.get("values", []):
            if not isinstance(sample, list) or len(sample) != 2:
                continue
            try:
                values.append(float(sample[1]))
            except (TypeError, ValueError):
                continue
    if not values:
        return {"max": None, "avg": None}
    return {"max": max(values), "avg": sum(values) / len(values)}


def query_prometheus_metrics(start: float | None, end: float | None, output_dir: Path) -> dict[str, float | None]:
    output_dir.mkdir(parents=True, exist_ok=True)
    if start is None or end is None or end <= start:
        empty_metrics = {
            "opa_cpu_max": None,
            "opa_cpu_avg": None,
            "opa_mem_max": None,
            "opa_mem_avg": None,
            "envoy_cpu_max": None,
            "envoy_cpu_avg": None,
            "envoy_mem_max": None,
            "envoy_mem_avg": None,
        }
        write_json(output_dir / "summary.json", empty_metrics)
        return empty_metrics

    query_results = {name: prom_query_range(query, start, end) for name, query in PROM_QUERIES.items()}
    for name, payload in query_results.items():
        write_json(output_dir / f"{name}.json", payload)

    opa_cpu = summarize_prometheus_series(query_results["opa_cpu"])
    opa_mem = summarize_prometheus_series(query_results["opa_mem"])
    envoy_cpu = summarize_prometheus_series(query_results["envoy_cpu"])
    envoy_mem = summarize_prometheus_series(query_results["envoy_mem"])
    summary = {
        "opa_cpu_max": opa_cpu["max"],
        "opa_cpu_avg": opa_cpu["avg"],
        "opa_mem_max": opa_mem["max"],
        "opa_mem_avg": opa_mem["avg"],
        "envoy_cpu_max": envoy_cpu["max"],
        "envoy_cpu_avg": envoy_cpu["avg"],
        "envoy_mem_max": envoy_mem["max"],
        "envoy_mem_avg": envoy_mem["avg"],
    }
    write_json(output_dir / "summary.json", summary)
    return summary


def transport_runner_path(transport_mode: str) -> Path:
    return {
        "envoy-canonical": SVT_DIR / "load-tests" / "individual" / "envoy-canonical" / "run",
        "envoy-legacy": SVT_DIR / "load-tests" / "individual" / "envoy-legacy" / "run",
        "opa-direct": SVT_DIR / "load-tests" / "individual" / "opa-direct" / "run",
    }[transport_mode]


def run_transport(
    *,
    transport_mode: str,
    scenario: str,
    target_rps: int,
    output_dir: Path,
    threads: int,
    ramp_seconds: int,
    duration_seconds: int,
    base_authn: dict[str, Any],
) -> dict[str, Any]:
    run_dir = output_dir / "runs" / f"{transport_mode}__{scenario}__{target_rps}rps"
    generated_dir = run_dir / "generated"
    jmeter_dir = run_dir / "jmeter"
    prometheus_dir = run_dir / "prometheus"
    run_dir.mkdir(parents=True, exist_ok=True)

    scenario_meta = generate_run_assets(scenario, transport_mode, generated_dir)

    tokens = acquire_user_tokens()
    tokens_file = run_dir / "tokens.properties"
    write_tokens_properties(tokens_file, tokens)

    authn_payload = build_authn_cache_payload(base_authn, tokens_file)
    write_json(generated_dir / "authn.json", authn_payload)

    restart_opa()
    upload_authn_document(generated_dir / "authn.json")
    upload_policy_ref_index(generated_dir / "policies-ref-index.json")
    seed_via_authz_policy_admin("domainPolicies", generated_dir / "policies.json")
    seed_via_authz_policy_admin("domainPIPs", generated_dir / "pips.json")
    # Wait one full pull tick plus a margin for the seeded data to reach OPA.
    time.sleep(SVT_PULL_WAIT_SECONDS)

    env = os.environ.copy()
    env.update(
        {
            "SCENARIO_CSV": str((generated_dir / "requests.csv").resolve()),
            "TOKENS_FILE": str(tokens_file.resolve()),
            "ARTIFACTS_DIR": str(jmeter_dir.resolve()),
            "TARGET_RPS": str(target_rps),
            "THREADS": str(threads),
            "RAMP_SECONDS": str(ramp_seconds),
            "DURATION_SECONDS": str(duration_seconds),
            "PROJECT_NAME": PROJECT_NAME,
            "SVT_KC_PORT": str(SVT_KC_PORT),
            "SVT_AUTHZ_PORT": str(SVT_AUTHZ_PORT),
            "SVT_AUTHZ_ADMIN_PORT": str(SVT_AUTHZ_ADMIN_PORT),
            "SVT_PROMETHEUS_PORT": str(SVT_PROMETHEUS_PORT),
        }
    )
    run_command([str(transport_runner_path(transport_mode))], env=env)

    jtl_summary = summarize_jtl_payload(jmeter_dir / "results.jtl")
    prom_summary = query_prometheus_metrics(
        jtl_summary["window_start_epoch_s"],
        jtl_summary["window_end_epoch_s"],
        prometheus_dir,
    )

    row = {
        "transport_mode": transport_mode,
        "scenario": scenario,
        "target_rps": target_rps,
        "achieved_rps": jtl_summary["achieved_rps"],
        "p95_ms": jtl_summary["p95_ms"],
        "error_count": jtl_summary["error_count"],
        "opa_cpu_max": prom_summary["opa_cpu_max"],
        "opa_mem_max": prom_summary["opa_mem_max"],
        "opa_cpu_avg": prom_summary["opa_cpu_avg"],
        "opa_mem_avg": prom_summary["opa_mem_avg"],
        "envoy_cpu_max": prom_summary["envoy_cpu_max"],
        "envoy_mem_max": prom_summary["envoy_mem_max"],
        "envoy_cpu_avg": prom_summary["envoy_cpu_avg"],
        "envoy_mem_avg": prom_summary["envoy_mem_avg"],
        "artifacts_dir": str(run_dir.resolve()),
    }

    run_metadata = {
        "transport_mode": transport_mode,
        "scenario": scenario,
        "target_rps": target_rps,
        "threads": threads,
        "ramp_seconds": ramp_seconds,
        "duration_seconds": duration_seconds,
        "generated": scenario_meta,
        "jmeter_summary": jtl_summary,
        "prometheus_summary": prom_summary,
        "artifacts": {
            "generated_dir": str(generated_dir.resolve()),
            "jmeter_dir": str(jmeter_dir.resolve()),
            "prometheus_dir": str(prometheus_dir.resolve()),
            "tokens_file": str(tokens_file.resolve()),
        },
    }
    write_json(run_dir / "run-metadata.json", run_metadata)
    return row


def xlsx_column_name(index: int) -> str:
    result = []
    current = index
    while current > 0:
        current, remainder = divmod(current - 1, 26)
        result.append(chr(65 + remainder))
    return "".join(reversed(result))


def xlsx_cell(ref: str, value: Any) -> str:
    if value is None or value == "":
        return f'<c r="{ref}"/>'
    if isinstance(value, bool):
        numeric = "1" if value else "0"
        return f'<c r="{ref}"><v>{numeric}</v></c>'
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            return f'<c r="{ref}"/>'
        return f'<c r="{ref}"><v>{value}</v></c>'
    return f'<c r="{ref}" t="inlineStr"><is><t>{escape(str(value))}</t></is></c>'


def build_sheet_xml(headers: list[str], rows: list[dict[str, Any]]) -> str:
    xml_rows: list[str] = []
    header_cells = [xlsx_cell(f"{xlsx_column_name(index)}1", header) for index, header in enumerate(headers, start=1)]
    xml_rows.append(f'<row r="1">{"".join(header_cells)}</row>')
    for row_index, row in enumerate(rows, start=2):
        row_cells = []
        for column_index, header in enumerate(headers, start=1):
            ref = f"{xlsx_column_name(column_index)}{row_index}"
            row_cells.append(xlsx_cell(ref, row.get(header)))
        xml_rows.append(f'<row r="{row_index}">{"".join(row_cells)}</row>')
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetData>'
        + "".join(xml_rows)
        + "</sheetData></worksheet>"
    )


def write_workbook(path: Path, rows: list[dict[str, Any]]) -> None:
    headers = [
        "transport_mode",
        "scenario",
        "target_rps",
        "achieved_rps",
        "p95_ms",
        "error_count",
        "opa_cpu_max",
        "opa_mem_max",
        "opa_cpu_avg",
        "opa_mem_avg",
        "envoy_cpu_max",
        "envoy_mem_max",
        "envoy_cpu_avg",
        "envoy_mem_avg",
        "artifacts_dir",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
            "</Types>",
        )
        archive.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            "</Relationships>",
        )
        archive.writestr(
            "xl/workbook.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="summary" sheetId="1" r:id="rId1"/></sheets></workbook>',
        )
        archive.writestr(
            "xl/_rels/workbook.xml.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
            "</Relationships>",
        )
        archive.writestr(
            "xl/styles.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts>'
            '<fills count="1"><fill><patternFill patternType="none"/></fill></fills>'
            '<borders count="1"><border/></borders>'
            '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
            '<cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>'
            '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
            "</styleSheet>",
        )
        archive.writestr("xl/worksheets/sheet1.xml", build_sheet_xml(headers, rows))


def sort_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    transport_index = {name: index for index, name in enumerate(TRANSPORT_MODE_ORDER)}
    scenario_index = {name: index for index, name in enumerate(SCENARIO_ORDER)}
    return sorted(
        rows,
        key=lambda row: (
            transport_index[row["transport_mode"]],
            scenario_index[row["scenario"]],
            int(row["target_rps"]),
        ),
    )


def parse_csv_list(raw: str | None, allowed: tuple[str, ...]) -> list[str]:
    if not raw:
        return list(allowed)
    items = [item.strip() for item in raw.split(",") if item.strip()]
    invalid = sorted(set(items) - set(allowed))
    if invalid:
        raise ValueError(f"unsupported values: {', '.join(invalid)}")
    return items


def parse_rps_list(raw: str | None) -> list[int]:
    if not raw:
        return list(DEFAULT_TARGET_RPS)
    values = sorted({int(item.strip()) for item in raw.split(",") if item.strip()})
    if not values:
        raise ValueError("target RPS list must not be empty")
    return values


def run_matrix(args: argparse.Namespace) -> None:
    transport_modes = parse_csv_list(args.transport_modes, TRANSPORT_MODE_ORDER)
    scenarios = parse_csv_list(args.scenarios, SCENARIO_ORDER)
    target_rps_values = parse_rps_list(args.target_rps)

    output_root = Path(args.output_dir) if args.output_dir else DEFAULT_OUTPUT_ROOT / now_timestamp()
    output_root.mkdir(parents=True, exist_ok=True)

    wait_for_public_health()
    wait_for_backend_health()
    restart_opa()

    ensure_matrix_users()
    base_authn = capture_authn_base()
    write_json(output_root / "authn-base.json", base_authn)

    rows: list[dict[str, Any]] = []
    for transport_mode in transport_modes:
        for scenario in scenarios:
            for target_rps in target_rps_values:
                row = run_transport(
                    transport_mode=transport_mode,
                    scenario=scenario,
                    target_rps=target_rps,
                    output_dir=output_root,
                    threads=args.threads,
                    ramp_seconds=args.ramp_seconds,
                    duration_seconds=args.duration_seconds,
                    base_authn=base_authn,
                )
                rows.append(row)

    sorted_rows = sort_rows(rows)
    write_json(
        output_root / "matrix-summary.json",
        {
            "transport_modes": transport_modes,
            "scenarios": scenarios,
            "target_rps": target_rps_values,
            "rows": sorted_rows,
        },
    )
    workbook_path = output_root / "individual-svt-matrix.xlsx"
    write_workbook(workbook_path, sorted_rows)
    print(json.dumps({"output_dir": str(output_root.resolve()), "workbook": str(workbook_path.resolve())}))


def generate_scenario(args: argparse.Namespace) -> None:
    meta = generate_run_assets(args.scenario, args.transport_mode, Path(args.output_dir))
    print(json.dumps(meta, separators=(",", ":")))


def summarize_jtl(args: argparse.Namespace) -> None:
    print(json.dumps(summarize_jtl_payload(Path(args.jtl)), separators=(",", ":")))


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run-matrix")
    run_parser.add_argument("--transport-modes", help="Comma-separated subset of transport modes")
    run_parser.add_argument("--scenarios", help="Comma-separated subset of scenarios")
    run_parser.add_argument("--target-rps", help="Comma-separated target RPS values")
    run_parser.add_argument("--threads", type=int, default=30)
    run_parser.add_argument("--ramp-seconds", type=int, default=5)
    run_parser.add_argument("--duration-seconds", type=int, default=60)
    run_parser.add_argument("--output-dir")
    run_parser.set_defaults(func=run_matrix)

    generate_parser = sub.add_parser("generate-scenario")
    generate_parser.add_argument("--scenario", choices=SCENARIO_ORDER, required=True)
    generate_parser.add_argument("--transport-mode", choices=TRANSPORT_MODE_ORDER, required=True)
    generate_parser.add_argument("--output-dir", required=True)
    generate_parser.set_defaults(func=generate_scenario)

    summarize_parser = sub.add_parser("summarize-jtl")
    summarize_parser.add_argument("--jtl", required=True)
    summarize_parser.set_defaults(func=summarize_jtl)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
