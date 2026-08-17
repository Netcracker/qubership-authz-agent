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

"""Idempotent realm.json patcher for the per-scenario decision-time sweep.

Adds — only if missing —:

  1. Per-scenario realm roles `PS_<SCENARIO>_ROLE_NN` for every
     scenario × role-index pair declared in `build-per-scenario-seeds.py`.
  2. Protocol mappers on the `authz-agent` client for the new token
     claims used by RLS-condition / RLS-predicate scenarios
     (`region`, `country`, `division`, `field06`..`field10`).
  3. One `svt-bench-<scenario>` user per inventory entry, carrying the
     scenario-specific role set + attributes needed by its
     conditions / predicates.

Existing entries (mixed-flow users, audience mapper, ROLE_SVT_*) are
left untouched. Re-running yields a byte-for-byte identical file when
the inventory has not changed.

Run from the authz-agent repo root:

    tests/svt/scripts/build-per-scenario-realm.py

Inventory is imported from `build-per-scenario-seeds.py` — the seed
script and the realm patcher share the same scenario list so the
runtime mapping (user ↔ scenario ↔ roles ↔ policies) stays in sync.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SVT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
REALM_PATH = os.path.join(SVT_DIR, "common", "compose", "keycloak",
                          "svt-realm.json")
SEEDS_PATH = os.path.join(SCRIPT_DIR, "build-per-scenario-seeds.py")


def _load_inventory() -> tuple[list[dict], callable, callable]:
    """Import the seed-builder module by file path so this script does
    not depend on package layout. Returns (SCENARIOS, role_name,
    scenario_tag) — only the pieces this patcher needs."""
    spec = importlib.util.spec_from_file_location("seeds_mod", SEEDS_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.SCENARIOS, mod.role_name, mod.scenario_tag


def claim_mapper_block(claim: str) -> dict:
    """Standard Keycloak `oidc-usermodel-attribute-mapper` for a single
    string claim. Matches the existing `department` mapper's shape."""
    return {
        "name": claim,
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-attribute-mapper",
        "consentRequired": False,
        "config": {
            "user.attribute": claim,
            "claim.name": claim,
            "jsonType.label": "String",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
            "multivalued": "false",
        },
    }


# The 8 attribute-backed claims this patcher adds. Header-PIP scenarios
# do not need a mapper (the JMeter request sends the header directly).
EXTRA_TOKEN_CLAIMS = [
    "region", "country", "division",
    "field06", "field07", "field08", "field09", "field10",
]


def user_attributes(spec: dict) -> dict:
    """Map the scenario's conditions / predicates to the user
    attributes Keycloak should expose. The `email` claim is exposed by
    Keycloak's built-in email mapper (reads `.email` directly — no user
    attribute needed); every other token claim reads from a same-named
    user attribute via an `oidc-usermodel-attribute-mapper`. Header
    claims are supplied directly by the JMeter request body and
    therefore produce no realm-level attribute."""
    scenario = spec["scenario"]
    kind = spec["kind"]
    attrs: dict[str, list[str]] = {}

    def add_token_claim(claim: str) -> None:
        # `emailFromToken` resolves through the built-in email mapper —
        # do not duplicate as a user attribute.
        if claim == "emailFromToken":
            return
        if not claim.endswith("FromToken"):
            return
        attrs.setdefault(claim_attribute_name(claim), [
            attribute_value_for_scenario(scenario, claim)])

    if kind in ("rls_condition", "rls_predicate"):
        for _field, claim, _source in spec.get(
                "conditions", spec.get("predicates", [])):
            add_token_claim(claim)
    elif kind == "rls_predicate_summary_compound":
        for claim, _source in spec.get("pip_claims", []):
            add_token_claim(claim)
    return attrs


def claim_attribute_name(claim: str) -> str:
    """Convert a PIP claim name (e.g. `regionFromToken`) to the user
    attribute key it reads (e.g. `region`). The PIP catalogue in the
    seed builder follows the same mapping."""
    if claim.endswith("FromToken"):
        return claim[: -len("FromToken")]
    if claim.endswith("FromHeader"):
        return claim[: -len("FromHeader")]
    return claim


def attribute_value_for_scenario(scenario: str, claim: str) -> str:
    """Deterministic per-(scenario, claim) attribute value. The exact
    value does not matter for decision-time measurement — the predicate
    short-circuits to the same evaluation cost regardless — but a
    deterministic string lets the JMeter request optionally compare
    against the same value when needed."""
    short_claim = claim_attribute_name(claim)
    return f"{scenario}-{short_claim}"


def build_bench_user(spec: dict, role_name) -> dict:
    """Realm user representation for one scenario bench user."""
    scenario = spec["scenario"]
    user: dict = {
        "username": f"svt-bench-{scenario}",
        "email": f"svt-bench-{scenario}@example.com",
        "enabled": True,
        "emailVerified": True,
        "firstName": "SVT",
        "lastName": f"Bench-{scenario}",
        "credentials": [
            {"type": "password", "value": "password", "temporary": False}],
        "realmRoles": [
            role_name(scenario, i)
            for i in range(1, int(spec.get("role_count", 1)) + 1)],
    }
    attrs = user_attributes(spec)
    if attrs:
        # Insert attributes between lastName and credentials to mirror
        # the existing mixed-flow user layout.
        user_with_attrs = {}
        for k, v in user.items():
            user_with_attrs[k] = v
            if k == "lastName":
                user_with_attrs["attributes"] = attrs
        user = user_with_attrs
    return user


def patch_realm() -> tuple[int, int, int]:
    with open(REALM_PATH, encoding="utf-8") as f:
        realm = json.load(f)
    scenarios, role_name, _scenario_tag = _load_inventory()

    # 1. Realm roles ──────────────────────────────────────────────────
    existing_roles = {r["name"] for r in realm["roles"]["realm"]}
    added_roles = 0
    for spec in scenarios:
        n = int(spec.get("role_count", 1))
        for i in range(1, n + 1):
            name = role_name(spec["scenario"], i)
            if name in existing_roles:
                continue
            realm["roles"]["realm"].append({
                "name": name, "composite": False, "clientRole": False,
            })
            existing_roles.add(name)
            added_roles += 1

    # 2. Protocol mappers ─────────────────────────────────────────────
    authz_client = next(
        c for c in realm["clients"] if c.get("clientId") == "authz-agent")
    mapper_names = {m["name"] for m in authz_client.get("protocolMappers", [])}
    added_mappers = 0
    for claim in EXTRA_TOKEN_CLAIMS:
        if claim in mapper_names:
            continue
        authz_client.setdefault("protocolMappers", []).append(
            claim_mapper_block(claim))
        mapper_names.add(claim)
        added_mappers += 1

    # 3. Bench users ──────────────────────────────────────────────────
    # Drop any pre-existing `svt-bench-*` users so the rebuild is
    # canonical. Non-bench users (svt-admin, svt-mixed-NNN, …) are
    # preserved in their original positions.
    realm["users"] = [
        u for u in realm.get("users", [])
        if not u["username"].startswith("svt-bench-")
    ]
    added_users = 0
    for spec in scenarios:
        realm["users"].append(build_bench_user(spec, role_name))
        added_users += 1

    with open(REALM_PATH, "w", encoding="utf-8") as f:
        json.dump(realm, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return added_roles, added_mappers, added_users


def main() -> int:
    if not os.path.isfile(REALM_PATH):
        print(f"realm not found: {REALM_PATH}", file=sys.stderr)
        return 1
    roles, mappers, users = patch_realm()
    print(f"added: roles={roles}, mappers={mappers}, users={users}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
