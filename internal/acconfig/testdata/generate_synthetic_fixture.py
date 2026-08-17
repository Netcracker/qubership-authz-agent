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

"""
Generator for internal/acconfig/testdata/policy_setsV3_real_dev4.json.

This script produces the synthetic fixture that replaces the original 1.9 MB
capture from the internal cloud-platform-security-dev-4 environment.  The
original contained real policy names, component names, tenant UUIDs and role
names drawn from internal Netcracker product domains (BSS, ConversionTestCases,
ROLE_notification-svc, etc.), which must not appear in the public repository.

Shape characteristics preserved (verified by the test suite):
  - 1294 SIMPLIFIED policy sets, 0 DEFAULT
  - 2207 total rules, 0 DENY, 0 skip on ConvertPolicySets
  - Rule-count distribution per policy set matches the original (see
    DISTRIBUTION below), exercising the parser on single-rule to 58-rule sets
  - Four role-target operator patterns are present in proportion to the
    original capture:
      CONTAINS single           ~11 %  of rules
      CONTAINS ANY single       ~25 %
      CONTAINS ANY multi-value  ~52 %
      OR chain                  ~17 % (may mix CONTAINS / CONTAINS ANY)
  - The authz-agent-smoke and authz-agent-smoke2 policy sets are preserved
    verbatim: TestConvertPolicySets_RealDev4Payload looks for them by name.

Content replaced:
  - Internal product names (BSS, ConversionTestCases, ...)     → synth-Comp-*
  - Internal resource types (ConvPerf0244, ...)                → RESOURCE-NNNN
  - Internal role names (ROLE_notification-svc, BSS_ROLE_*)    → ROLE_VIEWER etc.
  - Real UUIDs and tenant IDs from the internal environment    → generated UUIDs
  - Real hash and timestamp                                    → zero hash / epoch

Usage (from repository root):
    python3 internal/acconfig/testdata/generate_synthetic_fixture.py \
        > internal/acconfig/testdata/policy_setsV3_real_dev4.json
"""

import json
import random
import sys

# Deterministic seed: the date of the original capture.
# Changing the seed changes UUIDs but not the counts or structural properties.
SEED = 20260819
rng = random.Random(SEED)


# ---------------------------------------------------------------------------
# Synthetic name pools
# ---------------------------------------------------------------------------

COMPONENTS = [
    "Comp-Alpha", "Comp-Beta", "Comp-Gamma", "Comp-Delta", "Comp-Epsilon",
    "Comp-Zeta", "Comp-Eta", "Comp-Theta", "Comp-Iota", "Comp-Kappa",
    "Comp-Lambda", "Comp-Mu", "Comp-Nu", "Comp-Xi", "Comp-Omicron",
    "Comp-Pi", "Comp-Rho", "Comp-Sigma", "Comp-Tau", "Comp-Upsilon",
]

RESOURCE_TYPES = [f"RESOURCE-{i:04d}" for i in range(1, 201)]

ROLES = [
    "ROLE_VIEWER", "ROLE_EDITOR", "ROLE_ADMIN", "ROLE_MANAGER",
    "ROLE_OPERATOR", "ROLE_AUDITOR", "ROLE_READER", "ROLE_WRITER",
    "ROLE_OWNER", "ROLE_GUEST", "ROLE_SUPER-ADMIN", "ROLE_TENANT-ADMIN",
    "ROLE_CLOUD-ADMIN", "ROLE_M2M", "ROLE_SERVICE", "ROLE_SYSTEM",
    "ROLE_DEVELOPER", "ROLE_TESTER", "ROLE_DEPLOYER", "ROLE_MONITOR",
    "ROLE_REPORTER", "ROLE_ANALYST", "ROLE_APPROVER", "ROLE_REVIEWER",
]

OPERATIONS = ["READ", "LIST", "CREATE", "UPDATE", "DELETE"]

# Fixed synthetic tenant IDs (replaces real UUIDs from the internal environment).
TENANT_IDS = [
    "aaaaaaaa-0001-4000-8000-000000000001",
    "aaaaaaaa-0002-4000-8000-000000000002",
    "aaaaaaaa-0003-4000-8000-000000000003",
    "aaaaaaaa-0004-4000-8000-000000000004",
    "aaaaaaaa-0005-4000-8000-000000000005",
    "aaaaaaaa-0006-4000-8000-000000000006",
    "aaaaaaaa-0007-4000-8000-000000000007",
    "aaaaaaaa-0008-4000-8000-000000000008",
    "aaaaaaaa-0009-4000-8000-000000000009",
    "aaaaaaaa-000a-4000-8000-00000000000a",
]


# ---------------------------------------------------------------------------
# Operator-pattern proportions from the original capture
#   CONTAINS single           251 / 2207  ~11.4 %   → weight 11
#   CONTAINS ANY single       563 / 2207  ~25.5 %   → weight 26
#   CONTAINS ANY multi-value 1137 / 2207  ~51.5 %   → weight 52
#   OR chain                  381 / 2207  ~17.3 %   → weight 17
# Bucket index cycles through 0-3 weighted by the PATTERN_WEIGHTS table.
# ---------------------------------------------------------------------------

PATTERN_WEIGHTS = [11, 26, 52, 17]   # sums to 106; proportional to original

_pattern_wheel = []
for _idx, _w in enumerate(PATTERN_WEIGHTS):
    _pattern_wheel.extend([_idx] * _w)
# pre-shuffle so we don't get 11×0 then 26×1 etc. in a long run
rng.shuffle(_pattern_wheel)
_pattern_pos = 0


def _next_pattern() -> int:
    """Return the next operator-pattern index from the pre-built wheel."""
    global _pattern_pos
    idx = _pattern_wheel[_pattern_pos % len(_pattern_wheel)]
    _pattern_pos += 1
    return idx


def _pick_roles(pool: list, n: int) -> list:
    return rng.sample(pool, min(n, len(pool)))


def _rule_target_for_pattern(pattern: int, role_pool: list) -> str:
    if pattern == 0:
        # CONTAINS single
        r = rng.choice(role_pool)
        return f"subject.roles CONTAINS '{r}'"
    elif pattern == 1:
        # CONTAINS ANY single
        r = rng.choice(role_pool)
        return f"subject.roles CONTAINS ANY '{r}'"
    elif pattern == 2:
        # CONTAINS ANY multi-value (2–4 roles)
        n = rng.randint(2, min(4, len(role_pool)))
        roles = _pick_roles(role_pool, n)
        return "subject.roles CONTAINS ANY " + ",".join(f"'{r}'" for r in roles)
    else:
        # OR chain (2–4 clauses, mixing CONTAINS / CONTAINS ANY)
        n = rng.randint(2, min(4, len(role_pool)))
        parts = []
        for r in _pick_roles(role_pool, n):
            if rng.random() < 0.5:
                parts.append(f"subject.roles CONTAINS '{r}'")
            else:
                parts.append(f"subject.roles CONTAINS ANY '{r}'")
        return " OR ".join(parts)


# ---------------------------------------------------------------------------
# UUID generation (deterministic, using the seeded rng)
# ---------------------------------------------------------------------------

def _fake_uuid() -> str:
    """Return a UUID-shaped string generated from the seeded rng."""
    n = rng.getrandbits(128)
    # Force version 4 and variant bits so the string looks like a v4 UUID.
    n &= ~(0xf000 << 48)
    n |= 0x4000 << 48
    n &= ~(0xc000 << 62)
    n |= 0x8000 << 62
    h = f"{n:032x}"
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


# ---------------------------------------------------------------------------
# Policy-set generator
# ---------------------------------------------------------------------------

def _make_rule(role_pool: list, ps_idx: int, rule_idx: int) -> dict:
    pattern = _next_pattern()
    target = _rule_target_for_pattern(pattern, role_pool)
    return {
        "ruleId": _fake_uuid(),
        "name": f"synth-rule-{ps_idx}-{rule_idx}",
        "target": target,
        "condition": "true",
        "effect": "ALLOW",
        "ruleType": "DEFAULT",
        "tenantId": rng.choice(TENANT_IDS),
    }


def _make_policy_set(ps_idx: int, n_rules: int) -> dict:
    component = COMPONENTS[ps_idx % len(COMPONENTS)]
    resource_type = RESOURCE_TYPES[ps_idx % len(RESOURCE_TYPES)]
    operation = OPERATIONS[ps_idx % len(OPERATIONS)]
    tenant_id = rng.choice(TENANT_IDS)
    role_pool = _pick_roles(ROLES, rng.randint(4, 10))

    rules = [_make_rule(role_pool, ps_idx, i) for i in range(n_rules)]

    return {
        "policySetId": _fake_uuid(),
        "name": f"synth-{component}_{resource_type}_PolicySet",
        "domain": component,
        "target": f"resourceType == '{resource_type}'",
        "component": "RUNTIME",
        "combiningAlgorithm": "DENY_UNLESS_PERMIT",
        "createdWhen": 1784295220479,
        "lastModifiedWhen": 1784295220479,
        "type": "SIMPLIFIED",
        "status": "ACTIVE",
        "tenantId": tenant_id,
        "policySets": [],
        "policies": [
            {
                "policyId": _fake_uuid(),
                "name": f"synth-{component}_{resource_type}_{operation}_Policy",
                "target": f"operation == '{operation}'",
                "combiningAlgorithm": "DENY_UNLESS_PERMIT",
                "tenantId": tenant_id,
                "rules": rules,
            }
        ],
    }


# ---------------------------------------------------------------------------
# Distribution
#
# Exactly mirrors the original capture's per-policy-set rule-count histogram
# minus the two smoke entries (which are appended verbatim below and together
# account for 3 of the 2207 rules: smoke1 has 2 rules, smoke2 has 1 rule).
#
# Each tuple is (number_of_policy_sets, rules_per_policy_set).
# ---------------------------------------------------------------------------

DISTRIBUTION = [
    (1111, 1),
    (58,   2),
    (17,   3),
    (30,   4),
    (26,   5),
    (10,   6),
    (4,    7),
    (5,    8),
    (5,    9),
    (4,   10),
    (2,   11),
    (1,   12),
    (2,   13),
    (1,   14),
    (1,   15),
    (2,   17),
    (2,   18),
    (1,   19),
    (1,   20),
    (2,   21),
    (1,   22),
    (1,   23),
    (1,   25),
    (1,   28),
    (1,   30),
    (1,   37),
    (1,   58),
]

_total_synthetic_sets  = sum(c      for c, _ in DISTRIBUTION)
_total_synthetic_rules = sum(c * n  for c, n in DISTRIBUTION)

assert _total_synthetic_sets  == 1292, (
    f"BUG: expected 1292 synthetic sets, got {_total_synthetic_sets}"
)
assert _total_synthetic_rules == 2204, (
    f"BUG: expected 2204 synthetic rules, got {_total_synthetic_rules}"
)


# ---------------------------------------------------------------------------
# The two smoke entries preserved verbatim.
#
# TestConvertPolicySets_RealDev4Payload looks for:
#   findPolicy(got, "authz-agent-smoke", "ORDER", "READ", "ROLE_CLOUD-ADMIN")
# The second entry (smoke2) is present in the fixture for completeness; the
# test does not search for it by name.
# ---------------------------------------------------------------------------

SMOKE_ENTRIES = [
    {
        "policySetId": "ff65efd2-dfe3-3df1-74f4-89db8aac1ee4",
        "name": "authz-agent-smoke_RUNTIME_ORDER_PolicySet",
        "domain": "authz-agent-smoke",
        "target": "resourceType == 'ORDER'",
        "component": "RUNTIME",
        "combiningAlgorithm": "DENY_UNLESS_PERMIT",
        "createdWhen": 1785540697605,
        "lastModifiedWhen": 1785540697605,
        "type": "SIMPLIFIED",
        "status": "ACTIVE",
        "tenantId": "44b43b97-db5b-48ab-ad58-365d37920bc0",
        "policySets": [],
        "policies": [
            {
                "policyId": "65efd2df-e33d-f174-f489-db8aac1ee415",
                "name": "authz-agent-smoke_RUNTIME_ORDER_READ_Policy",
                "target": "operation == 'READ'",
                "combiningAlgorithm": "DENY_UNLESS_PERMIT",
                "tenantId": "44b43b97-db5b-48ab-ad58-365d37920bc0",
                "rules": [
                    {
                        "ruleId": "efd2dfe3-3df1-74f4-89db-8aac1ee41538",
                        "target": "subject.roles CONTAINS ANY 'ROLE_CLOUD-ADMIN'",
                        "condition": "true",
                        "effect": "ALLOW",
                        "ruleType": "DEFAULT",
                        "tenantId": "44b43b97-db5b-48ab-ad58-365d37920bc0",
                    }
                ],
            },
            {
                "policyId": "751beb3a-92ed-e6ed-7d09-84a3b9770c14",
                "name": "authz-agent-smoke_RUNTIME_ORDER_DELETE_Policy",
                "target": "operation == 'DELETE'",
                "combiningAlgorithm": "DENY_UNLESS_PERMIT",
                "tenantId": "44b43b97-db5b-48ab-ad58-365d37920bc0",
                "rules": [
                    {
                        "ruleId": "1beb3a92-ede6-ed7d-0984-a3b9770c1452",
                        "target": "subject.roles CONTAINS ANY 'ROLE_NOBODY'",
                        "condition": "true",
                        "effect": "ALLOW",
                        "ruleType": "DEFAULT",
                        "tenantId": "44b43b97-db5b-48ab-ad58-365d37920bc0",
                    }
                ],
            },
        ],
    },
    {
        "policySetId": "0b167588-72f6-cb12-3b02-2cad14c0ae2e",
        "name": "authz-agent-smoke2_RUNTIME_INVOICE_PolicySet",
        "domain": "authz-agent-smoke2",
        "target": "resourceType == 'INVOICE'",
        "component": "RUNTIME",
        "combiningAlgorithm": "DENY_UNLESS_PERMIT",
        "createdWhen": 1785541293041,
        "lastModifiedWhen": 1785541293041,
        "type": "SIMPLIFIED",
        "status": "ACTIVE",
        "tenantId": "44b43b97-db5b-48ab-ad58-365d37920bc0",
        "policySets": [],
        "policies": [
            {
                "policyId": "16758872-f6cb-123b-022c-ad14c0ae2e14",
                "name": "authz-agent-smoke2_RUNTIME_INVOICE_READ_Policy",
                "target": "operation == 'READ'",
                "combiningAlgorithm": "DENY_UNLESS_PERMIT",
                "tenantId": "44b43b97-db5b-48ab-ad58-365d37920bc0",
                "rules": [
                    {
                        "ruleId": "758872f6-cb12-3b02-2cad-14c0ae2e14be",
                        "target": "subject.roles CONTAINS ANY 'ROLE_CLOUD-ADMIN'",
                        "condition": "true",
                        "effect": "ALLOW",
                        "ruleType": "DEFAULT",
                        "tenantId": "44b43b97-db5b-48ab-ad58-365d37920bc0",
                    }
                ],
            }
        ],
    },
]


# ---------------------------------------------------------------------------
# Generate
# ---------------------------------------------------------------------------

policy_sets = []
ps_idx = 0
for count, n_rules in DISTRIBUTION:
    for _ in range(count):
        policy_sets.append(_make_policy_set(ps_idx, n_rules))
        ps_idx += 1

policy_sets.extend(SMOKE_ENTRIES)

# Sanity-check final counts.
total_ps = len(policy_sets)
total_rules = sum(
    len(rule_list)
    for ps in policy_sets
    for p in ps["policies"]
    for rule_list in [p["rules"]]
)

assert total_ps == 1294, f"BUG: expected 1294 policy sets, got {total_ps}"
assert total_rules == 2207, f"BUG: expected 2207 rules, got {total_rules}"

print(
    f"Generated {total_ps} policy sets, {total_rules} rules.",
    file=sys.stderr,
)

output = {
    "hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "lastModificationTimestamp": "2026-08-19T00:00:00.000000",
    "policySets": policy_sets,
}

json.dump(output, sys.stdout, separators=(",", ":"))
sys.stdout.write("\n")
