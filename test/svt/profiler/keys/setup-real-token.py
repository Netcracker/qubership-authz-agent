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
Generate the ephemeral RSA keypair and refresh all profiler real-token fixtures.

Run once before using any bench-real-token.sh or profile-real-token.sh script:

    python3 test/svt/profiler/keys/setup-real-token.py

What this script does
---------------------
1. Generates a fresh RSA-2048 keypair with openssl and writes it to
   test/svt/profiler/keys/profiler-rsa-private.pem  (gitignored)
   test/svt/profiler/keys/profiler-rsa-public.pem   (gitignored)

2. Extracts the public key's RSA modulus (n) and exponent (e) in base64url
   encoding and builds the JWKS JSON string used by the OPA authn data.

3. For every profiler scenario directory that contains data-real-token.json:
   updates the "jwksJson" field with the freshly generated public key.

4. For every profiler scenario directory that contains input-real-token.json:
   regenerates the signed JWT in "authorizationToken" (and "subject" when
   present) using sign-jwt.py with the new private key.

Why the key is ephemeral
------------------------
The profiler benchmarks OPA policy-evaluation performance under RSA JWT
validation.  The specific key material does not affect performance or
correctness — any valid RSA-2048 keypair produces equivalent benchmark
numbers.  Committing a private key would be a finding in any security scan of
the repository, even though the key has no production trust chain.  Generating
it at runtime avoids both the finding and any need to manage key material in
the repository.

Requirements
------------
- python3 (stdlib only)
- openssl in PATH
"""

import base64
import json
import os
import re
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROFILER_DIR = os.path.dirname(SCRIPT_DIR)

PRIVATE_KEY = os.path.join(SCRIPT_DIR, "profiler-rsa-private.pem")
PUBLIC_KEY = os.path.join(SCRIPT_DIR, "profiler-rsa-public.pem")
SIGN_JWT = os.path.join(SCRIPT_DIR, "sign-jwt.py")

KID = "svt-authorize-profiler-idp-k1"
IDP_ID = "svt-authorize-profiler-idp"

# ---------------------------------------------------------------------------
# Scenario → JWT roles mapping.
# Source: decoded from input-real-token.json JWT payloads as committed.
# ---------------------------------------------------------------------------

def _scenario_roles(scenario_name: str) -> list:
    """Return the role list for a given profiler scenario directory name."""
    m = re.match(r"ols-single-(\d+)roles", scenario_name)
    if m:
        n = int(m.group(1))
        return [f"ROLE_SVT_{i:02d}" for i in range(1, n + 1)]
    return ["ROLE_SVT_ADMIN"]


# ---------------------------------------------------------------------------
# Step 1 — Generate RSA keypair
# ---------------------------------------------------------------------------

def generate_keypair() -> None:
    print("Generating RSA-2048 keypair ...", flush=True)
    r = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA",
         "-pkeyopt", "rsa_keygen_bits:2048",
         "-out", PRIVATE_KEY],
        capture_output=True,
    )
    if r.returncode != 0:
        print(f"openssl genpkey failed: {r.stderr.decode()}", file=sys.stderr)
        sys.exit(1)

    r = subprocess.run(
        ["openssl", "rsa", "-in", PRIVATE_KEY, "-pubout", "-out", PUBLIC_KEY],
        capture_output=True,
    )
    if r.returncode != 0:
        print(f"openssl rsa -pubout failed: {r.stderr.decode()}", file=sys.stderr)
        sys.exit(1)
    print(f"  private key → {PRIVATE_KEY}", flush=True)
    print(f"  public  key → {PUBLIC_KEY}", flush=True)


# ---------------------------------------------------------------------------
# Step 2 — Extract public key components for JWKS
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def extract_public_key_components() -> tuple:
    """Return (n_b64url, e_b64url) from the generated public key."""
    r = subprocess.run(
        ["openssl", "rsa", "-pubin", "-text", "-noout", "-in", PUBLIC_KEY],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(f"openssl rsa -text failed: {r.stderr}", file=sys.stderr)
        sys.exit(1)

    lines = r.stdout.split("\n")
    hex_parts: list = []
    in_modulus = False
    exponent = 65537  # default

    for line in lines:
        stripped = line.strip()
        if re.match(r"Modulus", stripped):
            in_modulus = True
            # Some openssl versions put the value on the same line: "Modulus: 00:ab:cd…"
            m = re.match(r"Modulus:\s*([0-9a-f:]+)", stripped, re.IGNORECASE)
            if m:
                hex_parts.append(m.group(1))
            continue
        if re.match(r"(Public-Key|Exponent)", stripped, re.IGNORECASE):
            in_modulus = False
            m = re.search(r"Exponent:\s*(\d+)", stripped, re.IGNORECASE)
            if m:
                exponent = int(m.group(1))
            continue
        if in_modulus and stripped:
            hex_parts.append(stripped)

    hex_str = "".join(hex_parts).replace(":", "").lower()
    if not hex_str:
        print("ERROR: could not parse RSA modulus from openssl output.", file=sys.stderr)
        print(r.stdout, file=sys.stderr)
        sys.exit(1)

    modulus_bytes = bytes.fromhex(hex_str)
    # Strip the leading 0x00 sign byte that DER encoding adds for positive integers.
    while modulus_bytes and modulus_bytes[0] == 0:
        modulus_bytes = modulus_bytes[1:]

    exp_bytes = exponent.to_bytes((exponent.bit_length() + 7) // 8, "big")
    return _b64url(modulus_bytes), _b64url(exp_bytes)


def build_jwks_json(n: str, e: str) -> str:
    """Build the JWKS JSON string embedded in data-real-token.json files."""
    jwks = {
        "keys": [
            {
                "alg": "RS256",
                "e": e,
                "kid": KID,
                "kty": "RSA",
                "n": n,
                "use": "sig",
            }
        ]
    }
    return json.dumps(jwks, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Step 3 — Update data-real-token.json for each scenario
# ---------------------------------------------------------------------------

def update_data_file(scenario_dir: str, jwks_json_str: str) -> None:
    path = os.path.join(scenario_dir, "data-real-token.json")
    if not os.path.isfile(path):
        return

    with open(path) as f:
        data = json.load(f)

    # Navigate to the jwksJson field and update it.
    try:
        kid_entry = data["authn"]["jwksByKid"][KID][0]
        kid_entry["jwksJson"] = jwks_json_str
    except (KeyError, IndexError, TypeError) as exc:
        print(f"  WARNING: unexpected structure in {path}: {exc}", file=sys.stderr)
        return

    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print(f"  updated data-real-token.json in {os.path.basename(scenario_dir)}", flush=True)


# ---------------------------------------------------------------------------
# Step 4 — Regenerate input-real-token.json JWTs for each scenario
# ---------------------------------------------------------------------------

def _sign_jwt(roles: list) -> str:
    """Sign a JWT with the freshly generated private key."""
    r = subprocess.run(
        [sys.executable, SIGN_JWT, "--roles", ",".join(roles)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(f"sign-jwt.py failed: {r.stderr}", file=sys.stderr)
        sys.exit(1)
    return r.stdout.strip()


def update_input_file(scenario_dir: str, scenario_name: str) -> None:
    path = os.path.join(scenario_dir, "input-real-token.json")
    if not os.path.isfile(path):
        return

    with open(path) as f:
        data = json.load(f)

    roles = _scenario_roles(scenario_name)
    token = _sign_jwt(roles)
    bearer = f"Bearer {token}"

    changed = False
    if "authorizationToken" in data:
        data["authorizationToken"] = bearer
        changed = True
    if "subject" in data:
        data["subject"] = bearer
        changed = True

    if changed:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        print(
            f"  regenerated input-real-token.json in {os.path.basename(scenario_dir)}"
            f" (roles: {', '.join(roles[:3])}{'…' if len(roles) > 3 else ''})",
            flush=True,
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    generate_keypair()
    n, e = extract_public_key_components()
    print(f"  RSA modulus (n) base64url: {n[:20]}…", flush=True)
    jwks_json_str = build_jwks_json(n, e)

    print("Updating scenario fixtures …", flush=True)
    for entry in sorted(os.listdir(PROFILER_DIR)):
        scenario_dir = os.path.join(PROFILER_DIR, entry)
        if not os.path.isdir(scenario_dir) or entry == "keys":
            continue
        update_data_file(scenario_dir, jwks_json_str)
        update_input_file(scenario_dir, entry)

    print("Done.  Run any bench-real-token.sh or profile-real-token.sh scenario.", flush=True)


if __name__ == "__main__":
    main()
