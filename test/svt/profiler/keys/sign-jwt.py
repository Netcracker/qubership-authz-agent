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

"""Sign a JWT for profiler scenarios using the profiler RSA private key.

Usage:
    sign-jwt.py [--roles ROLE1,ROLE2,...] [--extra-claims '{"key":"val"}']

Shells out to openssl for RSA signing (stdlib only, no pip).
"""
import argparse
import base64
import json
import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PRIVATE_KEY = os.path.join(SCRIPT_DIR, "profiler-rsa-private.pem")

FIXED_HEADER = {"alg": "RS256", "typ": "JWT", "kid": "svt-authorize-profiler-idp-k1"}

FIXED_PAYLOAD = {
    "iss": "https://svt-authorize-profiler.example.test/realms/main",
    "sub": "svt-profiler-user",
    "iat": 1704067200,
    "nbf": 1704067200,
    "exp": 4102444800,
    "aud": ["authz-agent"],
    "scope": "openid profile email",
    "preferred_username": "svt-profiler-user",
    "email": "svt-matrix-001@example.com",
}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_rs256(signing_input: str, key_path: str) -> str:
    proc = subprocess.run(
        ["openssl", "dgst", "-binary", "-sha256", "-sign", key_path],
        input=signing_input.encode("ascii"),
        capture_output=True,
    )
    if proc.returncode != 0:
        print(f"openssl error: {proc.stderr.decode()}", file=sys.stderr)
        sys.exit(1)
    return b64url(proc.stdout)


def mint_jwt(roles: list[str], extra_claims: dict | None = None) -> str:
    payload = dict(FIXED_PAYLOAD)
    payload["realm_access"] = {"roles": roles}
    if extra_claims:
        payload.update(extra_claims)

    header_b64 = b64url(json.dumps(FIXED_HEADER, separators=(",", ":")).encode())
    payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}"
    signature = sign_rs256(signing_input, PRIVATE_KEY)
    return f"{signing_input}.{signature}"


def main():
    parser = argparse.ArgumentParser(description="Sign a profiler JWT")
    parser.add_argument("--roles", default="ROLE_SVT_ADMIN", help="Comma-separated roles")
    parser.add_argument("--extra-claims", default=None, help="JSON object of extra claims")
    args = parser.parse_args()

    roles = [r.strip() for r in args.roles.split(",") if r.strip()]
    extra = json.loads(args.extra_claims) if args.extra_claims else None
    print(mint_jwt(roles, extra))


if __name__ == "__main__":
    main()
