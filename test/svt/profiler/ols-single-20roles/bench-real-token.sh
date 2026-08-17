#!/usr/bin/env bash

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

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${DIR}/../../../.." && pwd)"
OPA_BIN="${OPA_BIN:-${ROOT_DIR}/test/tools/opa/opa}"

if [[ ! -x "${OPA_BIN}" ]]; then
  if command -v opa >/dev/null 2>&1; then
    OPA_BIN="$(command -v opa)"
  else
    echo "error: OPA binary not found. Expected ${ROOT_DIR}/test/tools/opa/opa or opa in PATH." >&2
    echo "Install it with: ${ROOT_DIR}/test/scripts/install-opa.sh" >&2
    exit 1
  fi
fi

# Generate the profiler RSA keypair and refresh signed JWTs if not yet done.
KEYS_DIR="${ROOT_DIR}/test/svt/profiler/keys"
if [[ ! -f "${KEYS_DIR}/profiler-rsa-private.pem" ]]; then
  echo "profiler RSA key not found; running setup-real-token.py ..." >&2
  python3 "${KEYS_DIR}/setup-real-token.py"
fi

exec "${OPA_BIN}" bench --format pretty --count 5 \
  -d "${DIR}/../../../../charts/authz-agent/files/opa/policies" \
  -d "${DIR}/data.json" \
  -d "${DIR}/data-real-token.json" \
  -i "${DIR}/input-real-token.json" \
  'data.authorize.result'
