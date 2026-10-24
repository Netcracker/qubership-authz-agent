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
OPA_BIN="${OPA_BIN:-opa}"

if ! command -v "${OPA_BIN}" >/dev/null 2>&1; then
  echo "error: OPA binary not found: ${OPA_BIN}. Run mise install, or set OPA_BIN." >&2
  exit 1
fi

# Generate the profiler RSA keypair and refresh signed JWTs if not yet done.
KEYS_DIR="${ROOT_DIR}/test/svt/profiler/keys"
if [[ ! -f "${KEYS_DIR}/profiler-rsa-private.pem" ]]; then
  echo "profiler RSA key not found; running setup-real-token.py ..." >&2
  python3 "${KEYS_DIR}/setup-real-token.py"
fi

exec "${OPA_BIN}" eval --format pretty --profile --profile-sort total_time_ns --profile-limit 20 \
  -d "${DIR}/../../../../policies" \
  -d "${DIR}/data.json" \
  -d "${DIR}/data-real-token.json" \
  -i "${DIR}/input-real-token.json" \
  'data.authorize.results'
