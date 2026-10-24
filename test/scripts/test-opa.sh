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

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OPA_BIN="${OPA_BIN:-opa}"
# policies/ is the single source of truth for both Rego policies and their
# _test.rego suites. fixtures/ and test-data/ live there too.
POLICY_DIR="${POLICY_DIR:-policies}"

if ! command -v "${OPA_BIN}" >/dev/null 2>&1; then
  cat >&2 <<EOF
error: OPA binary not found: ${OPA_BIN}

Run mise install to put the OPA CLI that mise.toml pins on PATH,
or set OPA_BIN to the binary:
  OPA_BIN=/path/to/opa test/scripts/test-opa.sh
EOF
  exit 1
fi

cd "${ROOT_DIR}"

if [[ "$#" -eq 0 ]]; then
  set -- -v --timeout 30s
fi

exec "${OPA_BIN}" test "${POLICY_DIR}" "$@"
