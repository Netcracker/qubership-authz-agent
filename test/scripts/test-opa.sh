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
OPA_BIN="${OPA_BIN:-${ROOT_DIR}/test/tools/opa/opa}"
# policies/ is the single source of truth for both Rego policies and their
# _test.rego suites. fixtures/ and test-data/ live there too.
POLICY_DIR="${POLICY_DIR:-policies}"

if [[ ! -x "${OPA_BIN}" ]]; then
  cat >&2 <<EOF
error: OPA binary not found or not executable at ${OPA_BIN}

Install local OPA binary first:
  test/scripts/install-opa.sh

Or provide a custom binary path:
  OPA_BIN=/path/to/opa test/scripts/test-opa.sh
EOF
  exit 1
fi

cd "${ROOT_DIR}"

if [[ "$#" -eq 0 ]]; then
  set -- -v --timeout 30s
fi

exec "${OPA_BIN}" test "${POLICY_DIR}" "$@"
