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
OPA_BIN="${OPA_BIN:-opa}"

if ! command -v "${OPA_BIN}" >/dev/null 2>&1; then
  echo "error: OPA binary not found: ${OPA_BIN}. Run mise install, or set OPA_BIN." >&2
  exit 1
fi

exec "${OPA_BIN}" eval --format pretty --profile --profile-sort location --profile-sort total_time_ns --profile-limit 1000 --explain=full \
  -d "${DIR}/../../../../policies" \
  -d "${DIR}/data.json" \
  -i "${DIR}/input.json" \
  'data.authorize.results'
