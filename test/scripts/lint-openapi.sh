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

# Structural lint for api/openapi.yaml.
#
# Delegates to the same kin-openapi validator the runtime conformance
# suite uses (see test/integration/testify/spec_conformance.go +
# spec_lint_test.go). Running here makes the spec fail to merge before
# Docker Compose boots if openapi.yaml is malformed.
#
# Per api/README.md § "Lint tool", this validator is
# the chosen lint backend — no Node.js/npx toolchain dependency.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TESTIFY_DIR="${ROOT_DIR}/test/integration/testify"

if [ ! -d "${TESTIFY_DIR}" ]; then
  echo "error: testify suite directory not found at ${TESTIFY_DIR}" >&2
  exit 2
fi

echo "[lint-openapi] running kin-openapi structural validation"
cd "${TESTIFY_DIR}"
go test -run '^TestOpenAPISpecLints$' -count=1 ./...
