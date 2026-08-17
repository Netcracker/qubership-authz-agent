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

# Build the decision-log-collector image required by the split parity authz
# stack. This keeps docker-compose.authz-agent.yml free of build: directives.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
IMAGE_TAG="${PARITY_DECISION_LOG_COLLECTOR_IMAGE:-decision-log-collector:local}"
SOURCE_TAG="${PARITY_DECISION_LOG_COLLECTOR_SOURCE_TAG:-$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo local-worktree)}"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is not installed or not on PATH" >&2
  exit 1
fi

echo "[build-decision-log-collector] source tag: ${SOURCE_TAG}"
echo "[build-decision-log-collector] image tag:  ${IMAGE_TAG}"
echo "[build-decision-log-collector] source dir: ${REPO_ROOT}"

echo "[build-decision-log-collector] building Docker image ${IMAGE_TAG}"
docker build \
  --label "authz-agent.parity.source-tag=${SOURCE_TAG}" \
  -f "${REPO_ROOT}/build/collector/Dockerfile" \
  -t "${IMAGE_TAG}" \
  "${REPO_ROOT}"

echo "[build-decision-log-collector] done: ${IMAGE_TAG} (source ${SOURCE_TAG})"
