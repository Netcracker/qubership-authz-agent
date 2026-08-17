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

# Build every image the runtime integration stack needs, in one call.
#
# Builds the five repo-local images (with the exact tags the Compose stack
# expects) and pulls the two base images. Safe to re-run: Docker reuses the
# layer cache. After this succeeds, `test/scripts/test-envoy-runtime.sh` can
# start the stack without rebuilding.
#
# Override the target platform or base image refs via env vars, e.g.:
#   DOCKER_PLATFORM=linux/arm64 test/scripts/build-runtime-images.sh
#   ENVOY_IMAGE=envoyproxy/envoy:v1.31-latest test/scripts/build-runtime-images.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

# The Dockerfiles rely on the BUILDPLATFORM/TARGETARCH build args, which only
# the BuildKit frontend provides — the legacy builder aborts with
# "failed to parse platform" on the very first FROM.
export DOCKER_BUILDKIT=1

DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
KEYCLOAK_IMAGE="${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.0}"
ENVOY_IMAGE="${ENVOY_IMAGE:-envoyproxy/envoy:v1.31-latest}"

log() { echo "[build-images] $*"; }

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

require_cmd docker

# --- Repo-local images (built) --------------------------------------------
# Tag                              Dockerfile                                   Context
# authz-pap-client:local           build/pap-client/Dockerfile                  . (repo root)
# decision-log-collector:local     build/collector/Dockerfile                   . (repo root)
# pip-stub:local                   test/integration/pipstub/Dockerfile          test/integration/pipstub
# upstream-capture:local           test/integration/upstream-capture/Dockerfile test/integration/upstream-capture
# authz-policy-admin:local         build/authz-policy-admin/Dockerfile          . (repo root)

log "building authz-pap-client:local (pap-client binary) for ${DOCKER_PLATFORM}"
docker build --platform "${DOCKER_PLATFORM}" -t authz-pap-client:local \
  -f build/pap-client/Dockerfile .

log "building decision-log-collector:local for ${DOCKER_PLATFORM}"
docker build --platform "${DOCKER_PLATFORM}" -t decision-log-collector:local \
  -f build/collector/Dockerfile .

log "building pip-stub:local (also reused as entitlements-mock) for ${DOCKER_PLATFORM}"
docker build --platform "${DOCKER_PLATFORM}" -t pip-stub:local \
  -f test/integration/pipstub/Dockerfile test/integration/pipstub

log "building upstream-capture:local for ${DOCKER_PLATFORM}"
docker build --platform "${DOCKER_PLATFORM}" -t upstream-capture:local \
  -f test/integration/upstream-capture/Dockerfile test/integration/upstream-capture

log "building authz-policy-admin:local (policy-pull source) for ${DOCKER_PLATFORM}"
docker build --platform "${DOCKER_PLATFORM}" -t authz-policy-admin:local \
  -f build/authz-policy-admin/Dockerfile .

# --- Base images (pulled) --------------------------------------------------
log "pulling base image ${KEYCLOAK_IMAGE} for ${DOCKER_PLATFORM}"
docker pull --platform "${DOCKER_PLATFORM}" "${KEYCLOAK_IMAGE}"

log "pulling base image ${ENVOY_IMAGE} for ${DOCKER_PLATFORM}"
docker pull --platform "${DOCKER_PLATFORM}" "${ENVOY_IMAGE}"

log "done. local images:"
docker images | grep -E 'authz-pap-client|decision-log-collector|pip-stub|upstream-capture|authz-policy-admin' || true
