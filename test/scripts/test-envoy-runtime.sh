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
DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
PROJECT_NAME="${PROJECT_NAME:-authz-agent-runtime-test}"
AUTHZ_AGENT_HTTP_PORT="${AUTHZ_AGENT_HTTP_PORT:-18080}"
AUTHZ_AGENT_ADMIN_PORT="${AUTHZ_AGENT_ADMIN_PORT:-19901}"
KC_HTTP_PORT="${KC_HTTP_PORT:-15556}"
KC_CLIENT_ID="${KC_CLIENT_ID:-authz-agent}"
KC_CLIENT_SECRET="${KC_CLIENT_SECRET:-authz-agent-secret}"
KC_EXPIRED_CLIENT_ID="${KC_EXPIRED_CLIENT_ID:-authz-agent-expired}"
KC_EXPIRED_CLIENT_SECRET="${KC_EXPIRED_CLIENT_SECRET:-authz-agent-expired-secret}"
KC_REALM="${KC_REALM:-authz-test}"
KC_USERNAME="${KC_USERNAME:-order-reader}"
KC_ADMIN_USERNAME="${KC_ADMIN_USERNAME:-admin}"
KC_PASSWORD="${KC_PASSWORD:-password}"
KC_TOKEN_SCOPE="${KC_TOKEN_SCOPE:-openid}"
KC_EXPIRED_WAIT_SECONDS="${KC_EXPIRED_WAIT_SECONDS:-6}"
PIP_STUB_PORT="${PIP_STUB_PORT:-19999}"
ENTITLEMENTS_STUB_PORT="${ENTITLEMENTS_STUB_PORT:-19998}"
AUTHZ_AGENT_PARTIAL_PERMISSIVE_PORT="${AUTHZ_AGENT_PARTIAL_PERMISSIVE_PORT:-18081}"
AUTHZ_AGENT_PARTIAL_STRICT_PORT="${AUTHZ_AGENT_PARTIAL_STRICT_PORT:-18082}"
AUTHZ_POLICY_ADMIN_PORT="${AUTHZ_POLICY_ADMIN_PORT:-18090}"
# OPA's own port, published straight to the host by the runtime compose
# (docker-compose.yml maps ${OPA_DIRECT_PORT:-18181}:8181). The suite reaches it
# directly for the Envoy-vs-OPA parity check and the ADR-0077 lockdown checks.
OPA_DIRECT_PORT="${OPA_DIRECT_PORT:-18181}"
# Match AUTHZ_PAP_CLIENT_PULL_INTERVAL in docker-compose.yml (2 s).
AUTHZ_PAP_CLIENT_PULL_INTERVAL="${AUTHZ_PAP_CLIENT_PULL_INTERVAL:-2}"
# OPA write-path auth token (ADR-0077). Must match authn/opa-auth-token in the
# runtime compose stack; override to use a different token in non-standard stacks.
OPA_AUTH_TOKEN="${OPA_AUTH_TOKEN:-test-opa-auth-token}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-${ROOT_DIR}/test/artifacts}"
export DOCKER_DEFAULT_PLATFORM="${DOCKER_DEFAULT_PLATFORM:-${DOCKER_PLATFORM}}"
# Host that the stack's published ports answer on, as seen from wherever this
# script runs. On a developer machine the daemon is local, so localhost is
# right. Under Docker-in-Docker (the CI runner) the stack lives in the daemon's
# own container and localhost points at the job container instead — the suite
# then fails at its first step with "keycloak not ready". Set
# RUNTIME_TEST_HOST=docker there. This only covers host-published ports;
# container-to-container URLs inside the Compose network are unaffected.
RUNTIME_TEST_HOST="${RUNTIME_TEST_HOST:-localhost}"
export RUNTIME_TEST_HOST
export OPA_DIRECT_PORT
export PROJECT_NAME AUTHZ_AGENT_HTTP_PORT AUTHZ_AGENT_ADMIN_PORT KC_HTTP_PORT PIP_STUB_PORT ENTITLEMENTS_STUB_PORT AUTHZ_AGENT_PARTIAL_PERMISSIVE_PORT AUTHZ_AGENT_PARTIAL_STRICT_PORT AUTHZ_POLICY_ADMIN_PORT AUTHZ_PAP_CLIENT_PULL_INTERVAL OPA_AUTH_TOKEN
export OPA_DIRECT_URL="${OPA_DIRECT_URL:-http://${RUNTIME_TEST_HOST}:${OPA_DIRECT_PORT}}"
export ENTITLEMENTS_MOCK_URL="${ENTITLEMENTS_MOCK_URL:-http://${RUNTIME_TEST_HOST}:${ENTITLEMENTS_STUB_PORT}}"
export AUTHZ_POLICY_ADMIN_URL="${AUTHZ_POLICY_ADMIN_URL:-http://${RUNTIME_TEST_HOST}:${AUTHZ_POLICY_ADMIN_PORT}}"

COMPOSE_CMD=(docker compose -p "${PROJECT_NAME}" -f "${ROOT_DIR}/test/integration/runtime/docker-compose.yml")
COMPOSE_M2M_KEYCLOAK_CMD=(docker compose -p "${PROJECT_NAME}-m2m" -f "${ROOT_DIR}/test/integration/runtime/docker-compose.yml" -f "${ROOT_DIR}/test/integration/runtime/docker-compose.m2m-keycloak.yml")
# Set RUN_M2M_KEYCLOAK_PROFILE=true to run an extra m2m-keycloak phase after
# the default static-token phase. Default: false (CI keeps test time minimal).
RUN_M2M_KEYCLOAK_PROFILE="${RUN_M2M_KEYCLOAK_PROFILE:-false}"

log() {
  echo "[runtime-test] $*"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

cleanup() {
  "${COMPOSE_CMD[@]}" down -v >/dev/null 2>&1 || true
  "${COMPOSE_M2M_KEYCLOAK_CMD[@]}" down -v >/dev/null 2>&1 || true
}

show_stack_logs() {
  "${COMPOSE_CMD[@]}" logs --no-color keycloak envoy opa-bootstrap opa pap-client decision-log-collector pip-stub entitlements-mock authz-policy-admin opa-partial-permissive-bootstrap opa-partial-permissive pap-client-partial-permissive opa-partial-strict-bootstrap opa-partial-strict pap-client-partial-strict || true
}

collect_artifacts() {
  local artifacts_dir="${ARTIFACTS_DIR}"
  mkdir -p "${artifacts_dir}"
  log "collecting runtime artifacts into ${artifacts_dir}"

  # Download OPA decision logs from the decision-log-collector via Envoy.
  local decision_log_url="http://${RUNTIME_TEST_HOST}:${AUTHZ_AGENT_HTTP_PORT}/internal/v1/decision-logs"
  local decision_log_file="${artifacts_dir}/decision-logs.jsonl"
  if curl -sf -o "${decision_log_file}" "${decision_log_url}" 2>/dev/null; then
    log "decision logs saved to ${decision_log_file} ($(wc -l < "${decision_log_file}" 2>/dev/null || echo 0) events)"
  else
    log "warning: could not download decision logs from ${decision_log_url}"
    rm -f "${decision_log_file}"
  fi

  # Save Docker Compose service logs.
  for svc in keycloak envoy opa-bootstrap opa pap-client decision-log-collector pip-stub entitlements-mock authz-policy-admin opa-partial-permissive-bootstrap opa-partial-permissive pap-client-partial-permissive opa-partial-strict-bootstrap opa-partial-strict pap-client-partial-strict; do
    local svc_log="${artifacts_dir}/${svc}.log"
    "${COMPOSE_CMD[@]}" logs --no-color "${svc}" >"${svc_log}" 2>&1 || true
    log "runtime log saved to ${svc_log}"
  done
}

require_cmd docker
require_cmd go
require_cmd curl

log "effective PROJECT_NAME=${PROJECT_NAME}"
log "effective DOCKER_DEFAULT_PLATFORM=${DOCKER_DEFAULT_PLATFORM}"
log "effective AUTHZ_AGENT_HTTP_PORT=${AUTHZ_AGENT_HTTP_PORT}"
log "effective AUTHZ_AGENT_ADMIN_PORT=${AUTHZ_AGENT_ADMIN_PORT}"
log "effective KC_HTTP_PORT=${KC_HTTP_PORT}"
log "effective PIP_STUB_PORT=${PIP_STUB_PORT}"
log "effective AUTHZ_AGENT_PARTIAL_PERMISSIVE_PORT=${AUTHZ_AGENT_PARTIAL_PERMISSIVE_PORT}"
log "effective AUTHZ_AGENT_PARTIAL_STRICT_PORT=${AUTHZ_AGENT_PARTIAL_STRICT_PORT}"

trap cleanup EXIT

cleanup

log "validating openapi.yaml (structural lint)"
"${ROOT_DIR}/test/scripts/lint-openapi.sh"

log "rendering runtime configs for Compose split topology"
"${ROOT_DIR}/test/scripts/render-runtime-configs.sh"

log "starting runtime stack (build + up)"
if ! "${COMPOSE_CMD[@]}" up -d --build keycloak pip-stub entitlements-mock opa-bootstrap opa pap-client decision-log-collector envoy pap-client-partial-permissive pap-client-partial-strict; then
  log "error: main compose up failed (port conflict or image build error)"
  "${COMPOSE_CMD[@]}" logs --no-color 2>&1 | tail -60 || true
  exit 1
fi

TESTIFY_DIR="${ROOT_DIR}/test/integration/testify"

FULL_SUITE="true"
for arg in "$@"; do
  case "$arg" in -run|-run=*) FULL_SUITE="false"; break;; esac
done

log "running Testify suite from host (module: ${TESTIFY_DIR}, full_suite=${FULL_SUITE})"
SUITE_PASS=true
if ! (cd "${TESTIFY_DIR}" && \
     BASE_URL="http://${RUNTIME_TEST_HOST}:${AUTHZ_AGENT_HTTP_PORT}" \
     KC_BASE_URL="http://${RUNTIME_TEST_HOST}:${KC_HTTP_PORT}/auth/realms/${KC_REALM}" \
     KC_CLIENT_ID="${KC_CLIENT_ID}" \
     KC_CLIENT_SECRET="${KC_CLIENT_SECRET}" \
     KC_EXPIRED_CLIENT_ID="${KC_EXPIRED_CLIENT_ID}" \
     KC_EXPIRED_CLIENT_SECRET="${KC_EXPIRED_CLIENT_SECRET}" \
     KC_USERNAME="${KC_USERNAME}" \
     KC_ADMIN_USERNAME="${KC_ADMIN_USERNAME}" \
     KC_PASSWORD="${KC_PASSWORD}" \
     KC_TOKEN_SCOPE="${KC_TOKEN_SCOPE}" \
     KC_EXPIRED_WAIT_SECONDS="${KC_EXPIRED_WAIT_SECONDS}" \
     PIP_STUB_URL="http://${RUNTIME_TEST_HOST}:${PIP_STUB_PORT}" \
     PIP_STUB_INTERNAL_URL="http://pip-stub:8090" \
     AUTHZ_POLICY_ADMIN_URL="http://${RUNTIME_TEST_HOST}:${AUTHZ_POLICY_ADMIN_PORT}" \
     AUTHZ_PAP_CLIENT_PULL_INTERVAL="${AUTHZ_PAP_CLIENT_PULL_INTERVAL}" \
     OPA_AUTH_TOKEN="${OPA_AUTH_TOKEN}" \
     FULL_RUNTIME_SUITE="${FULL_SUITE}" \
     DEGRADED_PERMISSIVE_URL="http://${RUNTIME_TEST_HOST}:${AUTHZ_AGENT_PARTIAL_PERMISSIVE_PORT}" \
     DEGRADED_STRICT_URL="http://${RUNTIME_TEST_HOST}:${AUTHZ_AGENT_PARTIAL_STRICT_PORT}" \
     go test -v -count=1 -timeout 600s -tags integration ./... "$@"); then
  SUITE_PASS=false
fi

collect_artifacts

if [ "${SUITE_PASS}" = "false" ]; then
  log "Testify suite failed; dumping runtime stack logs"
  show_stack_logs
  exit 1
fi

# ── m2m-keycloak profile (optional second phase) ─────────────────────────────
# Run only when RUN_M2M_KEYCLOAK_PROFILE=true. Uses a separate Compose project
# so the two stacks don't share containers. Activates the m2m_keycloak.* testify
# steps that are skipped in the default profile.
#
# The m2m overlay reuses the same host ports as the default stack (by design —
# both phases run sequentially, never concurrently). Tear down the main stack
# first so ports are free before the m2m stack binds them.
if [ "${RUN_M2M_KEYCLOAK_PROFILE}" = "true" ]; then
  log "stopping main stack before m2m-keycloak phase (shared host ports — sequential phases)"
  "${COMPOSE_CMD[@]}" down -v

  log "starting m2m-keycloak runtime stack (token-fetcher + Keycloak client_credentials)"
  if ! "${COMPOSE_M2M_KEYCLOAK_CMD[@]}" up -d --build keycloak pip-stub entitlements-mock token-fetcher opa-bootstrap opa pap-client decision-log-collector envoy pap-client-partial-permissive pap-client-partial-strict; then
    log "error: m2m-keycloak compose up failed (port conflict or image build error)"
    "${COMPOSE_M2M_KEYCLOAK_CMD[@]}" logs --no-color 2>&1 | tail -60 || true
    "${COMPOSE_M2M_KEYCLOAK_CMD[@]}" down -v >/dev/null 2>&1 || true
    exit 1
  fi

  log "running Testify suite with M2M_KEYCLOAK_PROFILE=true"
  M2M_PASS=true
  if ! (cd "${TESTIFY_DIR}" && \
       BASE_URL="http://${RUNTIME_TEST_HOST}:${AUTHZ_AGENT_HTTP_PORT}" \
       KC_BASE_URL="http://${RUNTIME_TEST_HOST}:${KC_HTTP_PORT}/auth/realms/${KC_REALM}" \
       KC_CLIENT_ID="${KC_CLIENT_ID}" \
       KC_CLIENT_SECRET="${KC_CLIENT_SECRET}" \
       KC_EXPIRED_CLIENT_ID="${KC_EXPIRED_CLIENT_ID}" \
       KC_EXPIRED_CLIENT_SECRET="${KC_EXPIRED_CLIENT_SECRET}" \
       KC_USERNAME="${KC_USERNAME}" \
       KC_ADMIN_USERNAME="${KC_ADMIN_USERNAME}" \
       KC_PASSWORD="${KC_PASSWORD}" \
       KC_TOKEN_SCOPE="${KC_TOKEN_SCOPE}" \
       KC_EXPIRED_WAIT_SECONDS="${KC_EXPIRED_WAIT_SECONDS}" \
       PIP_STUB_URL="http://${RUNTIME_TEST_HOST}:${PIP_STUB_PORT}" \
       PIP_STUB_INTERNAL_URL="http://pip-stub:8090" \
       AUTHZ_POLICY_ADMIN_URL="http://${RUNTIME_TEST_HOST}:${AUTHZ_POLICY_ADMIN_PORT}" \
       AUTHZ_PAP_CLIENT_PULL_INTERVAL="${AUTHZ_PAP_CLIENT_PULL_INTERVAL}" \
       OPA_AUTH_TOKEN="${OPA_AUTH_TOKEN}" \
       FULL_RUNTIME_SUITE="false" \
       M2M_KEYCLOAK_PROFILE="true" \
       DEGRADED_PERMISSIVE_URL="http://${RUNTIME_TEST_HOST}:${AUTHZ_AGENT_PARTIAL_PERMISSIVE_PORT}" \
       DEGRADED_STRICT_URL="http://${RUNTIME_TEST_HOST}:${AUTHZ_AGENT_PARTIAL_STRICT_PORT}" \
       go test -v -count=1 -timeout 600s -tags integration -run "TestRuntimeSuite/TestM2MKeycloak" ./...); then
    M2M_PASS=false
  fi

  if [ "${M2M_PASS}" = "false" ]; then
    log "m2m-keycloak suite failed; dumping m2m stack logs"
    "${COMPOSE_M2M_KEYCLOAK_CMD[@]}" logs --no-color keycloak envoy opa-bootstrap opa pap-client token-fetcher decision-log-collector pip-stub entitlements-mock opa-partial-permissive-bootstrap opa-partial-permissive pap-client-partial-permissive opa-partial-strict-bootstrap opa-partial-strict pap-client-partial-strict || true
  fi

  "${COMPOSE_M2M_KEYCLOAK_CMD[@]}" down -v >/dev/null 2>&1 || true

  if [ "${M2M_PASS}" = "false" ]; then
    exit 1
  fi
  log "m2m-keycloak profile tests passed"
fi

log "all runtime integration tests passed"
