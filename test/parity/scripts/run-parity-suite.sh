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

# run-parity-suite.sh — entrypoint for the parity replay suite.
#
# Brings up the authz-agent compose stack (if not already up), waits for
# all services to go healthy, then drives the Go/testify parity suite under
# test/parity/suite/ against the authz-agent profile.
#
# There is no legacy collection profile (PARITY_PROFILE=legacy).
# The goldens in test/parity/suite/testdata/golden/ are a frozen capture of the
# legacy access-control service's behaviour; they cannot be regenerated from this
# repository. See test/parity/README.md for details.
#
# Golden record mode (PARITY_GOLDEN_RECORD=1) has also been removed — the suite
# is replay-only.
#
# Teardown is intentionally NOT automatic. The developer decides whether to
# drop the stack (docker compose down -v) between runs.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
SUITE_DIR="${REPO_ROOT}/test/parity/suite"
PROFILE="${PARITY_PROFILE:-authz-agent}"
COMMON_LOG="/tmp/parity-suite.log"

log() { printf '[run-parity-suite] %s\n' "$*"; }
fail() { printf '[run-parity-suite] ERROR: %s\n' "$*" >&2; exit 1; }

if ! command -v docker >/dev/null 2>&1; then
  fail "docker CLI not found on PATH"
fi

if ! command -v go >/dev/null 2>&1; then
  fail "go toolchain not found on PATH"
fi

if [[ "${PROFILE}" != "authz-agent" ]]; then
  fail "PARITY_PROFILE=${PROFILE} is not supported. Only 'authz-agent' is available; golden collection cannot run from this repository."
fi

COMPOSE_FILE="${REPO_ROOT}/test/parity/compose/docker-compose.authz-agent.yml"
COMPOSE_ARGS=(-p parity-authz -f "${COMPOSE_FILE}")
AC_PORT="${PARITY_AUTHZ_PORT:-28100}"
IDP_PORT="${PARITY_AUTHZ_IDP_PORT:-25558}"
PIP_PORT="${PARITY_AUTHZ_PIP_PORT:-28191}"
EA_PORT="${PARITY_AUTHZ_EA_PORT:-28192}"
AUTHZ_ADMIN_PORT="${PARITY_AUTHZ_ADMIN_PORT:-28182}"
AUTHZ_ADMIN_TOKEN="${PARITY_AUTHZ_ADMIN_TOKEN:-parity-admin-token}"
PROFILE_LOG="/tmp/parity-suite-authz-agent.log"

# --- 1. Bring stack up if nothing is running under the parity compose file.
# The authz-agent profile mounts envoy.yaml/opa-config.yaml from
# test/.runtime-configs/, rendered by render-runtime-configs.sh from the
# placeholder templates under charts/authz-agent/files/. Render
# unconditionally — the script is idempotent and cheap.
log "rendering runtime configs for Compose split topology"
"${REPO_ROOT}/test/scripts/render-runtime-configs.sh"

running="$(docker compose "${COMPOSE_ARGS[@]}" ps --services --filter status=running 2>/dev/null || true)"
if [[ -z "${running}" ]]; then
  log "stack is down; starting via docker compose up -d"
  docker compose "${COMPOSE_ARGS[@]}" up -d
else
  log "stack already running; reusing existing containers"
fi

# --- 2. Wait for every service's healthcheck to go green. Generous cap —
# cold Keycloak bring-up is dominated by augmentation build (~90 s).
log "waiting for all services to reach (healthy)"
deadline=$(( $(date +%s) + 360 ))
while true; do
  if [[ $(date +%s) -ge ${deadline} ]]; then
    docker compose "${COMPOSE_ARGS[@]}" ps
    fail "services did not reach healthy within 360s"
  fi
  total=$(docker compose "${COMPOSE_ARGS[@]}" ps --format '{{.Health}}' | grep -c . || true)
  healthy=$(docker compose "${COMPOSE_ARGS[@]}" ps --format '{{.Health}}' | grep -c healthy || true)
  if [[ "${healthy}" -ge "${total}" ]]; then
    log "all services healthy"
    break
  fi
  sleep 2
done

# --- 3. Drive the Go/testify suite with the PARITY_* env block the suite reads.
log "running Go parity suite under ${SUITE_DIR} (profile=${PROFILE})"
cd "${SUITE_DIR}"

export PARITY_AC_BASE_URL="${PARITY_AC_BASE_URL:-http://localhost:${AC_PORT}}"
export PARITY_IDP_BASE_URL="${PARITY_IDP_BASE_URL:-http://localhost:${IDP_PORT}/auth/realms/parity}"
export PARITY_PIP_MOCK_CONTROL_URL="${PARITY_PIP_MOCK_CONTROL_URL:-http://localhost:${PIP_PORT}}"
export PARITY_EA_MOCK_CONTROL_URL="${PARITY_EA_MOCK_CONTROL_URL:-http://localhost:${EA_PORT}}"
export PARITY_PROFILE="${PROFILE}"
export PARITY_AUTHZ_ADMIN_BASE_URL="${PARITY_AUTHZ_ADMIN_BASE_URL:-http://localhost:${AUTHZ_ADMIN_PORT}}"
export PARITY_AUTHZ_ADMIN_TOKEN="${PARITY_AUTHZ_ADMIN_TOKEN:-${AUTHZ_ADMIN_TOKEN}}"

set +e
go test -tags integration -run '^TestParitySuite$' -count=1 -v ./... 2>&1 | tee "${COMMON_LOG}"
rc=$?
set -e

cp "${COMMON_LOG}" "${PROFILE_LOG}"

leaf_tests="$(
  awk '
    /^=== RUN   TestParitySuite\// {
      name = $0
      sub(/^=== RUN   /, "", name)
      names[++n] = name
    }
    END {
      for (i = 1; i <= n; i++) {
        leaf = 1
        prefix = names[i] "/"
        for (j = 1; j <= n; j++) {
          if (i != j && index(names[j], prefix) == 1) {
            leaf = 0
            break
          }
        }
        if (leaf) {
          print names[i]
        }
      }
    }
  ' "${COMMON_LOG}"
)"

total=$(printf '%s\n' "${leaf_tests}" | grep -c . || true)
passed="$(
  printf '%s\n' "${leaf_tests}" | while IFS= read -r test_name; do
    [ -n "${test_name}" ] || continue
    if grep -Fq -- "--- PASS: ${test_name} (" "${COMMON_LOG}"; then
      printf '%s\n' "${test_name}"
    fi
  done | wc -l | tr -d ' '
)"

if [[ ${rc} -ne 0 ]]; then
  log "parity suite FAILED — scanning ${COMMON_LOG} for golden mismatches"
  find "${SUITE_DIR}/testdata/golden" -name '*.observed.json' -printf '  %p\n' || true
  exit "${rc}"
fi

log "parity suite green"
if [[ "${passed}" -eq "${total}" ]]; then
  printf 'Parity suite passed: %s/%s cases green against authz-agent.\n' "${passed}" "${total}"
else
  printf 'Parity suite: %s/%s cases green against authz-agent (see divergence backlog).\n' "${passed}" "${total}"
fi
