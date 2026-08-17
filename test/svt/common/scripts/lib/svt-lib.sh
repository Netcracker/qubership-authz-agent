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

# ─────────────────────────────────────────────────────────────────────────────
# Shared SVT library — common functions for load-test runners.
# Source this file from per-test and suite-level run scripts.
# ─────────────────────────────────────────────────────────────────────────────

# ── path resolution ─────────────────────────────────────────────────────────
# Callers must set SVT_DIR before sourcing this library.
if [[ -z "${SVT_DIR:-}" ]]; then
  echo "error: SVT_DIR must be set before sourcing svt-lib.sh" >&2
  exit 1
fi

COMMON_DIR="${SVT_DIR}/common"
COMPOSE_FILE="${COMMON_DIR}/compose/docker-compose.yml"
DATA_DIR="${COMMON_DIR}/jmeter/data"

# ── tunables (with defaults) ────────────────────────────────────────────────
PROJECT_NAME="${PROJECT_NAME:-authz-svt}"
SVT_KC_PORT="${SVT_KC_PORT:-25556}"
SVT_AUTHZ_PORT="${SVT_AUTHZ_PORT:-28080}"
SVT_AUTHZ_ADMIN_PORT="${SVT_AUTHZ_ADMIN_PORT:-29901}"
SVT_PROMETHEUS_PORT="${SVT_PROMETHEUS_PORT:-29090}"
# Host-published port of the authz-policy-admin that serves the access-control v3 config
# API.  This is the port host-side tooling seeds through; inside the compose
# network pap-client reaches the stub on its container port, so
# AUTHZ_PAP_CLIENT_SOURCE_URL is http://authz-policy-admin:18090 regardless of this value.
SVT_AUTHZ_POLICY_ADMIN_PORT="${SVT_AUTHZ_POLICY_ADMIN_PORT:-28093}"
# Simplified-policy domain the seeds are uploaded under.  The stub serves
# access-control's per-domain paths, and its v3 export is the union of all
# domains, so one domain is enough for the load stand.
SVT_AUTHZ_POLICY_ADMIN_DOMAIN="${SVT_AUTHZ_POLICY_ADMIN_DOMAIN:-SVT}"
# Pull interval of the PolicyPuller, in seconds.  Passed into the compose stack
# so the wait after every re-seed stays tied to the real cadence instead of a
# hardcoded constant that silently rots when the interval changes.
SVT_PAP_PULL_INTERVAL="${SVT_PAP_PULL_INTERVAL:-2}"
# One full pull tick plus a margin — how long to wait for re-seeded data to
# reach OPA.
SVT_PULL_WAIT_SECONDS=$((SVT_PAP_PULL_INTERVAL + 2))

export PROJECT_NAME SVT_KC_PORT SVT_AUTHZ_PORT SVT_AUTHZ_ADMIN_PORT SVT_PROMETHEUS_PORT SVT_AUTHZ_POLICY_ADMIN_PORT SVT_AUTHZ_POLICY_ADMIN_DOMAIN
export SVT_PAP_PULL_INTERVAL SVT_PULL_WAIT_SECONDS

KC_REALM="svt-test"
KC_CLIENT_ID="authz-agent"
KC_CLIENT_SECRET="authz-agent-secret"

COMPOSE_CMD=(docker compose -p "${PROJECT_NAME}" -f "${COMPOSE_FILE}")

# ── helpers ─────────────────────────────────────────────────────────────────
svt_log() { echo "[svt] $*"; }

svt_require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

svt_wait_for_public_health() {
  local attempts="${1:-90}"
  local delay_seconds="${2:-2}"
  local i
  for ((i = 1; i <= attempts; i++)); do
    if curl -sf "http://localhost:${SVT_AUTHZ_PORT}/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep "${delay_seconds}"
  done
  return 1
}

svt_wait_for_backend_health() {
  local attempts="${1:-90}"
  local delay_seconds="${2:-2}"
  local i
  for ((i = 1; i <= attempts; i++)); do
    if "${COMPOSE_CMD[@]}" exec -T opa pap-client healthcheck >/dev/null 2>&1; then
      return 0
    fi
    sleep "${delay_seconds}"
  done
  return 1
}

svt_merged_seed_policies() {
  # Print the merged simplified-policy seed. The runtime sees the
  # concatenation of three sources:
  #
  #   1. hand-authored base       : svt-policies.json
  #   2. additive mixed-flow      : svt-mixed-flow-policies.json     (optional)
  #   3. additive per-scenario    : svt-per-scenario-policies.json   (optional)
  #
  # Optional sources are skipped gracefully when the file is absent,
  # so existing test suites that pre-date a given report keep working.
  local base="${COMMON_DIR}/compose/seed/svt-policies.json"
  local mixed="${COMMON_DIR}/compose/seed/svt-mixed-flow-policies.json"
  local per_scenario="${COMMON_DIR}/compose/seed/svt-per-scenario-policies.json"
  local sources=("${base}")
  [ -f "${mixed}" ] && sources+=("${mixed}")
  [ -f "${per_scenario}" ] && sources+=("${per_scenario}")
  if [ "${#sources[@]}" -eq 1 ]; then
    cat "${base}"
  else
    jq -s 'add' "${sources[@]}"
  fi
}

svt_merged_seed_pips() {
  # Print the merged PIP seed. Same three-tier shape as policies — base
  # PIPs always uploaded; mixed-flow and per-scenario PIPs concatenated
  # when present. Result is deduplicated by PIP `name` so the merged
  # set never carries two entries for the same logical claim.
  local base="${COMMON_DIR}/compose/seed/svt-pips.json"
  local mixed="${COMMON_DIR}/compose/seed/svt-mixed-flow-pips.json"
  local per_scenario="${COMMON_DIR}/compose/seed/svt-per-scenario-pips.json"
  local sources=("${base}")
  [ -f "${mixed}" ] && sources+=("${mixed}")
  [ -f "${per_scenario}" ] && sources+=("${per_scenario}")
  if [ "${#sources[@]}" -eq 1 ]; then
    cat "${base}"
  else
    jq -s 'add | unique_by(.name)' "${sources[@]}"
  fi
}

svt_upload_seeds() {
  # PUT the merged simplified policies + PIPs to the authz-policy-admin on access-control's
  # own simplified-policy paths (the stub serves them verbatim —
  # authz-agent-ADR-0073).  pap-client's PolicyPuller fetches the v3 export on
  # the next pull tick and pushes the converted data to OPA.
  # Used both by tests/svt/scripts/up at first boot and by svt_restart_opa
  # after every OPA restart.  The re-seed after a restart is belt-and-braces:
  # the puller's applied hashes live in memory, so a restarted agent re-applies
  # the current data on its first tick regardless.
  local base code
  base="http://localhost:${SVT_AUTHZ_POLICY_ADMIN_PORT}/access/v1/simplifiedPolicies"
  code=$(svt_merged_seed_policies | curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -H "Content-Type: application/json" \
    --data-binary @- \
    "${base}/domainPolicies/${SVT_AUTHZ_POLICY_ADMIN_DOMAIN}")
  if [ "${code}" != "200" ]; then
    svt_log "ERROR: policy re-seed failed (HTTP ${code})"
    exit 1
  fi
  code=$(svt_merged_seed_pips | curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -H "Content-Type: application/json" \
    --data-binary @- \
    "${base}/domainPIPs/${SVT_AUTHZ_POLICY_ADMIN_DOMAIN}")
  if [ "${code}" != "200" ]; then
    svt_log "ERROR: PIP re-seed failed (HTTP ${code})"
    exit 1
  fi
}

svt_restart_opa() {
  svt_log "restarting 'opa' service before next measured phase..."
  "${COMPOSE_CMD[@]}" restart opa >/dev/null
  svt_log "waiting for public health after OPA restart..."
  if ! svt_wait_for_public_health 90 2; then
    svt_log "ERROR: stack did not become healthy after OPA restart"
    exit 1
  fi
  # OPA restart clears the in-memory data document; the on-disk
  # /etc/opa/data/{policies,pips}.json files still exist and the
  # PolicyPuller will repopulate OPA on the next pull tick.  We re-upload
  # seeds to the authz-policy-admin so the puller always sees current data even if
  # the stub was also restarted.  This keeps RLS conditions referencing
  # subject.emailFromToken (and the additive mixed-flow scenarios)
  # evaluating correctly after the restart.
  svt_log "re-seeding policies + PIPs after OPA restart..."
  svt_upload_seeds
  # Wait for the OPA pull loop to fetch and apply the re-seeded data:
  # one full tick plus a margin, derived from the interval the stack runs with.
  svt_log "waiting ${SVT_PULL_WAIT_SECONDS}s for OPA pull loop to apply re-seeded data..."
  sleep "${SVT_PULL_WAIT_SECONDS}"
  # Warm OPA's Rego JIT + Envoy upstream connection pool before the
  # measurement window opens. Without this, the first 200-500 ms of
  # any JMeter run land on cold caches and the p99 tail at high RPS
  # carries a one-shot compile-pause that biases the whole window
  # (visible as a `med=3 ms / p95=47 ms` blow-out in canonical
  # ols-single @ 1000 RPS). Best-effort — failures do not abort.
  if [[ -n "${TOKEN_SVT_ADMIN:-}" ]]; then
    svt_log "warming OPA Rego cache (50 admin authorize calls)..."
    local _warmup_body
    _warmup_body=$(printf '{"input":{"resources":[{"resourceType":"ORDER","operation":"READ","resource":{}}],"subject":"Bearer %s","ignoreRls":true}}' "${TOKEN_SVT_ADMIN}")
    local _i
    for _i in $(seq 1 50); do
      curl -sf -o /dev/null -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${TOKEN_SVT_ADMIN}" \
        --data-raw "${_warmup_body}" \
        "http://localhost:${SVT_AUTHZ_PORT}/access/v1/authorize" 2>/dev/null || break
    done
  fi
  svt_log "OPA restart complete"
}

svt_preflight_public() {
  svt_require_cmd docker
  svt_require_cmd curl
  svt_require_cmd jq
  if ! svt_wait_for_public_health 1 1; then
    svt_log "ERROR: backend is not healthy — run 'tests/svt/scripts/up' first"
    exit 1
  fi
}

svt_preflight_backend() {
  svt_require_cmd docker
  svt_require_cmd curl
  svt_require_cmd jq
  if ! svt_wait_for_backend_health 1 1; then
    svt_log "ERROR: backend is not healthy — run 'tests/svt/scripts/up' first"
    exit 1
  fi
}

svt_acquire_token() {
  local username=$1
  local password=$2
  local token
  token=$(curl -sf -X POST \
    "http://localhost:${SVT_KC_PORT}/realms/${KC_REALM}/protocol/openid-connect/token" \
    -d "grant_type=password" \
    -d "client_id=${KC_CLIENT_ID}" \
    -d "client_secret=${KC_CLIENT_SECRET}" \
    -d "username=${username}" \
    -d "password=${password}" \
    -d "scope=openid" | jq -r '.access_token')

  if [ -z "${token}" ] || [ "${token}" = "null" ]; then
    svt_log "ERROR: failed to acquire token for ${username}"
    exit 1
  fi
  echo "${token}"
}

# ── per-scenario bench users (28; one per bench-report scenario) ────────────
# Inventory mirrors `tests/svt/scripts/build-per-scenario-seeds.py` —
# every scenario gets a dedicated `svt-bench-<scenario>` Keycloak user.
# Tokens land in JMeter properties named `token_svt_bench_<scenario_underscored>`.
SVT_BENCH_SCENARIOS=(
  ols-single
  ols-single-10roles
  ols-single-20roles
  ols-single-30roles
  ols-single-50roles
  ols-single-100roles
  ols-bulk-50
  ols-bulk-100
  ols-bulk-1000
  rls-condition-1-expression
  rls-condition-2-expression
  rls-condition-3-expression
  rls-condition-5-expression
  rls-predicate
  rls-predicate-summary-2-predicates
  rls-predicate-summary-3-predicates
  rls-predicate-summary-4-predicates
  rls-predicate-summary-5-predicates
  rls-predicate-summary-10-predicates
  rls-predicate-pips-1-token-pip
  rls-predicate-pips-2-token-pip
  rls-predicate-pips-3-token-pip
  rls-predicate-pips-1-header-pip
  rls-predicate-pips-2-header-pip
  rls-predicate-pips-3-header-pip
  rls-predicate-summary-10-predicates-3-token-pip
  wildcard-all-single
  wildcard-mixed-bulk
)

# Convert a kebab-case scenario name to the underscored form JMeter
# properties + bash variables require. `ols-single-10roles` →
# `ols_single_10roles`.
svt_bench_scenario_underscored() { echo "$1" | tr '-' '_'; }

svt_acquire_all_tokens() {
  svt_log "acquiring user tokens from Keycloak..."
  TOKEN_SVT_ADMIN=$(svt_acquire_token svt-admin password)
  TOKEN_SVT_MANAGER=$(svt_acquire_token svt-manager password)
  TOKEN_SVT_OPERATOR=$(svt_acquire_token svt-operator password)
  TOKEN_SVT_VIEWER=$(svt_acquire_token svt-viewer password)
  TOKEN_SVT_RESTRICTED=$(svt_acquire_token svt-restricted password)
  TOKEN_SVT_MULTIROLE=$(svt_acquire_token svt-multirole password)
  TOKEN_SVT_MIXED_001=$(svt_acquire_token svt-mixed-001 password)
  TOKEN_SVT_MIXED_002=$(svt_acquire_token svt-mixed-002 password)
  TOKEN_SVT_MIXED_003=$(svt_acquire_token svt-mixed-003 password)
  TOKEN_SVT_MIXED_004=$(svt_acquire_token svt-mixed-004 password)
  TOKEN_SVT_MIXED_005=$(svt_acquire_token svt-mixed-005 password)
  TOKEN_SVT_MIXED_006=$(svt_acquire_token svt-mixed-006 password)
  TOKEN_SVT_MIXED_007=$(svt_acquire_token svt-mixed-007 password)
  TOKEN_SVT_MIXED_008=$(svt_acquire_token svt-mixed-008 password)
  # ── 28 per-scenario bench users (one per bench-report scenario) ─────
  # The token is stashed in a dynamic bash variable named
  # `TOKEN_SVT_BENCH_<SCENARIO_UPPER_UNDERSCORE>` so `svt_write_tokens_file`
  # can emit a matching `token_svt_bench_<scenario_underscored>` line
  # without enumerating the 28 names twice.
  local scenario underscored upper varname token
  for scenario in "${SVT_BENCH_SCENARIOS[@]}"; do
    underscored=$(svt_bench_scenario_underscored "${scenario}")
    upper=$(echo "${underscored}" | tr '[:lower:]' '[:upper:]')
    varname="TOKEN_SVT_BENCH_${upper}"
    token=$(svt_acquire_token "svt-bench-${scenario}" password)
    printf -v "${varname}" '%s' "${token}"
    export "${varname?}"
  done
  svt_log "all tokens acquired"
}

svt_write_tokens_file() {
  local tokens_file=$1
  cat > "${tokens_file}" <<TOKEOF
token_svt_admin=${TOKEN_SVT_ADMIN}
token_svt_manager=${TOKEN_SVT_MANAGER}
token_svt_operator=${TOKEN_SVT_OPERATOR}
token_svt_viewer=${TOKEN_SVT_VIEWER}
token_svt_restricted=${TOKEN_SVT_RESTRICTED}
token_svt_multirole=${TOKEN_SVT_MULTIROLE}
token_svt_mixed_001=${TOKEN_SVT_MIXED_001}
token_svt_mixed_002=${TOKEN_SVT_MIXED_002}
token_svt_mixed_003=${TOKEN_SVT_MIXED_003}
token_svt_mixed_004=${TOKEN_SVT_MIXED_004}
token_svt_mixed_005=${TOKEN_SVT_MIXED_005}
token_svt_mixed_006=${TOKEN_SVT_MIXED_006}
token_svt_mixed_007=${TOKEN_SVT_MIXED_007}
token_svt_mixed_008=${TOKEN_SVT_MIXED_008}
TOKEOF
  local scenario underscored upper varname
  for scenario in "${SVT_BENCH_SCENARIOS[@]}"; do
    underscored=$(svt_bench_scenario_underscored "${scenario}")
    upper=$(echo "${underscored}" | tr '[:lower:]' '[:upper:]')
    varname="TOKEN_SVT_BENCH_${upper}"
    # shellcheck disable=SC2086
    eval "echo \"token_svt_bench_${underscored}=\${${varname}}\"" >> "${tokens_file}"
  done
}

# ── JMeter runners ──────────────────────────────────────────────────────────

# Run a full (Envoy-boundary) JMeter test in a given mode.
# Usage: svt_run_jmeter_full <mode> <result_dir> <jmx_path> <target_rps> <threads> <ramp> <duration>
svt_run_jmeter_full() {
  local mode=$1
  local result_dir=$2
  local jmx_path=$3
  local target_rps=$4
  local threads=$5
  local ramp=$6
  local duration=$7
  local tokens_file=$8

  svt_log "running JMeter full '${mode}' (threads=${threads}, rps=${target_rps}, duration=${duration}s)..."
  mkdir -p "${result_dir}/temp"

  "${COMPOSE_CMD[@]}" run --rm --no-deps \
    --user "$(id -u):$(id -g)" \
    -v "${jmx_path}:/plans/test.jmx:ro" \
    -v "${DATA_DIR}:/data:ro" \
    -v "${tokens_file}:/tokens.properties:ro" \
    -v "${result_dir}:/results" \
    -e JMETER_HOME=/opt/apache-jmeter-5.5 \
    jmeter \
      -n \
      -t /plans/test.jmx \
      -q /tokens.properties \
      -Jmode="${mode}" \
      -Jthreads="${threads}" \
      -Jramp_seconds="${ramp}" \
      -Jduration_seconds="${duration}" \
      -Jauthz_host=envoy \
      -Jauthz_port=8080 \
      -Jtarget_rps="${target_rps}" \
      -j /results/jmeter.log \
      -l /results/results.jtl

  svt_log "'${mode}' run complete — generating dashboard..."
  "${COMPOSE_CMD[@]}" run --rm --no-deps \
    --user "$(id -u):$(id -g)" \
    -v "${result_dir}:/results" \
    -e JMETER_HOME=/opt/apache-jmeter-5.5 \
    jmeter \
      -g /results/results.jtl \
      -j /results/jmeter-report.log \
      -Jjmeter.reportgenerator.temp_dir=/results/temp \
      -o /results/dashboard

  svt_log "'${mode}' dashboard generated"
}

# Run an OPA-direct JMeter test.
# Usage: svt_run_jmeter_opa_direct <result_dir> <jmx_path> <target_rps> <threads> <ramp> <duration>
svt_run_jmeter_opa_direct() {
  local result_dir=$1
  local jmx_path=$2
  local target_rps=$3
  local threads=$4
  local ramp=$5
  local duration=$6
  local tokens_file=$7

  svt_log "running JMeter opa-direct (threads=${threads}, rps=${target_rps}, duration=${duration}s)..."
  mkdir -p "${result_dir}/temp"

  "${COMPOSE_CMD[@]}" run --rm --no-deps \
    --user "$(id -u):$(id -g)" \
    -v "${jmx_path}:/plans/test.jmx:ro" \
    -v "${DATA_DIR}:/data:ro" \
    -v "${tokens_file}:/tokens.properties:ro" \
    -v "${result_dir}:/results" \
    -e JMETER_HOME=/opt/apache-jmeter-5.5 \
    jmeter \
      -n \
      -t /plans/test.jmx \
      -q /tokens.properties \
      -Jthreads="${threads}" \
      -Jramp_seconds="${ramp}" \
      -Jduration_seconds="${duration}" \
      -Jopa_host=opa \
      -Jopa_port=8181 \
      -Jtarget_rps="${target_rps}" \
      -j /results/jmeter.log \
      -l /results/results.jtl

  svt_log "opa-direct run complete — generating dashboard..."
  "${COMPOSE_CMD[@]}" run --rm --no-deps \
    --user "$(id -u):$(id -g)" \
    -v "${result_dir}:/results" \
    -e JMETER_HOME=/opt/apache-jmeter-5.5 \
    jmeter \
      -g /results/results.jtl \
      -j /results/jmeter-report.log \
      -Jjmeter.reportgenerator.temp_dir=/results/temp \
      -o /results/dashboard

  svt_log "opa-direct dashboard generated"
}

# Run a generic Envoy-boundary scenario from a generated CSV.
# Usage: svt_run_jmeter_envoy_scenario <result_dir> <jmx_path> <scenario_csv> <target_rps> <threads> <ramp> <duration> <tokens_file>
svt_run_jmeter_envoy_scenario() {
  local result_dir=$1
  local jmx_path=$2
  local scenario_csv=$3
  local target_rps=$4
  local threads=$5
  local ramp=$6
  local duration=$7
  local tokens_file=$8

  svt_log "running JMeter envoy scenario (threads=${threads}, rps=${target_rps}, duration=${duration}s)..."
  mkdir -p "${result_dir}/temp"

  "${COMPOSE_CMD[@]}" run --rm --no-deps \
    --user "$(id -u):$(id -g)" \
    -v "${jmx_path}:/plans/test.jmx:ro" \
    -v "${scenario_csv}:/scenario/requests.csv:ro" \
    -v "${tokens_file}:/tokens.properties:ro" \
    -v "${result_dir}:/results" \
    -e JMETER_HOME=/opt/apache-jmeter-5.5 \
    jmeter \
      -n \
      -t /plans/test.jmx \
      -q /tokens.properties \
      -Jthreads="${threads}" \
      -Jramp_seconds="${ramp}" \
      -Jduration_seconds="${duration}" \
      -Jauthz_host=envoy \
      -Jauthz_port=8080 \
      -Jscenario_csv=/scenario/requests.csv \
      -Jtarget_rps="${target_rps}" \
      -j /results/jmeter.log \
      -l /results/results.jtl

  svt_log "envoy scenario run complete — generating dashboard..."
  "${COMPOSE_CMD[@]}" run --rm --no-deps \
    --user "$(id -u):$(id -g)" \
    -v "${result_dir}:/results" \
    -e JMETER_HOME=/opt/apache-jmeter-5.5 \
    jmeter \
      -g /results/results.jtl \
      -j /results/jmeter-report.log \
      -Jjmeter.reportgenerator.temp_dir=/results/temp \
      -o /results/dashboard

  svt_log "envoy scenario dashboard generated"
}

# Run a generic direct-OPA scenario from a generated CSV.
# Usage: svt_run_jmeter_opa_direct_scenario <result_dir> <jmx_path> <scenario_csv> <target_rps> <threads> <ramp> <duration> <tokens_file>
svt_run_jmeter_opa_direct_scenario() {
  local result_dir=$1
  local jmx_path=$2
  local scenario_csv=$3
  local target_rps=$4
  local threads=$5
  local ramp=$6
  local duration=$7
  local tokens_file=$8

  svt_log "running JMeter opa-direct scenario (threads=${threads}, rps=${target_rps}, duration=${duration}s)..."
  mkdir -p "${result_dir}/temp"

  "${COMPOSE_CMD[@]}" run --rm --no-deps \
    --user "$(id -u):$(id -g)" \
    -v "${jmx_path}:/plans/test.jmx:ro" \
    -v "${scenario_csv}:/scenario/requests.csv:ro" \
    -v "${tokens_file}:/tokens.properties:ro" \
    -v "${result_dir}:/results" \
    -e JMETER_HOME=/opt/apache-jmeter-5.5 \
    jmeter \
      -n \
      -t /plans/test.jmx \
      -q /tokens.properties \
      -Jthreads="${threads}" \
      -Jramp_seconds="${ramp}" \
      -Jduration_seconds="${duration}" \
      -Jopa_host=opa \
      -Jopa_port=8181 \
      -Jscenario_csv=/scenario/requests.csv \
      -Jtarget_rps="${target_rps}" \
      -j /results/jmeter.log \
      -l /results/results.jtl

  svt_log "opa-direct scenario run complete — generating dashboard..."
  "${COMPOSE_CMD[@]}" run --rm --no-deps \
    --user "$(id -u):$(id -g)" \
    -v "${result_dir}:/results" \
    -e JMETER_HOME=/opt/apache-jmeter-5.5 \
    jmeter \
      -g /results/results.jtl \
      -j /results/jmeter-report.log \
      -Jjmeter.reportgenerator.temp_dir=/results/temp \
      -o /results/dashboard

  svt_log "opa-direct scenario dashboard generated"
}

# ── Prometheus snapshot ─────────────────────────────────────────────────────
svt_snapshot_prometheus() {
  local prom_dir=$1
  mkdir -p "${prom_dir}"
  svt_log "snapshotting Prometheus TSDB..."
  local snap_resp
  snap_resp=$(curl -sf -X POST \
    "http://localhost:${SVT_PROMETHEUS_PORT}/api/v1/admin/tsdb/snapshot" 2>&1 || true)
  echo "${snap_resp}" > "${prom_dir}/snapshot-response.json"
  svt_log "Prometheus snapshot response saved"
}

# ── Run metadata ────────────────────────────────────────────────────────────
svt_write_run_metadata_full() {
  local meta_file=$1
  local timestamp=$2
  local threads=$3
  local ramp=$4
  local duration=$5
  local target_rps=$6
  cat > "${meta_file}" <<METAEOF
{
  "timestamp": "${timestamp}",
  "profile": "full",
  "threads": ${threads},
  "ramp_seconds": ${ramp},
  "duration_seconds": ${duration},
  "target_rps": ${target_rps},
  "host_baseline": {
    "os": "Ubuntu 24.04.4 LTS",
    "kernel": "6.18.7-76061807-generic",
    "cpu": "AMD Ryzen 9 8945HS (16 logical / 8 physical)",
    "memory_gib": 92,
    "swap_gib": 8,
    "docker_engine": "29.3.1",
    "docker_compose": "v5.1.1"
  },
  "measured_containers": ["envoy", "opa", "decision-log-collector"],
  "container_limits": {
    "opa_cpus": 8,
    "opa_mem_limit": "8g"
  }
}
METAEOF
}

# ── Mixed-flow helpers (sweep-level metrics + JMeter run) ───────────────────

# Capture an idle metrics window (no JMeter activity). Records start/end
# epoch ms to a JSON file under the artifacts directory; the report
# generator (tests/svt/scripts/mixed-load-report) queries Prometheus for
# the same window afterwards.
#
# Usage: svt_capture_idle_window <label> <artifacts_dir> <window_seconds>
svt_capture_idle_window() {
  local label=$1
  local artifacts_dir=$2
  local window_seconds=$3
  mkdir -p "${artifacts_dir}"
  local start_ms end_ms
  start_ms=$(date +%s%3N)
  svt_log "capturing idle '${label}' window: ${window_seconds}s..."
  sleep "${window_seconds}"
  end_ms=$(date +%s%3N)
  cat > "${artifacts_dir}/idle-${label}.json" <<IDLEEOF
{
  "label": "${label}",
  "window_seconds": ${window_seconds},
  "start_ms": ${start_ms},
  "end_ms": ${end_ms}
}
IDLEEOF
  svt_log "idle '${label}' window complete (${start_ms}..${end_ms})"
}

# Run a single mixed-flow JMeter iteration at the given target RPS, mode,
# and per-thread-group thread count. Mirrors svt_run_jmeter_full but uses
# the mixed-flow JMX and emits per-iteration metadata (start/end ms, JMX
# log paths) so the report generator can pull Prometheus ranges aligned
# to the load window.
#
# Usage: svt_run_jmeter_mixed_flow <mode> <result_dir> <jmx_path> \
#          <target_rps> <threads> <ramp> <duration> <tokens_file>
svt_run_jmeter_mixed_flow() {
  local mode=$1
  local result_dir=$2
  local jmx_path=$3
  local target_rps=$4
  local threads=$5
  local ramp=$6
  local duration=$7
  local tokens_file=$8

  svt_log "running mixed-flow JMeter '${mode}' (rps=${target_rps}, threads=${threads}, duration=${duration}s)..."
  mkdir -p "${result_dir}/temp"
  local start_ms end_ms
  start_ms=$(date +%s%3N)

  # Use the host-networked `jmeter-host` compose service (one bridge
  # hop removed; targets `localhost:${SVT_AUTHZ_PORT}` directly). See
  # authz-agent-ADR-0056.
  #
  # NB: the justb4/jmeter:5.5 entrypoint recomputes JVM_ARGS from the
  # container cgroup at every start (auto-sizes to ~40 % of host RAM)
  # and ignores `-e JVM_ARGS` env. To override the heap, an entrypoint
  # wrapper or a different image is required; tried `-e JVM_ARGS`
  # on 2026-05-19, confirmed not honored by the image.
  "${COMPOSE_CMD[@]}" run --rm --no-deps \
    --user "$(id -u):$(id -g)" \
    -v "${jmx_path}:/plans/test.jmx:ro" \
    -v "${tokens_file}:/tokens.properties:ro" \
    -v "${result_dir}:/results" \
    -e JMETER_HOME=/opt/apache-jmeter-5.5 \
    jmeter-host \
      -n \
      -t /plans/test.jmx \
      -q /tokens.properties \
      -Jmode="${mode}" \
      -Jthreads="${threads}" \
      -Jramp_seconds="${ramp}" \
      -Jduration_seconds="${duration}" \
      -Jauthz_host=localhost \
      -Jauthz_port="${SVT_AUTHZ_PORT}" \
      -Jtarget_rps="${target_rps}" \
      -j /results/jmeter.log \
      -l /results/results.jtl

  end_ms=$(date +%s%3N)
  cat > "${result_dir}/window.json" <<WINEOF
{
  "mode": "${mode}",
  "target_rps": ${target_rps},
  "threads": ${threads},
  "ramp_seconds": ${ramp},
  "duration_seconds": ${duration},
  "start_ms": ${start_ms},
  "end_ms": ${end_ms}
}
WINEOF
  svt_log "mixed-flow '${mode}' iteration complete (${start_ms}..${end_ms})"
}

# Run a per-scenario JMX in opa-direct mode against the bridged `jmeter`
# compose service. OPA's port 8181 is NOT exposed to the host, so the
# host-networked `jmeter-host` service used by svt_run_jmeter_mixed_flow
# cannot reach it. The per-scenario JMX template reads ${AUTHZ_HOST} /
# ${AUTHZ_PORT} for the HTTPSampler; for opa-direct we override them to
# opa:8181 here. window.json is emitted with the same shape as the
# mixed-flow helper so the driver's Prometheus range queries align to
# the load window identically across all three transport modes.
#
# Usage: svt_run_jmeter_per_scenario_opa_direct <mode> <result_dir>
#   <jmx_path> <target_rps> <threads> <ramp> <duration> <tokens_file>
svt_run_jmeter_per_scenario_opa_direct() {
  local mode=$1
  local result_dir=$2
  local jmx_path=$3
  local target_rps=$4
  local threads=$5
  local ramp=$6
  local duration=$7
  local tokens_file=$8

  svt_log "running per-scenario JMeter '${mode}' (rps=${target_rps}, threads=${threads}, duration=${duration}s)..."
  mkdir -p "${result_dir}/temp"
  local start_ms end_ms
  start_ms=$(date +%s%3N)

  "${COMPOSE_CMD[@]}" run --rm --no-deps \
    --user "$(id -u):$(id -g)" \
    -v "${jmx_path}:/plans/test.jmx:ro" \
    -v "${tokens_file}:/tokens.properties:ro" \
    -v "${result_dir}:/results" \
    -e JMETER_HOME=/opt/apache-jmeter-5.5 \
    jmeter \
      -n \
      -t /plans/test.jmx \
      -q /tokens.properties \
      -Jmode="${mode}" \
      -Jthreads="${threads}" \
      -Jramp_seconds="${ramp}" \
      -Jduration_seconds="${duration}" \
      -Jauthz_host=opa \
      -Jauthz_port=8181 \
      -Jtarget_rps="${target_rps}" \
      -j /results/jmeter.log \
      -l /results/results.jtl

  end_ms=$(date +%s%3N)
  cat > "${result_dir}/window.json" <<WINEOF
{
  "mode": "${mode}",
  "target_rps": ${target_rps},
  "threads": ${threads},
  "ramp_seconds": ${ramp},
  "duration_seconds": ${duration},
  "start_ms": ${start_ms},
  "end_ms": ${end_ms}
}
WINEOF
  svt_log "per-scenario '${mode}' iteration complete (${start_ms}..${end_ms})"
}

svt_write_run_metadata_opa_direct() {
  local meta_file=$1
  local timestamp=$2
  local threads=$3
  local ramp=$4
  local duration=$5
  local target_rps=$6

  local opa_nano_cpus=0
  local opa_memory_bytes=0
  local opa_container_id
  opa_container_id=$("${COMPOSE_CMD[@]}" ps -q opa 2>/dev/null || true)
  if [[ -n "${opa_container_id}" ]]; then
    opa_nano_cpus=$(docker inspect -f '{{.HostConfig.NanoCpus}}' "${opa_container_id}" 2>/dev/null || echo 0)
    opa_memory_bytes=$(docker inspect -f '{{.HostConfig.Memory}}' "${opa_container_id}" 2>/dev/null || echo 0)
  fi

  cat > "${meta_file}" <<METAEOF
{
  "timestamp": "${timestamp}",
  "profile": "opa-direct",
  "threads": ${threads},
  "ramp_seconds": ${ramp},
  "duration_seconds": ${duration},
  "target_rps": ${target_rps},
  "target_endpoint": {
    "host": "opa",
    "port": 8181,
    "path": "/v1/data/authorize"
  },
  "host_baseline": {
    "os": "Ubuntu 24.04.4 LTS",
    "kernel": "6.18.7-76061807-generic",
    "cpu": "AMD Ryzen 9 8945HS (16 logical / 8 physical)",
    "memory_gib": 92,
    "swap_gib": 8,
    "docker_engine": "29.3.1",
    "docker_compose": "v5.1.1"
  },
  "measured_containers": ["opa", "decision-log-collector"],
  "container_limits": {
    "opa_nano_cpus": ${opa_nano_cpus},
    "opa_memory_bytes": ${opa_memory_bytes}
  }
}
METAEOF
}
