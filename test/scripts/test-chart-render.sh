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

# Chart-render assertions for the trusted-provider constructor
# (authz-agent-ADR-0075).
#
# The constructor is the one piece of this feature with no unit test behind it:
# what it produces is a rendered ConfigMap, and the only way to be sure a plain
# `helm install` points the agent at the platform IdP is to render it and look.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART_DIR="${ROOT_DIR}/helm-templates/authz-agent"
STUB_CHART_DIR="${ROOT_DIR}/helm-templates/authz-policy-admin"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

require_cmd helm
require_cmd jq

failures=0

fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

pass() {
  echo "ok: $*"
}

# Renders the chart and extracts the trusted-providers document as JSON.
providers_json() {
  helm template t "${CHART_DIR}" "$@" \
    | yq_providers
}

# The rendered ConfigMap embeds the document as a literal block. Pull it out
# without a YAML dependency: the block is the only thing between the
# `trusted-providers.json: |-` marker and the next unindented key.
yq_providers() {
  awk '
    /^  trusted-providers\.json: \|-$/ {capture=1; next}
    capture && /^    / {sub(/^    /, ""); print; next}
    capture {capture=0}
  '
}

# The documents the checks below read, each rendered on its own with
# --show-only, so that a check reads the agent's Deployment and no other. A
# render that fails returns Helm's error as the document, so the check reports
# it instead of ending the script.
hpa_of() { helm template t "${CHART_DIR}" "$@" --show-only templates/horizontalpodautoscaler.yaml 2>&1 || true; }
deployment_of() { helm template t "${CHART_DIR}" "$@" --show-only templates/deployment.yaml 2>&1 || true; }
field() {
  local document="$1"
  local key="$2"
  awk -v key="${key}" '$1 == key {print $2; exit}' <<<"${document}"
}
# Compares one block of the agent's Deployment, cut out by the named function,
# with a literal, and reports the diff.
expect_block() {
  local block_of="$1"
  local label="$2"
  local expected="$3"
  shift 3
  local got
  got="$("${block_of}" "$@")"
  if [[ "${got}" == "${expected}" ]]; then
    pass "${label}"
  elif [[ -z "${got}" ]]; then
    fail "${label}: no such block in the render: $(head -3 <<<"$(deployment_of "$@")")"
  else
    fail "${label}: $(diff <(echo "${expected}") <(echo "${got}") || true)"
  fi
}

# A plain install: one replica; the autoscaler disabled, with no policy and the
# target 75% of the 400m limit over the 350m request; the chart's part-of label
# and no session label.
plain_hpa="$(hpa_of)"
plain_summary="replicas=$(field "$(deployment_of)" replicas:) min=$(field "${plain_hpa}" minReplicas:) max=$(field "${plain_hpa}" maxReplicas:) target=$(field "${plain_hpa}" averageUtilization:) disabled=$(grep -c 'selectPolicy: Disabled' <<<"${plain_hpa}" || true) policies=$(grep -c 'type: P' <<<"${plain_hpa}" || true)"
if [[ "${plain_summary}" == "replicas=1 min=1 max=9999 target=85 disabled=2 policies=0" ]]; then
  pass "a plain install renders one replica and a disabled autoscaler (${plain_summary})"
else
  fail "a plain install renders ${plain_summary}, expected replicas=1 min=1 max=9999 target=85 disabled=2 policies=0"
fi
if [[ "${plain_hpa}" == *"app.kubernetes.io/part-of: 'Platform-Core-Security'"* && "${plain_hpa}" != *"sessionId"* ]]; then
  pass "the autoscaler carries the chart's part-of label and no session label by default"
else
  fail "the autoscaler's default labels are off: $(grep -E 'part-of|sessionId' <<<"${plain_hpa}" | tr -d ' ' | paste -sd, - || true)"
fi

labelled="$(hpa_of --set APPLICATION_NAME=billing --set DEPLOYMENT_SESSION_ID=s-42)"
if [[ "${labelled}" == *"app.kubernetes.io/part-of: 'billing'"* && "${labelled}" == *"deployment.netcracker.com/sessionId: 's-42'"* ]]; then
  pass "the autoscaler takes part-of from APPLICATION_NAME and the session label from DEPLOYMENT_SESSION_ID"
else
  fail "the autoscaler's labels do not follow APPLICATION_NAME and DEPLOYMENT_SESSION_ID: $(grep -E 'part-of|sessionId' <<<"${labelled}" | tr -d ' ' | paste -sd, - || true)"
fi

# minReplicas falls back to REPLICAS where nothing sets HPA_MIN_REPLICAS.
fallback="$(hpa_of --set HPA_ENABLED=true --set HPA_MAX_REPLICAS=5 --set REPLICAS=3)"
if [[ "$(field "${fallback}" minReplicas:)" == "3" ]]; then
  pass "an enabled autoscaler without HPA_MIN_REPLICAS takes its floor from REPLICAS"
else
  fail "expected minReplicas 3 from REPLICAS, got '$(field "${fallback}" minReplicas:)'"
fi

# Every profile validates against the schema and renders. The profile is
# applied over a memory limit no profile carries, so that a misspelled key,
# which the schema would admit, leaves that limit in the render in place of
# the profile's; the dev sizing mirrors values.yaml and could not be told from
# the default otherwise. REPLICAS reaches the Deployment. The autoscaler is the
# profile's: the bounds; the target, HPA_AVG_CPU_UTILIZATION_TARGET_PERCENT of
# CPU_LIMIT over CPU_REQUEST, so 75 renders as 85 for 400m over 350m and as
# 150 for 15 cores over 7500m, which also covers both spellings to_millicores
# accepts; and the behavior block, which carries the windows and policies of
# dbaas-operator's profiles, Disabled in both directions where the profile
# keeps the autoscaler off.
behavior_on='  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      selectPolicy: Max
      policies:
        - type: Pods
          value: 1
          periodSeconds: 60
    scaleDown:
      stabilizationWindowSeconds: 300
      selectPolicy: Max
      policies:
        - type: Pods
          value: 1
          periodSeconds: 60'
behavior_off="${behavior_on//selectPolicy: Max/selectPolicy: Disabled}"
sentinel="$(mktemp)"
trap 'rm -f "${sentinel}"' EXIT
printf 'MEMORY_LIMIT: 1Mi\n' >"${sentinel}"
for row in "dev:700Mi:1:1:9999:85:off" "dev-ha:700Mi:2:2:5:85:on" "prod:13Gi:2:2:5:150:on" "prod-nonha:13Gi:1:1:5:150:on"; do
  IFS=: read -r profile mem_limit replicas floor ceiling target mode <<<"${row}"
  profile_values=(-f "${sentinel}" -f "${CHART_DIR}/resource-profiles/${profile}.yaml")
  if ! rendered="$(helm template t "${CHART_DIR}" "${profile_values[@]}" 2>&1)"; then
    fail "the ${profile} profile does not render: ${rendered}"
    continue
  fi
  if [[ "${rendered}" == *"memory: '${mem_limit}'"* ]]; then
    pass "the ${profile} profile sizes the agent container (memory limit ${mem_limit})"
  else
    fail "the ${profile} profile does not set the memory limit ${mem_limit}; the render has: $(grep -E '^ +memory: ' <<<"${rendered}" | tr -d ' ' | paste -sd, - || true)"
  fi
  hpa="$(hpa_of "${profile_values[@]}")"
  summary="replicas=$(field "$(deployment_of "${profile_values[@]}")" replicas:) min=$(field "${hpa}" minReplicas:) max=$(field "${hpa}" maxReplicas:) target=$(field "${hpa}" averageUtilization:)"
  if [[ "${summary}" == "replicas=${replicas} min=${floor} max=${ceiling} target=${target}" ]]; then
    pass "the ${profile} profile renders ${summary}"
  else
    fail "the ${profile} profile renders ${summary}, expected replicas=${replicas} min=${floor} max=${ceiling} target=${target}"
  fi
  if [[ "${mode}" == "on" ]]; then
    expected_behavior="${behavior_on}"
  else
    expected_behavior="${behavior_off}"
  fi
  got_behavior="$(sed -n '/^  behavior:/,$p' <<<"${hpa}")"
  if [[ "${got_behavior}" == "${expected_behavior}" ]]; then
    pass "the ${profile} profile renders the scaling behavior with the autoscaler ${mode}"
  else
    fail "the ${profile} profile renders another scaling behavior: $(diff <(echo "${expected_behavior}") <(echo "${got_behavior}") || true)"
  fi
done

# ── Deployment strategy ──────────────────────────────────────────────────
#
# DEPLOYMENT_STRATEGY_TYPE selects one of the platform's four strategies, and
# unset renders the Kubernetes default of 25% surge and 25% unavailable. The
# whole block is compared, so a rollingUpdate left under Recreate would show.
strategy_of() { deployment_of "$@" | sed -n '/^  strategy:/,/^  selector:/p' | sed '$d'; }

# Renders a chart and returns the value of one environment variable, "" when
# the chart renders none. The empty string is what the absent case has to
# produce: an unguarded grep ends the whole run under `set -e`, and a suite
# that stops says less than one that names the check that failed.
env_value_of() {
  local chart="$1" name="$2"
  shift 2
  helm template t "${chart}" "$@" 2>&1 \
    | grep -A1 "name: ${name}$" \
    | awk -F"'" '/value:/ && !seen {print $2; seen=1}' || true
}

env_value() {
  local name="$1"
  shift
  env_value_of "${CHART_DIR}" "${name}" "$@"
}

# ── Default install: the platform convention, not an empty list ──────────

default_providers="$(providers_json)"

if [[ "$(jq -r '.providers | length' <<<"${default_providers}")" == "4" ]]; then
  pass "a default install generates one provider per platform realm"
else
  fail "expected 4 generated providers, got: ${default_providers}"
fi

if [[ "$(jq -r '.providers[0].issuer' <<<"${default_providers}")" == "http://identity-provider:8080/auth/realms/cloud-common" ]]; then
  pass "the issuer is composed as <IDENTITY_PROVIDER_URL>/auth/realms/<realm>"
else
  fail "unexpected composed issuer: $(jq -c '.providers[0]' <<<"${default_providers}")"
fi

if [[ "$(jq -r '[.providers[] | select(.required == true) | .id] | join(",")' <<<"${default_providers}")" == "cloud-common" ]]; then
  pass "cloud-common alone is required; the other realms may be absent"
else
  fail "expected only cloud-common to be required: ${default_providers}"
fi

# A generated entry that carried audiences would reject every token minted for
# a different client, which is not what "trust this realm" is meant to mean.
if [[ "$(jq -r '[.providers[] | select(has("audiences"))] | length' <<<"${default_providers}")" == "0" ]]; then
  pass "generated entries carry no audiences, so aud is not checked for them"
else
  fail "generated entries must not set audiences: ${default_providers}"
fi

# No entry may carry the removed field — pap-client rejects the file outright.
if [[ "$(jq -r '[.providers[] | select(has("algorithms"))] | length' <<<"${default_providers}")" == "0" ]]; then
  pass "no generated entry carries the removed 'algorithms' field"
else
  fail "'algorithms' was removed from the schema: ${default_providers}"
fi

if [[ "$(env_value AUTHZ_JWKS_BOOTSTRAP_REQUIRED)" == "false" ]]; then
  pass "a generated list forces the permissive bootstrap threshold"
else
  fail "expected AUTHZ_JWKS_BOOTSTRAP_REQUIRED=false for a generated list"
fi

# ── Overridden realm list and base URL ───────────────────────────────────

overridden="$(providers_json \
  --set-json 'AUTHZ_IDP_REALMS=["cloud-common","tenant-a"]' \
  --set IDENTITY_PROVIDER_URL=https://identity-provider:8443)"

expected='https://identity-provider:8443/auth/realms/tenant-a'
if [[ "$(jq -r '.providers[1].issuer' <<<"${overridden}")" == "${expected}" ]]; then
  pass "the realm list and base URL are both overridable"
else
  fail "expected ${expected}, got: ${overridden}"
fi

# A trailing slash on the base URL must not produce a doubled separator.
slashed="$(providers_json \
  --set-json 'AUTHZ_IDP_REALMS=["cloud-common"]' \
  --set IDENTITY_PROVIDER_URL=http://identity-provider:8080/)"

if [[ "$(jq -r '.providers[0].issuer' <<<"${slashed}")" == "http://identity-provider:8080/auth/realms/cloud-common" ]]; then
  pass "a trailing slash on IDENTITY_PROVIDER_URL is absorbed"
else
  fail "trailing slash leaked into the issuer: ${slashed}"
fi

# ── An explicit list wins outright ───────────────────────────────────────

explicit="$(providers_json \
  --set-json 'AUTHZ_TRUSTED_PROVIDERS=[{"id":"kc","jwksUri":"http://kc:8080/certs","audiences":["app"],"required":true}]')"

if [[ "$(jq -r '.providers | length' <<<"${explicit}")" == "1" && "$(jq -r '.providers[0].jwksUri' <<<"${explicit}")" == "http://kc:8080/certs" ]]; then
  pass "an explicit AUTHZ_TRUSTED_PROVIDERS replaces the generated list"
else
  fail "explicit providers were not used verbatim: ${explicit}"
fi

# Probed with `false` rather than the default `true`: values.yaml already
# defaults this to true, so asserting `true` would also pass if the helper
# hard-coded it and proved nothing.
if [[ "$(env_value AUTHZ_JWKS_BOOTSTRAP_REQUIRED \
  --set-json 'AUTHZ_TRUSTED_PROVIDERS=[{"id":"kc","jwksUri":"http://kc:8080/certs"}]' \
  --set AUTHZ_JWKS_BOOTSTRAP_REQUIRED=false)" == "false" ]]; then
  pass "an explicit list keeps the operator's bootstrap threshold"
else
  fail "expected the configured AUTHZ_JWKS_BOOTSTRAP_REQUIRED to survive"
fi

# ── Realm resolution is wired and disable-able ───────────────────────────

if [[ "$(env_value AUTHZ_TENANT_MANAGER_URL)" == "http://tenant-manager:8080" ]]; then
  pass "the agent is pointed at tenant-manager for realm display-name resolution"
else
  fail "expected AUTHZ_TENANT_MANAGER_URL to default to the in-namespace tenant-manager"
fi

# A namespace without tenant-manager must be able to turn resolution off, and an
# empty value is how pap-client is told to skip it entirely.
if [[ -z "$(env_value AUTHZ_TENANT_MANAGER_URL --set AUTHZ_TENANT_MANAGER_URL=)" ]]; then
  pass "realm resolution can be disabled by emptying AUTHZ_TENANT_MANAGER_URL"
else
  fail "expected an empty AUTHZ_TENANT_MANAGER_URL to render empty"
fi

# ── Emptying the realm list means no providers, and says so ──────────────

emptied="$(providers_json --set-json 'AUTHZ_IDP_REALMS=[]')"

if [[ "$(jq -r '.providers | length' <<<"${emptied}")" == "0" ]]; then
  pass "an empty AUTHZ_IDP_REALMS generates no providers (documented in values.yaml)"
else
  fail "expected no providers for an empty realm list: ${emptied}"
fi

# ── The schema rejects a half-filled entry ───────────────────────────────

if helm template t "${CHART_DIR}" \
  --set-json 'AUTHZ_TRUSTED_PROVIDERS=[{"id":"kc","issuer":"http://kc:8080/realms/x","jwksUri":"http://kc:8080/certs"}]' \
  >/dev/null 2>&1; then
  fail "an entry setting both issuer and jwksUri must be rejected by the schema"
else
  pass "an entry setting both issuer and jwksUri is rejected at render time"
fi

if helm template t "${CHART_DIR}" \
  --set-json 'AUTHZ_TRUSTED_PROVIDERS=[{"id":"kc","issuer":"http://kc:8080/realms/x","algorithms":["RS256"]}]' \
  >/dev/null 2>&1; then
  fail "an entry carrying the removed 'algorithms' field must be rejected"
else
  pass "an entry carrying the removed 'algorithms' field is rejected at render time"
fi

# A realm name becomes a provider id, so it inherits the id character set; and
# two identical realms would collapse into one slot of the published byId map.
if helm template t "${CHART_DIR}" --set-json 'AUTHZ_IDP_REALMS=["has space"]' >/dev/null 2>&1; then
  fail "a realm name outside the provider-id character set must be rejected"
else
  pass "a realm name outside the provider-id character set is rejected"
fi

if helm template t "${CHART_DIR}" --set-json 'AUTHZ_IDP_REALMS=["cpq","cpq"]' >/dev/null 2>&1; then
  fail "a duplicated realm must be rejected — it would collapse in the byId index"
else
  pass "a duplicated realm is rejected"
fi

# ── The agent Pod (authz-agent-ADR-0080) ─────────────────────────────────
#
# What the Pod template has to get right is structural and invisible to a unit
# test: how many containers it holds, which settings reach the process, and
# which objects it mounts to read them from.

all_manifests="$(helm template t "${CHART_DIR}")"

# The agent's own container, matched by name. The five names of the Pod it
# replaced stay in the pattern, so a return of any of them is counted.
agent_containers() {
  local rendered=$1
  echo "${rendered}" | grep -cE "^        - name: '?(authz-agent|envoy|opa|pap-client|collector|token-fetcher)'?$" || true
}

containers=$(agent_containers "${all_manifests}")
if [[ "${containers}" -eq 1 ]]; then
  pass "the agent Pod holds one container"
else
  fail "the agent Pod holds ${containers} containers, expected 1"
fi

# The renders are searched with a shell pattern rather than `grep -q`: this
# script runs under `set -o pipefail`, and a quiet grep exits at its first
# match, which leaves the writing side of the pipe with SIGPIPE and turns a
# found string into a failed pipeline.
# The image is IMAGE_REPOSITORY:TAG on both charts, as on the platform's, each
# defaulting to the repository the release publishes (TAG has no default, so
# the default render ends in a bare colon), and the override keys the charts
# had are refused.
for row in "${CHART_DIR}:ghcr.io/netcracker/qubership-authz-agent" "${STUB_CHART_DIR}:ghcr.io/netcracker/qubership-authz-policy-admin"; do
  chart="${row%%:*}"
  repository="${row#*:}"
  name="$(basename "${chart}")"
  default_image="$(field "$(helm template t "${chart}" --show-only templates/deployment.yaml 2>&1 || true)" image:)"
  if [[ "${default_image}" == "'${repository}:'" ]]; then
    pass "${name}: the image repository defaults to ${repository}"
  else
    fail "${name}: expected the default image '${repository}:', got ${default_image}"
  fi
  got_image="$(field "$(helm template t "${chart}" --set IMAGE_REPOSITORY=reg/img --set TAG=1.2.3 --show-only templates/deployment.yaml 2>&1 || true)" image:)"
  if [[ "${got_image}" == "'reg/img:1.2.3'" ]]; then
    pass "${name}: the image is IMAGE_REPOSITORY:TAG"
  else
    fail "${name}: expected image 'reg/img:1.2.3', got ${got_image}"
  fi
done
old_image="$(helm template t "${CHART_DIR}" --set AUTHZ_AGENT_IMAGE=x 2>&1 || true)"
if [[ "${old_image}" == *"no longer reads these values: AUTHZ_AGENT_IMAGE"* ]]; then
  pass "the agent chart refuses AUTHZ_AGENT_IMAGE by name"
else
  fail "the agent chart must refuse AUTHZ_AGENT_IMAGE by name, got: $(head -3 <<<"${old_image}")"
fi

# The M2M identity, which a platform install takes through a projected
# service-account token, and the mount mode that replaces the pull loop.
# Neither is rendered by the default above.
k8s_m2m="$(helm template t "${CHART_DIR}" --set KUBERNETES_M2M_ENABLED=true)"
if [[ "${k8s_m2m}" == *"serviceAccountToken"* && "${k8s_m2m}" != *"client-credentials"* ]]; then
  pass "the agent Pod takes the projected token under KUBERNETES_M2M_ENABLED"
else
  fail "the agent Pod does not take the projected token under KUBERNETES_M2M_ENABLED"
fi
if [[ "${k8s_m2m}" != *"AUTHZ_M2M_TOKEN_URL"* ]]; then
  pass "the agent Pod asks no identity provider for a token under KUBERNETES_M2M_ENABLED"
else
  fail "the agent Pod still sets AUTHZ_M2M_TOKEN_URL under KUBERNETES_M2M_ENABLED"
fi
# The token lands where the platform's charts put the netcracker-audience
# token, and the service is pointed at that file.
token_summary="path=$(field "${k8s_m2m}" path:) audience=$(field "${k8s_m2m}" audience:) mount=$(field "$(grep -A1 'name: projected-tokens' <<<"${k8s_m2m}" | tail -1)" mountPath:) file=$(env_value AUTHZ_PAP_CLIENT_TOKEN_FILE --set KUBERNETES_M2M_ENABLED=true)"
if [[ "${token_summary}" == "path=netcracker/token audience=netcracker mount=/var/run/secrets/tokens file=/var/run/secrets/tokens/netcracker/token" ]]; then
  pass "the projected token is mounted at the platform's path and the agent reads it from there"
else
  fail "the projected token renders ${token_summary}, expected path=netcracker/token audience=netcracker mount=/var/run/secrets/tokens file=/var/run/secrets/tokens/netcracker/token"
fi
if [[ "${all_manifests}" == *"client-credentials"* && "${all_manifests}" != *"serviceAccountToken"* ]]; then
  pass "the agent Pod takes the client-credentials Secret without KUBERNETES_M2M_ENABLED"
else
  fail "the agent Pod does not take the client-credentials Secret without KUBERNETES_M2M_ENABLED"
fi

mount_mode="$(helm template t "${CHART_DIR}" --set AUTHZ_POLICY_CONFIGMAP=my-policies)"
if [[ "${mount_mode}" == *"AUTHZ_POLICY_MOUNT_DIR"* && "${mount_mode}" == *"my-policies"* ]]; then
  pass "the agent Pod mounts AUTHZ_POLICY_CONFIGMAP and points the service at it"
else
  fail "the agent Pod does not mount AUTHZ_POLICY_CONFIGMAP"
fi

# Every setting the service reads has to reach it, and the objects it reads
# them from have to be mounted.
for env_name in AUTHZ_PUBLIC_ADDR AUTHZ_HTTP_ADDR AUTHZ_DATA_API_AUTHORIZATION AUTHZ_OPA_AUTH_TOKEN_FILE \
  AUTHZ_TRUSTED_PROVIDERS_FILE AUTHZ_JWKS_BOOTSTRAP_REQUIRED AUTHZ_PAP_CLIENT_SOURCE_URL \
  AUTHZ_PAP_CLIENT_PULL_INTERVAL AUTHZ_ENTITLEMENTS_URL AUTHZ_DECISION_LOG_FILE AUTHZ_DECISION_LOG_HEADERS; do
  if [[ "${all_manifests}" == *"name: ${env_name}"* ]]; then
    pass "the agent Pod sets ${env_name}"
  else
    fail "the agent Pod does not set ${env_name}"
  fi
done

for volume in "authz-agent-trusted-providers" "authz-agent-opa-auth" "authz-agent-client-credentials"; do
  if [[ "${all_manifests}" == *"${volume}"* ]]; then
    pass "the agent Pod mounts ${volume}"
  else
    fail "the agent Pod does not mount ${volume}"
  fi
done

# /health answers once the trusted providers are in order and /ready once the
# policies have loaded too, so a Pod waiting for its policy source is held out
# of the Service instead of being restarted.
if [[ "${all_manifests}" == *"path: /ready"* && "${all_manifests}" == *"path: /health"* ]]; then
  pass "the agent Pod probes /ready for readiness and /health for liveness"
else
  fail "the agent Pod does not separate the readiness and liveness probes"
fi

# The drain has to fit inside the grace period: five seconds for each of the
# two surfaces, then the decision-log drain, which on the path this chart
# renders is bounded by the writes to the volume. The template says why the
# default of thirty is not enough.
if [[ "${all_manifests}" == *"terminationGracePeriodSeconds: 45"* ]]; then
  pass "the agent Pod keeps a grace period longer than its drain"
else
  fail "the agent Pod leaves the grace period at the default"
fi

# The decision log is the only thing the container writes, and nothing rotates
# it, so the storage limit and the volume's own cap are what stand between a
# long-running Pod and a full node.
if [[ "${all_manifests}" == *"ephemeral-storage:"* && "${all_manifests}" == *"sizeLimit:"* ]]; then
  pass "the agent Pod declares its ephemeral storage and caps the decision-log volume"
else
  fail "the agent Pod leaves its ephemeral storage or the decision-log volume uncapped"
fi

# subPath breaks ConfigMap and Secret propagation: the kubelet swaps the
# `..data` symlink of a directory mount and never rewrites a subPath'd file,
# so a reload-without-restart stops working the moment one appears.
sp_count=$(echo "${all_manifests}" | grep -cE "^ +subPath:" || true)
if [[ "${sp_count}" -eq 0 ]]; then
  pass "no subPath mounts in the render"
else
  fail "unexpected subPath mounts in the render: found ${sp_count}, expected none"
fi

for absent in "authz-agent-runtime" "authz-agent-policies" "openpolicyagent/opa" "authz-agent-envoy" "authz-agent-pap-client" "authz-agent-collector" "authz-agent-token-fetcher" "authz-policy-admin"; do
  if [[ "${all_manifests}" == *"${absent}"* ]]; then
    fail "the render still carries ${absent}"
  else
    pass "the render has no ${absent}"
  fi
done

# ── Sizing and the resource profiles ─────────────────────────────────────
#
# The agent container is sized by the platform's own keys, so a resource
# profile written for any other platform service fits this chart, and the
# autoscaler comes from the profile alone.

# Probed with values no profile carries: a render that ignored a key and kept
# the default would not pass.
sized="$(helm template t "${CHART_DIR}" \
  --set CPU_REQUEST=123m --set CPU_LIMIT=456m \
  --set MEMORY_REQUEST=111Mi --set MEMORY_LIMIT=999Mi)"
for pair in "CPU_REQUEST:cpu: '123m'" "CPU_LIMIT:cpu: '456m'" "MEMORY_REQUEST:memory: '111Mi'" "MEMORY_LIMIT:memory: '999Mi'"; do
  key="${pair%%:*}"
  line="${pair#*:}"
  if [[ "${sized}" == *"${line}"* ]]; then
    pass "${key} reaches the agent container"
  else
    fail "${key} does not reach the agent container: no \"${line}\" in the render"
  fi
done

# The old names are refused rather than ignored: the schema admits unknown
# keys, so an install still carrying them would otherwise take the chart's
# defaults without a word. The guard's own text is matched, so a render that
# fails for another reason does not pass as the refusal.
old_name="$(helm template t "${CHART_DIR}" --set AUTHZ_AGENT_MEM_LIMIT=8Gi 2>&1 || true)"
if [[ "${old_name}" == *"no longer reads these values: AUTHZ_AGENT_MEM_LIMIT"* ]]; then
  pass "a values file still carrying AUTHZ_AGENT_MEM_LIMIT is refused at render time"
else
  fail "a values file still carrying AUTHZ_AGENT_MEM_LIMIT must be refused by name, got: $(head -3 <<<"${old_name}")"
fi

# The autoscaler is the platform's template, rendered on every install. Turned
# off, it carries selectPolicy Disabled in both directions and the bounds 1 and
# 9999, so it never scales. Turned on, maxReplicas comes from HPA_MAX_REPLICAS,
# which has no default, so a bare HPA_ENABLED=true is refused instead of
# rendered with a field the API server rejects.
hpa_alone="$(helm template t "${CHART_DIR}" --set HPA_ENABLED=true 2>&1 || true)"
if [[ "${hpa_alone}" == *"HPA_ENABLED=true requires HPA_MAX_REPLICAS"* ]]; then
  pass "HPA_ENABLED without HPA_MAX_REPLICAS is refused at render time"
else
  fail "HPA_ENABLED without HPA_MAX_REPLICAS must be refused, got: $(head -3 <<<"${hpa_alone}")"
fi

# A scaling policy renders whenever its *_VALUE is set, with periodSeconds
# empty when *_PERIOD_SECONDS is not, and the API server rejects that whether
# or not the autoscaler is enabled.
half_policy="$(helm template t "${CHART_DIR}" --set HPA_SCALING_UP_PODS_VALUE=1 2>&1 || true)"
if [[ "${half_policy}" == *"HPA_SCALING_UP_PODS_VALUE is set without HPA_SCALING_UP_PODS_PERIOD_SECONDS"* ]]; then
  pass "a scaling policy value without its period is refused at render time"
else
  fail "a scaling policy value without its period must be refused, got: $(head -3 <<<"${half_policy}")"
fi

expect_strategy() { expect_block strategy_of "$@"; }
rolling='  strategy:
    type: RollingUpdate
    rollingUpdate:'
expect_strategy "no DEPLOYMENT_STRATEGY_TYPE gives the 25% rolling update" "${rolling}
      maxSurge: 25%
      maxUnavailable: 25%"
expect_strategy "recreate gives Recreate and no rollingUpdate" '  strategy:
    type: Recreate' --set DEPLOYMENT_STRATEGY_TYPE=recreate
expect_strategy "best_effort_controlled_rollout gives no surge and 80% unavailable" "${rolling}
      maxSurge: 0
      maxUnavailable: 80%" --set DEPLOYMENT_STRATEGY_TYPE=best_effort_controlled_rollout
expect_strategy "ramped_slow_rollout gives one surge Pod and none unavailable" "${rolling}
      maxSurge: 1
      maxUnavailable: 0" --set DEPLOYMENT_STRATEGY_TYPE=ramped_slow_rollout
expect_strategy "custom_rollout without its two values gives the 25% rolling update" "${rolling}
      maxSurge: 25%
      maxUnavailable: 25%" --set DEPLOYMENT_STRATEGY_TYPE=custom_rollout
# The two values are strings in the schema, so a bare number has to be passed
# as one.
expect_strategy "custom_rollout takes DEPLOYMENT_STRATEGY_MAXSURGE and DEPLOYMENT_STRATEGY_MAXUNAVAILABLE" "${rolling}
      maxSurge: 2
      maxUnavailable: 1" --set DEPLOYMENT_STRATEGY_TYPE=custom_rollout \
  --set-string DEPLOYMENT_STRATEGY_MAXSURGE=2 --set-string DEPLOYMENT_STRATEGY_MAXUNAVAILABLE=1
expect_strategy "custom_rollout defaults each size on its own" "${rolling}
      maxSurge: 2
      maxUnavailable: 25%" --set DEPLOYMENT_STRATEGY_TYPE=custom_rollout --set-string DEPLOYMENT_STRATEGY_MAXSURGE=2
expect_strategy "the sizes are read under custom_rollout only" "${rolling}
      maxSurge: 25%
      maxUnavailable: 25%" --set-string DEPLOYMENT_STRATEGY_MAXSURGE=2 --set-string DEPLOYMENT_STRATEGY_MAXUNAVAILABLE=1

# The schema admits the four names and nothing else, the empty string included,
# which is why values.yaml carries no default for the type.
for bad_type in blue_green ""; do
  if helm template t "${CHART_DIR}" --set "DEPLOYMENT_STRATEGY_TYPE=${bad_type}" >/dev/null 2>&1; then
    fail "DEPLOYMENT_STRATEGY_TYPE '${bad_type}' must be rejected by the schema"
  else
    pass "DEPLOYMENT_STRATEGY_TYPE '${bad_type}' is rejected by the schema"
  fi
done

# ── Pod spread ───────────────────────────────────────────────────────────
#
# One constraint over CLOUD_TOPOLOGY_KEY by default; with CLOUD_TOPOLOGIES, one
# per entry, with maxSkew and whenUnsatisfiable defaulted per entry. The whole
# block is compared; the selector has to name the label the Pod template
# carries, which the DEPLOYMENT_RESOURCE_NAME checks read back from one render
# as values.
spread_of() { deployment_of "$@" | sed -n '/^      topologySpreadConstraints:/,/^      [a-zA-Z]/p' | sed '$d'; }
expect_spread() { expect_block spread_of "$@"; }
expect_spread "no CLOUD_TOPOLOGIES spreads over CLOUD_TOPOLOGY_KEY with skew 1 and ScheduleAnyway" '      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: ScheduleAnyway
          labelSelector:
            matchLabels:
              name: "authz-agent"'
expect_spread "CLOUD_TOPOLOGY_KEY sets the default constraint's key" '      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: topology.kubernetes.io/zone
          whenUnsatisfiable: ScheduleAnyway
          labelSelector:
            matchLabels:
              name: "authz-agent"' --set CLOUD_TOPOLOGY_KEY=topology.kubernetes.io/zone
expect_spread "CLOUD_TOPOLOGIES gives one constraint per entry, defaulting maxSkew and whenUnsatisfiable per entry" '      topologySpreadConstraints:
        - topologyKey: topology.kubernetes.io/zone
          maxSkew: 2
          whenUnsatisfiable: DoNotSchedule
          labelSelector:
            matchLabels:
              name: "authz-agent"
        - topologyKey: kubernetes.io/hostname
          maxSkew: 1
          whenUnsatisfiable: ScheduleAnyway
          labelSelector:
            matchLabels:
              name: "authz-agent"' \
  --set-json 'CLOUD_TOPOLOGIES=[{"topologyKey":"topology.kubernetes.io/zone","maxSkew":2,"whenUnsatisfiable":"DoNotSchedule"},{"topologyKey":"kubernetes.io/hostname"}]'

# The Pod template's name label and the spread selector's, read from one
# render as values, once with DEPLOYMENT_RESOURCE_NAME set and once with it
# empty, where both fall back to SERVICE_NAME.
for row in "authz-agent-v2:--set DEPLOYMENT_RESOURCE_NAME=authz-agent-v2" "agent-x:--set DEPLOYMENT_RESOURCE_NAME= --set SERVICE_NAME=agent-x"; do
  IFS=: read -r want flags <<<"${row}"
  # shellcheck disable=SC2086 # the flags are split on purpose
  doc="$(deployment_of ${flags})"
  label="$(field "$(sed -n '/^  template:/,/^    spec:/p' <<<"${doc}")" name: | tr -d "'\"")"
  selector="$(field "$(sed -n '/^      topologySpreadConstraints:/,/^      [a-zA-Z]/p' <<<"${doc}")" name: | tr -d "'\"")"
  if [[ "${label}" == "${want}" && "${selector}" == "${want}" ]]; then
    pass "the spread selector and the Pod template's name label are both ${want} (${flags})"
  else
    fail "expected the Pod template's name label and the spread selector to be ${want} (${flags}); label '${label}', selector '${selector}'"
  fi
done

if helm template t "${CHART_DIR}" --set CLOUD_TOPOLOGIES=kubernetes.io/hostname >/dev/null 2>&1; then
  fail "a CLOUD_TOPOLOGIES that is not a list must be rejected by the schema"
else
  pass "a CLOUD_TOPOLOGIES that is not a list is rejected by the schema"
fi

# ── The authz-policy-admin chart ─────────────────────────────────────────
#
# The access-control stub is a chart of its own. The agent's chart refuses the
# keys the stub had while it was part of it, so an old values file does not
# render an agent that pulls from nowhere; the stub's chart renders the claim,
# the Deployment and the Service under the stub's own name, one Pod under
# Recreate and no autoscaler, takes the platform sizing keys and refuses the
# old ones, and registers its upload API on the mesh only where
# MESH_ROUTES_ENABLED.

old_stub_key="$(helm template t "${CHART_DIR}" --set AUTHZ_POLICY_ADMIN_ENABLED=true 2>&1 || true)"
if [[ "${old_stub_key}" == *"no longer deploys authz-policy-admin and does not read AUTHZ_POLICY_ADMIN_ENABLED"* ]]; then
  pass "the agent chart refuses AUTHZ_POLICY_ADMIN_ENABLED by name"
else
  fail "the agent chart must refuse AUTHZ_POLICY_ADMIN_ENABLED by name, got: $(head -3 <<<"${old_stub_key}")"
fi
# Any key of the prefix, not the switch alone, and every carried key named.
old_stub_keys="$(helm template t "${CHART_DIR}" --set AUTHZ_POLICY_ADMIN_PORT=1 --set AUTHZ_POLICY_ADMIN_IMAGE=x 2>&1 || true)"
if [[ "${old_stub_keys}" == *"does not read AUTHZ_POLICY_ADMIN_IMAGE, AUTHZ_POLICY_ADMIN_PORT."* ]]; then
  pass "the agent chart refuses every AUTHZ_POLICY_ADMIN_* key and names each one"
else
  fail "the agent chart must refuse AUTHZ_POLICY_ADMIN_PORT and AUTHZ_POLICY_ADMIN_IMAGE by name, got: $(head -3 <<<"${old_stub_keys}")"
fi

stub_manifests="$(helm template t "${STUB_CHART_DIR}" 2>&1 || true)"
stub_deployment="$(helm template t "${STUB_CHART_DIR}" --show-only templates/deployment.yaml 2>&1 || true)"
stub_summary="kinds=$(grep -E '^kind: ' <<<"${stub_manifests}" | sort | paste -sd, - | tr -d ' ') replicas=$(field "${stub_deployment}" replicas:) strategy=$(field "${stub_deployment}" type:) route=$(grep -c 'prefix: /access/v1/simplifiedPolicies' <<<"${stub_manifests}" || true)"
if [[ "${stub_summary}" == "kinds=kind:Deployment,kind:Mesh,kind:PersistentVolumeClaim,kind:Service replicas=1 strategy=Recreate route=1" ]]; then
  pass "the stub chart renders its claim, Deployment, Service and mesh route, one Pod under Recreate (${stub_summary})"
else
  fail "the stub chart renders ${stub_summary}, expected kinds=kind:Deployment,kind:Mesh,kind:PersistentVolumeClaim,kind:Service replicas=1 strategy=Recreate route=1"
fi

for named in "name: 'authz-policy-admin'" "name: 'authz-policy-admin-data'" "claimName: 'authz-policy-admin-data'" "endpoint: 'http://authz-policy-admin:18090'"; do
  if [[ "${stub_manifests}" == *"${named}"* ]]; then
    pass "the stub chart names its objects after its own service name (${named})"
  else
    fail "the stub chart does not render ${named}"
  fi
done

stub_no_mesh_kinds="$(helm template t "${STUB_CHART_DIR}" --set MESH_ROUTES_ENABLED=false 2>&1 | grep -E '^kind: ' | sort | paste -sd, - | tr -d ' ' || true)"
if [[ "${stub_no_mesh_kinds}" == "kind:Deployment,kind:PersistentVolumeClaim,kind:Service" ]]; then
  pass "the stub chart drops the mesh route, and only it, with MESH_ROUTES_ENABLED false"
else
  fail "the stub chart renders ${stub_no_mesh_kinds} with MESH_ROUTES_ENABLED false, expected kind:Deployment,kind:PersistentVolumeClaim,kind:Service"
fi

# Probed with values no profile carries, as for the agent.
stub_sized="$(helm template t "${STUB_CHART_DIR}" --set CPU_REQUEST=123m --set CPU_LIMIT=456m --set MEMORY_REQUEST=111Mi --set MEMORY_LIMIT=999Mi \
  --set AUTHZ_POLICY_ADMIN_EPHEMERAL_STORAGE_REQUEST=11Mi --set AUTHZ_POLICY_ADMIN_EPHEMERAL_STORAGE_LIMIT=22Mi 2>&1 || true)"
for line in "cpu: '123m'" "cpu: '456m'" "memory: '111Mi'" "memory: '999Mi'" "ephemeral-storage: '11Mi'" "ephemeral-storage: '22Mi'"; do
  if [[ "${stub_sized}" == *"${line}"* ]]; then
    pass "the stub chart sizes its container from its keys (${line})"
  else
    fail "the stub chart does not render ${line}"
  fi
done

# The stub calls no Kubernetes API, so no token of the default ServiceAccount
# is mounted into it.
if [[ "${stub_deployment}" == *"automountServiceAccountToken: false"* ]]; then
  pass "the stub Pod mounts no service-account token"
else
  fail "the stub Pod must set automountServiceAccountToken: false"
fi

for old_key in AUTHZ_POLICY_ADMIN_MEM_LIMIT=1Gi AUTHZ_POLICY_ADMIN_ENABLED=true AUTHZ_POLICY_ADMIN_IMAGE=x; do
  refused="$(helm template t "${STUB_CHART_DIR}" --set "${old_key}" 2>&1 || true)"
  if [[ "${refused}" == *"does not read these values: ${old_key%%=*}"* ]]; then
    pass "the stub chart refuses ${old_key%%=*} by name"
  else
    fail "the stub chart must refuse ${old_key%%=*} by name, got: $(head -3 <<<"${refused}")"
  fi
done

if [[ "${stub_manifests}" != *"storageClassName"* ]]; then
  pass "the stub chart renders no storageClassName while AUTHZ_POLICY_ADMIN_STORAGE_CLASS is empty"
else
  fail "the stub chart renders a storageClassName with AUTHZ_POLICY_ADMIN_STORAGE_CLASS empty: $(grep storageClassName <<<"${stub_manifests}" | tr -d ' ')"
fi
classed="$(helm template t "${STUB_CHART_DIR}" --set AUTHZ_POLICY_ADMIN_STORAGE_CLASS=fast 2>&1 || true)"
if [[ "$(field "${classed}" storageClassName:)" == "'fast'" ]]; then
  pass "the stub chart renders storageClassName from AUTHZ_POLICY_ADMIN_STORAGE_CLASS"
else
  fail "expected storageClassName 'fast' from AUTHZ_POLICY_ADMIN_STORAGE_CLASS, got '$(field "${classed}" storageClassName:)'"
fi

# ── Platform conventions shared by both charts ───────────────────────────
#
# What config-server, control-plane and dbaas-operator all do, and these two
# charts do the same way: the deployer's session id on every object and never
# on the Pod template, part-of from APPLICATION_NAME, the container named after
# the service, a seccomp profile, and a root file system read-only on
# Kubernetes only.
for chart in "${CHART_DIR}" "${STUB_CHART_DIR}"; do
  name="$(basename "${chart}")"
  with_session="$(helm template t "${chart}" --set MESH_ROUTES_ENABLED=false --set DEPLOYMENT_SESSION_ID=s-42 2>&1 || true)"
  on_objects=$(grep -c "deployment.netcracker.com/sessionId: 's-42'" <<<"${with_session}" || true)
  objects=$(grep -c '^kind: ' <<<"${with_session}" || true)
  in_pod_template=$(sed -n '/^  template:/,/^    spec:/p' <<<"$(helm template t "${chart}" --set DEPLOYMENT_SESSION_ID=s-42 --show-only templates/deployment.yaml 2>&1 || true)" | grep -c sessionId || true)
  if [[ "${on_objects}" -eq "${objects}" && "${in_pod_template}" -eq 0 ]]; then
    pass "${name}: the session id labels every object (${objects}) and not the Pod template"
  else
    fail "${name}: the session id labels ${on_objects} of ${objects} objects and appears ${in_pod_template} times in the Pod template"
  fi
  if [[ "$(helm template t "${chart}" 2>&1 || true)" != *"sessionId"* ]]; then
    pass "${name}: no session label without DEPLOYMENT_SESSION_ID"
  else
    fail "${name}: a session label renders with DEPLOYMENT_SESSION_ID empty"
  fi

  deployment="$(helm template t "${chart}" --set APPLICATION_NAME=billing --set SERVICE_NAME=svc-x --show-only templates/deployment.yaml 2>&1 || true)"
  if [[ "${deployment}" == *"app.kubernetes.io/part-of: 'billing'"* && "${deployment}" == *"        - name: 'svc-x'"* ]]; then
    pass "${name}: part-of follows APPLICATION_NAME and the container is named after SERVICE_NAME"
  else
    fail "${name}: part-of or the container name does not follow the values: $(grep -E "part-of|^        - name:" <<<"${deployment}" | tr -d ' ' | sort -u | paste -sd, - || true)"
  fi

  default_deployment="$(helm template t "${chart}" --show-only templates/deployment.yaml 2>&1 || true)"
  # The container's securityContext is the block at ten spaces; the Pod's, at
  # six, is not read.
  container_security="$(sed -n '/^          securityContext:/,/^          [a-z]/p' <<<"${default_deployment}")"
  if [[ "${container_security}" == *"seccompProfile:"* && "${container_security}" == *"type: RuntimeDefault"* ]]; then
    pass "${name}: the container runs under the RuntimeDefault seccomp profile"
  else
    fail "${name}: no RuntimeDefault seccomp profile in the container's securityContext: $(tr -d ' ' <<<"${container_security}" | paste -sd, -)"
  fi

  # The template renders the root file system read-only on Kubernetes, and
  # writable on OpenShift or when the key is false.
  ro_summary="k8s=$(field "${default_deployment}" readOnlyRootFilesystem:) openshift=$(field "$(helm template t "${chart}" --set PAAS_PLATFORM=OPENSHIFT --show-only templates/deployment.yaml 2>&1 || true)" readOnlyRootFilesystem:) off=$(field "$(helm template t "${chart}" --set READONLY_CONTAINER_FILE_SYSTEM_ENABLED=false --show-only templates/deployment.yaml 2>&1 || true)" readOnlyRootFilesystem:)"
  if [[ "${ro_summary}" == "k8s=true openshift=false off=false" ]]; then
    pass "${name}: the root file system is read-only on Kubernetes and writable on OpenShift or when turned off"
  else
    fail "${name}: readOnlyRootFilesystem renders ${ro_summary}, expected k8s=true openshift=false off=false"
  fi
done

service_ports="$(helm template t "${CHART_DIR}" --show-only templates/service.yaml 2>&1 | grep -E '^    - name: |^      port: ' | tr -d ' ' | paste -sd, - || true)"
if [[ "${service_ports}" == "-name:web,port:8080,-name:data-api,port:8181" ]]; then
  pass "the agent's Service names its ports web (8080) and data-api (8181), as the container does"
else
  fail "the agent's Service ports render ${service_ports}, expected -name:web,port:8080,-name:data-api,port:8181"
fi

sa_namespace="$(field "$(helm template t "${CHART_DIR}" --set NAMESPACE=ns-x --show-only templates/configmap.yaml 2>&1 | sed -n '/^kind: ServiceAccount/,$p' || true)" namespace:)"
if [[ "${sa_namespace}" == "'ns-x'" ]]; then
  pass "the agent's ServiceAccount names its namespace from NAMESPACE"
else
  fail "the agent's ServiceAccount renders namespace ${sa_namespace}, expected 'ns-x'"
fi

# ── PodMonitor ───────────────────────────────────────────────────────────
#
# Under MONITORING_ENABLED the agent's metrics are scraped where the service
# serves them: /prometheus on the data-api port, from the Pods the Service
# selects.
monitor="$(helm template t "${CHART_DIR}" --show-only templates/podmonitor.yaml 2>&1 || true)"
monitor_summary="kind=$(field "${monitor}" kind:) operator=$(field "${monitor}" app.kubernetes.io/processed-by-operator:) port=$(field "${monitor}" port:) path=$(field "${monitor}" path:) interval=$(awk '$1 == "-" && $2 == "interval:" {print $3; exit}' <<<"${monitor}") selector=$(field "$(sed -n '/^  selector:/,$p' <<<"${monitor}")" name:)"
if [[ "${monitor_summary}" == "kind=PodMonitor operator=victoriametrics-operator port=data-api path=/prometheus interval=30s selector='authz-agent'" ]]; then
  pass "MONITORING_ENABLED renders a PodMonitor for the VictoriaMetrics operator on data-api /prometheus every 30s for the agent's Pods"
else
  fail "the PodMonitor renders ${monitor_summary}, expected kind=PodMonitor operator=victoriametrics-operator port=data-api path=/prometheus interval=30s selector='authz-agent'"
fi
if [[ "$(helm template t "${CHART_DIR}" --set MONITORING_ENABLED=false 2>&1 || true)" != *"kind: PodMonitor"* ]]; then
  pass "MONITORING_ENABLED false renders no PodMonitor"
else
  fail "a PodMonitor renders with MONITORING_ENABLED false"
fi

# ── Log level ────────────────────────────────────────────────────────────
#
# Both services log through the platform logger, which resolves its root level
# from logging.level.root, and LOGGING_LEVEL_ROOT is the variable that sets
# that property. Without this env entry the level could only be changed by
# editing the Deployment, so what the charts have to render is the variable,
# under the name the logger reads, on both services.
for chart in "${CHART_DIR}" "${STUB_CHART_DIR}"; do
  name="$(basename "${chart}")"
  rendered="$(env_value_of "${chart}" LOGGING_LEVEL_ROOT)"
  if [[ "${rendered}" == "info" ]]; then
    pass "${name} renders LOGGING_LEVEL_ROOT info by default"
  else
    fail "${name} renders LOGGING_LEVEL_ROOT '${rendered}', expected info"
  fi

  raised="$(env_value_of "${chart}" LOGGING_LEVEL_ROOT --set LOG_LEVEL=debug)"
  if [[ "${raised}" == "debug" ]]; then
    pass "${name} renders LOGGING_LEVEL_ROOT from LOG_LEVEL"
  else
    fail "${name} renders LOGGING_LEVEL_ROOT '${raised}' for LOG_LEVEL=debug, expected debug"
  fi

  # A level the logger does not parse leaves it at info, which reads in
  # production as a level that was set and did nothing; the schema refuses it
  # at install time instead.
  for bad_level in verbose ""; do
    if helm template t "${chart}" --set "LOG_LEVEL=${bad_level}" >/dev/null 2>&1; then
      fail "${name} accepted LOG_LEVEL '${bad_level}', which the logger does not parse"
    else
      pass "${name} refuses LOG_LEVEL '${bad_level}'"
    fi
  done
done

echo
if (( failures > 0 )); then
  echo "chart render checks: ${failures} failure(s)"
  exit 1
fi

echo "chart render checks: all passed"
