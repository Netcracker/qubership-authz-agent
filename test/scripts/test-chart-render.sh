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

env_value() {
  local name="$1"
  shift
  helm template t "${CHART_DIR}" "$@" \
    | grep -A1 "name: ${name}$" \
    | awk -F"'" '/value:/ && !seen {print $2; seen=1}'
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

# The agent's own container. The policy-admin Deployment is rendered beside it
# and is not one of them.
agent_containers() {
  local rendered=$1
  echo "${rendered}" | grep -cE "^        - name: (authz-agent|envoy|opa|pap-client|collector|token-fetcher)$" || true
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
image_lines=$(echo "${all_manifests}" | grep -cE "^          image: .*authz-agent:" || true)
if [[ "${image_lines}" -ge 1 ]]; then
  pass "the agent Pod runs the authz-agent image"
else
  fail "the agent Pod does not run the authz-agent image"
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

for absent in "authz-agent-runtime" "authz-agent-policies" "openpolicyagent/opa" "authz-agent-envoy" "authz-agent-pap-client" "authz-agent-collector" "authz-agent-token-fetcher"; do
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

# The autoscaler's bounds and target have no default, so turning it on without
# them is refused instead of rendered with empty fields for the API server to
# reject.
hpa_alone="$(helm template t "${CHART_DIR}" --set HPA_ENABLED=true 2>&1 || true)"
if [[ "${hpa_alone}" == *"HPA_ENABLED=true requires HPA_MIN_REPLICAS"* ]]; then
  pass "HPA_ENABLED without the autoscaler's bounds is refused at render time"
else
  fail "HPA_ENABLED without the autoscaler's bounds must be refused, got: $(head -3 <<<"${hpa_alone}")"
fi

if [[ "${all_manifests}" != *"kind: HorizontalPodAutoscaler"* ]]; then
  pass "a plain install renders no HorizontalPodAutoscaler"
else
  fail "a plain install renders a HorizontalPodAutoscaler"
fi

# Every profile validates against the schema and renders. The profile is
# applied over a memory limit no profile carries, so that a misspelled key,
# which the schema would admit, leaves that limit in the render in place of
# the profile's; the dev sizing mirrors values.yaml and could not be told from
# the default otherwise. The autoscaler's floor is the profile's: no autoscaler
# in dev, two Pods in dev-ha and prod, one in prod-nonha.
sentinel="$(mktemp)"
trap 'rm -f "${sentinel}"' EXIT
printf 'MEMORY_LIMIT: 1Mi\n' >"${sentinel}"
for row in "dev::700Mi" "dev-ha:2:700Mi" "prod:2:13Gi" "prod-nonha:1:13Gi"; do
  IFS=: read -r profile floor mem_limit <<<"${row}"
  if ! rendered="$(helm template t "${CHART_DIR}" -f "${sentinel}" -f "${CHART_DIR}/resource-profiles/${profile}.yaml" 2>&1)"; then
    fail "the ${profile} profile does not render: ${rendered}"
    continue
  fi
  if [[ "${rendered}" == *"memory: '${mem_limit}'"* ]]; then
    pass "the ${profile} profile sizes the agent container (memory limit ${mem_limit})"
  else
    fail "the ${profile} profile does not set the memory limit ${mem_limit}; the render has: $(grep -E '^ +memory: ' <<<"${rendered}" | tr -d ' ' | paste -sd, - || true)"
  fi
  if [[ -z "${floor}" ]]; then
    if [[ "${rendered}" != *"kind: HorizontalPodAutoscaler"* ]]; then
      pass "the ${profile} profile renders no HorizontalPodAutoscaler"
    else
      fail "the ${profile} profile renders a HorizontalPodAutoscaler"
    fi
    continue
  fi
  got_floor="$(awk '/^  minReplicas: /{print $2}' <<<"${rendered}")"
  if [[ "${got_floor}" == "${floor}" ]]; then
    pass "the ${profile} profile sets the autoscaler floor to ${floor}"
  else
    fail "the ${profile} profile sets the autoscaler floor to '${got_floor}', expected ${floor}"
  fi
done

echo
if (( failures > 0 )); then
  echo "chart render checks: ${failures} failure(s)"
  exit 1
fi

echo "chart render checks: all passed"
