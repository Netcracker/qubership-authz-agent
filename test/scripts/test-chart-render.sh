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
CHART_DIR="${ROOT_DIR}/charts/authz-agent"

# The chart's policy ConfigMap reads from files/opa/policies/ which is
# generated (gitignored). Populate it before rendering.
make -C "${ROOT_DIR}" copy-policies >/dev/null

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
  pass "pap-client is pointed at tenant-manager for realm display-name resolution"
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

# ── KUBERNETES_M2M_ENABLED=false (Keycloak sidecar mode) ─────────────────

# Helpers to render the full Deployment manifest for a given mode.
render_deployment() {
  # Capture helm's own diagnostics. Piping helm straight into awk under
  # `set -e` makes a template failure kill the script with no output at all:
  # the reader keeps the exit status, the error text goes nowhere useful, and
  # the run stops after the last passing check with nothing to read. Surface
  # the arguments and helm's message instead.
  local rendered rc=0
  rendered="$(helm template t "${CHART_DIR}" "$@" 2>&1)" || rc=$?
  if [[ ${rc} -ne 0 ]]; then
    printf 'helm template failed (exit %s)\n  args: %s\n%s\n' \
      "${rc}" "$*" "${rendered}" >&2
    return "${rc}"
  fi
  awk '/^---$/{found=0} /kind: Deployment/{found=1} found' <<<"${rendered}"
}

keycloak_manifest="$(render_deployment --set KUBERNETES_M2M_ENABLED=false)"

# (a) No projected ac-token volume.
if grep -q "serviceAccountToken" <<<"${keycloak_manifest}"; then
  fail "KUBERNETES_M2M_ENABLED=false must not render a projected serviceAccountToken volume"
else
  pass "KUBERNETES_M2M_ENABLED=false: no projected serviceAccountToken volume"
fi

# (b) emptyDir medium: Memory named ac-token.
# Checked on the ac-token block itself, not on the whole manifest: a stray
# "medium: Memory" belonging to some other volume must not satisfy this.
ac_token_block="$(grep -A3 "name: ac-token" <<<"${keycloak_manifest}" || true)"
if grep -q "medium: Memory" <<<"${ac_token_block}"; then
  pass "KUBERNETES_M2M_ENABLED=false: ac-token volume is emptyDir medium Memory"
else
  fail "KUBERNETES_M2M_ENABLED=false: expected emptyDir medium: Memory for ac-token"
fi

# (c) client-credentials Secret volume present.
if grep -q "client-credentials" <<<"${keycloak_manifest}"; then
  pass "KUBERNETES_M2M_ENABLED=false: client-credentials Secret volume present"
else
  fail "KUBERNETES_M2M_ENABLED=false: client-credentials Secret volume missing"
fi

# (d) Native sidecar token-fetcher in initContainers with restartPolicy: Always and startupProbe.
if grep -q "restartPolicy: Always" <<<"${keycloak_manifest}"; then
  pass "KUBERNETES_M2M_ENABLED=false: initContainer has restartPolicy: Always (native sidecar)"
else
  fail "KUBERNETES_M2M_ENABLED=false: initContainer restartPolicy: Always missing"
fi

if grep -q "startupProbe" <<<"${keycloak_manifest}"; then
  pass "KUBERNETES_M2M_ENABLED=false: startupProbe present on token-fetcher sidecar"
else
  fail "KUBERNETES_M2M_ENABLED=false: startupProbe missing on token-fetcher sidecar"
fi

if grep -q "name: token-fetcher" <<<"${keycloak_manifest}"; then
  pass "KUBERNETES_M2M_ENABLED=false: token-fetcher sidecar container present"
else
  fail "KUBERNETES_M2M_ENABLED=false: token-fetcher sidecar container missing"
fi

# (f) token-fetcher image reference must not be empty or malformed (e.g. "/...:").
# This catches the class of defect where TOKEN_FETCHER_IMAGE stays '' because
# bake-image-refs did not substitute it — which produces "image: /authz-agent-token-fetcher:"
# and an Init:InvalidImageName failure at deploy time.
# We render with an explicit non-empty TOKEN_FETCHER_IMAGE to simulate a baked chart.
baked_keycloak_manifest="$(render_deployment \
  --set KUBERNETES_M2M_ENABLED=false \
  --set 'TOKEN_FETCHER_IMAGE=registry.example.com/ns/authz-agent-token-fetcher:1')"
# Fed by here-string, not `echo |`: this is the only awk in the script that
# exits early, and an early exit can SIGPIPE the writer, which `pipefail` then
# turns into a silent script death. Harmless at today's manifest size (16 KB
# fits the pipe buffer) but it is a trap waiting for the chart to grow.
tf_image="$(awk '/name: token-fetcher/{found=1} found && /image:/{print; exit}' \
  <<<"${baked_keycloak_manifest}" \
  | sed 's/.*image: *//')"
# Valid: non-empty AND starts with a registry host (contains at least one dot before first slash).
if grep -qE '^[^/]+\.[^/]+/.+:.+$' <<<"${tf_image}"; then
  pass "KUBERNETES_M2M_ENABLED=false: token-fetcher image reference is non-empty and valid (${tf_image})"
else
  fail "KUBERNETES_M2M_ENABLED=false: token-fetcher image reference is empty or malformed: '${tf_image}'"
fi

# (e) backend volumeMount at /etc/authz/ac-token unchanged (present in Keycloak mode).
if grep -q "mountPath: /etc/authz/ac-token" <<<"${keycloak_manifest}"; then
  pass "KUBERNETES_M2M_ENABLED=false: backend volumeMount at /etc/authz/ac-token present"
else
  fail "KUBERNETES_M2M_ENABLED=false: backend volumeMount at /etc/authz/ac-token missing"
fi

# ── KUBERNETES_M2M_ENABLED=true (K8s projected token) ────────────────────

k8s_manifest="$(render_deployment --set KUBERNETES_M2M_ENABLED=true)"

# No sidecar in K8s mode.
if grep -q "name: token-fetcher" <<<"${k8s_manifest}"; then
  fail "KUBERNETES_M2M_ENABLED=true must not render a token-fetcher initContainer"
else
  pass "KUBERNETES_M2M_ENABLED=true: no token-fetcher sidecar"
fi

# Projected volume present in K8s mode.
if grep -q "serviceAccountToken" <<<"${k8s_manifest}"; then
  pass "KUBERNETES_M2M_ENABLED=true: projected serviceAccountToken volume present"
else
  fail "KUBERNETES_M2M_ENABLED=true: projected serviceAccountToken volume missing"
fi

# backend volumeMount at /etc/authz/ac-token also present in K8s mode.
if grep -q "mountPath: /etc/authz/ac-token" <<<"${k8s_manifest}"; then
  pass "KUBERNETES_M2M_ENABLED=true: backend volumeMount at /etc/authz/ac-token present"
else
  fail "KUBERNETES_M2M_ENABLED=true: backend volumeMount at /etc/authz/ac-token missing"
fi

# ── Readiness / liveness probe separation ────────────────────────────────────

default_deployment="$(render_deployment)"

# Readiness must use --readiness flag; liveness must NOT.
if grep -q '"pap-client", "healthcheck", "--readiness"' <<<"${default_deployment}"; then
  pass "backend readinessProbe uses pap-client healthcheck --readiness"
else
  fail "backend readinessProbe must use 'pap-client healthcheck --readiness'"
fi

if grep -qE '"pap-client", "healthcheck"[^,]' <<<"${default_deployment}"; then
  pass "backend livenessProbe uses pap-client healthcheck (no --readiness)"
else
  fail "backend livenessProbe must use 'pap-client healthcheck' without --readiness"
fi

# Liveness and readiness must NOT use the same command (they were identical before).
# grep -A2 cannot reach the command: line (it is 8+ lines after readinessProbe:);
# count occurrences of each distinct form instead to avoid a pipefail abort.
r_count=$(echo "${default_deployment}" | grep -c '"healthcheck", "--readiness"' 2>/dev/null || echo 0)
l_count=$(echo "${default_deployment}" | grep -cE '"healthcheck"\]' 2>/dev/null || echo 0)
if [[ "${r_count}" -ge 1 && "${l_count}" -ge 1 ]]; then
  pass "readinessProbe and livenessProbe use different healthcheck commands"
else
  fail "readinessProbe and livenessProbe must differ: readiness needs --readiness flag"
fi

# ── subPath-free invariant ─────────────────────────────────────────────────
#
# A volumeMount with subPath causes runc to abort container creation with
# "not a directory" when the parent directory does not exist in the rootfs
# (defect 7: opa-auth-token subPath: token).  It also prevents the kubelet from
# propagating Secret/ConfigMap updates into the mounted file.
#
# WHITELIST (pre-existing before this task, not changed here):
#   subPath: envoy.yaml   — single Envoy config file from the runtime-config
#                           ConfigMap; hot-reload not required; pre-dates this work.
#   subPath: opa-config.yaml — single OPA config file; same reasoning.
#
# Any new subPath outside this whitelist must be rejected here first.
#
# Strategy: render both modes, count total subPath occurrences, and compare
# against the known-good count (2).  If any new subPath is added to the chart,
# the count exceeds 2 and the assertion fails — forcing a deliberate whitelist
# extension with a written justification.
all_manifests="$(helm template t "${CHART_DIR}")"
keycloak_all="$(helm template t "${CHART_DIR}" --set KUBERNETES_M2M_ENABLED=false)"
k8s_all="$(helm template t "${CHART_DIR}" --set KUBERNETES_M2M_ENABLED=true)"

for label_manifest in "default:${all_manifests}" "keycloak-mode:${keycloak_all}" "k8s-mode:${k8s_all}"; do
  label="${label_manifest%%:*}"
  manifest="${label_manifest#*:}"
  # Match only actual YAML subPath keys (lines where subPath: appears as a
  # key with leading whitespace), NOT comment lines that mention subPath.
  sp_count=$(echo "${manifest}" | grep -cE '^\s+subPath:' 2>/dev/null || echo 0)
  # Whitelist: exactly 2 subPath uses (envoy.yaml, opa-config.yaml).
  if [[ "${sp_count}" -le 2 ]]; then
    pass "no unexpected subPath mounts in ${label} render (${sp_count} whitelisted)"
  else
    echo "${manifest}" | grep -E '^\s+subPath:' >&2
    fail "unexpected subPath mounts in ${label} render: found ${sp_count}, expected <=2 (envoy.yaml + opa-config.yaml only)"
  fi
done

echo
if (( failures > 0 )); then
  echo "chart render checks: ${failures} failure(s)"
  exit 1
fi

echo "chart render checks: all passed"
