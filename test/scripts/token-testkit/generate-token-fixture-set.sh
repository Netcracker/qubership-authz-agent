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

usage() {
  cat <<'EOF'
Usage:
  test/scripts/token-testkit/generate-token-fixture-set.sh [options]

Options:
  --toolkit-dir <path>         Toolkit directory with manifest.json (default: /tmp/authz-token-testkit)
  --output-dir <path>          Output directory for token fixtures (default: <toolkit-dir>/tokens)
  --subject <id>               Subject for valid user token (default: user-1)
  --audience <aud>             Audience for generated tokens (default: authz-agent)
  --roles <csv>                Roles for valid user token (default: ROLE_VIEWER)
  --service-subject <id>       Subject for service token (default: svc-authz)
  --service-level <level>      Level claim for service token (default: m2m)
  -h, --help                   Show this help

Prerequisite:
  test/scripts/token-testkit/generate-rsa-jwks.sh
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MINT_SCRIPT="${SCRIPT_DIR}/mint-jwt.sh"

toolkit_dir="/tmp/authz-token-testkit"
output_dir=""
subject="user-1"
audience="authz-agent"
roles="ROLE_VIEWER"
service_subject="svc-authz"
service_level="m2m"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --toolkit-dir)
      toolkit_dir="${2:-}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:-}"
      shift 2
      ;;
    --subject)
      subject="${2:-}"
      shift 2
      ;;
    --audience)
      audience="${2:-}"
      shift 2
      ;;
    --roles)
      roles="${2:-}"
      shift 2
      ;;
    --service-subject)
      service_subject="${2:-}"
      shift 2
      ;;
    --service-level)
      service_level="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

require_cmd jq
require_cmd date

if [[ ! -x "${MINT_SCRIPT}" ]]; then
  echo "error: mint script not executable: ${MINT_SCRIPT}" >&2
  exit 1
fi

manifest_file="${toolkit_dir}/manifest.json"
if [[ ! -f "${manifest_file}" ]]; then
  echo "error: manifest file not found: ${manifest_file}" >&2
  echo "run test/scripts/token-testkit/generate-rsa-jwks.sh first" >&2
  exit 1
fi

if [[ -z "${output_dir}" ]]; then
  output_dir="${toolkit_dir}/tokens"
fi
mkdir -p "${output_dir}"

private_key="$(jq -r '.privateKey' "${manifest_file}")"
kid="$(jq -r '.kid' "${manifest_file}")"
issuer="$(jq -r '.issuer' "${manifest_file}")"
provider_id="$(jq -r '.providerId' "${manifest_file}")"

if [[ -z "${private_key}" || -z "${kid}" || -z "${issuer}" ]]; then
  echo "error: manifest is missing required fields" >&2
  exit 1
fi

now="$(date +%s)"

valid_user_file="${output_dir}/valid-user.jwt"
valid_service_file="${output_dir}/valid-service.jwt"
expired_file="${output_dir}/expired.jwt"
wrong_issuer_file="${output_dir}/wrong-issuer.jwt"
unknown_kid_file="${output_dir}/unknown-kid.jwt"
tokens_json_file="${output_dir}/tokens.json"

"${MINT_SCRIPT}" \
  --private-key "${private_key}" \
  --kid "${kid}" \
  --issuer "${issuer}" \
  --subject "${subject}" \
  --audiences "${audience}" \
  --roles "${roles}" \
  --issued-at "${now}" \
  --expires-in 3600 \
  --output "${valid_user_file}" >/dev/null

"${MINT_SCRIPT}" \
  --private-key "${private_key}" \
  --kid "${kid}" \
  --issuer "${issuer}" \
  --subject "${service_subject}" \
  --audiences "${audience}" \
  --roles "ROLE_SERVICE" \
  --level "${service_level}" \
  --issued-at "${now}" \
  --expires-in 3600 \
  --output "${valid_service_file}" >/dev/null

"${MINT_SCRIPT}" \
  --private-key "${private_key}" \
  --kid "${kid}" \
  --issuer "${issuer}" \
  --subject "${subject}" \
  --audiences "${audience}" \
  --roles "${roles}" \
  --issued-at "$((now - 7200))" \
  --expires-in 300 \
  --output "${expired_file}" >/dev/null

"${MINT_SCRIPT}" \
  --private-key "${private_key}" \
  --kid "${kid}" \
  --issuer "https://idp.example.test/realms/unknown-provider" \
  --subject "${subject}" \
  --audiences "${audience}" \
  --roles "${roles}" \
  --issued-at "${now}" \
  --expires-in 3600 \
  --output "${wrong_issuer_file}" >/dev/null

"${MINT_SCRIPT}" \
  --private-key "${private_key}" \
  --kid "${provider_id}-unknown-kid" \
  --issuer "${issuer}" \
  --subject "${subject}" \
  --audiences "${audience}" \
  --roles "${roles}" \
  --issued-at "${now}" \
  --expires-in 3600 \
  --output "${unknown_kid_file}" >/dev/null

jq -n \
  --arg providerId "${provider_id}" \
  --arg issuer "${issuer}" \
  --arg audience "${audience}" \
  --arg validUser "$(cat "${valid_user_file}")" \
  --arg validService "$(cat "${valid_service_file}")" \
  --arg expired "$(cat "${expired_file}")" \
  --arg wrongIssuer "$(cat "${wrong_issuer_file}")" \
  --arg unknownKid "$(cat "${unknown_kid_file}")" \
  '{
    providerId: $providerId,
    issuer: $issuer,
    audience: $audience,
    tokens: {
      validUser: $validUser,
      validService: $validService,
      expired: $expired,
      wrongIssuer: $wrongIssuer,
      unknownKid: $unknownKid
    }
  }' > "${tokens_json_file}"

echo "Generated token fixture set:"
echo "  ${valid_user_file}"
echo "  ${valid_service_file}"
echo "  ${expired_file}"
echo "  ${wrong_issuer_file}"
echo "  ${unknown_kid_file}"
echo "  ${tokens_json_file}"
