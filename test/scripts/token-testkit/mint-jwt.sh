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
  test/scripts/token-testkit/mint-jwt.sh [options]

Required options:
  --issuer <iss>               JWT issuer
  --subject <sub>              JWT subject
  --private-key <path>         RSA private key path (PEM). Required for RS256
                               (the default), unused for --algorithm none/HS256.
  --kid <kid>                  Key ID in JWT header. Required unless --no-kid.

Optional:
  --algorithm <alg>            RS256 (default), HS256 or none. HS256 and none exist
                               only to mint the tokens the policy must REJECT:
                               `none` is an unsigned token, and HS256 combined with
                               --hmac-key <public key> is the key-confusion attack,
                               where the verifier's own public key is used as an
                               HMAC secret.
  --hmac-key <path>            Secret file for --algorithm HS256 (its raw bytes).
  --no-kid                     Omit the kid header claim. Rejected by the policy
                               since authz-agent-ADR-0075; kept mintable so the
                               rejection can be asserted.
  --drop-claim <name>          Remove a claim from the payload before signing.
                               Repeatable. For minting a token without `iss`,
                               which since authz-agent-ADR-0075 must still verify.
  --audiences <csv>            Audience list CSV (default: authz-agent)
  --roles <csv>                realm_access.roles CSV (default: ROLE_VIEWER)
  --scope <scope string>       Scope claim value (default: empty)
  --level <value>              Optional level claim (e.g. m2m|external)
  --issued-at <epoch>          iat value (default: current time)
  --expires-in <seconds>       Expiration from iat (default: 3600)
  --not-before-offset <sec>    nbf offset from iat (default: 0)
  --claims-file <path>         Extra claims JSON object merged into payload
  --output <path>              Write token to file instead of stdout
  -h, --help                   Show this help

Notes:
  - Generates an RS256 signed JWT unless --algorithm says otherwise.
  - Extra claims override base payload fields on key conflict.
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

b64url_encode() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

private_key=""
issuer=""
subject=""
kid=""
audiences_csv="authz-agent"
roles_csv="ROLE_VIEWER"
scope_value=""
level_value=""
issued_at=""
expires_in="3600"
not_before_offset="0"
claims_file=""
output_file=""
algorithm="RS256"
hmac_key=""
omit_kid="false"
drop_claims=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --algorithm)
      algorithm="${2:-}"
      shift 2
      ;;
    --hmac-key)
      hmac_key="${2:-}"
      shift 2
      ;;
    --no-kid)
      omit_kid="true"
      shift
      ;;
    --drop-claim)
      drop_claims+=("${2:-}")
      shift 2
      ;;
    --private-key)
      private_key="${2:-}"
      shift 2
      ;;
    --issuer)
      issuer="${2:-}"
      shift 2
      ;;
    --subject)
      subject="${2:-}"
      shift 2
      ;;
    --kid)
      kid="${2:-}"
      shift 2
      ;;
    --audiences)
      audiences_csv="${2:-}"
      shift 2
      ;;
    --roles)
      roles_csv="${2:-}"
      shift 2
      ;;
    --scope)
      scope_value="${2:-}"
      shift 2
      ;;
    --level)
      level_value="${2:-}"
      shift 2
      ;;
    --issued-at)
      issued_at="${2:-}"
      shift 2
      ;;
    --expires-in)
      expires_in="${2:-}"
      shift 2
      ;;
    --not-before-offset)
      not_before_offset="${2:-}"
      shift 2
      ;;
    --claims-file)
      claims_file="${2:-}"
      shift 2
      ;;
    --output)
      output_file="${2:-}"
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

require_cmd openssl
require_cmd jq
require_cmd date

case "${algorithm}" in
  RS256|HS256|none) ;;
  *)
    echo "error: --algorithm must be RS256, HS256 or none" >&2
    exit 1
    ;;
esac

if [[ -z "${issuer}" || -z "${subject}" ]]; then
  echo "error: --issuer and --subject are required" >&2
  usage >&2
  exit 1
fi

if [[ "${omit_kid}" != "true" && -z "${kid}" ]]; then
  echo "error: --kid is required unless --no-kid is given" >&2
  usage >&2
  exit 1
fi

if [[ "${algorithm}" == "RS256" ]]; then
  if [[ -z "${private_key}" ]]; then
    echo "error: --private-key is required for RS256" >&2
    usage >&2
    exit 1
  fi
  if [[ ! -f "${private_key}" ]]; then
    echo "error: private key file not found: ${private_key}" >&2
    exit 1
  fi
fi

if [[ "${algorithm}" == "HS256" ]]; then
  require_cmd od
  if [[ -z "${hmac_key}" || ! -f "${hmac_key}" ]]; then
    echo "error: --hmac-key <path> is required for HS256" >&2
    exit 1
  fi
fi

if [[ -z "${issued_at}" ]]; then
  issued_at="$(date +%s)"
fi

if ! [[ "${issued_at}" =~ ^[0-9]+$ && "${expires_in}" =~ ^[0-9]+$ && "${not_before_offset}" =~ ^-?[0-9]+$ ]]; then
  echo "error: --issued-at, --expires-in, --not-before-offset must be numeric" >&2
  exit 1
fi

nbf="$(( issued_at + not_before_offset ))"
exp="$(( issued_at + expires_in ))"

audiences_json="$(jq -cn --arg csv "${audiences_csv}" '$csv | split(",") | map(gsub("^\\s+|\\s+$";"")) | map(select(length > 0))')"
roles_json="$(jq -cn --arg csv "${roles_csv}" '$csv | split(",") | map(gsub("^\\s+|\\s+$";"")) | map(select(length > 0))')"

base_payload="$(
  jq -cn \
    --arg iss "${issuer}" \
    --arg sub "${subject}" \
    --argjson iat "${issued_at}" \
    --argjson nbf "${nbf}" \
    --argjson exp "${exp}" \
    --argjson aud "${audiences_json}" \
    --argjson roles "${roles_json}" \
    --arg scope "${scope_value}" \
    --arg level "${level_value}" \
    '{
      iss: $iss,
      sub: $sub,
      iat: $iat,
      nbf: $nbf,
      exp: $exp,
      aud: $aud,
      realm_access: { roles: $roles }
    }
    + (if $scope == "" then {} else {scope: $scope} end)
    + (if $level == "" then {} else {level: $level} end)'
)"

if [[ -n "${claims_file}" ]]; then
  if [[ ! -f "${claims_file}" ]]; then
    echo "error: claims file not found: ${claims_file}" >&2
    exit 1
  fi
  payload="$(
    jq -cn \
      --argjson base "${base_payload}" \
      --slurpfile extra "${claims_file}" \
      '$base * ($extra[0] // {})'
  )"
else
  payload="${base_payload}"
fi

for claim in ${drop_claims+"${drop_claims[@]}"}; do
  payload="$(jq -c --arg name "${claim}" 'del(.[$name])' <<<"${payload}")"
done

header="$(
  jq -cn \
    --arg alg "${algorithm}" \
    --arg kid "${kid}" \
    --argjson with_kid "$([[ "${omit_kid}" == "true" ]] && echo false || echo true)" \
    '{alg: $alg, typ: "JWT"} + (if $with_kid then {kid: $kid} else {} end)'
)"

header_b64="$(printf '%s' "${header}" | b64url_encode)"
payload_b64="$(printf '%s' "${payload}" | b64url_encode)"
signing_input="${header_b64}.${payload_b64}"

case "${algorithm}" in
  RS256)
    signature="$(
      printf '%s' "${signing_input}" \
        | openssl dgst -binary -sha256 -sign "${private_key}" \
        | b64url_encode
    )"
    ;;
  HS256)
    # od rather than `xxd -p -c <big>`: older vim-shipped xxd caps -c at 256 and
    # would silently wrap the key into multiple lines on some build agents.
    signature="$(
      printf '%s' "${signing_input}" \
        | openssl dgst -binary -sha256 -mac HMAC \
            -macopt "hexkey:$(od -An -v -tx1 "${hmac_key}" | tr -d ' \n')" \
        | b64url_encode
    )"
    ;;
  none)
    # An `alg: none` token has an empty signature segment by definition.
    signature=""
    ;;
esac

token="${signing_input}.${signature}"

if [[ -n "${output_file}" ]]; then
  mkdir -p "$(dirname "${output_file}")"
  printf '%s\n' "${token}" > "${output_file}"
  echo "${output_file}"
else
  printf '%s\n' "${token}"
fi
