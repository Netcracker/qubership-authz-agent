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
  test/scripts/token-testkit/generate-rsa-jwks.sh [options]

Options:
  --provider-id <id>           Provider identifier (default: primary-idp)
  --kid <kid>                  JWK key id (default: <provider-id>-k1)
  --issuer <url>               Issuer claim (default: https://idp.example.test/realms/<provider-id>)
  --audiences <csv>            Allowed audiences CSV (default: authz-agent)
  --output-dir <path>          Output directory (default: /tmp/authz-token-testkit)
  --force                      Overwrite existing keys
  -h, --help                   Show this help

Generated files:
  <output-dir>/keys/<provider-id>.private.pem
  <output-dir>/keys/<provider-id>.public.pem
  <output-dir>/jwks/<provider-id>.jwks.json
  <output-dir>/trusted-providers.json
  <output-dir>/manifest.json
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

hex_to_b64url() {
  local hex="$1"
  if [[ -z "${hex}" ]]; then
    echo ""
    return 0
  fi
  if (( ${#hex} % 2 != 0 )); then
    hex="0${hex}"
  fi
  printf '%s' "${hex}" \
    | xxd -r -p \
    | openssl base64 -A \
    | tr '+/' '-_' \
    | tr -d '='
}

provider_id="primary-idp"
kid=""
issuer=""
audiences_csv="authz-agent"
output_dir="/tmp/authz-token-testkit"
force="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --provider-id)
      provider_id="${2:-}"
      shift 2
      ;;
    --kid)
      kid="${2:-}"
      shift 2
      ;;
    --issuer)
      issuer="${2:-}"
      shift 2
      ;;
    --audiences)
      audiences_csv="${2:-}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:-}"
      shift 2
      ;;
    --force)
      force="true"
      shift
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
require_cmd xxd
require_cmd awk

if [[ -z "${provider_id}" ]]; then
  echo "error: --provider-id must not be empty" >&2
  exit 1
fi

if [[ -z "${kid}" ]]; then
  kid="${provider_id}-k1"
fi

if [[ -z "${issuer}" ]]; then
  issuer="https://idp.example.test/realms/${provider_id}"
fi

keys_dir="${output_dir}/keys"
jwks_dir="${output_dir}/jwks"
mkdir -p "${keys_dir}" "${jwks_dir}"

private_key="${keys_dir}/${provider_id}.private.pem"
public_key="${keys_dir}/${provider_id}.public.pem"
jwks_file="${jwks_dir}/${provider_id}.jwks.json"
trusted_providers_file="${output_dir}/trusted-providers.json"
manifest_file="${output_dir}/manifest.json"

if [[ -f "${private_key}" && "${force}" != "true" ]]; then
  echo "error: ${private_key} already exists (use --force to overwrite)" >&2
  exit 1
fi

if [[ "${force}" == "true" ]]; then
  rm -f "${private_key}" "${public_key}" "${jwks_file}" "${trusted_providers_file}" "${manifest_file}"
fi

openssl genrsa -out "${private_key}" 2048 >/dev/null 2>&1
openssl rsa -in "${private_key}" -pubout -out "${public_key}" >/dev/null 2>&1

mod_hex="$(
  openssl rsa -pubin -in "${public_key}" -text -noout \
    | awk '
      /Modulus:/ {in_mod=1; next}
      /Exponent:/ {in_mod=0}
      in_mod {
        gsub(/[:[:space:]]/, "", $0)
        printf "%s", $0
      }
    '
)"

exp_dec="$(
  openssl rsa -pubin -in "${public_key}" -text -noout \
    | awk '/Exponent:/{print $2; exit}'
)"

mod_hex="${mod_hex#00}"
if [[ -z "${exp_dec}" ]]; then
  echo "error: failed to extract RSA exponent from ${public_key}" >&2
  exit 1
fi

printf -v exp_hex '%x' "${exp_dec}"
if (( ${#exp_hex} % 2 != 0 )); then
  exp_hex="0${exp_hex}"
fi

n_b64="$(hex_to_b64url "${mod_hex}")"
e_b64="$(hex_to_b64url "${exp_hex}")"

jq -n \
  --arg kid "${kid}" \
  --arg n "${n_b64}" \
  --arg e "${e_b64}" \
  '{
    keys: [
      {
        kty: "RSA",
        use: "sig",
        alg: "RS256",
        kid: $kid,
        n: $n,
        e: $e
      }
    ]
  }' > "${jwks_file}"

audiences_json="$(jq -cn --arg csv "${audiences_csv}" '$csv | split(",") | map(gsub("^\\s+|\\s+$";"")) | map(select(length > 0))')"
jwks_uri="https://idp.example.test/realms/${provider_id}/protocol/openid-connect/certs"

# The generated entry uses the explicit form: `jwksUri` is fetched directly and
# `issuer` is absent. An entry carrying both is rejected at load
# (authz-agent-ADR-0075) — and the issuer here would in any case never be
# reachable, since these keys exist only on disk. The issuer stays in the
# manifest, where the minting side reads it as the `iss` claim to stamp.

jq -n \
  --arg provider_id "${provider_id}" \
  --arg issuer "${issuer}" \
  --arg jwks_uri "${jwks_uri}" \
  --argjson audiences "${audiences_json}" \
  '{
    providers: [
      {
        id: $provider_id,
        jwksUri: $jwks_uri,
        audiences: $audiences,
        required: true
      }
    ]
  }' > "${trusted_providers_file}"

jq -n \
  --arg provider_id "${provider_id}" \
  --arg issuer "${issuer}" \
  --arg kid "${kid}" \
  --arg private_key "${private_key}" \
  --arg public_key "${public_key}" \
  --arg jwks_file "${jwks_file}" \
  --arg trusted_providers_file "${trusted_providers_file}" \
  --argjson audiences "${audiences_json}" \
  '{
    providerId: $provider_id,
    issuer: $issuer,
    kid: $kid,
    audiences: $audiences,
    privateKey: $private_key,
    publicKey: $public_key,
    jwksFile: $jwks_file,
    trustedProvidersFile: $trusted_providers_file
  }' > "${manifest_file}"

echo "Generated token testkit assets:"
echo "  private key:       ${private_key}"
echo "  public key:        ${public_key}"
echo "  jwks:              ${jwks_file}"
echo "  trusted providers: ${trusted_providers_file}"
echo "  manifest:          ${manifest_file}"
