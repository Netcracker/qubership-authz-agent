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
OPA_VERSION="${OPA_VERSION:-1.14.0}"
OPA_BIN_DIR="${OPA_BIN_DIR:-${ROOT_DIR}/test/tools/opa}"
OPA_BIN_PATH="${OPA_BIN_DIR}/opa"

fail() {
  echo "error: $*" >&2
  exit 1
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "required command not found: $1"
  fi
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${file}" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${file}" | awk '{print $1}'
    return
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "${file}" | awk '{print $NF}'
    return
  fi
  fail "no SHA256 tool found (sha256sum/shasum/openssl)"
}

detect_platform() {
  local os
  local arch
  local suffix

  os="$(uname -s)"
  arch="$(uname -m)"

  case "${os}" in
    Linux) os="linux" ;;
    Darwin) os="darwin" ;;
    *)
      fail "unsupported OS: ${os} (supported: Linux, Darwin)"
      ;;
  esac

  case "${arch}" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
      fail "unsupported architecture: ${arch} (supported: amd64, arm64)"
      ;;
  esac

  suffix=""
  if [[ "${os}" == "linux" ]]; then
    suffix="_static"
  fi

  echo "${os}_${arch}${suffix}"
}

require_cmd curl
require_cmd awk
require_cmd install

OPA_PLATFORM="${OPA_PLATFORM:-$(detect_platform)}"
OPA_DOWNLOAD_URL="https://openpolicyagent.org/downloads/v${OPA_VERSION}/opa_${OPA_PLATFORM}"
OPA_DOWNLOAD_SHA_URL="${OPA_DOWNLOAD_URL}.sha256"

tmp_bin="$(mktemp)"
tmp_sha="$(mktemp)"
cleanup() {
  rm -f "${tmp_bin}" "${tmp_sha}"
}
trap cleanup EXIT

echo "Installing OPA v${OPA_VERSION} (${OPA_PLATFORM})"
echo "Download URL: ${OPA_DOWNLOAD_URL}"

curl -fsSL "${OPA_DOWNLOAD_URL}" -o "${tmp_bin}"
curl -fsSL "${OPA_DOWNLOAD_SHA_URL}" -o "${tmp_sha}"

expected_sha="$(awk '{print $1}' "${tmp_sha}")"
actual_sha="$(sha256_file "${tmp_bin}")"

if [[ -z "${expected_sha}" ]]; then
  fail "empty checksum from ${OPA_DOWNLOAD_SHA_URL}"
fi

if [[ "${actual_sha}" != "${expected_sha}" ]]; then
  fail "checksum mismatch for downloaded OPA binary"
fi

mkdir -p "${OPA_BIN_DIR}"
install -m 0755 "${tmp_bin}" "${OPA_BIN_PATH}"

echo "Installed: ${OPA_BIN_PATH}"
"${OPA_BIN_PATH}" version
