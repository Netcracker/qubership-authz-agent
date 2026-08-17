#!/bin/sh

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

# Render Envoy and OPA runtime configs for the Compose-based test stacks.
#
# Reads placeholder templates from
#   charts/authz-agent/files/{envoy/envoy.yaml.tmpl,
#                                     opa/opa-config.yaml.tmpl}
# and writes hostname-substituted output to
#   test/.runtime-configs/{envoy/envoy.yaml, opa/opa-config.yaml}
# (gitignored).
#
# The same templates are rendered for K8s by
# charts/authz-agent/templates/configmap.yaml via Helm `replace`,
# with all hosts mapped to 127.0.0.1 (Pod loopback). Defaults below match
# the Compose split topology: each process is its own Compose service.
#
# Override any host via env var:
#   OPA_HOST=opa COLLECTOR_HOST=decision-log-collector PAP_CLIENT_HOST=opa \
#     test/scripts/render-runtime-configs.sh

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SRC_DIR="${REPO_ROOT}/charts/authz-agent/files"
OUT_DIR="${REPO_ROOT}/test/.runtime-configs"

OPA_HOST="${OPA_HOST:-opa}"
COLLECTOR_HOST="${COLLECTOR_HOST:-decision-log-collector}"
PAP_CLIENT_HOST="${PAP_CLIENT_HOST:-opa}"

mkdir -p "${OUT_DIR}/envoy" "${OUT_DIR}/opa"

sed \
    -e "s/__PAP_CLIENT_HOST__/${PAP_CLIENT_HOST}/g" \
    -e "s/__OPA_HOST__/${OPA_HOST}/g" \
    -e "s/__COLLECTOR_HOST__/${COLLECTOR_HOST}/g" \
    "${SRC_DIR}/envoy/envoy.yaml.tmpl" > "${OUT_DIR}/envoy/envoy.yaml"

sed \
    -e "s/__COLLECTOR_HOST__/${COLLECTOR_HOST}/g" \
    "${SRC_DIR}/opa/opa-config.yaml.tmpl" > "${OUT_DIR}/opa/opa-config.yaml"

echo "rendered: ${OUT_DIR}/envoy/envoy.yaml"
echo "rendered: ${OUT_DIR}/opa/opa-config.yaml"
echo "  OPA_HOST=${OPA_HOST}"
echo "  COLLECTOR_HOST=${COLLECTOR_HOST}"
echo "  PAP_CLIENT_HOST=${PAP_CLIENT_HOST}"
