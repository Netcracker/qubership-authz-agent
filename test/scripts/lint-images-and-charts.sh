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

# Lints the charts under helm-templates/ with helm lint, lints every
# Dockerfile with hadolint, validates the rendered manifests of the three
# charts with kubeconform -strict, and scans the rendered product charts
# (authz-agent, authz-policy-admin) with trivy config. The test-stand chart is
# a test fixture and gets the schema check only.
#
# --lint-only runs helm lint and nothing else. The chart job of
# .github/workflows/integration-tests.yaml runs it once per Helm version.
#
# for_each_chart below is the one list of charts and their values files; the
# script fails on a chart under helm-templates/ that the list leaves out. The
# test-stand chart needs its generated files first: run
# `make test-stand-files`.
#
# hadolint, kubeconform, and trivy come from PATH. mise.toml pins their
# versions; `mise install` installs them.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

# The Kubernetes version whose API schemas kubeconform validates against.
KUBERNETES_VERSION="${KUBERNETES_VERSION:-1.34.0}"

lint_only=false
case "${1:-}" in
  "") ;;
  --lint-only) lint_only=true ;;
  *)
    echo "usage: $0 [--lint-only]" >&2
    exit 2
    ;;
esac

# Calls "$@" once per chart and values set, with the chart directory name, the
# file the render goes to (product/ is scanned by trivy, test-stand/ is not),
# and the values arguments.
for_each_chart() {
  "$@" authz-agent product/authz-agent.yaml \
    -f helm-templates/authz-agent/resource-profiles/dev.yaml -f test/k8s/values.yaml
  "$@" authz-policy-admin product/authz-policy-admin.yaml \
    -f helm-templates/authz-policy-admin/resource-profiles/dev.yaml -f test/k8s/policy-admin-values.yaml
  "$@" authz-test-stand test-stand/e2e.yaml -f test/k8s/test-stand-values.yaml
  "$@" authz-test-stand test-stand/parity.yaml -f test/k8s/parity/test-stand-values.yaml
}

listed=()
list_chart() { listed+=("$1"); }
for_each_chart list_chart
for chart_yaml in helm-templates/*/Chart.yaml; do
  chart="$(basename "$(dirname "${chart_yaml}")")"
  if [[ " ${listed[*]} " != *" ${chart} "* ]]; then
    echo "error: chart ${chart} is not linted; add it to for_each_chart in $0" >&2
    exit 1
  fi
done

if [[ ! -d helm-templates/authz-test-stand/files ]]; then
  echo "error: helm-templates/authz-test-stand/files is missing; run 'make test-stand-files' first" >&2
  exit 1
fi

lint_chart() {
  local chart="$1"
  shift 2
  helm lint "helm-templates/${chart}" "$@"
}

echo "[helm lint] charts, $(helm version --short)"
for_each_chart lint_chart
if [[ "${lint_only}" == true ]]; then
  exit 0
fi

for tool in hadolint kubeconform trivy; do
  if ! command -v "${tool}" >/dev/null; then
    echo "error: ${tool} is not on PATH; run 'mise install' (see mise.toml)" >&2
    exit 1
  fi
done

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
mkdir -p "${work}/product" "${work}/test-stand"

echo "[hadolint] Dockerfiles"
git ls-files -z '*Dockerfile' | xargs -0 hadolint

render_chart() {
  local chart="$1" out="$2"
  shift 2
  helm template "${chart}" "helm-templates/${chart}" "$@" > "${work}/${out}"
}

echo "[helm template] charts"
for_each_chart render_chart

echo "[kubeconform] rendered charts, Kubernetes ${KUBERNETES_VERSION}"
kubeconform -strict -summary -kubernetes-version "${KUBERNETES_VERSION}" \
  "${work}/product" "${work}/test-stand"

# --skip-check-update with an empty cache directory uses the checks built
# into the pinned trivy binary. With the default cache, trivy would load
# whatever checks an earlier run downloaded there.
echo "[trivy config] rendered product charts"
trivy config --quiet --skip-check-update --cache-dir "${work}/trivy-cache" --exit-code 1 \
  --ignorefile .github/linters/.trivyignore.yaml \
  "${work}/product"
