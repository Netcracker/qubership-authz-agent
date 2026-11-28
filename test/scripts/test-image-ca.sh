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

# Runs the agent image the way the chart runs it and checks that a private CA
# under /tmp/cert is trusted: a read-only root file system, all capabilities
# dropped, a uid and a gid other than the image's, writable directories where
# the chart mounts emptyDir volumes, and the CA in the layout a Secret volume
# has (a key that links through ..data into a timestamped directory).
#
# The agent gets two required trusted providers: a JWKS server whose
# certificate a test CA signed, and a public JWKS endpoint, so the run also
# shows that the public CAs of the image stay trusted. /health answers 200 only
# when the agent has loaded the keys of both.
#
# The same run with the agent binary as the entrypoint must not become healthy:
# that is what an image that bypasses the base image's entrypoint does.
#
# Usage: test/scripts/test-image-ca.sh [image]   (default: local/authz-agent:ci)
# Needs docker, openssl, and python3, and network access to
# https://www.googleapis.com.

set -euo pipefail

IMAGE="${1:-local/authz-agent:ci}"
NGINX_IMAGE="nginx:1.29-alpine@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de"
PUBLIC_JWKS_URI="https://www.googleapis.com/oauth2/v3/certs"
WAIT_SECONDS=60

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "error: required command not found: ${cmd}" >&2
    exit 1
  fi
}

require_cmd docker
require_cmd openssl
require_cmd python3

failures=0

fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

pass() {
  echo "ok: $*"
}

work="$(mktemp -d)"
network="image-ca-$$"
containers=()
cleanup() {
  if [[ "${#containers[@]}" -gt 0 ]]; then
    docker rm -f -v "${containers[@]}" >/dev/null 2>&1 || true
  fi
  docker network rm "${network}" >/dev/null 2>&1 || true
  rm -rf "${work}"
}
trap cleanup EXIT

# A test CA, and a certificate for the JWKS server, whose name on the docker
# network is jwks.
mkdir -p "${work}/tls" "${work}/authz"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "${work}/ca.key" -out "${work}/ca.crt" -days 1 \
  -subj "/CN=authz-agent image-ca test CA" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "${work}/tls/tls.key" -out "${work}/tls.csr" -subj "/CN=jwks" 2>/dev/null
printf 'subjectAltName=DNS:jwks\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' >"${work}/tls.ext"
openssl x509 -req -in "${work}/tls.csr" -CA "${work}/ca.crt" -CAkey "${work}/ca.key" -CAcreateserial \
  -out "${work}/tls/tls.crt" -days 1 -extfile "${work}/tls.ext" 2>/dev/null

# A JWKS with the public key of a separate RSA signing key.
openssl genrsa -out "${work}/signing.key" 2048 2>/dev/null
openssl rsa -in "${work}/signing.key" -noout -modulus | cut -d= -f2 | python3 -I -c '
import base64, json, sys
n = bytes.fromhex(sys.stdin.read().strip())
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
print(json.dumps({"keys": [{"kty": "RSA", "kid": "image-ca", "use": "sig", "alg": "RS256",
                            "n": b64(n), "e": b64((65537).to_bytes(3, "big"))}]}))
' >"${work}/tls/jwks.json"

cat >"${work}/tls/default.conf" <<'EOF'
server {
  listen 8443 ssl;
  ssl_certificate /etc/nginx/tls/tls.crt;
  ssl_certificate_key /etc/nginx/tls/tls.key;
  location = /jwks.json { root /etc/nginx/tls; default_type application/json; }
}
EOF

cat >"${work}/authz/trusted-providers.json" <<EOF
{"providers": [
  {"id": "private-ca", "jwksUri": "https://jwks:8443/jwks.json", "required": true},
  {"id": "public-ca", "jwksUri": "${PUBLIC_JWKS_URI}", "required": true}
]}
EOF

# The CA in the layout of a Secret volume: the key is a link through ..data
# into a timestamped directory, as the kubelet writes it.
mkdir -p "${work}/cert/..2026_01_01_00_00_00.000000001"
cp "${work}/ca.crt" "${work}/cert/..2026_01_01_00_00_00.000000001/corporate-ca.crt"
ln -s ..2026_01_01_00_00_00.000000001 "${work}/cert/..data"
ln -s ..data/corporate-ca.crt "${work}/cert/corporate-ca.crt"
chmod -R a+rX "${work}"

docker network create "${network}" >/dev/null
jwks="$(docker run -d --name "jwks-${network}" --network "${network}" --network-alias jwks \
  -v "${work}/tls:/etc/nginx/tls:ro" -v "${work}/tls/default.conf:/etc/nginx/conf.d/default.conf:ro" \
  "${NGINX_IMAGE}")"
containers+=("${jwks}")

# The agent loads its keys once at start, so the JWKS server has to answer
# before the first agent starts.
deadline=$((SECONDS + WAIT_SECONDS))
until docker exec "${jwks}" curl -sk -o /dev/null https://localhost:8443/jwks.json 2>/dev/null; do
  if ((SECONDS >= deadline)); then
    echo "error: the JWKS server did not answer https://localhost:8443/jwks.json within ${WAIT_SECONDS}s:" >&2
    docker logs "${jwks}" 2>&1 | tail -20 >&2
    exit 1
  fi
  sleep 1
done

# run_agent <label> [docker run options...]: starts the agent under the
# chart's restrictions and prints the container id.
run_agent() {
  local label="$1"
  shift
  docker run -d --name "agent-${label}-${network}" --network "${network}" \
    --read-only --cap-drop ALL --security-opt no-new-privileges:true --user 1000770000:1000770000 \
    --tmpfs /usr/local/share/ca-certificates:mode=1777 --tmpfs /etc/ssl/certs:mode=1777 --tmpfs /app/nss:mode=1777 \
    -v "${work}/cert:/tmp/cert:ro" -v "${work}/authz:/etc/authz:ro" \
    -e AUTHZ_TRUSTED_PROVIDERS_FILE=/etc/authz/trusted-providers.json -e SIGTERM_EXIT_DELAY=0 \
    "$@" "${IMAGE}"
}

# running <container>: succeeds while the container runs.
running() {
  local container="$1"
  [[ "$(docker inspect --format '{{.State.Running}}' "${container}" 2>/dev/null)" == true ]]
}

# bootstrap_line <container>: waits until the agent logs the outcome of its
# first bootstrap and prints that line, or prints nothing once the container
# has stopped or after WAIT_SECONDS.
bootstrap_line() {
  local container="$1" deadline=$((SECONDS + WAIT_SECONDS)) line
  while ((SECONDS < deadline)); do
    line="$(docker logs "${container}" 2>&1 | grep -o 'trusted providers: [0-9]* of [0-9]* providers bootstrapped' | head -1 || true)"
    if [[ -n "${line}" ]]; then
      echo "${line}"
      return
    fi
    running "${container}" || return 0
    sleep 1
  done
}

# health <container>: prints the status /health answers, polling until the
# listener answers at all, or prints none once the container has stopped or
# after WAIT_SECONDS.
health() {
  local container="$1" deadline=$((SECONDS + WAIT_SECONDS)) status
  while ((SECONDS < deadline)); do
    status="$(docker exec "${container}" curl -s -m 2 -o /dev/null -w '%{http_code}' localhost:8181/health 2>/dev/null || true)"
    if [[ -n "${status}" && "${status}" != 000 ]]; then
      echo "${status}"
      return
    fi
    running "${container}" || break
    sleep 1
  done
  echo none
}

# Behind the base image's entrypoint, as the image runs by default.
agent="$(run_agent entrypoint)"
containers+=("${agent}")
line="$(bootstrap_line "${agent}")"
status="$(health "${agent}")"
if [[ "${line}" == "trusted providers: 2 of 2 providers bootstrapped" && "${status}" == 200 ]]; then
  pass "${IMAGE} trusts the CA under /tmp/cert and the public CAs of its image"
else
  fail "${IMAGE} under the chart's restrictions logged '${line:-no bootstrap line within ${WAIT_SECONDS}s}' and /health answered ${status}, expected 2 of 2 providers and 200. A provider that failed to load is named in the log below; 'private-ca' means the CA under /tmp/cert did not reach the trust store, 'public-ca' that the image's own CAs did not or ${PUBLIC_JWKS_URI} is unreachable. Check that the image runs the base image's entrypoint (docker inspect --format '{{.Config.Entrypoint}} {{.Config.Cmd}}' ${IMAGE}) and look for 'Error updating CA certificates store' in the log:"
  docker logs "${agent}" 2>&1 | tail -40 >&2
fi

# The same run with the binary as the entrypoint. Without the base image's
# entrypoint nothing builds the trust store, so this run must not become
# healthy. If it does, the check of the default run cannot detect an image that
# bypasses the entrypoint.
bypass="$(run_agent bypass --entrypoint /usr/local/bin/authz-agent)"
containers+=("${bypass}")
line="$(bootstrap_line "${bypass}")"
status="$(health "${bypass}")"
if [[ "${line}" != "trusted providers: 2 of 2 providers bootstrapped" && "${status}" != 200 ]]; then
  pass "the same run without the base image's entrypoint does not become healthy"
else
  fail "the same run with --entrypoint /usr/local/bin/authz-agent logged '${line}' and /health answered ${status}, so the check of the default run cannot tell whether the base image's entrypoint built the trust store"
fi

if [[ "${failures}" -gt 0 ]]; then
  echo "image CA checks: ${failures} failed" >&2
  exit 1
fi
echo "image CA checks: all passed"
