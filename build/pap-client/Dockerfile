#
# pap-client image: the Policy Administration Point client that bootstraps
# JWKS data, pulls/watches policies and PIPs, writes them to the shared
# opa-data volume, and pushes them into OPA's Data API.
#
# OPA itself runs as the vanilla upstream openpolicyagent/opa image.
# This image carries only the pap-client binary; it is NOT bundled with OPA.
#
# Build contexts (passed with -f flag, context = repo root):
#   COPY go.mod go.sum ./
#   COPY components/ components/
#   COPY internal/ internal/

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS pap_client_builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
COPY components/ components/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -o /out/pap-client ./components/pap-client

# The platform base image: CA bundle, entrypoint that loads extra
# certificates, uid 10001 in the root group.
FROM ghcr.io/netcracker/qubership-core-base:2.4.2@sha256:78e39e1332035b539eb61f605a9a3b638ccad27b3c64ed0783f76b6b6d4de8c5

COPY --chown=10001:0 --chmod=555 --from=pap_client_builder /out/pap-client /usr/local/bin/pap-client

# Pre-create the directories that are later mounted as Docker or Kubernetes
# volumes. Docker copies the directory metadata from the image into a new named
# volume on first mount, so the volume root inherits this ownership rather than
# root's. Owner 10001 serves a plain Kubernetes install and Compose; group 0
# with group write serves OpenShift, where the uid is arbitrary and the gid is 0.
#
# /etc/opa/data   — shared opa-data volume: policies, JWKS, opa-auth-secret.json
# /var/run/authz  — authz-run volume: bootstrap-status.json
USER root
RUN mkdir -p /etc/opa/data /var/run/authz \
    && chown 10001:0 /etc/opa/data /var/run/authz \
    && chmod 775 /etc/opa/data /var/run/authz
USER 10001:10001

# The base image's entrypoint execs its arguments, so a subcommand is passed
# with the binary rather than on its own:
#   pap-client bootstrap   — writes JWKS and opa-auth-secret.json; used as init container.
#   pap-client healthcheck — liveness check (OPA + JWKS bootstrap).
#   pap-client healthcheck --readiness — adds the policiesLoaded latch gate.
CMD ["pap-client"]
