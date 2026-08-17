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

FROM alpine:3.21
RUN apk add --no-cache ca-certificates

COPY --from=pap_client_builder /out/pap-client /usr/local/bin/pap-client

# Pre-create the directories that are later bind-mounted as Docker or
# Kubernetes volumes, and set them to uid 1000 while we are still root.
# Docker copies the directory metadata from the image into a new named volume
# on first mount, so the volume root inherits uid 1000 ownership rather than
# root. Without this, Docker creates the mount point as root-owned (755) and
# the non-root pap-client binary cannot write to it.
#
# /etc/opa/data   — shared opa-data volume: policies, JWKS, opa-auth-secret.json
# /var/run/authz  — authz-run volume: bootstrap-status.json
RUN mkdir -p /etc/opa/data /var/run/authz \
    && chown 1000:1000 /etc/opa/data /var/run/authz

# Run as uid 1000 to match the OPA image's default uid. This lets the
# shared opa-data emptyDir carry 0o600 files (opa-auth-secret.json) that
# both containers read without relaxing permissions beyond the volume.
USER 1000

# Default entrypoint: running without args starts the pap-client HTTP server.
# Subcommands:
#   pap-client bootstrap   — writes JWKS and opa-auth-secret.json; used as init container.
#   pap-client healthcheck — liveness check (OPA + JWKS bootstrap).
#   pap-client healthcheck --readiness — adds the policiesLoaded latch gate.
ENTRYPOINT ["/usr/local/bin/pap-client"]
