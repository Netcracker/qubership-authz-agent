#
# token-fetcher sidecar image: obtains a Keycloak client_credentials token and
# keeps it refreshed on disk for the pap-client container's policy pull loop.
# Multi-stage pattern matching other images in build/.

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
COPY components/token-fetcher/ components/token-fetcher/
COPY internal/atomicfile/ internal/atomicfile/
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build \
    -o /out/token-fetcher ./components/token-fetcher

FROM ghcr.io/netcracker/qubership-core-base:2.4.2@sha256:78e39e1332035b539eb61f605a9a3b638ccad27b3c64ed0783f76b6b6d4de8c5

COPY --chown=10001:0 --chmod=555 --from=builder /out/token-fetcher /usr/local/bin/token-fetcher

# Mount points, pre-created so a Docker named volume inherits their ownership:
# /etc/secret        — client-credentials Secret (read-only)
# /etc/authz/ac-token — the token file pap-client reads
# /var/run/authz     — the startup marker the pap-client container waits for
# Owner 10001 for Compose, group 0 with group write for OpenShift.
USER root
RUN mkdir -p /etc/secret /var/run/authz /etc/authz/ac-token \
    && chown 10001:0 /etc/secret /var/run/authz /etc/authz/ac-token \
    && chmod 775 /var/run/authz /etc/authz/ac-token
USER 10001:10001

CMD ["token-fetcher"]
