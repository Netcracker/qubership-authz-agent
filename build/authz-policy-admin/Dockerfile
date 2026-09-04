#
# authz-policy-admin: access-control v3 config API stand-in.
#
# Used by the automated test stacks and by the optional AUTHZ_POLICY_ADMIN_ENABLED
# deployment in the Helm chart (authz-agent-ADR-0073). The build context is the
# repository root, like the other images.

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
COPY components/ components/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -o /out/authz-policy-admin ./components/authz-policy-admin

FROM ghcr.io/netcracker/qubership-core-base:2.4.2@sha256:78e39e1332035b539eb61f605a9a3b638ccad27b3c64ed0783f76b6b6d4de8c5

COPY --chown=10001:0 --chmod=555 --from=builder /out/authz-policy-admin /usr/local/bin/authz-policy-admin

# No data directory here: the chart mounts a PersistentVolumeClaim at
# AUTHZ_POLICY_ADMIN_DATA_DIR, and the Compose stacks keep policies in memory.
USER 10001:10001

EXPOSE 18090

CMD ["authz-policy-admin"]
