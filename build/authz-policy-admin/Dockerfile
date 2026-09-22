#
# authz-policy-admin: access-control v3 config API stand-in.
#
# Used by the automated test stacks and by its own Helm chart,
# helm-templates/authz-policy-admin (authz-agent-ADR-0073). The build context is
# the repository root, like the other images.

FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
COPY components/ components/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -o /out/authz-policy-admin ./components/authz-policy-admin

FROM ghcr.io/netcracker/qubership-core-base:alpine-2.5.5@sha256:1e207c43e907165f9c55838bb853465357a28bfd50799cf4aa66b959fe72a836

COPY --chmod=555 --from=builder /out/authz-policy-admin /usr/local/bin/authz-policy-admin

# No data directory here: the chart mounts a PersistentVolumeClaim at
# AUTHZ_POLICY_ADMIN_DATA_DIR, and the Compose stacks keep policies in memory.
USER 10001:10001

EXPOSE 18090

CMD ["authz-policy-admin"]
