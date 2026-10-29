#
# authz-policy-admin: access-control v3 config API stand-in.
#
# Used by the automated test stacks and by its own Helm chart,
# helm-templates/authz-policy-admin (authz-agent-ADR-0073). The build context is
# the repository root, like the other images.

FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
COPY components/ components/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -o /out/authz-policy-admin ./components/authz-policy-admin

FROM ghcr.io/netcracker/qubership-core-base:alpine-2.5.9@sha256:ab860790e4ecce56f8df673495cd5745ce587fffa7d7eb210d6d098563ccb26d

COPY --chmod=555 --from=builder /out/authz-policy-admin /usr/local/bin/authz-policy-admin

# No data directory here: the chart mounts a PersistentVolumeClaim at
# AUTHZ_POLICY_ADMIN_DATA_DIR, and the Compose stacks keep policies in memory.
USER 10001:10001

EXPOSE 18090

CMD ["authz-policy-admin"]
