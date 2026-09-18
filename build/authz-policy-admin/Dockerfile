#
# authz-policy-admin: access-control v3 config API stand-in.
#
# Used by the automated test stacks and by its own Helm chart,
# helm-templates/authz-policy-admin (authz-agent-ADR-0073). The build context is
# the repository root, like the other images.

FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:4cb7ac979db5fcc41cae44b2227ba5ab8a51e8807f40d9ba4dee20a0ad960b5b AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
COPY components/ components/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -o /out/authz-policy-admin ./components/authz-policy-admin

FROM ghcr.io/netcracker/qubership-core-base:2.5.4@sha256:9e9c011ea0671546ae74d0a3b6e8740a8098087ddd98bd9a7b02d9ab802c9ba6

COPY --chmod=555 --from=builder /out/authz-policy-admin /usr/local/bin/authz-policy-admin

# No data directory here: the chart mounts a PersistentVolumeClaim at
# AUTHZ_POLICY_ADMIN_DATA_DIR, and the Compose stacks keep policies in memory.
USER 10001:10001

EXPOSE 18090

CMD ["authz-policy-admin"]
