#
# authz-policy-admin: access-control v3 config API stand-in.
#
# Used by the automated test stacks and by the optional AUTHZ_POLICY_ADMIN_ENABLED
# deployment in the Helm chart (authz-agent-ADR-0073). The build context is the
# repository root, like the other images.

FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
COPY components/ components/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -o /out/authz-policy-admin ./components/authz-policy-admin

FROM ghcr.io/netcracker/qubership-core-base:2.5.0@sha256:d81cd148d874afea869c540defc632ff0bba36d90c809eaec3db0fcdd82ac7a5

COPY --chmod=555 --from=builder /out/authz-policy-admin /usr/local/bin/authz-policy-admin

# No data directory here: the chart mounts a PersistentVolumeClaim at
# AUTHZ_POLICY_ADMIN_DATA_DIR, and the Compose stacks keep policies in memory.
USER 10001:10001

EXPOSE 18090

CMD ["authz-policy-admin"]
