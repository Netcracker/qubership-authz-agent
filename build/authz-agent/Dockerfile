#
# authz-agent image: the authorization agent as one service. It embeds the
# Rego policies and the OPA library, and serves the check API, the canonical
# authorize route, and the data API.
#
# Build context is the repository root:
#   docker build -t authz-agent -f build/authz-agent/Dockerfile .
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:4cb7ac979db5fcc41cae44b2227ba5ab8a51e8807f40d9ba4dee20a0ad960b5b AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY components/ components/
COPY internal/ internal/
COPY policies/ policies/
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -o /out/authz-agent ./components/authz-agent

# The platform base image: CA bundle, uid 10001 in the root group.
FROM ghcr.io/netcracker/qubership-core-base:2.5.3@sha256:51063717c4536e8e6ee7afc2d1e0bee6f4c12237e818d6112cf55e149d6cbeca
COPY --chmod=555 --from=builder /out/authz-agent /usr/local/bin/authz-agent
USER 10001:10001
# The binary is the entrypoint rather than a CMD behind the base image's
# entrypoint script, whose certificate loading is not needed until the service
# talks TLS itself.
ENTRYPOINT ["/usr/local/bin/authz-agent"]
