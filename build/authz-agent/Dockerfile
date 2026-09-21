#
# authz-agent image: the authorization agent as one service. It embeds the
# Rego policies and the OPA library, and serves the check API, the canonical
# authorize route, and the data API.
#
# Build context is the repository root:
#   docker build -t authz-agent -f build/authz-agent/Dockerfile .
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS builder
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
FROM ghcr.io/netcracker/qubership-core-base:2.5.4@sha256:9e9c011ea0671546ae74d0a3b6e8740a8098087ddd98bd9a7b02d9ab802c9ba6
COPY --chmod=555 --from=builder /out/authz-agent /usr/local/bin/authz-agent
USER 10001:10001
# The binary is the entrypoint rather than a CMD behind the base image's
# entrypoint script, whose certificate loading is not needed until the service
# talks TLS itself.
ENTRYPOINT ["/usr/local/bin/authz-agent"]
