#
# authz-agent image: the authorization agent as one service. It embeds the
# Rego policies and the OPA library, serves the decision endpoints, and, until
# the chart switches, the slice of OPA's REST API the other containers use, so
# it can stand in for the OPA container.
#
# Build context is the repository root:
#   docker build -t authz-agent -f build/authz-agent/Dockerfile .
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS builder
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
FROM ghcr.io/netcracker/qubership-core-base:2.4.2@sha256:78e39e1332035b539eb61f605a9a3b638ccad27b3c64ed0783f76b6b6d4de8c5
COPY --chmod=555 --from=builder /out/authz-agent /usr/local/bin/authz-agent
USER 10001:10001
# The binary is the entrypoint rather than a CMD behind the base image's
# entrypoint script: the chart's OPA container passes OPA's command line as
# args, and the script would try to run its first word. The certificate
# loading of that script is not needed until the service talks TLS itself.
ENTRYPOINT ["/usr/local/bin/authz-agent"]
