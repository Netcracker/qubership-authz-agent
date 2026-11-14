#
# authz-agent image: the authorization agent as one service. It embeds the
# Rego policies and the OPA library, and serves the check API.
#
# Build context is the repository root:
#   docker build -t authz-agent -f build/authz-agent/Dockerfile .
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder
ARG TARGETOS
ARG TARGETARCH
# The Go build tags; empty in a release. The parity stand builds with
# paritytest, which adds POST /internal/v1/pull to the internal port.
ARG GO_BUILD_TAGS=""
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY components/ components/
COPY internal/ internal/
COPY policies/ policies/
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -tags "${GO_BUILD_TAGS}" -o /out/authz-agent ./components/authz-agent

# The platform base image: CA bundle, uid 10001 in the root group.
FROM ghcr.io/netcracker/qubership-core-base:alpine-2.5.13@sha256:891386ea91d90a1376e12f30b458fc23eb9793afd35f82817c90e4911cddd633
COPY --chmod=555 --from=builder /out/authz-agent /usr/local/bin/authz-agent
USER 10001:10001
# The binary is the command of the base image's entrypoint. The entrypoint adds
# the CA certificates found under /tmp/cert to the system trust store, runs the
# scripts in /app/init.d, and forwards signals to the agent. It holds SIGTERM
# back for SIGTERM_EXIT_DELAY seconds, 10 by default.
CMD ["authz-agent"]
