# opa-embedded spike: OPA as a Go library behind the Fiber server of the
# Qubership core libraries. Drops into the chart's OPA container unchanged:
# same arguments, same mounts, same REST slice.
#
# Build context is the repository root:
#   docker build -f spike/opa-embedded/Dockerfile -t local/opa-embedded:ci .
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY spike/opa-embedded/go.mod spike/opa-embedded/go.sum ./
RUN go mod download
COPY spike/opa-embedded/ ./
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" GOWORK=off \
    go build -o /out/opa-embedded .

FROM ghcr.io/netcracker/qubership-core-base:2.4.2@sha256:78e39e1332035b539eb61f605a9a3b638ccad27b3c64ed0783f76b6b6d4de8c5
COPY --chmod=555 --from=builder /out/opa-embedded /usr/local/bin/opa-embedded
USER 10001:10001
# The chart passes `run --server ...` as the container args, so the binary is
# the entrypoint and receives them directly, instead of the base image's
# entrypoint that would try to exec `run`.
ENTRYPOINT ["/usr/local/bin/opa-embedded"]
