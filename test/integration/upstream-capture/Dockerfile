FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /build
COPY main.go .
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -o /upstream-capture main.go

FROM ghcr.io/netcracker/qubership-core-base:2.4.2@sha256:78e39e1332035b539eb61f605a9a3b638ccad27b3c64ed0783f76b6b6d4de8c5
COPY --chown=10001:0 --chmod=555 --from=builder /upstream-capture /usr/local/bin/upstream-capture
USER 10001:10001
EXPOSE 9090
CMD ["upstream-capture"]
