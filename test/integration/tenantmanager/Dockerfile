FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /build
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -o /tenant-manager .

FROM ghcr.io/netcracker/qubership-core-base:alpine-2.5.13@sha256:891386ea91d90a1376e12f30b458fc23eb9793afd35f82817c90e4911cddd633
COPY --chmod=555 --from=builder /tenant-manager /usr/local/bin/tenant-manager
USER 10001:10001
EXPOSE 8080
# The binary is the entrypoint, as in the product images: the base image's
# entrypoint script loads certificates the emulator does not use.
ENTRYPOINT ["tenant-manager"]
