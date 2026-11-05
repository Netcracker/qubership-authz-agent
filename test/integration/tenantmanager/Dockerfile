FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /build
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -o /tenant-manager .

FROM ghcr.io/netcracker/qubership-core-base:alpine-2.5.11@sha256:1b80a6ba225210f2308c68679aa40e5211d4712269200a55862ec2a9061a55de
COPY --chmod=555 --from=builder /tenant-manager /usr/local/bin/tenant-manager
USER 10001:10001
EXPOSE 8080
# The binary is the entrypoint, as in the product images: the base image's
# entrypoint script loads certificates the emulator does not use.
ENTRYPOINT ["tenant-manager"]
