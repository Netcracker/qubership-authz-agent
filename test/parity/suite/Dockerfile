# Parity-suite image for the kind run.
#
# Compiles the replay suite once (go test -c) and ships the binary with the
# golden files, fixtures and accepted divergences it reads from testdata/ by
# relative path. Build with this directory as the context:
#   docker build -t local/authz-parity-suite:ci -f test/parity/suite/Dockerfile test/parity/suite

FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine3.24@sha256:fa4881266890ef051f0ce63afdfaccb69bbe8186084387f4fafd60d7ecbabc71 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go test -c -tags integration -o /out/parity.test .

FROM ghcr.io/netcracker/qubership-core-base:alpine-2.5.11@sha256:1b80a6ba225210f2308c68679aa40e5211d4712269200a55862ec2a9061a55de

# Everything the image ships stays root-owned: the inputs world-readable, the
# binary world-executable, so the runtime uid can run it but not change it.
COPY testdata/ /app/test/parity/suite/testdata/
COPY --chmod=555 --from=builder /out/parity.test /app/test/parity/suite/parity.test

WORKDIR /app/test/parity/suite
USER 10001:10001

CMD ["./parity.test"]
