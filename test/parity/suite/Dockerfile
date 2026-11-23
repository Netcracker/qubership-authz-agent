# Parity-suite image for the kind run.
#
# Compiles the replay suite once (go test -c) and ships the binary with the
# golden files, fixtures and accepted divergences it reads from testdata/ by
# relative path. Build with this directory as the context:
#   docker build -t local/authz-parity-suite:ci -f test/parity/suite/Dockerfile test/parity/suite

FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go test -c -tags integration -o /out/parity.test .

FROM ghcr.io/netcracker/qubership-core-base:alpine-2.5.15@sha256:a3af3751d9187ce7f8ffd67a5aa8465fee78056c79f964bfa7727ea00da681da

# Everything the image ships stays root-owned: the inputs world-readable, the
# binary world-executable, so the runtime uid can run it but not change it.
COPY testdata/ /app/test/parity/suite/testdata/
COPY --chmod=555 --from=builder /out/parity.test /app/test/parity/suite/parity.test

WORKDIR /app/test/parity/suite
USER 10001:10001

CMD ["./parity.test"]
