# Parity-suite image for the kind run.
#
# Compiles the replay suite once (go test -c) and ships the binary with the
# golden files, fixtures and accepted divergences it reads from testdata/ by
# relative path. The suite module replaces authz-agent/test/suitecheck with
# ../../suitecheck, so the build keeps the repository layout under /src. Build
# with the repository root as the context:
#   docker build -t local/authz-parity-suite:ci -f test/parity/suite/Dockerfile .

FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src/test/parity/suite
COPY test/suitecheck/ /src/test/suitecheck/
COPY test/parity/suite/go.mod test/parity/suite/go.sum ./
RUN go mod download
COPY test/parity/suite/ ./
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go test -c -tags integration -o /out/parity.test .

FROM ghcr.io/netcracker/qubership-core-base:alpine-2.6.1@sha256:7be670fc57c243195c63597106413e1b0365381c2d186a71cb6d12fcffc2278b

# Everything the image ships stays root-owned: the inputs world-readable, the
# binary world-executable, so the runtime uid can run it but not change it.
COPY test/parity/suite/testdata/ /app/test/parity/suite/testdata/
COPY --chmod=555 --from=builder /out/parity.test /app/test/parity/suite/parity.test

WORKDIR /app/test/parity/suite
USER 10001:10001

CMD ["./parity.test"]
