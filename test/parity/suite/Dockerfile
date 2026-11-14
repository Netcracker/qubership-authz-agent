# Parity-suite image for the kind run.
#
# Compiles the replay suite once (go test -c) and ships the binary with the
# golden files, fixtures and accepted divergences it reads from testdata/ by
# relative path. Build with this directory as the context:
#   docker build -t local/authz-parity-suite:ci -f test/parity/suite/Dockerfile test/parity/suite
#
# The image of the export-fed profile also ships an export bundle, under
# testdata/export-bundle, from a build context of that name:
#   docker build --build-context export-bundle=<bundle dir> \
#     -t local/authz-parity-suite-export:ci -f test/parity/suite/Dockerfile test/parity/suite
# Without it the stage below is empty and the image carries no bundle;
# .dockerignore keeps a bundle under testdata/ out of the build context.

FROM scratch AS export-bundle

FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go test -c -tags integration -o /out/parity.test .

FROM ghcr.io/netcracker/qubership-core-base:alpine-2.5.13@sha256:891386ea91d90a1376e12f30b458fc23eb9793afd35f82817c90e4911cddd633

# Everything the image ships stays root-owned: the inputs world-readable, the
# binary world-executable, so the runtime uid can run it but not change it.
COPY testdata/ /app/test/parity/suite/testdata/
COPY --from=export-bundle / /app/test/parity/suite/testdata/export-bundle/
COPY --chmod=555 --from=builder /out/parity.test /app/test/parity/suite/parity.test

WORKDIR /app/test/parity/suite
USER 10001:10001

CMD ["./parity.test"]
