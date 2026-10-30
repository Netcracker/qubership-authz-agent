# Runtime-suite image for the kind end-to-end run.
#
# Compiles the Testify suite once (go test -c) and ships the binary with the
# files it reads at run time: testdata/, api/openapi.yaml, and test/readme.md.
# The image keeps the repository layout under /app because the suite resolves
# those files by relative path from its own directory. Build with the
# repository root as the context:
#   docker build -t local/authz-runtime-suite:ci -f test/integration/testify/Dockerfile .

FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src/test/integration/testify
COPY test/integration/testify/go.mod test/integration/testify/go.sum ./
RUN go mod download
COPY test/integration/testify/ ./
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go test -c -tags integration -o /out/runtime.test .

FROM ghcr.io/netcracker/qubership-core-base:alpine-2.5.9@sha256:ab860790e4ecce56f8df673495cd5745ce587fffa7d7eb210d6d098563ccb26d

# Everything the image ships stays root-owned: the inputs world-readable, the
# binary world-executable, so the runtime uid can run it but not change it.
COPY api/openapi.yaml /app/api/openapi.yaml
COPY test/readme.md /app/test/readme.md
COPY test/integration/testify/testdata/ /app/test/integration/testify/testdata/
COPY --chmod=555 --from=builder /out/runtime.test /app/test/integration/testify/runtime.test

WORKDIR /app/test/integration/testify
USER 10001:10001

# The base image's entrypoint execs its arguments, so a caller passing its own
# flags passes the binary too — see suite.args in
# test/k8s/test-stand-values.yaml.
CMD ["./runtime.test"]
