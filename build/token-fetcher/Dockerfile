#
# token-fetcher sidecar image: obtains a Keycloak client_credentials token and
# keeps it refreshed on disk for the pap-client container's policy pull loop.
# Multi-stage pattern matching other images in build/.

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
COPY components/token-fetcher/ components/token-fetcher/
COPY internal/atomicfile/ internal/atomicfile/
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build \
    -o /out/token-fetcher ./components/token-fetcher

FROM alpine:3.21

RUN apk add --no-cache ca-certificates \
  && mkdir -p /etc/secret /var/run/authz /etc/authz/ac-token

COPY --from=builder /out/token-fetcher /usr/local/bin/token-fetcher

ENTRYPOINT ["/usr/local/bin/token-fetcher"]
