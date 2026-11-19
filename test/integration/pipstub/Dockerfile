FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -o /pip-stub .

FROM ghcr.io/netcracker/qubership-core-base:alpine-2.5.15@sha256:a3af3751d9187ce7f8ffd67a5aa8465fee78056c79f964bfa7727ea00da681da
COPY --chmod=555 --from=builder /pip-stub /usr/local/bin/pip-stub
USER 10001:10001
EXPOSE 8090
CMD ["pip-stub"]
