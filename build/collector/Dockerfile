#
# Decision-log-collector: minimal image for OPA decision-log ingest and download.

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
COPY components/decision-log-collector/ components/decision-log-collector/
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -o /out/decision-log-collector ./components/decision-log-collector

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

COPY --from=builder /out/decision-log-collector /usr/local/bin/decision-log-collector

ENTRYPOINT ["/usr/local/bin/decision-log-collector"]
