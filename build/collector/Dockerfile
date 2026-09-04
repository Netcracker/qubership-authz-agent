#
# Decision-log-collector: minimal image for OPA decision-log ingest and download.

FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
COPY components/decision-log-collector/ components/decision-log-collector/
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -o /out/decision-log-collector ./components/decision-log-collector

FROM ghcr.io/netcracker/qubership-core-base:2.4.2@sha256:78e39e1332035b539eb61f605a9a3b638ccad27b3c64ed0783f76b6b6d4de8c5

COPY --chmod=555 --from=builder /out/decision-log-collector /usr/local/bin/decision-log-collector

# The default sink, used when DECISION_LOG_FILE is not set (the Compose stacks).
# The chart mounts a volume elsewhere and points DECISION_LOG_FILE at it.
# Owner 10001 for Compose, group 0 with group write for OpenShift.
USER root
RUN mkdir -p /var/log/authz \
    && chown 10001:0 /var/log/authz \
    && chmod 775 /var/log/authz
USER 10001:10001

CMD ["decision-log-collector"]
