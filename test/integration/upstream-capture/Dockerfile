FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /build
COPY main.go .
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -o /upstream-capture main.go

FROM alpine:3.20
COPY --from=builder /upstream-capture /upstream-capture
EXPOSE 9090
ENTRYPOINT ["/upstream-capture"]
