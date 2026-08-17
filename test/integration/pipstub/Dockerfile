FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -o /pip-stub .

FROM alpine:3.20
COPY --from=builder /pip-stub /pip-stub
EXPOSE 8090
ENTRYPOINT ["/pip-stub"]
