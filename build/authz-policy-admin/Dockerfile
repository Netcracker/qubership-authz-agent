#
# authz-policy-admin: access-control v3 config API stand-in.
#
# Used by the automated test stacks and by the optional AUTHZ_POLICY_ADMIN_ENABLED
# deployment in the Helm chart (authz-agent-ADR-0073). The build context is the
# repository root, like the other images.

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
COPY components/ components/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -o /out/authz-policy-admin ./components/authz-policy-admin

FROM alpine:3.21

COPY --from=builder /out/authz-policy-admin /usr/local/bin/authz-policy-admin

EXPOSE 18090

ENTRYPOINT ["/usr/local/bin/authz-policy-admin"]
