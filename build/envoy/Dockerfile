#
# Envoy proxy with bundled Lua filters.
# Runtime config (envoy.yaml) is mounted from a ConfigMap by the Helm chart;
# only the stable Lua filter scripts are baked into the image.
#
# This image stays on the upstream Envoy image rather than the platform base:
# the Envoy binary links against glibc, and the platform base is Alpine.

FROM envoyproxy/envoy:v1.39-latest@sha256:57e14a549d7bd43c8d3f6d03e8cfa653e037d4b38e133acd9b54f38c524401b4

COPY configs/envoy/lua /etc/envoy/lua

EXPOSE 8080 9901

# The upstream image starts as root and drops to its `envoy` user (uid 101)
# only when started that way. Starting as that user directly skips the drop,
# which the entrypoint handles, and gives the image a numeric non-root default
# for runAsNonRoot checks. Both ports are unprivileged.
USER 101:101

ENTRYPOINT ["/usr/local/bin/envoy", "-c", "/etc/envoy/envoy.yaml"]
