#
# Envoy proxy with bundled Lua filters.
# Runtime config (envoy.yaml) is mounted from a ConfigMap by the Helm chart;
# only the stable Lua filter scripts are baked into the image.

FROM envoyproxy/envoy:v1.31-latest

COPY configs/envoy/lua /etc/envoy/lua

EXPOSE 8080 9901

ENTRYPOINT ["/usr/local/bin/envoy", "-c", "/etc/envoy/envoy.yaml"]
