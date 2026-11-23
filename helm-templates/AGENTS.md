# Agent instructions for the charts

The charts support Helm 3.19 or later, and Helm 4.x. Use only template functions and chart features that Helm 3.19
has.

A new chart needs an entry in `for_each_chart` in `test/scripts/lint-images-and-charts.sh`.

Render a number that is the whole value of a string field the container reads, such as an environment variable, with
`int64 | quote`. Helm reads a number in a values file as a float and prints one of 1000000 or more in exponent form,
such as `1e+06`, where `int64` prints decimal digits. `int64` turns a missing value into `0`, and so does a string it
cannot parse, such as `2s`. So in a chart with a `values.schema.json` the key has `type: integer` there and is in that
file's `required` list, and in a chart without one the template wraps the value in `required`. A number that Kubernetes
reads as a number, such as `replicas` or a container port, is rendered as it is, without `int64 | quote`. A new integer
setting of authz-agent also goes into `integer_settings` in `test/scripts/test-chart-render.sh`.
