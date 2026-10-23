# Agent instructions for the charts

The charts support Helm 3.19 or later, and Helm 4.x. Use only template functions and chart features that Helm 3.19
has.

A new chart needs an entry in `for_each_chart` in `test/scripts/lint-images-and-charts.sh`.
