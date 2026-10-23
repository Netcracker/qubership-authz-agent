# Contribution Guide

We'd love to accept patches and contributions to this project.
Please, follow these guidelines to make the contribution process easy and effective for everyone involved.

## Contributor License Agreement

You must sign the [Contributor License Agreement](https://github.com/Netcracker/qubership-workflow-hub/blob/main/CLA/cla.md) in order to contribute.

## Code of Conduct

Please make sure to read and follow the [Code of Conduct](CODE-OF-CONDUCT.md).

## Local Lint Hooks

Run `make install-hooks` once after cloning to wire the pre-commit hook. The hook
runs golangci-lint, shellcheck, yamllint, markdownlint, and zizmor on staged files
before every commit, matching the CI super-linter checks. Run `make lint` at any
time to lint the full tree.

`make lint` also lints the charts with `helm lint` and the Dockerfiles with
hadolint, validates the rendered charts with kubeconform, and scans the rendered
product charts with trivy, as the `Chart lint and render` CI job does. It builds the test-stand chart files
with Docker first. `mise install` installs hadolint, kubeconform, and trivy at
the versions `mise.toml` pins. Findings the charts accept on purpose are listed,
each with its reason, in `.github/linters/.trivyignore.yaml`.
