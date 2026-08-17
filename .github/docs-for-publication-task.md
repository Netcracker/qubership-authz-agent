# Notes for the publication task

This file lists the GitHub API operations that must be performed after the internal
review, when the repository is made public.  They are GitHub settings
and cannot be applied as files in the working tree.

## Repository settings

### Topics

Set these topics on the repository:

```text
core  authz  go  qubership-core
```

Do **not** use `cloud-core` — that tag marks the companion-agent tier
(`qubership-core-*` services that ship beside a product consumer).
`qubership-authz-agent` is a standalone product at the same tier as
`qubership-maas` and `qubership-core-dbaas-agent`.

### Forking

Enable forking for the repository (disabled by default for org repos).

### Central topic registry

Register the repository in `Netcracker/.github/config/topics.json` under the
`core` and `authz` topics.  This file is maintained by a separate team; open a
PR there after publication.  It is parked here rather than blocked on it.

## Secrets and variables

The workflows in `.github/workflows/` expect the following to be configured on
the repository.

### Variables (`vars.*`)

| Variable | Used by | Purpose |
| --- | --- | --- |
| `SONAR_PROJECT_KEY` | `go-build.yaml` → `generic-go-build.yaml` | SonarQube project key for code-quality scans |
| `SONAR_ORGANIZATION` | inherited via `secrets: inherit` in `go-build.yaml` | SonarQube organisation (set at org level) |
| `SONAR_HOST_URL` | inherited | SonarQube server URL (set at org level) |

### Secrets (`secrets.*`)

| Secret | Used by | Purpose |
| --- | --- | --- |
| `SONAR_TOKEN` | `go-build.yaml` → `generic-go-build.yaml` | Token to authenticate to SonarQube |
| `CLA_ACCESS_TOKEN` | `cla.yaml` | Personal access token for the CLA assistant to write to `cla-storage` |
| `GITHUB_TOKEN` | all release workflows | Automatically provided by GitHub Actions; no manual setup needed |

`SONAR_*` variables and `SONAR_TOKEN` are typically configured at the organisation
level and inherited by all repositories via `secrets: inherit`.  Verify that they
are set for the organisation before the first CI run.

## Branch protection

Apply the organisation's standard branch-protection rule to `main`:

- Require PR reviews (at least 1 approver from CODEOWNERS)
- Require status checks to pass (`Build` from `go-build.yaml`)
- Require branches to be up to date before merging

The organisation's `Netcracker/.github/config/Protect-main-branch.json` contains
the canonical rule configuration.

## Container registry

Images are pushed to `ghcr.io/netcracker/` on release.  The release workflow uses
`GITHUB_TOKEN` (automatic) for authentication to the GitHub Container Registry.
No additional secrets are needed.

## docker-dev-config.json discovery

The shared `docker-build.yaml` reads `.github/docker-dev-config.json` and runs
one Docker build per component entry using a matrix strategy.  The five-entry
array in this repository's `docker-dev-config.json` is handled in a single
workflow run; no per-component config files are needed.  This was confirmed by
reading `Netcracker/qubership-core-infra/.github/workflows/docker-build.yaml`
at `71206242f5967ac6691337913593f8623863f711` (v2.5.2), which uses
`matrix: component: ${{ fromJson(needs.load_config.outputs.components) }}`.
