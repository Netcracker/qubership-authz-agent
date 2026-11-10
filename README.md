# qubership-authz-agent

[![codecov](https://codecov.io/gh/Netcracker/qubership-authz-agent/graph/badge.svg)](https://codecov.io/gh/Netcracker/qubership-authz-agent)

An OPA-based authorization service for Kubernetes.  The deliverable is a
**Helm chart** that assembles the agent Pod: one container, `authz-agent`, a Go
service carrying the policy engine as a library, the check API, and the loops
that feed the engine (authz-agent-ADR-0080).  See
[`components/authz-agent/README.md`](components/authz-agent/README.md).

`authz-policy-admin`, the primary policy source, is a service of its own with
its own chart, `helm-templates/authz-policy-admin`: a Deployment with its
Service and PersistentVolumeClaim.  Its image name has no `authz-agent-` prefix
because it is not a container of the agent Pod.

## Maturity

**Pre-1.0, no releases yet.**  The component has no published release and no
stable API commitment.  The access-control-compatible API surface — the legacy
check endpoints the agent translates — is deliberately partly unimplemented:
only the paths that the test suites exercise are wired.  The deployment assumes
a Kubernetes cluster running the Netcracker platform (Keycloak realm structure,
M2M credential provisioning, optional service-mesh route registration).  A
team deploying this without the platform will need to supply their own identity
provider and adjust the Helm values accordingly.

## Policy source

[`authz-policy-admin`](components/authz-policy-admin/README.md) is the
supported policy source.  Install its chart beside the agent's, point the
agent's `AUTHZ_PAP_CLIENT_SOURCE_URL` at its Service
(`http://authz-policy-admin:18090` with the chart's defaults), and load
simplified policies and PIPs over its unauthenticated HTTP API.

Pulling policies from the platform's access-control service is also supported:
set `AUTHZ_PAP_CLIENT_SOURCE_URL` to the access-control service URL.  When
that is set, `authz-policy-admin` is not needed.

## Charts

The agent's chart is at `helm-templates/authz-agent/` and the policy source's
at `helm-templates/authz-policy-admin/`. Each chart takes its sizing from a
resource profile in its `resource-profiles/` directory (dev, dev-ha, prod,
prod-nonha); `values.yaml` carries none, so pass a profile with `-f`:

```sh
helm template helm-templates/authz-agent -f helm-templates/authz-agent/resource-profiles/dev.yaml
helm template helm-templates/authz-policy-admin -f helm-templates/authz-policy-admin/resource-profiles/dev.yaml
```

The kind suites run on a third chart, the test fixture `helm-templates/authz-test-stand/`; see
[its README](helm-templates/authz-test-stand/README.md). The charts support Helm 3.19 or later, or Helm 4.x.

## Building images

Each image has its own Dockerfile under `build/`:

```sh
# Build an image locally
docker build -t authz-agent:local        -f build/authz-agent/Dockerfile .
docker build -t authz-policy-admin:local -f build/authz-policy-admin/Dockerfile .
```

The images are named as the platform names its images: `qubership-` plus the
service, as in `ghcr.io/netcracker/qubership-authz-agent` and
`ghcr.io/netcracker/qubership-authz-policy-admin`. On every push to `main` or an
`lts/**` branch, and on every pull request from a branch of this repository, CI
builds the five components of `.github/docker-dev-config.json` (the two
services, the test stand's images, and the transfer image) and pushes them to
ghcr.io; a pull request from a fork builds none of them. A release is cut by hand with the
Docker Images Release workflow (`.github/workflows/docker-release.yaml`), which
tags the commit, builds the images `.qubership/docker.cfg` lists, and
publishes the GitHub release with notes composed from the merged pull requests.
Besides the two services, the release publishes the test stand's images,
`qubership-authz-pip-stub` and `qubership-authz-parity-suite`, and
`qubership-authz-agent-transfer`, which carries the Helm charts; see
[helm-templates/authz-test-stand](helm-templates/authz-test-stand/README.md).

## Testing

See `test/BASELINE.md` for recorded baseline results.  All suites below were
verified from a clean clone on public images.

### Prerequisites

- Go 1.24+
- [OPA CLI](https://www.openpolicyagent.org/docs/latest/#1-download-opa) (for Rego tests; `mise install` installs the version `mise.toml` pins)
- Docker, `kind`, and `kubectl` (for the integration and parity suites, which run on kind)
- Docker Compose (for the load suite only)
- `helm` 3.19 or later, or 4.x (for the chart render test, and to install the test stand and run the suites on kind); see
  [docs/local-integration-tests.md](docs/local-integration-tests.md#2-prerequisites) for the versions the kind targets
  need

### Unit tests — Go

```sh
# Root module (four binaries + shared packages): 249 tests
go test -count=1 ./...

# Parity replay module
cd test/parity/suite && go test -count=1 ./...

# Integration testify module (non-integration tests only without a running stack)
cd test/integration/testify && go test -count=1 ./...

# Pip-stub module
cd test/integration/pipstub && go test -count=1 ./...

# Tenant-manager emulator module
cd test/integration/tenantmanager && go test -count=1 ./...

# Report module of make mutation-diff
cd tools/mutationreport && go test -count=1 ./...
```

### Mutation testing of a change

`make mutation-diff` mutates the Go lines your branch changes outside `test/` and reports every mutant on them that no
test kills. Run it before you open a pull request, or on a pull request you review. The diff starts at the merge base of
`HEAD` and `MUTATION_BASE`, `origin/main` by default, so fetch `origin` first. For a pull request that targets another
branch, such as the parent of a stacked pull request, set `MUTATION_BASE` to that branch. In a clone of a fork,
`origin` is the fork, so fetch the upstream repository and pass its branch, for example `MUTATION_BASE=upstream/main`
after `git fetch upstream`. In a shallow clone, run `git fetch --unshallow origin` first: without a merge base, the
diff starts at the tip of the base, and the target says so. Uncommitted changes to tracked files count, and a new
file counts once it is committed or added with `git add -N`.

```sh
make mutation-diff
make mutation-diff MUTATION_BASE=origin/<target-branch>
```

The target runs [mutago](https://github.com/quality-gates/mutago) at the version `tools/mutago/go.mod` pins, built
with `go tool`, so it needs only Go. It takes its file and mutator settings from `.mutago.yml`. It mutates the packages
of the changed files, excludes `test/` (`exclude_dirs` in `.mutago.yml`), and does not mutate `_test.go` files.

Before any mutation, the tests of each changed package run once without the test cache, within 300 seconds. A
mutant's tests may then run 5 times as long as the slowest of those runs, and a mutant whose tests run longer counts as
killed. Set `MUTATION_TIMEOUT` to a number of seconds to use that fixed limit for the clean runs and every mutant
instead, for example when a clean run needs more than 300 seconds. mutago runs the mutants in parallel and leaves the
source files unmodified. A change in `internal/token/verify` that gives five mutants takes about 3 seconds, and about
12 seconds with an empty build cache.

The report lists each changed line with a mutant that no test killed, under its file and with its source text, and
under the line each such mutant: what mutago changed, the mutator, and the function the line is in. Mutants of one
kind on a line are counted rather than repeated. The files with the most mutants come first, and the report shows at
most 10 files, 20 lines per file, and 50 lines in all. It ends with what to do with each surviving mutant: add or
strengthen a test, or, when the mutant changes nothing a caller can observe, say in the pull request why it is
equivalent. A mutant mutago could not classify is listed as errored and is reported as unresolved.
`test/artifacts/mutation/report.txt` holds the whole report, with each mutant's diff and a hint for the test that
kills it, and `mutago.log` beside it holds mutago's own output. `tools/mutationreport` writes the report from mutago's
files.

When the changed files get no mutant, the report lists them and says why that can be: no enabled mutator changes the
lines, as with comments, imports, declarations, and number literals, or the git config sets `diff.external`, and mutago
cannot read the diff an external tool prints. For `diff.external`, the report names the scope that sets it and the
step that reruns the target without it. A changed file that the default build leaves out, behind a build tag such as
the one of `testroutes_paritytest.go`, is named in every report, since mutago never sees its lines.

The target exits 0 when mutago completed its run, whether or not a mutant survived, so that the report rather than
the exit status decides what happens to each mutant. It also exits 0 when no file of the changed packages is built,
since that run has nothing to mutate. When the run did not complete, the target exits with mutago's own status, or 3
when mutago exited 0 without its summary, and the report shows the first and the last lines of mutago's output, such
as `Baseline test failed for "<package>"` when the tests of a changed package fail before any mutation. Status 2 comes
from the target itself, for a `MUTATION_BASE` that is not a commit in the clone or for a build that failed. `make`
turns a non-zero status into its own exit status 2 and prints the target's status after `Error` in its last line.

Do not accept survivors with `--update-baseline`; the target reads no baseline file. mutago also skips the lines that
a `// mutator-disable-next-line`, `// mutator-disable-func`, or `// mutator-disable-regexp` comment marks, so such a
comment hides survivors the same way and does not belong in the code.

mutago reads the output of a plain `git diff`, so the target overrides the git settings that change its colors, its
prefixes, or the quoting of its paths, and unsets `GIT_CONFIG_PARAMETERS`, through which `git -c` passes settings to
commands it starts.

### jsonPath against Jayway

`internal/jsonpath` is compared with Jayway JsonPath 2.9.0, one of the versions legacy access-control evaluates jsonPath
with. The
test needs Java 17 or later and Maven, which resolves the Jayway jars:

```sh
make test-jayway

# Also run the queries of a json-path-comparison checkout
make test-jayway JSONPATH_COMPARISON_DIR=/path/to/json-path-comparison
```

The paths and documents that Jayway's own tests evaluate are a third set of inputs. `make jayway-suite-calls` runs
those tests with a Java agent that records each read, and writes the calls into `JAYWAY_SUITE_CALLS`; `JAYWAY_SRC_DIR`
is a checkout of [json-path/JsonPath](https://github.com/json-path/JsonPath) at tag `json-path-2.9.0`. Its Gradle build
runs on Java 17, not on 21:

```sh
JAVA_HOME=/path/to/jdk-17 make jayway-suite-calls JAYWAY_SRC_DIR=/path/to/JsonPath JAYWAY_SUITE_CALLS=/tmp/jayway-calls
make test-jayway JAYWAY_SUITE_CALLS=/tmp/jayway-calls
```

The test fails on an answer that differs from Jayway's unless `internal/jsonpath/jayway_test.go` lists the difference.

### Unit tests — Rego

```sh
# 352 policy tests
opa test policies/
```

### Chart render

```sh
bash test/scripts/test-chart-render.sh
```

### Integration test suite

Runs the Testify suite as a Job inside a kind cluster, against the Helm chart.
This is the check CI runs (`.github/workflows/integration-tests.yaml`).
Requires Docker, `kind`, `kubectl`, and `helm`.

```sh
make e2e          # cluster, images, harness, chart, suite
make e2e-logs     # container logs and events into test/artifacts/kind/
make e2e-down     # delete the cluster
```

Expected: every group passes, including the two catalog coverage checks. See
[test/k8s/README.md](test/k8s/README.md) for the individual targets and
[docs/local-integration-tests.md](docs/local-integration-tests.md) for a
walkthrough from a clean machine.

### Parity replay

Replays recorded HTTP requests against the agent and compares responses against
golden files captured from the legacy access-control service.  The goldens are
a frozen capture; they cannot be regenerated from this repository (see
`test/parity/README.md`).

```sh
make parity        # harness, chart, suite in namespace authz-parity
make parity-logs   # artifacts into test/artifacts/kind/parity/
```

Expected: 135/135 PASS. This is what CI runs (job `Parity on kind`).

## Development

After cloning, enable the bundled pre-commit hook so every commit is linted
with the same tools and configuration the CI uses (`.github/linters/`):

```sh
make install-hooks
```

`make lint` runs the same checks over the whole tree. See
[CONTRIBUTING.md](CONTRIBUTING.md) for details.
