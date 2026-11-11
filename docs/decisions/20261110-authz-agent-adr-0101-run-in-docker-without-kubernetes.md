# Run the agent in Docker on the platform base image without Kubernetes

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0080: Replace Envoy, the Lua filters, and the OPA container with one Go service that embeds OPA](20260907-authz-agent-adr-0080-single-go-service-with-embedded-opa.md):
  the one image of the agent that this record runs outside Kubernetes.
- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  the term stops the start, ADR-0091 R14 and R18, readiness and liveness, ADR-0091 R44, the leeway against the clock,
  and ADR-0091 R72 and R78, `IDENTITY_PROVIDER_URL` read by the chart alone.
- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  ADR-0092 R16, `legacy` as the only M2M mode outside Kubernetes.
- [authz-agent-ADR-0093: Take the tenant of a decision from the verified user token, then from the request](20261029-authz-agent-adr-0093-tenant-of-a-decision.md):
  ADR-0093 R11 and R14, the default tenant with and without tenant-manager.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  the topology file and the token for the API server, which exist only in a cluster.
- [authz-agent-ADR-0096: Choose the token the agent sends with a setting of its own](20261105-authz-agent-adr-0096-token-the-agent-sends.md):
  ADR-0096 R1 to R8, the setting that chooses the agent's token, which the agent reads with or without the chart.

## Context

The agent ships as one image for `linux/amd64` and `linux/arm64`, built on the platform base image
`ghcr.io/netcracker/qubership-core-base`, Alpine flavor, pinned by digest. The Helm chart is the only documented way to
run it, and the top-level README states that the deployment assumes a Kubernetes cluster. Some installations have no
Kubernetes and run containers with Docker.

The entrypoint of the base image, `/usr/bin/entrypoint.sh`, prepares the container and then runs its arguments:

- It adds every certificate in `.crt`, `.cer`, and `.pem` files under `/tmp/cert` to the trust store of the image. It
  also reads `/var/run/secrets/kubernetes.io/serviceaccount` when that directory exists.
- It runs the scripts in `/app/init.d`.
- For a uid that has no entry in `/etc/passwd`, it adds one through `nss_wrapper`.
- It forwards signals to the process, and waits `SIGTERM_EXIT_DELAY` seconds, 10 by default, before it forwards
  `SIGTERM`.

The base image runs as uid 10001 in group 0 and ships `curl`. The agent's Dockerfile replaces that entrypoint with the
binary, so none of this runs for the agent.

On November 10, 2026 the image of `main` ran under Docker on the base image `alpine-2.5.12`, with Keycloak and a policy
source on one Docker network and no Kubernetes. It ran with a read-only root file system, all capabilities dropped, a
uid without an entry in `/etc/passwd`, and a memory limit, which it applied to the Go memory limit. It became ready,
refused a request without `Authorization` with 401, and returned allow and deny decisions. The entrypoint of the base
image, run alone, completed without a Kubernetes directory.

The chart does part of the work, and the agent does not repeat it:

- The values schema refuses invalid values, while the agent replaces an invalid value with its default and logs
  nothing. In that run `AUTHZ_PAP_CLIENT_PULL_INTERVAL=2s` gave 30 seconds and `AUTHZ_JWKS_BOOTSTRAP_REQUIRED=ture` gave
  strict bootstrap.
- The chart builds the trusted providers file and `AUTHZ_M2M_TOKEN_URL` from `IDENTITY_PROVIDER_URL`, mounts the
  client credentials at `/etc/secret`, and probes `/ready` and `/health` on the internal port.
- Without `AUTHZ_M2M_TOKEN_URL` the agent waits for the projected token `/var/run/secrets/tokens/netcracker/token`,
  because only the chart reads `KUBERNETES_M2M_ENABLED`.
- The agent's default for `AUTHZ_TENANT_MANAGER_URL` is `http://tenant-manager:8080`, the name of a Service.

Kubernetes tokens and the topology file of ADR-0094 exist only in a cluster, and ADR-0092 R16 leaves `legacy` as the
only M2M mode outside Kubernetes. The architect decided that TLS is not the agent's job.

Under Docker, `docker stop` and Compose wait 10 seconds by default before they kill the container. A container marked
unhealthy keeps running, and a restart policy acts only when the process exits. CI runs the agent only on kind.

Pull request #233, closed without merging, used the number ADR-0101 for a record on running the agent under systemd on
a Linux host. That record was never accepted, and this record takes the number.

## Decision

We will support running the agent from its image under Docker, with no Kubernetes, on the platform base image and
behind its entrypoint, configured by environment variables and mounted files alone. The repository ships a Compose
example, and CI runs it.

### Terms

- **Docker target**: the agent run from its release image by Docker Engine, alone or with Docker Compose v2, on
  `linux/amd64` or `linux/arm64`, with no Kubernetes component.
- **Platform entrypoint**: `/usr/bin/entrypoint.sh` of `ghcr.io/netcracker/qubership-core-base`.
- **Chart check**: a constraint that `helm-templates/authz-agent/values.schema.json` puts on a value that the chart
  passes to the container as an environment variable.
- **Compose example**: `deploy/docker/compose.yaml` and the files beside it in `deploy/docker`.
- **Docker page**: `deploy/docker/README.md`.
- **Stops the start**: as ADR-0091 defines it.

### Rules

#### The image

- **R1** (`image`). The image of the agent is built on `ghcr.io/netcracker/qubership-core-base`, Alpine flavor, pinned
  by digest.
- **R2** (`image`). The platform entrypoint starts the agent: the image keeps the entrypoint of the base image, and the
  binary is its command.
- **R3** (`image`). A CA certificate in a `.crt`, `.cer`, or `.pem` file under `/tmp/cert` is trusted by the agent's
  outgoing TLS connections.
- **R4** (`image`, `startup`). On the Docker target, wherever the agent starts and becomes ready with the uid of the
  image and no other limit, it also starts and becomes ready with any uid in group 0, a read-only root file system, and
  all Linux capabilities dropped.

#### Configuration without the chart

- **R5** (`startup`). In the M2M mode `legacy`, the agent starts, becomes ready, and serves on the Docker target with
  environment variables and mounted files alone: no Kubernetes API server, no chart, no service account token, and no
  topology file.
- **R6** (`startup`, `client`). A value of an environment variable stops the start when its chart check refuses it,
  with a message that names the variable and the values that the chart check accepts. The agent reads the value as the
  type the chart check names: an integer as decimal digits with an optional sign, a boolean as `true` or `false` without
  regard to case, and a value from a list without regard to case. An empty integer, boolean, or value from a list
  means the default, as an unset one does.
- **R7** (`startup`, `client`). The default of every setting whose value the agent uses in `legacy`, with
  `KUBERNETES_M2M_ENABLED` set to `false`, names no Kubernetes Service, no host inside a cluster, and no path that only
  Kubernetes mounts.

#### The Compose example

- **R8** (`docker`). The Compose example runs the agent from its release image, mounts the trusted providers file at
  `/etc/authz` and the client credentials at `/etc/secret`, and holds an example trusted providers file.
- **R9** (`docker`). The environment file of the Compose example lists every setting the agent reads, each with its
  default and a comment, and sets `M2M_AUTH_MODE` to `legacy` and `KUBERNETES_M2M_ENABLED` to `false`.
- **R10** (`docker`). The Compose example gives the agent a stop grace period of 30 seconds.
- **R11** (`docker`). The Compose example declares a healthcheck that runs `curl` against `/ready` on the internal port.
- **R12** (`docker`). The Compose example sets the restart policy `unless-stopped`.
- **R13** (`docker`). The Compose example publishes the public port and publishes the internal port on `127.0.0.1`
  alone, if at all.
- **R14** (`docker`). The Docker page shows how to trust a private CA through `/tmp/cert`.
- **R15** (`docker`). The Docker page requires a host clock synchronized over NTP.
- **R16** (`docker`). The Docker page states that the agent serves plain HTTP and that a proxy in front of the public
  port terminates TLS.

#### The check in CI

- **R17** (`ci`). On every pull request and every push to `main`, a CI job on the GitHub-hosted runner `ubuntu-26.04`
  builds the image of that commit and starts the Compose example with it. An override file adds Keycloak and a policy
  source as containers. The job then runs against the agent every case of `test/integration/testify` that the kind job
  runs, except a case that needs a Kubernetes token, the topology file, or the Kubernetes API.

#### Kubernetes

- **R18** (`chart`, `image`). In the Pod of the chart with a read-only root file system, the platform entrypoint
  completes without an error and loads the certificates of R3.

### Implementation notes

Adds no requirement.

- R2 and R18: replace `ENTRYPOINT ["/usr/local/bin/authz-agent"]` in `build/authz-agent/Dockerfile` with
  `CMD ["authz-agent"]`, as `build/authz-policy-admin/Dockerfile` does. The platform entrypoint writes to
  `/usr/local/share/ca-certificates`, `/etc/ssl/certs`, and `/app/nss`. Under `--read-only`, Docker keeps them writable
  through the `VOLUME` lines of the base image. The chart mounts nothing there, so it needs `emptyDir` volumes at those
  paths. The entrypoint then copies the bundle of the image back into `/etc/ssl/certs` from `/app/volumes/certs`.
- R3: the entrypoint runs `update-ca-certificates`, which rewrites `/etc/ssl/certs/ca-certificates.crt`, the bundle that
  Go reads on Alpine.
- R6: let the parsers in `components/authz-agent/config.go` and `internal/pips/entitlements.go` return an error instead
  of the fallback, collect the errors of every setting, and report them together before the agent listens. A table test
  over each chart check, with its boundary values and a value such as `2s`, can then confirm R6. `boolean` in
  `config.go` accepts `1`, `yes`, and `on` today, and R6 refuses them.
- R9: a test that compares the keys of the environment file with the variables the agent reads, through `loadConfig`
  and through `os.Getenv` in `internal/pips/entitlements.go`, keeps R9 true as settings are added.
- R4 and R5: the override of R17 can run the agent with `read_only: true`, `cap_drop: [ALL]`, and a uid such as
  `12345:0`, so that every run of the job shows both. `docker compose up --wait` in the job also runs the healthcheck of
  R11. The job replaces the release image with the image of the commit, so R8 to R13 stay properties of the files that
  a reader checks.
- R10: the 10 seconds of `SIGTERM_EXIT_DELAY` and up to 5 seconds for each of the two surfaces of the agent make 20
  seconds, and 30 leave room.
- R17: the suite reads every address from its environment, as `test/integration/testify/helpers.go` lists them. The
  realms of `test/k8s/authn` and the images of `test/integration/pipstub` and `test/integration/tenantmanager` serve the
  override as they serve kind.

### Justification

The base image is the platform's runtime, and its entrypoint is how the platform adds a private CA and runs init
scripts in any container (R1, R2). The agent calls Keycloak, PIPs, and the policy source over HTTPS, so the CA of an
installation has to reach its trust store without rebuilding the image (R3, R14). The run of November 10 showed that
the agent needs neither root nor a writable root file system, and the rule keeps it so (R4).

Outside the chart nobody else checks the configuration. Kubernetes tokens and the topology file exist only in a cluster,
so `legacy` is the mode on the Docker target (R5). An operator who mistypes a value has to learn it at the start, as
ADR-0092 R15 does for the mode, rather than run with a default they did not choose (R6). R6 reads a boolean as ADR-0096
R3 reads `KUBERNETES_M2M_ENABLED`, so that no setting accepts a spelling another one refuses. A default that names a
Service, such as `http://tenant-manager:8080`, cannot resolve on a Docker network that has no such container, and with
that address the agent would stay not ready (ADR-0093 R11). An empty address uses the default tenant as given, as
ADR-0093 R14 states, so R7 keeps such names out of the defaults. The agent's token on the Docker target follows from
ADR-0096 R1 to R8, which the agent reads without the chart.

The Compose example replaces the Pod specification for an operator, and CI runs the same file, so a change that breaks
the Docker target fails a check (R8, R9, R17). The trusted providers file and `AUTHZ_M2M_TOKEN_URL` stay in the example,
because the agent does not read `IDENTITY_PROVIDER_URL` (ADR-0091 R78). In Kubernetes the chart sets `keycloak.url`
from it (ADR-0091 R72) and builds `AUTHZ_M2M_TOKEN_URL` from it as well. The platform entrypoint forwards `SIGTERM`
after 10 seconds, and the agent then takes up to 5 seconds for each of its two surfaces. Docker's default of 10 seconds
would kill the agent before it shuts down (R10). Docker
shows the state of a container only through a healthcheck. `/ready` is the state that a dependent container waits for,
and the restart policy covers a process that exits (R11, R12). Docker has no NetworkPolicy, and the internal port
serves metrics and the probes (R13). Token checks compare `exp` and `nbf` with the host clock, with a leeway of 30
seconds (ADR-0091 R44). A clock that drifts further makes the agent refuse valid tokens or accept expired ones (R15).
TLS stays outside the agent, as the architect decided (R16).

A job pinned to `ubuntu-26.04` keeps the runner the same until a change moves it, while `ubuntu-latest` moves on
GitHub's schedule (R17). The suite already exercises the agent on kind over HTTP alone, so in Docker it covers the same
paths, apart from the cases that read what only a cluster has (R17).

The chart runs the same image behind the same entrypoint, and on Kubernetes it sets a read-only root file system by
default. The directories that the entrypoint writes have to stay writable there (R18).

### Alternatives considered

- **A1. Keep the binary as the entrypoint of the image.** Rejected by R2: a private CA could reach the agent only by
  replacing the bundle under `/etc/ssl/certs`, and the init scripts of the platform would not run.
- **A2. Run the agent as a process under systemd on a Linux host.** The image and the runtime of the platform would
  differ between the two targets, and the release would need a second artifact.
- **A3. Let the agent build the trusted providers file and `AUTHZ_M2M_TOKEN_URL` from `IDENTITY_PROVIDER_URL`.**
  ADR-0091 R78 keeps that setting in the chart, and the same logic would live in two places.
- **A4. Log a warning and keep the default for an invalid value.** Rejected by R6: the warning is easy to miss, and the
  agent would run, for example, in a bootstrap mode the operator did not choose.
- **A5. Put the healthcheck into the Dockerfile.** The kubelet ignores it, and the address would be fixed in the image
  while `AUTHZ_HTTP_ADDR` can move the internal port.
- **A6. Check only readiness and one decision in CI.** Rejected by R17: a regression on the Docker target outside that
  path would pass.
- **A7. Publish the internal port on every interface.** Rejected by R13: anyone on the network could read the metrics.

## Consequences

Positive:

- A value that `helm install --skip-schema-validation` lets into the Pod, such as a pull interval of `2s`, stops the
  start instead of turning into the default (R6).

Negative:

- The agent receives `SIGTERM` 10 seconds after a stop, in Docker and in the Pod. A plain `docker run` needs
  `--stop-timeout 30`, or Docker kills the agent before it shuts down.
- Docker does not restart a container that hangs without exiting. The healthcheck only marks it, and the monitoring of
  the installation has to act (R11, R12).
- On the Docker target the operator writes the trusted providers file and `AUTHZ_M2M_TOKEN_URL`, which the chart builds
  in Kubernetes.
- Values that the agent uses today and the chart checks refuse now stop the start, such as `AUTHZ_JWKS_HTTP_TIMEOUT=0`
  and the booleans `yes`, `on`, and `1` (R6).
- On the Docker target only `legacy` works, so services that call with Kubernetes tokens cannot use such an agent
  (ADR-0092 R16).
- With an empty default address, which R7 allows, an agent run without the chart and without
  `AUTHZ_TENANT_MANAGER_URL` asks tenant-manager nothing. It uses a realm named by a tenant's display name as written,
  and the default tenant as given (ADR-0093 R14). The chart passes its own address, so a Pod sees no change.

Follow-ups:

- The top-level README and `components/authz-agent/README.md` link the Docker page instead of stating that the
  deployment assumes Kubernetes.

## Open points

- **O1.** R6 reads a boolean as `true` or `false` alone, as ADR-0096 R3 does, so `1`, `yes`, and `on`, which the agent
  accepts today, stop the start. The other answer keeps those spellings for every boolean, the one of ADR-0096
  included. The maintainers decide. It affects R6.
