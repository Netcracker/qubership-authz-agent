# Run the services on a Linux host without Kubernetes, tested on Ubuntu 26.04 LTS

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
  the single binary of the agent that this record releases on its own.
- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  ADR-0091 R14 and R18, readiness and liveness, and ADR-0091 R44, the leeway against the clock.
- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  ADR-0092 R16, `legacy` as the only M2M mode outside Kubernetes.
- [authz-agent-ADR-0093: Take the tenant of a decision from the verified user token, then from the request](20261029-authz-agent-adr-0093-tenant-of-a-decision.md):
  ADR-0093 R11 and R14, the default tenant with and without tenant-manager.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  the topology file and the token for the API server, which a Linux host does not have.
- [authz-agent-ADR-0096: Choose the token the agent sends with a setting of its own](20261105-authz-agent-adr-0096-token-the-agent-sends.md):
  ADR-0096 R2 and R8, the token the agent sends and the pairs with `M2M_AUTH_MODE` that stop the start.

## Context

The repository delivers two services, `authz-agent` and `authz-policy-admin`, and each one is installed with its Helm
chart. The top-level README states that the deployment assumes a Kubernetes cluster. Some installations have to run on
Linux hosts, physical or virtual, with no orchestrator at all.

`docker-release.yaml` publishes a container image of each service for `linux/amd64` and `linux/arm64`. The binary inside
is a static Go build (`CGO_ENABLED=0`). No release asset carries the binary on its own.

Both services read their settings from the environment. The agent reads its files from paths that are settings, and the
defaults are the paths the chart mounts: `/etc/authz/trusted-providers.json`, `/etc/secret/username`,
`/etc/secret/password`, and `/var/run/secrets/tokens/netcracker/token`. The default of `AUTHZ_TENANT_MANAGER_URL` is
`http://tenant-manager:8080`, a Service name inside the namespace.

In Kubernetes the cluster does part of the work. The kubelet restarts a container that exits and probes liveness and
readiness. Secrets reach the container as files. A PersistentVolumeClaim keeps the policies of `authz-policy-admin`.
Services and NetworkPolicies decide who reaches a port. The values schema of a chart refuses some values before a Pod
is created. On a Linux host systemd starts the services, and nothing else of this exists.

Both surfaces of the agent listen on `0.0.0.0` by default: the public one on port 8080 and the internal one, which
serves `/prometheus`, on port 8181. `authz-policy-admin` listens on every interface on `AUTHZ_POLICY_ADMIN_PORT`, 18090
by default, and changes policies without authentication. The agent serves plain HTTP. The architect decided that TLS is
not the agent's job and that a proxy in front of it terminates TLS.

The image takes its CA bundle from the platform base image. A binary started on a host reads the CA bundle of the host.

Every CI job runs on `ubuntu-latest`. GitHub made the runners `ubuntu-26.04` and `ubuntu-26.04-arm` generally available
on September 17, 2026 ([actions/runner-images#14747](https://github.com/actions/runner-images/issues/14747)), and moves
`ubuntu-latest` from Ubuntu 24.04 to 26.04 between October 19 and November 19, 2026
([actions/runner-images#14748](https://github.com/actions/runner-images/issues/14748)).

## Decision

We will release and test both services for two deployment targets: Kubernetes with their Helm charts, and a Linux host
without an orchestrator, where systemd runs each service from its release binary. We test the Linux host target on
Ubuntu 26.04 LTS.

### Terms

- **Services**: `authz-agent` and `authz-policy-admin`, the components under `components/`. The stubs and the suites
  under `test/` are not services.
- **Kubernetes target**: an installation of the services with the charts under `helm-templates/` on a Kubernetes
  cluster.
- **Linux host target**: an installation of the services on a Linux host, physical or virtual, where systemd starts
  each service from the binary of R1. No Kubernetes component and no container runtime takes part in running the
  services.
- **Installation page**: `deploy/linux/README.md`, the page that tells an operator how to install the services on a
  Linux host.
- **Host files**: the systemd units, the environment files, the examples, and the installation page under
  `deploy/linux`.
- **Stops the start**: the service exits with an error before it serves a request. ADR-0091 uses the same words for
  the agent.

### Rules

#### The release

- **R1** (`ci`). A release publishes, for each service and for `linux/amd64` and `linux/arm64`, a statically linked
  binary built from the same commit and with the same build flags as the binary in the image of that release.
- **R2** (`ci`). The GitHub release of a version carries, for each service and each platform of R1, one archive with
  the binary and the host files of that service, and a SHA-256 checksum of each archive.

#### A service without Kubernetes

- **R3** (`startup`). In the M2M mode `legacy`, each service starts, becomes ready, and serves on the Linux host target
  with no Kubernetes API server, no chart, and no file that only Kubernetes provides, such as the topology file or the
  token for the API server of ADR-0094.
- **R4** (`startup`). A value that the values schema of a chart refuses for a setting that the chart passes to the
  container also stops the start of the service, with a message that names the setting.
- **R5** (`startup`). Every file that a service reads on the Linux host target has a setting for its path.
- **R6** (`client`). Outgoing calls of the services go through the proxy that `HTTPS_PROXY`, `HTTP_PROXY`, and
  `NO_PROXY` name, as Go's `net/http` reads them.

#### The host files

- **R7** (`host`). `deploy/linux` holds, for each service, a systemd unit and an environment file. The environment file
  lists every setting the service reads, each with its default value and a comment. The files of the agent also hold an
  example trusted providers file.
- **R8** (`host`). The environment file of the agent sets `M2M_AUTH_MODE` to `legacy`, `KUBERNETES_M2M_ENABLED` to
  `false`, and `AUTHZ_TENANT_MANAGER_URL` to the empty string, with a comment that an installation with tenant-manager
  sets its address there.
- **R9** (`host`). The unit runs the service as a system user of its own, not as `root`, and that user cannot write the
  binary, the unit, the environment file, or the trusted providers file.
- **R10** (`host`). The unit passes the client ID and the client secret of the agent as the files that
  `AUTHZ_M2M_CLIENT_ID_FILE` and `AUTHZ_M2M_CLIENT_SECRET_FILE` name, and only the process of the service can read them.
  Neither the unit nor the environment file holds their values.
- **R11** (`host`). The unit restarts a service whose process ends, unless systemd ended it on a stop request.
- **R12** (`host`). The unit treats a service as started once its process runs, and does not wait for it to become
  ready.
- **R13** (`host`). The unit of `authz-policy-admin` sets `AUTHZ_POLICY_ADMIN_DATA_DIR` to a directory that keeps its
  content across a restart of the service and of the host.
- **R14** (`startup`). `authz-policy-admin` reads the address it listens on, host and port, from a setting.
- **R15** (`host`). The environment files bind every listening socket of the services to `127.0.0.1`: the public and
  the internal surface of the agent, and the API of `authz-policy-admin`.
- **R16** (`host`). `deploy/linux` holds an example nginx configuration that terminates TLS in front of the public
  surface of the agent and forwards no request to its internal surface.
- **R17** (`host`). The installation page requires a host clock synchronized over NTP.
- **R18** (`host`). The installation page names Ubuntu 26.04 LTS as the tested distribution and states that the
  project does not test other Linux distributions.

#### The check in CI

- **R19** (`ci`). On every pull request and every push to `main`, a CI job on the GitHub-hosted runner `ubuntu-26.04`
  installs both services from binaries built from that commit, with the host files, under the systemd of the runner. It
  then runs against them every case of the integration suite that needs no Kubernetes. Keycloak and the stubs the suite
  needs may run in containers on the runner.

### Justification

A host without an orchestrator usually has systemd as its init, and a static Go binary needs nothing else from it but
the kernel and a CA bundle. The release already builds that binary inside the image, so publishing it beside the image
costs one more upload and keeps one build for both targets (R1, R2).

The services already read every setting from the environment, so one binary can serve both targets. What the cluster
did has to move into the binary or into the host files. Checks that the values schema makes reach no host, so the
service makes them at start (R4). Kubernetes tokens and the topology file exist only in a cluster, and ADR-0092 R16
already leaves `legacy` as the only mode on a host (R3). A host has paths of its own for credentials and state, so every
file needs a path setting (R5). A host in a closed network may reach Keycloak and the policy source only through a
proxy (R6).

The environment file of the agent starts from values that work on a host (R8). `KUBERNETES_M2M_ENABLED` set to `true`
in `legacy` stops the start (ADR-0096 R8). The default address of tenant-manager names a Service that a host cannot
resolve, and the agent stays not ready until tenant-manager answers (ADR-0093 R11). With an empty address the default
tenant is used as given (ADR-0093 R14).

The unit and its environment file take over the work of the Pod specification (R7, R8). A restart after every
unrequested exit matches what the kubelet does with a container (R11). Waiting for readiness would hand the agent's
readiness to systemd, which kills a service that is not ready within its start timeout (R12).

Each host rule closes a gap that the cluster closed before. A service user of its own, with read-only access to its
files, limits what a compromised process can change (R9). systemd shows the environment of a unit to unprivileged
clients over D-Bus, and the environment passes down to child processes, so the client secret goes only into a file that
the service alone can read (R10). The chart keeps the policies on a PersistentVolumeClaim, and the host needs a
directory that survives a reboot (R13). On a host no Service and no NetworkPolicy decides who reaches a port: the
internal surface serves metrics, and `authz-policy-admin` changes policies without authentication, so every socket
listens on the loopback address until the operator opens it (R14, R15). TLS stays outside the agent, as the architect
decided, so the host files show how a proxy adds it (R16). Token checks compare `exp` and `nbf` with the host clock,
with a leeway of 30 seconds (ADR-0091 R44). A host clock that drifts further makes the agent refuse valid tokens or
accept expired ones (R17).

Ubuntu 26.04 LTS is the newest LTS release, and GitHub hosts runners for it. A job pinned to `ubuntu-26.04` tests the
same release that the installation page names (R18, R19). The test runs against the services as systemd units, so it
also checks the host files (R19).

### Alternatives considered

- **A1. Run the container image under Docker or Podman on the host.** The host would need a container runtime and
  access to the image registry, and a host without an orchestrator does not always have either. The image still runs
  that way, and this record neither tests nor forbids it.
- **A2. Publish `.deb` packages.** A package serves one family of distributions and needs a signed APT repository that
  the project would run. The archive of R2 works on any distribution with systemd, and a package can later wrap it.
- **A3. Report readiness to systemd with `Type=notify`.** Rejected by R12: while Keycloak cannot be reached the agent
  stays not ready (ADR-0091 R14), and systemd would kill it at the start timeout. In Kubernetes the same agent waits
  and becomes ready on its own.
- **A4. Run the job on `ubuntu-latest`.** Rejected by R19: GitHub moves the label to a newer release on its own
  schedule, so the tested distribution would change with no change to this record.
- **A5. Put the client credentials into the environment file.** Rejected by R10: the environment of a unit is visible
  to unprivileged clients and passes down to child processes.
- **A6. Bind the sockets to every interface, as the chart does.** Rejected by R15: on a host nothing in front of the
  port limits who reaches the metrics or the policy API.

## Consequences

Negative:

- Each release publishes a second set of artifacts, and a change that adds a setting also changes the environment file
  of its service (R7).
- On a host nothing restarts a process that hangs without exiting: no one probes liveness (ADR-0091 R18), and the unit
  has no watchdog. The monitoring of the installation has to watch the process.
- On a host the CA bundle of the host, not the bundle of the base image, decides which TLS servers the services trust.
- An installation that runs `authz-policy-admin` and the agent on different hosts has to open the policy API to the
  network and protect it there, because the API has no authentication (R15).
- Running outside the tested distribution is the operator's risk (R18).

Follow-ups:

- The top-level README and `components/authz-agent/README.md` link the installation page of `deploy/linux` instead of
  stating that the deployment assumes Kubernetes.
- Standard support of Ubuntu 26.04 LTS ends in 2031. Before that, a record that supersedes R18 and R19 moves the tested
  distribution to a newer release.

## Open points

- **O1.** Does the job of R19 also run on the runner `ubuntu-26.04-arm`? The answers are yes, so that both platforms of
  R1 are tested, or no, so that the `linux/arm64` archive ships untested on a host. The maintainers decide. It affects
  R18 and R19.
- **O2.** This record assumes that `authz-policy-admin` belongs to the Linux host target, because it is the supported
  policy source in Kubernetes too. The other answer is the agent alone, with the policies pulled from access-control.
  The architect decides. It affects R1, R2, R7, R13, R14, R15, and R19.
