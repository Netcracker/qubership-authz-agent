# Run the agent from its image in a container runtime without Kubernetes

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record. On 2026-11-23 the architect and the owner of the policy
  decision code agreed to drop the M2M modes, so the container target can run without the provider `kubernetes` rather
  than in `legacy` (R5).
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0080: Replace Envoy, the Lua filters, and the OPA container with one Go service that embeds OPA](20260907-authz-agent-adr-0080-single-go-service-with-embedded-opa.md):
  the one image of the agent that this record runs outside Kubernetes.
- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  the term stops the start; ADR-0091 R14, readiness; ADR-0091 R18, liveness; ADR-0091 R44, the leeway against the clock;
  and ADR-0091 R78, `IDENTITY_PROVIDER_URL`, which the agent does not read.
- [authz-agent-ADR-0093: Take the tenant of a decision from the verified user token, then from the request](20261029-authz-agent-adr-0093-tenant-of-a-decision.md):
  ADR-0093 R11 and R13, the translation of the default tenant through tenant-manager with the agent's token.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  the topology file and the token for the API server, which exist only in a cluster.
- [authz-agent-ADR-0096: Choose the token the agent sends by `M2M_AUTH_MODE`](20261105-authz-agent-adr-0096-token-the-agent-sends.md):
  the agent's token and the agent's client credentials token, as
  [#338](https://github.com/Netcracker/qubership-authz-agent/pull/338) defines them.
- [authz-agent-ADR-0104: Describe the two trusted providers in a fixed directory of provider files](https://github.com/Netcracker/qubership-authz-agent/pull/329),
  proposed in #329: the provider directory and the provider files (ADR-0104 R1, R2), the reading of the provider files
  at start alone (ADR-0104 R5), the two providers and their types (ADR-0104 R6), the required sources (ADR-0104 R25),
  the Kubernetes token (ADR-0104 R22), the refusal of a token whose `iss` matches no provider (ADR-0104 R21), and the
  refusal of a token with the claim `kubernetes.io` whose source is another provider (ADR-0104 R27).
- [authz-agent-ADR-0106: Trust a private CA only through the system roots of the base image](https://github.com/Netcracker/qubership-authz-agent/pull/330),
  proposed in #330: ADR-0106 R1, the system roots that every HTTPS request of the agent verifies against.
- [authz-agent-ADR-0107: Have the agent check its own settings, whether or not the chart renders them](https://github.com/Netcracker/qubership-authz-agent/pull/359),
  proposed in #359: the checks of the agent's settings, which hold on this target as on any other, and ADR-0107 R3, the
  empty default of the address of a service.

## Context

The agent is documented to run only in Kubernetes. Some installations have no Kubernetes and run containers with Docker
or another OCI container runtime. In Kubernetes the cluster and the chart provide facilities that the agent relies on,
from the restart of a container that hangs to a rolling update.

## Decision

We will support running the agent from its release image in an OCI container runtime without Kubernetes, configured by
environment variables and mounted files alone, and give each duty that Kubernetes and the chart carry to the agent, the
runtime, or the operator, or record it as lost. The repository ships an example for Docker Compose.

### Terms

- **Container target**: the agent run from its release image, on `linux/amd64` or `linux/arm64`, by an OCI container
  runtime, with no Kubernetes component, that can do each of these: run the container as a uid other than 0, with a
  read-only root file system, no new privileges, its default seccomp profile, and all Linux capabilities dropped; limit
  its memory; pass environment variables to it; mount files, writable volumes, and a tmpfs into it; send `SIGTERM` to it
  and wait a set time before it kills it; restart it when its process exits; and check an HTTP endpoint of it on a
  schedule.
- **Compose example**: `deploy/docker/compose.yaml` and the files beside it in `deploy/docker`, run by Docker Compose v2
  on Docker Engine.
- **Container page**: `deploy/docker/README.md`.
- **Public surface**: the listener whose address `AUTHZ_PUBLIC_ADDR` sets.
- **Internal surface**: the listener whose address `AUTHZ_HTTP_ADDR` sets.
- **Stops the start**: as ADR-0091 defines it.
- **Agent variable**: as ADR-0107 defines it.
- **The agent's token**, **the agent's client credentials token**: as ADR-0096 defines them.
- **Provider directory**, **provider file**, **provider `identity-provider`**, **provider `kubernetes`**, **`realms`
  provider**, **`single` provider**, **required source**, **Kubernetes token**: as ADR-0104 defines them.
- **Token for the API server**, **topology file**: as ADR-0094 defines them.

### Rules

#### The image and the agent

- **R4** (`image`, `startup`). On the container target, running as the user of the image or as any uid in group 0, with
  no new privileges, the default seccomp profile, a read-only root file system, and all Linux capabilities dropped,
  changes neither whether the agent starts nor whether it becomes ready.
- **R5** (`startup`). With provider files that hold the provider `identity-provider`, as a `realms` or a `single`
  provider, and no provider `kubernetes`, the agent starts, becomes ready, and serves on the container target with
  environment variables and mounted files alone: no Kubernetes API server, no service account token, and no topology
  file.
- **R31** (`startup`). Once the agent process receives `SIGTERM`, the agent accepts no new connection on either surface,
  finishes each request in flight that ends within 10 seconds, and exits within 10 seconds.
- **R32** (`startup`). The agent exits with a non-zero status when it stops the start, and when either surface stops
  serving for a reason other than `SIGTERM` or `SIGINT`.

#### The duties without Kubernetes

- **R33** (`docker`). The container page states the duty of each row of this table whose owners include the runtime or
  the operator, and the loss of each row whose owner is none:

  | What Kubernetes or the chart provides | Owner on the container target | Duty |
  | --- | --- | --- |
  | Container hardening | Operator | Runs the container as the user of the image or as any uid in group 0 other than 0, with no new privileges, a read-only root file system, the default seccomp profile, and all capabilities dropped (R4). |
  | Restart after the process exits | Runtime | Restarts the container when the agent exits (R32). |
  | Restart of an agent that hangs | Operator | Checks the liveness of the agent (ADR-0091 R18) on `/health` of the internal surface, and restarts the container when the check fails. |
  | Readiness | Runtime and operator | The runtime checks `/ready` on the internal surface (ADR-0091 R14), and the operator starts no dependent container and sends no client to the agent before it passes. |
  | Metrics | Operator | Scrapes `/prometheus` on the internal surface. |
  | Secrets | Operator | Makes the client credentials readable to the uid the agent runs as, and to no other user of the host. |
  | Provider files | Operator | Mounts the provider files in the provider directory (ADR-0104 R1), readable to the uid the agent runs as. |
  | Restart after a provider file changes | Operator | Restarts the container after it changes a provider file, which the agent reads only at start (ADR-0104 R5). |
  | Service names | Agent and operator | ADR-0107 R3 gives the default of each agent variable that holds the address of a service, and the operator sets the address of each service that the installation uses. |
  | Network isolation | Operator | Lets no other host reach the public surface except through the TLS proxy on the same host. Publishes the internal surface only on an interface that the monitoring reaches and that a firewall or a private network closes to every other host, and the page warns that the internal surface serves the metrics and the probes. |
  | TLS for clients | Operator | Runs a proxy that terminates TLS in front of the public surface on the same host, in the same container network or on `127.0.0.1`. A load balancer on another host reaches the agent through that proxy over TLS. |
  | Routes of the platform gateway | Operator | Sends the clients to the TLS proxy on the same host. |
  | A cluster network for the calls of the agent | Operator | Uses `https` for every service on another host whose address a setting or a provider file gives the agent, tenant-manager included. The page states what `http` lets anyone on the network path do: serve keys of their own and forge tokens that the agent accepts, read the client secret or the agent's token, or answer for tenant-manager and choose the policy data of the default tenant. |
  | Resource limits | Operator | Sets a memory limit on the container. |
  | Log collection and rotation | Operator | Collects the logs of the container and rotates them. |
  | Clock | Operator | Keeps a host clock that differs from the clocks of the token issuers by less than the leeway of ADR-0091 R44. |
  | Graceful termination | Agent and runtime | The agent stops within the time of R31, and the runtime waits for the container to exit, longer than 10 seconds after the agent receives `SIGTERM`, before it kills the container. The page names each delay between the stop of the container and the moment the agent receives `SIGTERM`, and the setting that changes it. |
  | Trust in a private CA | Operator | Puts the CA certificates under `/tmp/cert` and restarts the container after it changes them. Mounts a tmpfs that the uid of the agent can write at `/usr/local/share/ca-certificates` and at `/etc/ssl/certs`, so that no CA outlives the container. |
  | Replicas, autoscaling, and a rolling update | None | Nothing keeps a second agent serving while the agent is replaced, so an upgrade stops the checks for its duration, and nothing adds an agent under load. |

- **R34** (`docker`). The Compose example, with its placeholders replaced by the addresses and the credentials of an
  installation, brings the agent to ready on the container target. It meets the duties of R33 for container hardening,
  the restart after the process exits, readiness, network isolation, and graceful termination, and it uses `https` in
  every URL it gives the agent.

#### The README files

- **R28** (`docker`). The top-level `README.md` and `components/authz-agent/README.md` link the container page as a
  supported way to run the agent, and neither states that the agent runs only in Kubernetes.

### Implementation notes

Adds no requirement. Where the image runs the agent behind the entrypoint of its base image, the delay before the agent
receives `SIGTERM` is `SIGTERM_EXIT_DELAY` seconds, 10 by default, and the entrypoint adds the CAs under `/tmp/cert` to
the two directories of the row Trust in a private CA. The entrypoint also writes the public roots of the image into
`/etc/ssl/certs`, so a tmpfs there holds no roots for an image that runs the agent without it.

### Justification

No rule on the agent, its image, or the duties of R33 depends on Docker. The agent and its image need only what an OCI
container runtime provides, so the container target is defined by those capabilities, and Docker Compose appears only in
the example (R34). The agent needs neither root nor a writable root file system, and R4 keeps it so.

The token for the API server and the topology file exist only in a cluster, and the services of an installation on the
container target run in no cluster, so none of them holds a service account token that an API server signs. A provider
`kubernetes` would still be a required source (ADR-0104 R6, R25), and the agent would wait for the keys of an API server
that the installation does not have (ADR-0091 R14). So R5 requires the agent to work without one, whichever type the
provider `identity-provider` has.

Kubernetes restarts a container whose liveness probe fails, and waits for the grace period of the Pod after `SIGTERM`.
The container target guarantees a restart only when the process exits, and a kill when the container does not stop
within the wait of the runtime. So the agent exits on a failure it does not recover from (R32), and it stops within a
bound that the runtime waits out (R31, R33). Docker waits 10 seconds by default from the moment it sends the signal to
the container, and a delay before the agent receives the signal counts against that wait, so the page names each such
delay and the Compose example waits longer (R33, R34). Docker shows the state of a container only through a healthcheck,
and a healthcheck that passed while `/ready` reports the agent not ready would let `docker compose up --wait` go on with
an agent that is not ready (R33, R34).

Every facility that Kubernetes and the chart provide falls to the agent, the runtime, or the operator, or is lost, and
the container page tells the operator which duties are theirs (R33). The chart runs the container hardened, and R4 lets
the operator do the same with the user of the image or a uid in group 0 (R33). The container target does not restart a
container that hangs without exiting, so the monitoring of the installation checks its liveness on `/health`, which keys
and tenant-manager do not affect (ADR-0091 R18), and restarts it, and the internal surface is reachable from the
monitoring and from no other host (R33). The agent reads the provider files only at start (ADR-0104 R5), and nothing on
the container target restarts it when they change, so the operator does (R33). The agent sets its Go memory limit from
the memory limit of its container, so without a limit on the container a large policy set can grow until the OOM killer
of the host picks a process (R33). Token checks compare `exp` and `nbf` with the host clock, with a leeway of 30 seconds
(ADR-0091 R44), and a clock that is further off makes the agent refuse valid tokens or accept expired ones; any way of
keeping time meets the duty (R33). A bind mount keeps the owner and the mode of each file, and under R4 the agent may
run as a uid that owns none of them, so the operator makes the credentials readable to that uid alone (R33).

The public surface takes bearer tokens over plain HTTP. A proxy on another host would send them over the host network in
clear text, and any host that reaches the published port could call the agent past the proxy, so the proxy runs on the
same host (R33). TLS stays outside the agent for its clients, as the architect decided. Inside a cluster a call to
`http://identity-provider:8080` stays in the cluster network. On the container target Keycloak, tenant-manager, and the
policy source often run on other hosts. An `http` key URL there lets anyone on the path serve keys of their own and sign
tokens that the agent accepts for any subject and tenant. An `http` token endpoint sends the client secret in clear
text, and the agent sends its own token to the policy source and to tenant-manager, whose answer chooses the policy data
of the default tenant (ADR-0093 R11, R13). So the operator uses `https` for every such service on another host (R33).
Every HTTPS request of the agent verifies the certificate against the system roots alone (ADR-0106 R1), so an
installation with a private CA puts it under `/tmp/cert`, and the directories where the CAs are added have to be
writable. A volume there outlives the container and would keep a CA that the operator removed from `/tmp/cert`, so both
are a tmpfs, whether or not the root file system is read-only (R33).

A reader looks in the README files for how to run the agent, so both link the container page, and a sentence that ties
the agent to Kubernetes would send that reader away (R28).

### Alternatives considered

- **A7. Leave both surfaces reachable from every host on the network.** Rejected by R33: anyone on the network could
  read the metrics, and a client that reached the public surface directly would send its bearer token in clear text,
  where anyone on the network path can read and reuse it.
- **A10. Ship the example as a `docker run` command line.** Rejected by R34: the stop timeout, the healthcheck, the
  restart policy, and the port bindings would each become a flag that every operator has to repeat.
- **A12. Let a proxy on another host reach the public surface over the host network.** Rejected by R33: bearer tokens
  would cross the host network in clear text, and every host that reaches the published port could call the agent past
  the proxy.

## Consequences

Negative:

- The container target does not restart a container that hangs without exiting, so the monitoring of the installation
  has to (R33).
- Nothing takes an agent that stops being ready after its start out of service, so requests keep reaching it (R33).
- Under a runtime that restarts the container on exit, a configuration that stops the start makes the runtime start the
  agent again and again, each start ending with the same message in the logs of the container (R32, R33).
- A change to a provider file has no effect until the operator restarts the container (R33).
- Nothing keeps a second agent serving while the agent is replaced, so an upgrade stops the checks of the installation
  for its duration (R33).
- A PIP that a policy declares by the name of a Kubernetes Service is reached only where the operator gives that name to
  a container or a host, and one that a policy declares with an `http` URL on another host receives the agent's token in
  clear text: the duties of R33 cover the addresses that the operator sets, and not the declarations in the policies.
- On the container target the operator writes the address of Keycloak in the provider file, once for the issuers and
  once for the keys, and again as the token endpoint of the agent's client credentials token (ADR-0091 R78).
- Where the provider files on the container target hold no provider `kubernetes`, as R5 allows, no token is a Kubernetes
  token, and services that call with tokens that an API server signs cannot use such an agent (R5). Such a token is
  refused under ADR-0104 R21 or R27.
