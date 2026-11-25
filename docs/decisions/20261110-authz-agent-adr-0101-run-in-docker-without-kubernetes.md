# Run the agent in Docker without Kubernetes

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record. On 2026-11-23 the architect and the owner of the policy
  decision code agreed to drop the M2M modes, so the Docker target runs without the provider `kubernetes` rather than
  in `legacy` (R5, R8).
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0080: Replace Envoy, the Lua filters, and the OPA container with one Go service that embeds OPA](20260907-authz-agent-adr-0080-single-go-service-with-embedded-opa.md):
  the one image of the agent that this record runs outside Kubernetes.
- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  the term stops the start; ADR-0091 R14, readiness; ADR-0091 R44, the leeway against the clock; ADR-0091 R64, the
  removal of `AUTHZ_JWKS_BOOTSTRAP_REQUIRED`; and ADR-0091 R78, `IDENTITY_PROVIDER_URL`, which the agent does not read.
- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  ADR-0092 R15, which has the agent leave `M2M_AUTH_MODE` unread.
- [authz-agent-ADR-0093: Take the tenant of a decision from the verified user token, then from the request](20261029-authz-agent-adr-0093-tenant-of-a-decision.md):
  ADR-0093 R11 and R14, the default tenant with and without tenant-manager.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  the topology file and the token for the API server, which exist only in a cluster.
- [authz-agent-ADR-0096: Choose the token the agent sends with a setting of its own](20261105-authz-agent-adr-0096-token-the-agent-sends.md):
  ADR-0096 R1, `AUTHZ_M2M_TOKEN_SOURCE`, which the agent reads itself; ADR-0096 R3, how the agent reads that setting,
  which R6 follows for every value from a list; ADR-0096 R5, the token endpoint that `client-credentials` requires;
  ADR-0096 R7, which files the agent leaves unread with each value.
- [authz-agent-ADR-0104: Describe the two trusted providers in a fixed directory of provider files](https://github.com/Netcracker/qubership-authz-agent/pull/329),
  proposed in #329: the provider directory and the provider files (ADR-0104 R1, R2), the two providers and their types
  (ADR-0104 R6), the required sources (ADR-0104 R25), the Kubernetes token (ADR-0104 R22), the refusal of a token whose
  `iss` matches no provider (ADR-0104 R21), and the refusal of a token with the claim `kubernetes.io` whose source is
  another provider (ADR-0104 R27).
- [authz-agent-ADR-0106: Trust a private CA only through the system roots of the base image](https://github.com/Netcracker/qubership-authz-agent/pull/330),
  proposed in #330: ADR-0106 R1, the system roots that every HTTPS request of the agent verifies against.

## Context

The agent is documented to run only in Kubernetes. Some installations have no Kubernetes and run containers with
Docker. At 5a351ef5 the agent took the default for a value it could not read, and logged nothing.

## Decision

We will support running the agent from its image with Docker Compose, with no Kubernetes, configured by environment
variables and mounted files alone, which the agent checks itself on every target. The repository ships a Compose
example.

### Terms

- **Docker target**: the agent run from its release image by Docker Compose v2 on Docker Engine, on `linux/amd64` or
  `linux/arm64`, with no Kubernetes component.
- **Compose example**: `deploy/docker/compose.yaml` and the files beside it in `deploy/docker`.
- **Docker page**: `deploy/docker/README.md`.
- **Public surface**: the listener whose address `AUTHZ_PUBLIC_ADDR` sets.
- **Internal surface**: the listener whose address `AUTHZ_HTTP_ADDR` sets.
- **Agent variable**: an environment variable that code built into the agent binary from `components/authz-agent` or
  `internal` reads by name, `LOGGING_LEVEL_ROOT` included. A variable that only a test, the Go runtime, or the standard
  library reads, such as `GOMEMLIMIT` or `HTTPS_PROXY`, is not one, and neither is `LOG_LEVEL`, which R30 governs.
- **Settings table**: the table under `## Configuration` in `components/authz-agent/README.md`.
- **Stops the start**: as ADR-0091 defines it.
- **Provider directory**, **provider file**, **provider `identity-provider`**, **provider `kubernetes`**, **`realms`
  provider**, **`single` provider**, **required source**, **Kubernetes token**: as ADR-0104 defines them.
- **Token for the API server**, **topology file**: as ADR-0094 defines them.

### Rules

#### The image

- **R4** (`image`, `startup`). On the Docker target, running as any uid in group 0, with a read-only root file system
  and all Linux capabilities dropped, changes neither whether the agent starts nor whether it becomes ready.

#### Configuration

- **R5** (`startup`). With provider files that hold the provider `identity-provider`, as a `realms` or a `single`
  provider, and no provider `kubernetes`, the agent starts, becomes ready, and serves on the Docker target with
  environment variables and mounted files alone: no Kubernetes API server, no service account token, and no topology
  file.
- **R6** (`startup`, `client`). Before it serves a request, on every target, the agent checks the value of every agent
  variable and stops the start on a value that the row of the variable in the settings table does not accept, with a
  message that names the variable and the values its row accepts. The agent reads an integer as decimal digits with an
  optional sign, a boolean as `true` or `false` alone, without regard to case, and a value from a list without regard
  to case. An unset agent variable, and an empty integer, boolean, or value from a list, takes the default of its row,
  or does what the row says where it gives no default; an empty value of any other type does what its row says.
- **R7** (`startup`, `client`). The settings table gives an empty default to every agent variable that holds the address
  of a service the agent calls, `AUTHZ_TENANT_MANAGER_URL` included.
- **R20** (`startup`, `client`). An agent variable that its row in the settings table marks as required, always or under
  values of other agent variables, stops the start when it is unset or empty while it is required, with a message that
  names the variable and, where values of others require it, those values. R20 takes precedence over the default that
  R6 gives an unset or empty variable.
- **R21** (`startup`, `client`). The settings table has a row for each agent variable; a row may name several
  variables. A row gives the type and the values or the range accepted. It gives the default, or, where the variable has
  none, what the agent does without a value. It says whether the variable is required, always or under values of other
  agent variables that the row names, and what an empty value does where the type admits one. An empty default is a
  default. The range of a number lies within the values that its destination type holds in its unit.
- **R30** (`startup`). The agent takes its root log level from `LOGGING_LEVEL_ROOT`. A non-empty `LOG_LEVEL` stops the
  start, with a message that names `LOGGING_LEVEL_ROOT`.

#### The Compose example and the Docker page

- **R8** (`docker`). The Compose example runs the agent from its release image, mounts its provider files at the
  provider directory and the client credentials at `/etc/secret`, and holds an example provider file with the provider
  `identity-provider` and without the provider `kubernetes`.
- **R9** (`docker`, `startup`). The environment file of the Compose example lists every agent variable with a comment.
  It gives each variable that the configuration of the example requires a placeholder, such as an address under
  `example.com`, gives every other variable that has a default the default of its row in the settings table, and leaves
  each remaining variable commented out. It sets `AUTHZ_M2M_TOKEN_SOURCE` to `client-credentials`.
- **R10** (`docker`). The Compose example gives the agent a stop grace period of 30 seconds.
- **R11** (`docker`). The Compose example declares a healthcheck on `/ready` of the internal surface, which passes only
  while `/ready` reports the agent ready.
- **R12** (`docker`). The Compose example sets the restart policy `unless-stopped`.
- **R13** (`docker`). The Compose example publishes the ports of the public surface and of the internal surface on no
  address other than `127.0.0.1`.
- **R14** (`docker`). The Docker page shows how to trust a private CA through `/tmp/cert`.
- **R15** (`docker`). The Docker page requires a host clock synchronized over NTP.
- **R16** (`docker`). The Docker page states that the agent serves plain HTTP and that a proxy in front of the public
  surface terminates TLS. It states that a proxy in a container on the same host reaches the public surface over the
  Compose network, and that a proxy on another host needs the port of the public surface published on an interface
  that host reaches.
- **R29** (`docker`). The Docker page shows how to make the client credentials mounted at `/etc/secret` readable to the
  uid the agent runs as, without making them readable to other users of the host.

#### The README files

- **R28** (`docker`). The top-level `README.md` and `components/authz-agent/README.md` link the Docker page as a
  supported way to run the agent, and neither states that the agent runs only in Kubernetes.

### Justification

The agent calls Keycloak, the PIPs, and the policy source over HTTPS and verifies their certificates against the system
roots alone (ADR-0106 R1). An installation with a private CA puts it under `/tmp/cert`, and the Docker page shows how
(R14). The agent needs neither root nor a writable root file system, and R4 keeps it so. Under R4 the agent may run as a
uid that owns none of the files the operator mounts. A bind mount keeps the owner and mode of each file, so the Docker
page shows how to make the credentials readable to that uid without making them readable to every user of the host
(R29).

On the Docker target nothing but the agent checks its configuration. The token for the API server and the topology file
exist only in a cluster, and the services of an installation on the Docker target run in no cluster, so none of them
holds a service account token that an API server signs. A provider `kubernetes` would still be a required source
(ADR-0104 R6, R25), and the agent would wait for the keys of an API server that the installation does not have
(ADR-0091 R14). So the example's provider file holds no provider `kubernetes`, and R5 requires the agent to work without
one, whichever type the provider `identity-provider` has (R8). A mistyped value of any agent variable stops the start,
so an operator learns of it at once rather than running with a default they did not choose (R6). The settings table
keeps the list in one file, so a new variable joins it in the change that adds it (R21). A variable can be optional and
still have no default, so a row gives the default and whether the variable is required separately (R21). A number that
its destination type cannot hold would overflow instead of being refused, so its range ends within that type, and the
row gives the bound (R21). A variable that the values of others require, such as `AUTHZ_M2M_TOKEN_URL` with
`AUTHZ_M2M_TOKEN_SOURCE=client-credentials` under ADR-0096 R5, is marked in its row, and R20 stops the start without it.
R6 reads a value from a list as ADR-0096 R3 reads `AUTHZ_M2M_TOKEN_SOURCE`, so that no setting accepts a spelling
another one refuses. The platform logger reads `LOG_LEVEL` when `LOGGING_LEVEL_ROOT` is unset or empty, and runs at
`info` with only a warning when it cannot parse the value. So the root log level has one name, `LOGGING_LEVEL_ROOT`, and
a non-empty `LOG_LEVEL` stops the start (R30).

A default address such as `http://tenant-manager:8080` names a service that only some networks have, whether the name
belongs to a Kubernetes Service or to a Compose service. With an address of tenant-manager the agent stays not ready
until the translation through tenant-manager succeeds (ADR-0093 R11), and with an empty one it uses the default tenant
as given (ADR-0093 R14). An empty default lets an agent without tenant-manager start, and an operator who has one names
it (R7). With `AUTHZ_M2M_TOKEN_SOURCE=client-credentials`, which the agent reads itself (ADR-0096 R1), the agent gets
its token from `AUTHZ_M2M_TOKEN_URL` (ADR-0096 R5) and does not read the agent's token file of ADR-0096 (ADR-0096 R7).
That file lies under `/var/run/secrets`, where nothing is mounted on the Docker target, so the Compose example sets
`AUTHZ_M2M_TOKEN_SOURCE` to `client-credentials` (R9).

An operator starts from the Compose example, so it carries what the agent needs to start (R8, R9). The provider file
and `AUTHZ_M2M_TOKEN_URL` stay in the example, because the agent does not read `IDENTITY_PROVIDER_URL`
(ADR-0091 R78). Docker's default stop timeout is too short for the agent to stop gracefully, so the example sets a
longer one (R10). A reader looks in the README files for how to run the agent, so both link the Docker page, and a
sentence that ties the agent to Kubernetes would send that reader away (R28).

Docker shows the state of a container only through a healthcheck, and keeps running a container marked unhealthy. A
dependent container waits until the agent is ready (ADR-0091 R14), and a healthcheck that passed while `/ready` reports
the agent not ready would let `docker compose up --wait` go on with an agent that is not ready (R11). The restart policy
covers a process that exits (R12). Docker publishes a port on every interface unless the mapping names one. The internal
surface serves the metrics and the probes, and the public surface takes bearer tokens over plain HTTP, so the example
keeps both on `127.0.0.1`. A proxy in a container on the same host needs no published port, and the interface a proxy on
another host reaches is the operator's choice (R13, R16). Token checks compare `exp` and `nbf` with the host clock, with
a leeway of 30 seconds (ADR-0091 R44). A clock that drifts further makes the agent refuse valid tokens or accept expired
ones (R15). TLS stays outside the agent for its clients, as the architect decided (R16).

### Alternatives considered

- **A2. Run the agent as a process under systemd on a Linux host.** The agent would run outside its image on one
  target, and the release would need a second artifact.
- **A3. Let the agent build the provider `identity-provider` and `AUTHZ_M2M_TOKEN_URL` from `IDENTITY_PROVIDER_URL`.**
  ADR-0091 R78 decides that the agent does not read that setting.
- **A4. Log a warning and keep the default for an invalid value.** Rejected by R6: the warning is easy to miss, and the
  agent would run, for example, with a pull interval the operator did not choose.
- **A5. Put the healthcheck into the Dockerfile.** The address would be fixed in the image, while `AUTHZ_HTTP_ADDR` can
  change the address of the internal surface.
- **A7. Publish the ports on every interface.** Rejected by R13: anyone on the network could read the metrics, and a
  client that reached the public surface directly would send its bearer token in clear text, where anyone on the
  network path can read and reuse it.
- **A8. Accept `1`, `yes`, `on`, `0`, `no`, and `off` for every boolean.** Rejected by R6: ADR-0091 R64 removes
  `AUTHZ_JWKS_BOOTSTRAP_REQUIRED`, the one setting that accepted them at 5a351ef5, so no setting needs them.
- **A10. Support `docker run` without Compose.** The stop grace period, the healthcheck, the restart policy, and the
  port bindings would each become a flag that every operator has to repeat.
- **A11. Accept `LOG_LEVEL` as a second name of the log level and check both.** Rejected by R30: with two names for one
  setting, an operator has to know which one the agent reads when both are set.

## Consequences

Negative:

- Docker does not restart a container that hangs without exiting. The healthcheck only marks it, and the monitoring of
  the installation has to act (R11, R12).
- A configuration that stops the start makes the restart policy start the agent again and again, each start ending
  with the same message in `docker compose logs` (R12).
- On the Docker target the operator writes the address of Keycloak in the provider file, once for the issuers and
  once for the keys, and again in `AUTHZ_M2M_TOKEN_URL` (ADR-0091 R78).
- A value that the agent at 5a351ef5 replaced with its default, such as `5s` for a number of seconds, now stops the
  start (R6).
- An installation without the chart that sets `LOG_LEVEL` now stops the start, and moves the value to
  `LOGGING_LEVEL_ROOT` (R30).
- An installation that ran v0.1.0 without the chart and uses tenant-manager sets `AUTHZ_TENANT_MANAGER_URL` before it
  upgrades. Without it the agent sends no request to tenant-manager: it uses the default tenant as given (ADR-0093 R14)
  and a realm named by a tenant's display name as written (R7).
- Releases before 1.0, v0.1.0 included, carry no stable API or configuration commitment, so the release notes of each
  release that implements R6, R7, or R30 list what it changes for an installation without the chart.
- On the Docker target the provider files hold no provider `kubernetes`, so no token is a Kubernetes token, and
  services that call with tokens that an API server signs cannot use such an agent (R5, R8). Such a token is refused
  under ADR-0104 R21 or R27.
