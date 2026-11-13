# Run the agent in Docker without Kubernetes

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
  the term stops the start; ADR-0091 R2, the CA of the requests to Keycloak; ADR-0091 R14, readiness; ADR-0091 R44,
  the leeway against the clock; ADR-0091 R64, the removal of `AUTHZ_JWKS_BOOTSTRAP_REQUIRED`; and ADR-0091 R78,
  `IDENTITY_PROVIDER_URL`, which the agent does not read.
- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  ADR-0092 R15, a value of `M2M_AUTH_MODE` that stops the start; ADR-0092 R16, `legacy` as the only M2M mode outside
  Kubernetes.
- [authz-agent-ADR-0093: Take the tenant of a decision from the verified user token, then from the request](20261029-authz-agent-adr-0093-tenant-of-a-decision.md):
  ADR-0093 R11 and R14, the default tenant with and without tenant-manager.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  the topology file and the token for the API server, which exist only in a cluster.
- [authz-agent-ADR-0096: Choose the token the agent sends with a setting of its own](20261105-authz-agent-adr-0096-token-the-agent-sends.md):
  ADR-0096 R1, `KUBERNETES_M2M_ENABLED`, which the agent reads itself; ADR-0096 R3, how the agent reads that setting,
  which R6 follows for every boolean; ADR-0096 R5, the token endpoint that `KUBERNETES_M2M_ENABLED=false` requires;
  ADR-0096 R8, the pairs of that setting and the M2M mode that stop the start.

## Context

The agent is documented to run only in Kubernetes. Some installations have no Kubernetes and run containers with
Docker. At 5a351ef5 the agent took the default for a value it could not read, and logged nothing.

## Decision

We will support running the agent from its image under Docker, with no Kubernetes, configured by environment variables
and mounted files alone, which the agent checks itself on every target. The repository ships a Compose example, and CI
runs it.

### Terms

- **Docker target**: the agent run from its release image by Docker Engine, alone or with Docker Compose v2, on
  `linux/amd64` or `linux/arm64`, with no Kubernetes component.
- **Compose example**: `deploy/docker/compose.yaml` and the files beside it in `deploy/docker`.
- **Docker page**: `deploy/docker/README.md`.
- **Agent variable**: an environment variable that code built into the agent binary from `components/authz-agent` or
  `internal` reads by name, `LOGGING_LEVEL_ROOT` included. A variable that only a test, the Go runtime, or the standard
  library reads, such as `GOMEMLIMIT` or `HTTPS_PROXY`, is not one.
- **Settings table**: the table under `## Configuration` in `components/authz-agent/README.md`.
- **Stops the start**: as ADR-0091 defines it.

### Rules

#### The image

- **R4** (`image`, `startup`). On the Docker target, wherever the agent starts and becomes ready with the uid of the
  image and no other limit, it also starts and becomes ready with any uid in group 0, a read-only root file system, and
  all Linux capabilities dropped.
- **R19** (`image`). On the Docker target, under the restrictions of R4, an agent started from the release image adds
  the CA certificates in the `.crt`, `.cer`, and `.pem` files under `/tmp/cert` at its start to the system roots of the
  image. Every HTTPS call of the agent that trusts the system roots trusts those certificates too, and refuses a server
  whose certificate was not signed by a CA that the call trusts. Where `keycloak.caFile` holds a CA (ADR-0091 R2), a
  call to that Keycloak trusts that CA instead.

#### Configuration

- **R5** (`startup`). In the M2M mode `legacy`, the agent starts, becomes ready, and serves on the Docker target with
  environment variables and mounted files alone: no Kubernetes API server, no service account token, and no topology
  file.
- **R6** (`startup`, `client`). Before it serves a request, on every target, the agent checks the value of every agent
  variable and stops the start on a value that the row of the variable in the settings table does not accept, with a
  message that names the variable and the values its row accepts. The agent reads an integer as decimal digits with an
  optional sign, a boolean as `true` or `false` alone, without regard to case, and a value from a list without regard
  to case. An unset agent variable, and an empty integer, boolean, or value from a list, takes the default of its row;
  an empty value of any other type does what its row says.
- **R7** (`startup`, `client`). The settings table gives an empty default to every agent variable that holds the address
  of a service the agent calls, `AUTHZ_TENANT_MANAGER_URL` included. With `KUBERNETES_M2M_ENABLED=false` the agent opens
  no file under `/var/run/secrets` that the default of an agent variable names.
- **R20** (`startup`, `client`). An agent variable that its row in the settings table marks as required, always or under
  values of other agent variables, stops the start when it is unset or empty while it is required, with a message that
  names the variable and, where values of others require it, those values. R20 takes precedence over the default that
  R6 gives an unset or empty variable.
- **R21** (`startup`, `client`). The settings table has a row for each agent variable; a row may name several
  variables. A row gives the type, the values or the range accepted, the default or, where there is none, that the
  variable is always required, what an empty value does where the type admits one, and the values of other agent
  variables that make the variable required, where some do. An empty default is a default. The range of a number lies
  within the values that its destination type holds in its unit: `-9223372036` to `9223372036` for a number of seconds.
  The range of `AUTHZ_ENTITLEMENTS_HTTP_RETRIES`, and of `AUTHZ_JWKS_HTTP_RETRIES` while the agent reads it, ends at
  `<retry maximum>`.

#### The Compose example

- **R8** (`docker`). The Compose example runs the agent from its release image, mounts the trusted providers file at
  `/etc/authz` and the client credentials at `/etc/secret`, and holds an example trusted providers file.
- **R9** (`docker`, `startup`). The environment file of the Compose example lists every agent variable with a comment.
  It gives each variable that the configuration of the example requires a placeholder, such as an address under
  `example.com`, and every other variable the default of its row in the settings table. It sets `M2M_AUTH_MODE` to
  `legacy` and `KUBERNETES_M2M_ENABLED` to `false`.
- **R10** (`docker`). The Compose example gives the agent a stop grace period of 30 seconds.
- **R11** (`docker`). The Compose example declares a healthcheck on `/ready` of the internal port, which passes when
  `/ready` answers 200, and fails when it answers 503 or any status of 400 or above, when the connection fails, and when
  no answer comes within the healthcheck's timeout.
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
- **R24** (`ci`). The job of R17 shows, against the image of the commit run under the restrictions of R4, that a value
  R6 refuses stops the start, and that an unset variable that the configuration of the Compose example requires stops
  the start.
- **R25** (`ci`). The job of R17 shows, against the image of the commit run under the restrictions of R4, that an HTTPS
  call to a server whose certificate a CA under `/tmp/cert` signed succeeds, and that a call to a server whose
  certificate was signed by a CA that neither `/tmp/cert` nor the image trusts fails (R19).
- **R26** (`ci`). The job of R17 shows that the healthcheck of R11 reports the container unhealthy while `/ready`
  answers 503, and healthy once it answers 200.
- **R27** (`ci`). The job of R17 shows that `docker compose stop` ends the agent of the Compose example through
  `SIGTERM` within the stop grace period of R10, with an exit status other than 137.

### Implementation notes

Adds no requirement.

- R6, R20, and R21: let `loadConfig` in `components/authz-agent/config.go` check every agent variable, collect the
  values it refuses, and return them in one error that `main` reports before the agent listens. The platform logger
  drops errors at the log level `fatal`, so let `main` raise the level to `error` for that report.
- R9: a test that compares the keys of the environment file with the agent variables keeps R9 true as variables are
  added.
- R11: the image ships `curl`, and `curl --fail` exits with an error on a status of 400 or above.
- R4, R5, and R24 to R27: the override of R17 can run the agent as a uid such as `12345:0`, and the Compose example
  already sets `read_only: true` and `cap_drop: [ALL]`. For the CA, a small HTTPS server with the certificate of a
  test CA, and one with the certificate of another test CA, can stand in for a PIP. Starting the agent while the policy
  source is stopped, and then starting the source, moves `/ready` from 503 to 200. The job replaces the release image
  with the image of the commit, so R8 to R13 stay properties of the files that a reader checks.
- R17: the suite reads every address from its environment, as `test/integration/testify/helpers.go` lists them. The
  realms of `test/k8s/authn` and the images of `test/integration/pipstub` and `test/integration/tenantmanager` serve the
  override as they serve kind.

### Justification

The agent calls Keycloak, the PIPs, and the policy source over HTTPS. An installation with a private CA needs the
release image to trust that CA under the same restrictions as the rest of its run, and the Docker page shows an operator
how (R14, R19). The agent needs neither root nor a writable root file system, and R4 keeps it so.

On the Docker target nothing but the agent checks its configuration. The token for the API server and the topology file
exist only in a cluster, so ADR-0092 R16 leaves `legacy` as the only mode outside Kubernetes, and R5 requires that mode
to work with neither. A mistyped value of any agent variable stops the start, as an unknown mode does under
ADR-0092 R15, so an operator learns of it at once rather than running with a default they did not choose (R6). The
settings table keeps the list in one file, so a new variable joins it in the change that adds it (R21). A number that
its destination type cannot hold, such as a number of seconds above `9223372036`, overflows `time.Duration` instead of
being refused, so its range ends there (R21). A variable that the values of others require, such as
`AUTHZ_M2M_TOKEN_URL` with `KUBERNETES_M2M_ENABLED=false` under ADR-0096 R5, is marked in its row, and R20 stops the
start without it; a pair that a record forbids, such as those of ADR-0096 R8, stops the start as that record says. R6
reads a boolean as ADR-0096 R3 reads `KUBERNETES_M2M_ENABLED`, so that no setting accepts a spelling another one
refuses.

A default address such as `http://tenant-manager:8080` names a service that only some networks have, whether the name
belongs to a Kubernetes Service or to a Compose service. With an address of tenant-manager the agent stays not ready
until the translation through tenant-manager succeeds (ADR-0093 R11), and with an empty one it uses the default tenant
as given (ADR-0093 R14). An empty default lets an agent without tenant-manager start, and an operator who has one names
it (R7). With `KUBERNETES_M2M_ENABLED=false` the agent gets its token from `AUTHZ_M2M_TOKEN_URL` (ADR-0096 R5) and needs
no file under `/var/run/secrets`, where nothing is mounted on the Docker target (R7).

An operator starts from the Compose example, and CI runs the same file, so a change that breaks the Docker target fails
a check (R8, R9, R17). The trusted providers file and `AUTHZ_M2M_TOKEN_URL` stay in the example, because the agent does
not read `IDENTITY_PROVIDER_URL` (ADR-0091 R78). The agent shuts its two surfaces down one after the other, each in up
to 5 seconds, so in up to 10 seconds, all of Docker's default stop timeout, and 30 seconds leave a margin (R10).

Docker shows the state of a container only through a healthcheck, and keeps running a container marked unhealthy. A
dependent container waits until the agent is ready (ADR-0091 R14), and a healthcheck that passed on a 503 from `/ready`
would let `docker compose up --wait` go on with an agent that is not ready (R11). The restart policy covers a process
that exits (R12). Docker publishes a port on every interface unless the mapping names one, and the internal port serves
the metrics, `/ready`, and `/health` (R13). Token checks compare `exp` and `nbf` with the host clock, with a leeway of
30 seconds (ADR-0091 R44). A clock that drifts further makes the agent refuse valid tokens or accept expired ones (R15).
TLS stays outside the agent for its clients, as the architect decided (R16).

A job on `ubuntu-26.04` stays on Ubuntu 26.04 until a change to the workflow moves it, while `ubuntu-latest` moves to
the next Ubuntu release on GitHub's schedule (R17). GitHub still updates the tools of either image every week, Docker
and Compose among them. The suite already exercises the agent on kind over HTTP alone, so in Docker it covers the same
paths, apart from the cases that read what only a cluster has (R17). The suite shows neither a refused configuration,
nor a private CA under the restrictions of R4, nor a failing healthcheck, nor a stop within the grace period, so the job
shows each of them in a rule of its own, which a change can bring apart from the others (R24 to R27).

### Alternatives considered

- **A2. Run the agent as a process under systemd on a Linux host.** The agent would run outside its image on one
  target, and the release would need a second artifact.
- **A3. Let the agent build the trusted providers file and `AUTHZ_M2M_TOKEN_URL` from `IDENTITY_PROVIDER_URL`.**
  ADR-0091 R78 decides that the agent does not read that setting.
- **A4. Log a warning and keep the default for an invalid value.** Rejected by R6: the warning is easy to miss, and the
  agent would run, for example, with a pull interval the operator did not choose.
- **A5. Put the healthcheck into the Dockerfile.** The address would be fixed in the image, while `AUTHZ_HTTP_ADDR` can
  move the internal port.
- **A6. Check only readiness and one decision in CI.** Rejected by R17: a regression on the Docker target outside that
  path would pass.
- **A7. Publish the internal port on every interface.** Rejected by R13: anyone on the network could read the metrics.
- **A8. Accept `1`, `yes`, `on`, `0`, `no`, and `off` for every boolean.** Rejected by R6: ADR-0096 R3 would have to
  accept them as well, and ADR-0091 R64 removes `AUTHZ_JWKS_BOOTSTRAP_REQUIRED`, the one setting that accepted them at
  5a351ef5.

## Consequences

Negative:

- A plain `docker run` needs `--stop-timeout 30`, or Docker kills the agent before it shuts down (R10).
- Docker does not restart a container that hangs without exiting. The healthcheck only marks it, and the monitoring of
  the installation has to act (R11, R12).
- On the Docker target the operator writes the address of Keycloak twice, in the trusted providers file and in
  `AUTHZ_M2M_TOKEN_URL` (ADR-0091 R78).
- The agent at 5a351ef5 started with values that now stop the start, such as `AUTHZ_JWKS_HTTP_TIMEOUT=5s` and
  `AUTHZ_M2M_RENEW_BEFORE_SECONDS=1m` (R6). While the agent reads `AUTHZ_JWKS_BOOTSTRAP_REQUIRED`, `yes`, `on`, `1`,
  `no`, `off`, and `0` stop the start for that setting as well (R6).
- On the Docker target only `legacy` works, so services that call with Kubernetes tokens cannot use such an agent
  (ADR-0092 R16).
- With the empty default of R7, an agent without `AUTHZ_TENANT_MANAGER_URL` sends no request to tenant-manager. It uses
  the default tenant as given (ADR-0093 R14), and a realm named by a tenant's display name as written.

Follow-ups:

- The top-level README and `components/authz-agent/README.md` link the Docker page instead of stating that the
  deployment assumes Kubernetes.

## Open points

- **O2.** The maximum of `AUTHZ_ENTITLEMENTS_HTTP_RETRIES`, and of `AUTHZ_JWKS_HTTP_RETRIES` while the agent reads it,
  `<retry maximum>` in R21. The answers under consideration are a bound that no installation needs to exceed, such as
  `100`, and the largest value of its destination type. The architect decides. It affects R21.
