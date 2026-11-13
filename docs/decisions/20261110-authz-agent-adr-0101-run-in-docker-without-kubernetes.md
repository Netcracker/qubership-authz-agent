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
  the term stops the start; ADR-0091 R2, the CA of the requests to Keycloak; ADR-0091 R14 and R18, readiness and
  liveness; ADR-0091 R44, the leeway against the clock;
  ADR-0091 R64, the removal of `AUTHZ_JWKS_BOOTSTRAP_REQUIRED`; and ADR-0091 R72 and R78, `IDENTITY_PROVIDER_URL` read
  by the chart alone.
- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  ADR-0092 R16, `legacy` as the only M2M mode outside Kubernetes.
- [authz-agent-ADR-0093: Take the tenant of a decision from the verified user token, then from the request](20261029-authz-agent-adr-0093-tenant-of-a-decision.md):
  ADR-0093 R11 and R14, the default tenant with and without tenant-manager.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  the topology file and the token for the API server, which exist only in a cluster; ADR-0094 R7, the cluster CA of an
  in-cluster issuer.
- [authz-agent-ADR-0096: Choose the token the agent sends with a setting of its own](20261105-authz-agent-adr-0096-token-the-agent-sends.md):
  ADR-0096 R1 to R8, the setting that chooses the agent's token, which the agent reads with or without the chart;
  ADR-0096 R5, the token endpoint that `KUBERNETES_M2M_ENABLED=false` requires; ADR-0096 R8, the pairs of that setting
  and the M2M mode that stop the start.

## Context

The agent ships as one image for `linux/amd64` and `linux/arm64`, built on the platform base image
`ghcr.io/netcracker/qubership-core-base`, Alpine flavor, pinned by digest. The Helm chart is the only documented way to
run it, and the top-level README states that the deployment assumes a Kubernetes cluster. Some installations have no
Kubernetes and run containers with Docker.

The entrypoint of the base image, `/usr/bin/entrypoint.sh`, adds the certificates in `.crt`, `.cer`, and `.pem` files
under `/tmp/cert` to the trust store of the container at each start, gives a uid that has no entry in `/etc/passwd` one
through `nss_wrapper`, and passes `SIGTERM` on to the process after `SIGTERM_EXIT_DELAY` seconds, 10 by default.

In Kubernetes the chart does part of the work around the agent. Its values schema refuses invalid values before the Pod
exists. It builds the trusted providers file and `AUTHZ_M2M_TOKEN_URL` from `IDENTITY_PROVIDER_URL`, mounts the client
credentials, and probes `/ready` and `/health` on the internal port. Under Docker none of that runs: every value reaches
the agent as the operator wrote it, and every address the agent calls comes from the operator or from the agent's own
default. At 5a351ef5 the agent took the default for a value it could not read, and logged nothing.

Kubernetes tokens and the topology file of ADR-0094 exist only in a cluster, and ADR-0092 R16 leaves `legacy` as the
only M2M mode outside Kubernetes. The architect decided that the agent does not terminate TLS for its clients.

## Decision

We will support running the agent from its image under Docker, with no Kubernetes, on the platform base image,
configured by environment variables and mounted files alone, which the agent checks itself on every target. The
repository ships a Compose example, and CI runs it.

### Terms

- **Docker target**: the agent run from its release image by Docker Engine, alone or with Docker Compose v2, on
  `linux/amd64` or `linux/arm64`, with no Kubernetes component.
- **Chart check**: a constraint that `helm-templates/authz-agent/values.schema.json` puts on a value that the chart
  passes to the container as an environment variable.
- **Compose example**: `deploy/docker/compose.yaml` and the files beside it in `deploy/docker`.
- **Docker page**: `deploy/docker/README.md`.
- **Agent variable**: an environment variable that code built into the agent binary from `components/authz-agent` or
  `internal` reads by name, `LOGGING_LEVEL_ROOT` included. A variable that only a test, the Go runtime, the standard
  library, or the entrypoint of the image reads, such as `GOMEMLIMIT`, `HTTPS_PROXY`, or `SIGTERM_EXIT_DELAY`, is not
  one.
- **Settings table**: the table under `## Configuration` in `components/authz-agent/README.md`.
- **Stops the start**: as ADR-0091 defines it.

### Rules

#### The image

- **R1** (`image`). The image of the agent is built on `ghcr.io/netcracker/qubership-core-base`, Alpine flavor, pinned
  by digest.
- **R4** (`image`, `startup`). On the Docker target, wherever the agent starts and becomes ready with the uid of the
  image and no other limit, it also starts and becomes ready with any uid in group 0, a read-only root file system, and
  all Linux capabilities dropped.
- **R19** (`image`, `chart`). An agent started from the release image adds the CA certificates in the `.crt`, `.cer`,
  and `.pem` files under `/tmp/cert` at its start to the system roots of the image: every HTTPS call that trusts the
  system roots trusts them too, and refuses a server whose certificate no CA that the call trusts signed. A call whose
  CA ADR-0091 R2 or ADR-0094 R7 names trusts that CA instead. This holds under the restrictions of R4, on the Docker
  target and in the chart's Pod.

#### Configuration without the chart

- **R5** (`startup`). In the M2M mode `legacy`, the agent starts, becomes ready, and serves on the Docker target with
  environment variables and mounted files alone: no Kubernetes API server, no chart, no service account token, and no
  topology file.
- **R6** (`startup`, `client`). Before it serves a request, on every target, with or without the chart, the agent checks
  the value of every agent variable and stops the start on a value that the row of the variable in the settings table
  does not accept, with a message that names the variable and the values its row accepts. The agent reads an integer as
  decimal digits with an optional sign, a boolean as `true` or `false` alone, without regard to case, and a value from a
  list without regard to case. An unset agent variable, and an empty integer, boolean, or value from a list, takes the
  default of its row; an empty value of any other type does what its row says.
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

#### The chart

- **R22** (`chart`, `startup`). For every agent variable that the chart sets from a key of its `values.yaml`, the chart
  check of that key refuses each value that R6 refuses for the variable, and every value that the chart check accepts
  reaches the container as a value that R6 accepts.
- **R23** (`chart`). The chart passes `AUTHZ_TENANT_MANAGER_URL` from its value of the same name,
  `http://tenant-manager:8080` by default.

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
  certificate a CA signed that neither `/tmp/cert` nor the image trusts fails (R19).
- **R26** (`ci`). The job of R17 shows that the healthcheck of R11 reports the container unhealthy while `/ready`
  answers 503, and healthy once it answers 200.
- **R27** (`ci`). The job of R17 shows that `docker compose stop` ends the agent of the Compose example through
  `SIGTERM` within the stop grace period of R10, with an exit status other than 137.

### Implementation notes

Adds no requirement.

- R6, R20, and R21: let `loadConfig` in `components/authz-agent/config.go` check every agent variable, collect the
  values it refuses, and return them in one error that `main` reports before the agent listens. The platform logger
  drops errors at the log level `fatal`, so let `main` raise the level to `error` for that report.
- R22: a test that reads `helm-templates/authz-agent/values.schema.json` and runs `loadConfig` at both sides of each
  bound keeps the agent and the chart in step, and a render check with a large integer in a values file shows the value
  the container gets.
- R19: run the agent behind the entrypoint of the base image, which reads `/tmp/cert` at each start. Under a read-only
  root file system the trust store needs writable volumes, which the image declares and the chart mounts.
- R9: a test that compares the keys of the environment file with the agent variables keeps R9 true as variables are
  added.
- R11: the base image ships `curl`, and `curl --fail` exits with an error on a status of 400 or above.
- R4, R5, and R24 to R27: the override of R17 can run the agent as a uid such as `12345:0`, and the Compose example
  already sets `read_only: true` and `cap_drop: [ALL]`. For the CA, a small HTTPS server with the certificate of a
  test CA, and one with the certificate of another test CA, can stand in for a PIP. Starting the agent while the policy
  source is stopped, and then starting the source, moves `/ready` from 503 to 200. The job replaces the release image
  with the image of the commit, so R8 to R13 stay properties of the files that a reader checks.
- R10: the agent shuts its two surfaces down one after the other, each in up to 5 seconds, so in up to 10 seconds. The
  entrypoint of the base image adds `SIGTERM_EXIT_DELAY`, 10 seconds by default, which makes 20, and 30 leave room; an
  example that sets the delay to 0 stops sooner.
- R17: the suite reads every address from its environment, as `test/integration/testify/helpers.go` lists them. The
  realms of `test/k8s/authn` and the images of `test/integration/pipstub` and `test/integration/tenantmanager` serve the
  override as they serve kind.

### Justification

The base image is the platform's runtime (R1). Its entrypoint adds the CAs under `/tmp/cert` to the trust store, which
is how the platform gives any container a private CA. The agent calls Keycloak, PIPs, and the policy source over HTTPS,
so an installation with a private CA needs the release image to trust that CA under the same restrictions as the rest of
its run, and the Docker page shows an operator how (R14, R19). Keycloak and the API server of the cluster keep the CAs
that their own records name. The agent needs neither root nor a writable root file
system, and R4 keeps it so.

Outside Kubernetes nothing but the agent checks its configuration. Kubernetes tokens and the topology file exist only in
a cluster, so `legacy` is the mode on the Docker target (R5). An operator who mistypes a value has to learn it at the
start, as ADR-0092 R15 does for the mode, rather than run with a default they did not choose, and that holds for every
agent variable, not only for those the chart checks (R6). The settings table keeps the list in one file, so a new
variable joins it in the change that adds it (R21). A number that its destination type cannot hold, such as a number of
seconds above `9223372036`, overflows `time.Duration` instead of being refused, so its range ends there (R21). A
variable that the values of others require, such as `AUTHZ_M2M_TOKEN_URL` with `KUBERNETES_M2M_ENABLED=false` under
ADR-0096 R5, is marked in its row, and R20 stops the start without it; a pair that a record forbids, such as those of
ADR-0096 R8, stops the start as that record says. The chart refuses the same values earlier, at install, and renders
every value it accepts in a form the agent reads (R22). R6 reads a boolean as ADR-0096 R3 reads
`KUBERNETES_M2M_ENABLED`, so that no setting accepts a spelling another one refuses.

A default address such as `http://tenant-manager:8080` names a service that only some networks have, whether the name
belongs to a Kubernetes Service or to a Compose service. With an address of tenant-manager the agent stays not ready
until tenant-manager answers (ADR-0093 R11), and with an empty one it uses the default tenant as given (ADR-0093 R14).
An empty default lets an agent without tenant-manager start, and an operator who has one names it (R7). The chart keeps
its address, so a Pod sees no change (R23). The agent's token on the Docker target follows from ADR-0096 R1 to R8,
which the agent reads without the chart.

The Compose example replaces the Pod specification for an operator, and CI runs the same file, so a change that breaks
the Docker target fails a check (R8, R9, R17). The trusted providers file and `AUTHZ_M2M_TOKEN_URL` stay in the example,
because the agent does not read `IDENTITY_PROVIDER_URL` (ADR-0091 R78). In Kubernetes the chart sets `keycloak.url` from
it (ADR-0091 R72) and builds `AUTHZ_M2M_TOKEN_URL` from it as well. The agent shuts its two surfaces down one after the
other, each in up to 5 seconds, which is all of Docker's default stop timeout of 10 seconds, and the entrypoint of the
base image waits 10 seconds more before it forwards `SIGTERM` (R10). Docker shows the state of a container only through
a healthcheck, and keeps running a container marked unhealthy. `/ready` is the state that a dependent container waits
for, and a healthcheck that passed on a 503 would let `docker compose up --wait` go on with an agent that is not ready
(R11). The restart policy covers a process that exits (R12). Docker has no NetworkPolicy, and the internal port serves
metrics and the probes (R13). Token checks compare `exp` and `nbf` with the host clock, with a leeway of 30 seconds
(ADR-0091 R44). A clock that drifts further makes the agent refuse valid tokens or accept expired ones (R15). TLS stays
outside the agent for its clients, as the architect decided (R16).

A job on `ubuntu-26.04` stays on Ubuntu 26.04 until a change to the workflow moves it, while `ubuntu-latest` moves to
the next Ubuntu release on GitHub's schedule (R17). GitHub still updates the tools of either image every week, Docker
and Compose among them. The suite already exercises the agent on kind over HTTP alone, so in Docker it covers the same
paths, apart from the cases that read what only a cluster has (R17). The suite shows neither a refused configuration,
nor a private CA under the restrictions of R4, nor a failing healthcheck, nor a stop through the entrypoint, so the job
shows each of them in a rule of its own, which a change can bring apart from the others (R24 to R27).

### Alternatives considered

- **A2. Run the agent as a process under systemd on a Linux host.** The image and the runtime of the platform would
  differ between the two targets, and the release would need a second artifact.
- **A3. Let the agent build the trusted providers file and `AUTHZ_M2M_TOKEN_URL` from `IDENTITY_PROVIDER_URL`.**
  ADR-0091 R78 keeps that setting in the chart, and the same logic would live in two places.
- **A4. Log a warning and keep the default for an invalid value.** Rejected by R6: the warning is easy to miss, and the
  agent would run, for example, with a pull interval the operator did not choose.
- **A5. Put the healthcheck into the Dockerfile.** The kubelet ignores it, and the address would be fixed in the image
  while `AUTHZ_HTTP_ADDR` can move the internal port.
- **A6. Check only readiness and one decision in CI.** Rejected by R17: a regression on the Docker target outside that
  path would pass.
- **A7. Publish the internal port on every interface.** Rejected by R13: anyone on the network could read the metrics.
- **A8. Accept `1`, `yes`, `on`, `0`, `no`, and `off` for every boolean.** Rejected by R6: ADR-0096 R3 would have to
  accept them as well, and ADR-0091 R64 removes `AUTHZ_JWKS_BOOTSTRAP_REQUIRED`, the one setting that accepted them at
  5a351ef5.
- **A9. Check only the settings that the chart checks.** Rejected by R6: an agent run without the chart would still take
  the default for a mistyped value of every other setting, such as `AUTHZ_M2M_RENEW_BEFORE_SECONDS`.

## Consequences

Positive:

- A value that `helm install --skip-schema-validation` lets into the Pod, such as a pull interval of `2s`, stops the
  start instead of turning into the default (R6).

Negative:

- A plain `docker run` needs `--stop-timeout 30`, or Docker kills the agent before it shuts down (R10).
- Docker does not restart a container that hangs without exiting. The healthcheck only marks it, and the monitoring of
  the installation has to act (R11, R12).
- On the Docker target the operator writes the trusted providers file and `AUTHZ_M2M_TOKEN_URL`, which the chart builds
  in Kubernetes.
- The agent at 5a351ef5 started with values that now stop the start: values that the chart checks refuse, such as
  `AUTHZ_JWKS_HTTP_TIMEOUT=0`, and unreadable values of settings no chart check covers, such as
  `AUTHZ_M2M_RENEW_BEFORE_SECONDS=1m` (R6). While the agent reads `AUTHZ_JWKS_BOOTSTRAP_REQUIRED`, `yes`, `on`, `1`,
  `no`, `off`, and `0` stop the start for that setting as well (R6).
- On the Docker target only `legacy` works, so services that call with Kubernetes tokens cannot use such an agent
  (ADR-0092 R16).
- With an empty default address, which R7 requires, an agent run without the chart and without
  `AUTHZ_TENANT_MANAGER_URL` asks tenant-manager nothing. It uses a realm named by a tenant's display name as written,
  and the default tenant as given (ADR-0093 R14). A Pod keeps the address of the chart (R23).

Follow-ups:

- The top-level README and `components/authz-agent/README.md` link the Docker page instead of stating that the
  deployment assumes Kubernetes.

## Open points

- **O2.** The maximum of `AUTHZ_ENTITLEMENTS_HTTP_RETRIES`, and of `AUTHZ_JWKS_HTTP_RETRIES` while the agent reads it,
  `<retry maximum>` in R21. The answers under consideration are a bound that no installation needs to exceed, such as
  `100`, and the largest integer that the values schema holds exactly, `9007199254740991`. The architect decides. It
  affects R21 and R22.
