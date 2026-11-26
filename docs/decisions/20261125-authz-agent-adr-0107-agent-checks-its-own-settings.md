# Have the agent check its own settings, whether or not the chart renders them

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record and decides O1.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  the term stops the start, and ADR-0091 R64, the removal of `AUTHZ_JWKS_BOOTSTRAP_REQUIRED`.
- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  ADR-0092 R15 as [#338](https://github.com/Netcracker/qubership-authz-agent/pull/338) narrows it: what `M2M_AUTH_MODE`
  changes in the tokens the agent accepts and in whether the agent starts.
- [authz-agent-ADR-0093: Take the tenant of a decision from the verified user token, then from the request](20261029-authz-agent-adr-0093-tenant-of-a-decision.md):
  ADR-0093 R11 and R14, the default tenant with and without tenant-manager.
- [authz-agent-ADR-0096: Choose the token the agent sends by M2M_AUTH_MODE](20261105-authz-agent-adr-0096-token-the-agent-sends.md):
  ADR-0096 R1, R2, R3, and R20 as [#338](https://github.com/Netcracker/qubership-authz-agent/pull/338) rewrites them:
  `M2M_AUTH_MODE` and the token it chooses for the agent to send, how the agent reads it, which R2 of this record
  follows for every value from a list, and the inputs that the agent reads for each value, among them the token endpoint
  in `AUTHZ_OUTGOING_TOKEN_URL`.
- [authz-agent-ADR-0101: Run the agent from its image in a container runtime without Kubernetes](https://github.com/Netcracker/qubership-authz-agent/pull/235),
  proposed in #235: the target where no chart renders the agent variables.

## Context

In Kubernetes the chart renders the agent variables. Its values schema checks their types and ranges, and its template
removes a trailing slash from `AUTHZ_PAP_CLIENT_SOURCE_URL`. The chart also changes two values that it does not
normalize. It renders `AUTHZ_JWKS_BOOTSTRAP_REQUIRED` as `false` where `AUTHZ_TRUSTED_PROVIDERS` is empty, whatever the
value given, and ADR-0091 R64 removes that variable. Helm prints an integer of 1000000 or more from a values file in
exponent form, such as `1e+06` for 1000000. Without the chart an operator sets the same variables directly, on the
target of ADR-0101 or in a cluster with manifests of their own. At 5a351ef5 the agent took the default for a value it
could not read, and logged nothing.

The platform logger reads `LOG_LEVEL` where `LOGGING_LEVEL_ROOT` is unset or empty, and runs at `info` with only a
warning when it cannot parse the value. The entrypoint of the base image takes its own log level from `IMAGE_LOG_LEVEL`,
and from `LOG_LEVEL` where that is unset. Releases up to v0.1.0 read a setting through a loader that matches its name
without regard to case. The platform's deployer passes `M2M_AUTH_MODE` to every service of an installation (ADR-0092).
Kubernetes gives each container a set of variables for every Service in its namespace, named after the Service
([Kubernetes documentation](https://kubernetes.io/docs/concepts/services-networking/service/#environment-variables)),
and the chart names the Service of the agent `authz-agent` by default. authz-policy-admin, the other program of this
repository, reads settings whose names begin with `AUTHZ_POLICY_ADMIN_`.

While ADR-0101 was proposed, it held R2 of this record as its R6 and R20, R3 as its R7, R4 as its R21, and R5 as its
R30.

## Decision

We will have the agent check the value of every setting it reads, rely on no check, default, or normalization of the
chart, and refuse a misspelled or retired name in the prefix `AUTHZ_`, so that one environment gives the same agent with
the chart and without it.

### Terms

- **Agent variable**: an environment variable that code built into the agent binary from `components/authz-agent` or
  `internal` reads by name, `LOGGING_LEVEL_ROOT` included, whatever the values of other agent variables and the files
  present at start. `AUTHZ_OUTGOING_TOKEN_URL` is one also where the agent leaves it unread, with `M2M_AUTH_MODE=k8s`
  and with `M2M_AUTH_MODE=hybrid` when the agent's token file is present at the start. A variable that only a test, the
  Go runtime, or the standard library reads, such as `GOMEMLIMIT` or `HTTPS_PROXY`, is not one, and neither is
  `LOG_LEVEL`, which R5 governs.
- **Settings table**: the table of agent variables under `## Configuration` in `components/authz-agent/README.md`, with
  the text of that section that defines the forms and the bounds its rows name.
- **Chart**: the Helm chart in `helm-templates/authz-agent`, its values schema included.
- **Service variable**: an environment variable whose name has one of the forms that Kubernetes gives the variables of a
  Service: `<service>_SERVICE_HOST`, `<service>_SERVICE_PORT`, `<service>_SERVICE_PORT_<port name>`, `<service>_PORT`,
  and `<service>_PORT_<port>_<protocol>` followed by nothing, `_PROTO`, `_PORT`, or `_ADDR`. `<service>` and
  `<port name>` are upper-case letters, digits, and `_`; `<port>` is a decimal number; `<protocol>` is `TCP`, `UDP`, or
  `SCTP`.
- **Policy-admin variable**: an environment variable whose name begins with `AUTHZ_POLICY_ADMIN_`.
- **Stops the start**: as ADR-0091 defines it.
- **The agent's token file**, **present at the start**: as ADR-0096 defines them.

### Rules

#### Values

- **R1** (`startup`, `chart`). The agent relies on no check, no default, and no normalization that only the chart
  applies to the value of an agent variable. The agent refuses a value that the chart would refuse, or reads it as its
  row in the settings table states. The agent treats a value that the chart would normalize, such as by removing a
  trailing slash, as it treats the normalized value, or it stops the start on it. A default in the values file of the
  chart is a value that the chart renders.
- **R2** (`startup`, `client`). Before it serves a request, the agent checks the value of every agent variable. A value
  that the row of the variable in the settings table does not accept stops the start, with a message that names the
  variable and the values its row accepts. A variable that its row marks as required, always or under a condition that
  the row names, stops the start when it is unset or empty while it is required, with a message that names it and, where
  a condition requires it, that condition. The agent reads an integer as decimal digits with an optional sign, a boolean
  as `true` or `false` alone, without regard to case, and a value from a list without regard to case. An unset agent
  variable that is not required, and an empty integer, boolean, or value from a list that is not required, takes the
  default of its row, or does what the row says where the row gives no default. Any other empty value does what its row
  says.
- **R3** (`startup`, `client`). The settings table gives an empty default to every agent variable that holds the address
  of a service the agent calls, `AUTHZ_TENANT_MANAGER_URL` included.
- **R4** (`startup`, `client`). The settings table has a row for each agent variable; a row may name several variables.
  A row gives the type and the values or the range accepted, itself or by naming a form that the settings table defines
  once. It gives the default, or, where the variable has none, what the agent does without a value. It says whether the
  variable is required: always, or under a condition that the row names and that the agent can evaluate at start, such
  as values of other agent variables or whether a file is present at start. It says what an empty value does where the
  type admits one. An empty default is a default. The range of a number lies within the values that its destination type
  holds in its unit.

#### Names

- **R5** (`startup`). The agent takes its root log level from `LOGGING_LEVEL_ROOT` alone. A non-empty `LOG_LEVEL` stops
  the start, with a message that names `LOGGING_LEVEL_ROOT`.
- **R6** (`startup`). A set environment variable whose name begins with `AUTHZ_`, in upper or lower case or a mix of
  both, and that is not an agent variable, a service variable, or a policy-admin variable stops the start, whatever its
  value, the empty string included, with a message that names the variable and not its value.

### Implementation notes

Adds no requirement. A test can compare the names that `config.go` reads with the rows of the settings table, which
keeps R4 and R6 in step: a name that the code reads and the table lacks breaks R4, and a row that no code reads
documents a name that R6 refuses. Under R6 a variable in the prefix `AUTHZ_` that the chart renders and the agent no
longer reads stops the start under the chart, where the end-to-end suite on kind fails, and in
`test/svt/common/compose/docker-compose.yml`, which only a manual run of the load test starts.

### Justification

The agent runs with the chart and without it, and an operator who moves an installation from one to the other keeps the
same values. At 5a351ef5 the agent relied on the values schema: without the chart, a value such as `5s` for a number of
seconds, which the schema refuses, got the default of the agent. So the agent relies on no check, default, or
normalization of the chart (R1). The puller appends `/access/v3/config/policySets` to the base URL in
`AUTHZ_PAP_CLIENT_SOURCE_URL`, and both the chart and the agent remove a trailing slash from it, so
`https://pap.example.com/` gives the same requests with and without the chart. R1 keeps it so for each check or
normalization the chart gains later. The defaults of the chart are chosen for a cluster, such as
`http://tenant-manager:8080`, so the agent keeps defaults of its own (R1, R3).

A mistyped value of any agent variable stops the start, so an operator learns of it at once rather than running with a
default they did not choose (R2). A required variable has no default to fall back on while it is required, so a missing
value is one more value that its row does not accept (R2). A variable that a condition requires is marked in its row
with that condition (R4). The condition can rest on a file as well as on values: ADR-0096 R20 makes
`AUTHZ_OUTGOING_TOKEN_URL` required under conditions that include whether the agent's token file is present at the
start. So R2 and R4 speak of a condition that the row names. R2 reads a value from a list as ADR-0096 R3 reads
`M2M_AUTH_MODE`, so that no setting accepts a spelling another one refuses. The settings table keeps the list in one
file, so a new variable joins it in the change that adds it (R4). A variable can be optional and still have no default,
so a row gives the default and whether the variable is required separately (R4). A number that its destination type
cannot hold would overflow instead of being refused, so its range ends within that type, and the row gives the bound
(R4).

A default address such as `http://tenant-manager:8080` names a service that only some networks have, whether the name
belongs to a Kubernetes Service or to a Compose service. With an address of tenant-manager the agent stays not ready
until the translation through tenant-manager succeeds (ADR-0093 R11), and with an empty one it uses the default tenant
as given (ADR-0093 R14). An empty default lets an agent without tenant-manager start, and an operator who has one names
it (R3).

The platform logger reads `LOG_LEVEL` where `LOGGING_LEVEL_ROOT` is unset or empty, and a value it cannot parse costs
only a warning. So the root log level has one name, `LOGGING_LEVEL_ROOT`, and a non-empty `LOG_LEVEL` stops the start
(R5).

A misspelled name, such as `AUTHZ_PAP_CLIENT_PULL_INTERVALS`, would leave its variable at the default with no message,
the outcome that R2 refuses for a value. So a name in the prefix `AUTHZ_` that is not an agent variable stops the start,
and a variable that the agent no longer reads, such as `AUTHZ_JWKS_BOOTSTRAP_REQUIRED` after ADR-0091 R64, falls under
the same rule (R6). Names outside the prefix belong to the runtime and to other programs, such as `PATH` and `HOSTNAME`,
and a misspelling there cannot be told from a variable meant for another program. So R6 refuses no name outside the
prefix, and of the names outside the prefix that are not agent variables, only `LOG_LEVEL`, which the platform logger
inside the agent reads, has a rule of its own (R5). `M2M_AUTH_MODE`, which the platform's deployer passes to every
service, chooses the token the agent sends (ADR-0096 R2, ADR-0092 R15), so it is an agent variable, and R2 checks its
value. Inside the prefix, Kubernetes gives the container of the agent a service variable for each Service of its
namespace, `AUTHZ_AGENT_SERVICE_HOST` for the Service `authz-agent` among them, and an environment file shared with
authz-policy-admin holds its policy-admin variables, so R6 accepts both. A misplaced secret lands in an unknown name as
easily as in a known one, so the message leaves the value out (R6). Releases up to v0.1.0 matched a name without regard
to case, and the agent now reads it as written, so R6 compares the prefix without regard to case, and
`authz_pap_client_pull_interval` stops the start rather than leaving the interval at its default.

### Alternatives considered

- **A1. Log a warning and keep the default for an invalid value.** Rejected by R2: the warning is easy to miss, and the
  agent would run, for example, with a pull interval the operator did not choose.
- **A2. Accept `1`, `yes`, `on`, `0`, `no`, and `off` for every boolean.** Rejected by R2: ADR-0091 R64 removes
  `AUTHZ_JWKS_BOOTSTRAP_REQUIRED`, the one setting that accepted them at 5a351ef5, so no setting needs them.
- **A3. Accept `LOG_LEVEL` as a second name of the log level and check both.** Rejected by R5: with two names for one
  setting, an operator has to know which one the agent reads when both are set.
- **A4. Leave the checks to the values schema of the chart.** Rejected by R1 and R2: an installation without the chart
  would get none of them.
- **A5. Refuse every set variable that is not an agent variable.** Rejected by R6: the environment of a container holds
  variables of the runtime and of other programs, such as `PATH` and `HOSTNAME`, and the agent would stop in every
  installation.
- **A6. Turn the service variables off in the chart with `enableServiceLinks: false`, and refuse them too.** Rejected by
  R6: a Pod from manifests other than the chart would still get the service variables of `authz-agent`, and the agent
  would stop there.
- **A7. Refuse only the names on a list of retired variables.** Rejected by R6: a misspelled name would still start the
  agent on its default with no message.

## Consequences

Negative:

- A value that the agent at 5a351ef5 read or replaced with its default and that its row does not accept, such as `5s`
  for a number of seconds, a number with a space around it, or `yes` for a boolean, now stops the start (R2).
- An installation without the chart whose environment sets the variable `LOG_LEVEL` now stops the start, and moves the
  value to `LOGGING_LEVEL_ROOT` (R5).
- An installation that ran v0.1.0 without the chart and uses tenant-manager sets `AUTHZ_TENANT_MANAGER_URL` before it
  upgrades. Without it the agent sends no request to tenant-manager: it uses the default tenant as given (R3,
  ADR-0093 R14).
- An installation without the chart whose environment still sets a variable that the agent no longer reads, such as
  `AUTHZ_JWKS_BOOTSTRAP_REQUIRED`, now stops the start, and removes the variable before it upgrades (R6).
- A misspelled name in the prefix `AUTHZ_` that has the form of a service variable, such as `AUTHZ_PUBLIC_PORT`, or that
  begins with `AUTHZ_POLICY_ADMIN_`, still starts the agent with no message (R6).
- An operator who sets `LOG_LEVEL` for the entrypoint of the base image, where the image runs the agent behind it, sets
  `IMAGE_LOG_LEVEL` instead, since a non-empty `LOG_LEVEL` stops the start (R5).
- Releases before 1.0, v0.1.0 included, carry no stable configuration commitment, so an installation without the chart
  can meet the changes that R2, R3, R5, and R6 bring when it upgrades; O1 asks whether the platform agrees.

## Open points

- **O1.** Does the support window of the Netcracker platform cover v0.1.0? The top-level `README.md` waives a
  configuration commitment for releases before 1.0, but the platform applies the window of a repository only where it is
  longer than its own. The architect (`mr-joom`) decides. If the platform window does not cover releases before 1.0, R2,
  R3, R5, and R6 stand as written. If it covers v0.1.0, a value or a name that R2, R5, or R6 refuses and that v0.1.0
  accepted gets a warning that names it for the deprecation period that the platform requires, instead of stopping the
  start, and the default that R3 changes stays for that period too. O1 affects R2, R3, R5, and R6.
