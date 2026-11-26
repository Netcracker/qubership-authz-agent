# Choose the token the agent sends by `M2M_AUTH_MODE`

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record. On 2026-11-25 the owner, the architect, and the owner of the
  policy decision code agreed that `M2M_AUTH_MODE` chooses the token the agent sends, while the tokens the agent
  accepts stay the same in every mode.
- The owner of the policy decision code (`vlsi`) returned the questionnaire of 2026-11-03 and reviewed this record on
  2026-11-05 and 2026-11-25.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  ADR-0092 R11, the tokens that the agent accepts in every mode, and ADR-0092 R15, under which `M2M_AUTH_MODE` chooses
  only the token the agent sends.
- [authz-agent-ADR-0093: Take the tenant of a decision from the verified user token, then from the request](20261029-authz-agent-adr-0093-tenant-of-a-decision.md):
  ADR-0093 R11, the call to tenant-manager, and ADR-0093 R7, the `Tenant` header of outgoing calls.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  the term token for `netcracker`, ADR-0094 R3, under which the chart mounts it as R20 of this record states, and the
  Kubernetes tokens the agent accepts.
- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  ADR-0091 R14, the readiness conditions that the policy pull and the default tenant feed.
- [authz-agent-ADR-0104: Describe the two trusted providers in a fixed directory of provider files](https://github.com/Netcracker/qubership-authz-agent/pull/329),
  proposed in #329: the term Kubernetes token (ADR-0104 R22), and ADR-0104 R14, under which the agent stops the start
  when it cannot read the token for the API server.
- [authz-agent-ADR-0107: Have the agent check its own settings, whether or not the chart renders them](https://github.com/Netcracker/qubership-authz-agent/pull/359),
  proposed in #359: ADR-0107 R2, which checks the value of every agent variable, `M2M_AUTH_MODE` included, and may
  refuse a setting that R20 of this record leaves unread.

## Context

The agent presents one token on the policy pull and on calls to PIPs, entitlements, User Management, and
tenant-manager.

The agent gets that token in one of two ways. It obtains a token with client credentials from a token endpoint, which
the chart builds from `IDENTITY_PROVIDER_URL` as the token endpoint of the realm `cloud-common` under `/auth/realms/`.
Or it reads a token from a file that the deployment mounts, as the chart mounts the token for `netcracker` of ADR-0094.
The kubelet writes that file before the container starts. The agent does not parse the token in the file, so it cannot
tell which issuer signed it. Keycloak 17 and later serve their realms without `/auth` by default, so such a Keycloak
answers a token endpoint under `/auth/realms/` with 404.

`KUBERNETES_M2M_ENABLED`, a boolean chart value, `false` by default, chooses between the two ways: with `false` the
chart sets `AUTHZ_M2M_TOKEN_URL` and mounts the client credentials, and with `true` it mounts the token for
`netcracker`. The container does not read the value: the agent reads the token file whenever `AUTHZ_M2M_TOKEN_URL` is
empty, and it has to run without the chart as well. `KUBERNETES_M2M_ENABLED` is also a deployment parameter of the
platform, which deprecates it in favor of `M2M_AUTH_MODE`.

The platform's deployer passes `M2M_AUTH_MODE`, with the value `legacy`, `hybrid`, or `k8s`, to every service of an
installation, and the other services that read it accept tokens by it: in `k8s` only Kubernetes tokens, and in `legacy`
no token that the API server signed. Before this record the agent left the mode unread and accepted every kind of token
whatever its value.

A PIP declaration can set headers today: `setHeaders` and `forwardHeaders` take precedence over the agent's token, and
`forwardHeaders` can forward the caller's `Authorization`.

## Decision

We will choose the token the agent sends by `M2M_AUTH_MODE`: the agent's client credentials token in `legacy`, the
content of the agent's token file, such as the token for `netcracker`, in `k8s`, and in `hybrid` the content of that
file when it is present at the start and the client credentials token when it is absent at the start.

### Terms

- **The agent's client credentials token**: the token that the agent obtains with client credentials from the token
  endpoint in `AUTHZ_OUTGOING_TOKEN_URL`.
- **The agent's token file**: `/var/run/secrets/tokens/netcracker/token`, the path of the token for `netcracker` of
  ADR-0094.
- **Present at the start**, **absent at the start**: the agent's token file is present at the start when, as the agent
  starts, resolving its path, symbolic links followed, finds a file system object of any kind, and absent at the start
  when resolving reports that the path, or the target of a symbolic link on it, does not exist. Any other failure to
  resolve the path, such as a loop of links, a component that is not a directory, or a directory the agent cannot
  search, leaves the file neither present nor absent at the start.
- **The agent's token**: the token that R2 has the agent present to the recipients of R10.
- **Stops the start**: as ADR-0091 defines it.
- **Agent variable**: as ADR-0107 defines it.
- **Kubernetes token**: as ADR-0104 defines it.
- **Token for `netcracker`**, **token for the API server**: as ADR-0094 defines them.

### Rules

#### The mode

- **R1** (`startup`). The agent reads `M2M_AUTH_MODE` from its environment, `legacy` by default.
- **R2** (`startup`). `legacy` sends the agent's client credentials token, and `k8s` sends the content of the agent's
  token file without the white space around it. `hybrid` sends the content of the agent's token file without the white
  space around it when that file is present at the start, and the agent's client credentials token when it is absent
  at the start.
  The agent chooses once, at the start.
- **R3** (`startup`). The value is compared without regard to case, and an empty value means `legacy`, the default of
  R1. Any other value stops the start, with a message that names `M2M_AUTH_MODE` and the three values.
- **R4** (`chart`). The chart passes the value `M2M_AUTH_MODE` to the container under the same name, `legacy` by
  default. Its values schema accepts `legacy`, `hybrid`, and `k8s` alone.
- **R17** (`chart`). The chart does not read `KUBERNETES_M2M_ENABLED`, and its values schema accepts that key with any
  value.

#### What each mode reads, and what the chart mounts and passes

- **R20** (`startup`, `client`, `chart`). For each mode, this table gives the inputs that the agent reads and the ones
  that the chart mounts or passes; `hybrid` has a column for the agent's token file present at the start and one for the
  file absent at the start, and the chart, which cannot tell them apart, does the same in both. An input that the table
  marks unread for a column is one that the agent in that case does not use: it sends no request to an unread token
  endpoint and opens no unread file. A set value of a setting that names an unread input stops the start only where
  ADR-0107 R2 refuses that value, and that refusal takes precedence over this rule. In `hybrid`, an agent's token file
  that is neither present nor absent at the start stops the start, which takes precedence over R2.

  | Input | `legacy` | `hybrid`, token file present at the start | `hybrid`, token file absent at the start | `k8s` |
  | --- | --- | --- | --- | --- |
  | The token endpoint in `AUTHZ_OUTGOING_TOKEN_URL` | Read. An unset or empty value stops the start, with a message that names the mode. | Unread. | Read. An unset or empty value stops the start, with a message that names the mode and the path of the agent's token file. | Unread. |
  | The client id and the client secret, in the files that `AUTHZ_OUTGOING_CLIENT_ID_FILE` and `AUTHZ_OUTGOING_CLIENT_SECRET_FILE` name | Read at the start and at each fetch of the agent's client credentials token. At the start, a file that is missing, that the agent cannot read, that is not a regular file once symbolic links are followed, or that is empty or holds only white space stops the start, with a message that names the file. A later fetch that fails on a file falls under R13 and R14. | Unread. | Read, as in `legacy`. | Unread. |
  | How long before its expiry the agent renews its client credentials token, in `AUTHZ_OUTGOING_RENEW_BEFORE_SECONDS` | Read. | Unread. | Read. | Unread. |
  | The agent's token file | Unread. | Read. A file that the agent cannot read, that is not a regular file once symbolic links are followed, or that is empty or holds only white space stops the start. The agent does not parse the token, so no other content of the file stops the start. | Absent, so unread. | Read. A file that is missing, that the agent cannot read, that is not a regular file once symbolic links are followed, or that is empty or holds only white space stops the start. The agent does not parse the token, so no other content of the file stops the start. |
  | In the chart, the Secret `<SERVICE_NAME>-client-credentials` | Mounted as required, `AUTHZ_OUTGOING_CLIENT_ID_FILE` and `AUTHZ_OUTGOING_CLIENT_SECRET_FILE` passed with the paths of its files, and `AUTHZ_OUTGOING_RENEW_BEFORE_SECONDS` passed. | Mounted as optional, and the same three settings passed. | Mounted as optional, and the same three settings passed. | Not mounted, and none of the three settings passed. |
  | In the chart, the token for `netcracker` | Not mounted. | Mounted at the agent's token file. | Mounted at the agent's token file. | Mounted at the agent's token file. |
  | In the chart, the value `AUTHZ_OUTGOING_TOKEN_URL` | Passed as R19 gives it. | Passed as R19 gives it. | Passed as R19 gives it. | Not passed. A set value is no reason to refuse to render. |

- **R21** (`startup`). In `hybrid` the agent logs once, at the start, which token it sends and whether the agent's
  token file was present at the start.
- **R19** (`chart`). Where R20 has the chart pass the token endpoint, the chart passes the value
  `AUTHZ_OUTGOING_TOKEN_URL`, empty by default, to the container under the same name. In place of an empty value it
  passes `IDENTITY_PROVIDER_URL`, less one trailing `/`, followed by
  `/auth/realms/cloud-common/protocol/openid-connect/token`.

#### The recipients

- **R10** (`client`). The policy pull and the calls to PIPs, entitlements, User Management, and tenant-manager all carry
  the agent's token.
- **R11** (`client`). The agent sets `Authorization` and `Tenant` itself, and takes neither from `setHeaders` or
  `forwardHeaders` of a PIP declaration.

#### A call without a valid token

- **R12** (`client`). The agent keeps its refresh: while it sends the content of the agent's token file, it reads the
  file again, and while it sends the agent's client credentials token, it renews that token before it expires.
- **R13** (`client`). Without a valid token only the call that needs it fails. For a PIP, entitlements, or User
  Management the value it would give is unknown, and the resources that depend on it are denied.
- **R14** (`startup`). The policy pull and the translation of the default tenant need the agent's token too, so while
  the agent sends its client credentials token, it stays not ready at the start while it cannot obtain that token,
  through the conditions of ADR-0091 R14.
- **R15** (`client`). A 401 from a recipient is a failure of that recipient.
- **R16** (`client`). The agent does not retry with the other token.

### Justification

The other services of an installation accept tokens by `M2M_AUTH_MODE`: in `k8s` Kubernetes tokens alone, and in
`legacy` no token that the API server signed. Choosing the token the agent sends by the same mode keeps it a token that
its recipients accept, with no setting of the agent's own that an operator has to keep in step with the mode (R1, R2).
The agent still accepts every kind of token, so the mode decides only what it sends (ADR-0092 R11, R15). Reading the
mode in the agent gives a deployment without the chart the same rule (R1).

In `hybrid` the platform moves toward Kubernetes tokens, so the agent sends the token for `netcracker` where the
deployment provides it, and its client credentials token where it does not, as in a run without Kubernetes (R2). A token
file absent at the start means that the deployment provides no Kubernetes token. A token file present at the start that
fails the checks of R20 is an error of the deployment, so it stops the start instead of selecting the other token, and
so does a token file that is neither present nor absent at the start (R20). The agent chooses once at the start, so a
run sends one kind of token. A call that a recipient refuses fails, as R15 says, and no retry with the other token hides
the refusal (R2, R16). The log line of the start tells an operator which of the two tokens a `hybrid` run sends, since
nothing else in the deployment shows it (R21).

A run without the platform's deployer, such as a container under Docker, has no mode. With `legacy` as the default, a
run that sets the token endpoint, as the Docker example does, keeps sending the client credentials token it sent before
this record; a run that read the token file sets the mode, as a Negative consequence says (R1). An empty value means the
default, as ADR-0107 R2 reads every value from a list (R3). The values schema accepts the three values only as the
deployer writes them, as it accepts the levels of `LOG_LEVEL` only in lowercase, so a values file spells a mode one way;
the agent compares without regard to case and reads an empty value as the default for a deployment without the chart
(R3, R4).

A recipient that refuses the agent's token answers 401. Where that is the policy source or tenant-manager, the policy
pull or the translation of the default tenant fails, and the agent stays not ready (R15; ADR-0091 R14). Where only a
PIP, entitlements, or User Management refuses it, the agent turns ready and denies the resources that depend on that
recipient (R13).

The deployment puts the agent's token file and the files of the client credentials in place before the container
starts: the kubelet writes a projected volume and a Secret, and Docker binds files. A file that is missing, unreadable,
or empty at the start is therefore an error of the deployment that no wait repairs, like a token for the API server
that the agent cannot read (ADR-0104 R14). A Keycloak that does not answer can recover, so the agent waits for it
instead (R14, R20).

The client secret leaves the agent only in requests to the token endpoint. In `k8s` the agent needs neither the endpoint
nor the credentials, so the chart mounts no Secret and the Secret need not exist. In `hybrid` the chart mounts the
token for `netcracker`, so with the chart the agent never reads the Secret there, and the chart mounts the Secret as
optional so that a missing Secret does not keep the Pod from starting (R20). A value that ADR-0107 R2 refuses still
stops the start, because that check treats every agent variable alike, and the operator learns of a mistyped token
endpoint at once rather than when the mode changes.

Building the token endpoint from `IDENTITY_PROVIDER_URL` lets one value move the agent to a Keycloak on another host
that keeps the platform's paths. A Keycloak without `/auth` needs the endpoint written out. The chart value has the name
of the agent's setting, so the agent's message about a wrong endpoint names a chart value that the operator can set
(R19).

The platform deprecates `KUBERNETES_M2M_ENABLED`, so the token the agent sends does not depend on it, and the values
schema does not refuse a deployment that still passes it (R17).

A PIP address comes from the policy configuration. A declaration that replaced the token could send a caller's token to
that address, and the recipient would see the caller and not the agent (R11).

The other token would rarely help, because the services of an installation accept tokens by their own mode, and a retry
would hide a token that the recipient refuses (R16).

### Alternatives considered

- **A1. Choose the token with a setting of the agent's own, `AUTHZ_OUTGOING_TOKEN_SOURCE`, with the values
  `client-credentials` and `token-file`.** Rejected by R1 and R2: an operator would keep that setting in step with the
  mode of the recipients, and an installation that changed its mode would send a token its recipients refuse until the
  agent was changed too. An earlier version of this record made the agent read it.
- **A2. Let an unset `M2M_AUTH_MODE` stop the start.** Rejected by R1: a run without the platform's deployer has no
  mode, and such a run that sets the token endpoint keeps sending the client credentials token under the default.
- **A3. Keep the value in the chart alone.** Rejected by R1: the agent has to run without the chart as well.
- **A4. In `hybrid`, switch to the client credentials token during the run when a recipient refuses the token for
  `netcracker` or its file disappears.** Rejected by R2 and R16: the agent chooses once, at the start, and a retry with
  the other token would hide a token that the recipient refuses.
- **A5. Let a PIP declaration set these headers.** Rejected by R11: the token of a caller would reach an address from
  the policy configuration, and a PIP could answer for another tenant than the decision.
- **A6. Let a setting name the agent's token file.** Rejected by R20: a deployment puts the token at the path ADR-0094
  names, as the chart's projected volume does, and a setting that the mount does not follow points the agent at a file
  that does not exist. An earlier version of this record had this setting.
- **A7. Choose the token with `KUBERNETES_M2M_ENABLED`.** Rejected by R2 and R17: the platform deprecates that
  parameter in favor of `M2M_AUTH_MODE`. An earlier version of this record made the agent read it.
- **A9. Build the token endpoint from `IDENTITY_PROVIDER_URL` alone.** Rejected by R19: a Keycloak that serves its
  realms without `/auth` answers that endpoint with 404, and the agent stays not ready (R14).
- **A10. Refuse a set `AUTHZ_OUTGOING_TOKEN_URL` that ADR-0107 R2 accepts in `k8s`.** Rejected by R20: changing the
  mode would take two changes, and in `k8s` the agent sends the client secret nowhere either way.
- **A11. In `k8s`, stop the start only on a missing token file.** Rejected by R20: an empty or unreadable file is the
  same error of the deployment, and the agent would start without a token and stay not ready, with only warnings in
  its log.
- **A12. Send the token file whenever `AUTHZ_OUTGOING_TOKEN_URL` is empty.** Rejected by R1 and R20: the endpoint would
  choose the token, so a token endpoint lost from a configuration would switch the agent to another token without a
  message, while in `legacy` an empty endpoint stops the start. An earlier version of the agent chose the token this
  way.
- **A13. Keep the prefix `AUTHZ_M2M_` of the earlier settings, as in `AUTHZ_M2M_TOKEN_URL`.** Rejected by R20: ADR-0092
  defines an M2M token as a kind of token that the agent accepts, and `M2M_AUTH_MODE` covers both the tokens a service
  accepts and the tokens it sends, so a reader could take `AUTHZ_M2M_*` for settings of the tokens the agent accepts.
- **A14. In `hybrid`, send the client credentials token when the agent's token file is present at the start but fails
  the checks of R20.** Rejected by R20: a token file present at the start but empty or unreadable is an error of the
  deployment, and the other token would hide it.

## Consequences

Positive:

- An installation whose mode is `k8s` or `hybrid` sends the token for `netcracker` with no setting of the agent's own.
  With the chart, `hybrid` always finds the projected token, so its client credentials token serves a run without the
  chart (R2, R20).

Negative:

- An agent in `legacy`, or in `hybrid` with the agent's token file absent at the start, whose client credentials files
  are missing or empty stops the start (R20). This holds with the chart as well, for a Secret that lacks a key or holds
  an empty value. An earlier version of the agent started in that case and stayed not ready.
- The chart's render fails when a deployer passes an empty or an upper-case `M2M_AUTH_MODE`, while the agent without
  the chart reads such a value (R3, R4).
- No value of `M2M_AUTH_MODE` that R3 accepts stops the start because of what the recipients accept. Where a recipient
  refuses the agent's token, every call that carries it fails, and a failed policy pull or translation of the default
  tenant keeps the agent not ready through ADR-0091 R14 (R2, R15). Where only a PIP, entitlements, or User Management
  refuses it, the agent turns ready and denies the resources that depend on that recipient (R13).
- Outside Kubernetes nothing renews the agent's token file on its own. The agent reads the file again (R12), so a
  process that the operator runs can renew it. Without one, a run in `k8s`, or in `hybrid` with the file present at
  the start, serves only a token that outlives the run of the agent, such as the static token of a test stand. A run
  without Kubernetes that has neither a process that renews the file nor such a token uses `legacy`, or `hybrid` with
  the file absent at the start.
- A deployment that sets `KUBERNETES_M2M_ENABLED=true` and not `M2M_AUTH_MODE` gets `legacy`, and needs the Secret
  `<SERVICE_NAME>-client-credentials`, until its mode is `k8s` or `hybrid` (R4, R17, R20).
- An agent without the chart that reads its token file with the token endpoint empty stops the start until it sets
  `M2M_AUTH_MODE` to `k8s` or `hybrid` (R1, R20).
- In `legacy`, and in `hybrid` with the agent's token file absent at the start, an installation whose Keycloak serves
  its realms without `/auth` sets `AUTHZ_OUTGOING_TOKEN_URL`. Without it the agent stays not ready (R14, R19).
- A PIP that forwards the caller's `Authorization` or `Tenant` receives the agent's token and the tenant of the decision
  instead.
- In `k8s`, and in `hybrid` with the agent's token file present at the start, the agent sends PIPs the content of its
  token file, such as the token for `netcracker`, in place of its client credentials token (R2).
