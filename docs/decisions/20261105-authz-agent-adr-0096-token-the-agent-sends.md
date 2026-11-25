# Choose the token the agent sends with a setting of its own

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record. On 2026-11-23 the architect and the owner of the policy
  decision code agreed to drop the M2M modes, and with them the rules that refused `client-credentials` in `k8s`.
- The owner of the policy decision code (`vlsi`) returned the questionnaire of 2026-11-03 and reviewed this record on
  2026-11-05 and 2026-11-25.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  ADR-0092 R11, the tokens that the agent accepts, and ADR-0092 R15, which has the agent leave `M2M_AUTH_MODE` unread.
- [authz-agent-ADR-0093: Take the tenant of a decision from the verified user token, then from the request](20261029-authz-agent-adr-0093-tenant-of-a-decision.md):
  ADR-0093 R11, the call to tenant-manager, and ADR-0093 R7, the `Tenant` header of outgoing calls.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  the term token for `netcracker`, ADR-0094 R3, which mounts it when R2 of this record chooses it, and the Kubernetes
  tokens the agent accepts.
- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  ADR-0091 R14, the readiness conditions that the policy pull and the default tenant feed.
- [authz-agent-ADR-0104: Describe the two trusted providers in a fixed directory of provider files](https://github.com/Netcracker/qubership-authz-agent/pull/329),
  proposed in #329: the term Kubernetes token (ADR-0104 R22), and ADR-0104 R14, under which the agent stops the start
  when it cannot read the token for the API server.
- [authz-agent-ADR-0107: Have the agent check its own settings, whether or not the chart renders them](https://github.com/Netcracker/qubership-authz-agent/pull/359),
  proposed in #359: ADR-0107 R2, which checks the value of every agent variable and may refuse a setting that R20 of
  this record leaves unread.

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

The platform's deployer passes `M2M_AUTH_MODE` to every service of an installation, and the services that read it
accept tokens by it: in `k8s` only Kubernetes tokens, and in `legacy` no token that the API server signed. The agent
does not read it (ADR-0092 R15).

A PIP declaration can set headers today: `setHeaders` and `forwardHeaders` take precedence over the agent's token, and
`forwardHeaders` can forward the caller's `Authorization`.

## Decision

We will choose the token the agent sends with the setting `AUTHZ_OUTGOING_TOKEN_SOURCE`, which the agent reads
itself: `client-credentials`, the default, or `token-file`.

### Terms

- **The agent's client credentials token**: the token that the agent obtains with client credentials from the token
  endpoint in `AUTHZ_OUTGOING_TOKEN_URL`.
- **The agent's token file**: `/var/run/secrets/tokens/netcracker/token`, the path of the token for `netcracker` of
  ADR-0094.
- **The agent's token**: the token that R2 has the agent present to the recipients of R10.
- **Stops the start**: as ADR-0091 defines it.
- **Agent variable**: as ADR-0107 defines it.
- **Kubernetes token**: as ADR-0104 defines it.
- **Token for `netcracker`**, **token for the API server**: as ADR-0094 defines them.

### Rules

#### The setting

- **R1** (`startup`). The agent reads `AUTHZ_OUTGOING_TOKEN_SOURCE` from its environment, `client-credentials` by
  default.
- **R2** (`startup`). `client-credentials` sends the agent's client credentials token, and `token-file` sends the
  content of the agent's token file without the white space around it.
- **R3** (`startup`). The value is compared without regard to case, and an empty value means `client-credentials`, the
  default of R1. Any other value stops the start.
- **R4** (`chart`). The chart passes the value `AUTHZ_OUTGOING_TOKEN_SOURCE` to the container under the same name,
  `client-credentials` by default. Its values schema accepts `client-credentials` and `token-file` alone.
- **R17** (`chart`). The chart does not read `KUBERNETES_M2M_ENABLED`, and its values schema accepts that key with any
  value.

#### What each value reads, and what the chart mounts and passes

- **R20** (`startup`, `client`, `chart`). For each value of `AUTHZ_OUTGOING_TOKEN_SOURCE`, this table gives the inputs
  that the agent reads and the ones that the chart mounts or passes. An input that the table marks unread for a value
  is one that the agent with that value does not use: it sends no request to an unread token endpoint and opens no
  unread file. A set value of a setting that names an unread input stops the start only where ADR-0107 R2 refuses that
  value, and that refusal takes precedence over this rule.

  | Input | `client-credentials` | `token-file` |
  | --- | --- | --- |
  | The token endpoint in `AUTHZ_OUTGOING_TOKEN_URL` | Read. An unset or empty value stops the start. | Unread. |
  | The client id and the client secret, in the files that `AUTHZ_OUTGOING_CLIENT_ID_FILE` and `AUTHZ_OUTGOING_CLIENT_SECRET_FILE` name | Read at each fetch of the agent's client credentials token. A file that the agent cannot read fails that fetch: at the start R14 applies, and later R13. | Unread. |
  | How long before its expiry the agent renews its client credentials token, in `AUTHZ_OUTGOING_RENEW_BEFORE_SECONDS` | Read. | Unread. |
  | The agent's token file | Unread. | Read. A file that is missing, that the agent cannot read, that is not a regular file once symbolic links are followed, or that is empty or holds only white space stops the start. The agent does not parse the token, so no other content of the file stops the start. |
  | In the chart, the Secret `<SERVICE_NAME>-client-credentials` | Mounted, and `AUTHZ_OUTGOING_CLIENT_ID_FILE` and `AUTHZ_OUTGOING_CLIENT_SECRET_FILE` passed with the paths of its files. | Not mounted, and neither file setting passed. |
  | In the chart, the value `AUTHZ_OUTGOING_TOKEN_URL` | Passed as R19 gives it. | Not passed. A set value is no reason to refuse to render. |

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

- **R12** (`client`). The agent keeps its refresh: with `token-file` it reads the agent's token file again, and with
  `client-credentials` it renews the agent's client credentials token before it expires.
- **R13** (`client`). Without a valid token only the call that needs it fails. For a PIP, entitlements, or User
  Management the value it would give is unknown, and the resources that depend on it are denied.
- **R14** (`startup`). The policy pull and the translation of the default tenant need the agent's token too, so with
  `client-credentials` the agent stays not ready at the start while it cannot obtain its client credentials token,
  through the conditions of ADR-0091 R14.
- **R15** (`client`). A 401 from a recipient is a failure of that recipient.
- **R16** (`client`). The agent does not retry with the other token.

### Justification

The agent accepts every kind of token (ADR-0092 R11), so choosing which token to send is a decision of its own, and an
installation switches to the token for `netcracker` when its recipients accept it (R2). The values name how the agent
gets its token, not who signs it. A token endpoint reached with client credentials need not belong to Keycloak, and the
agent does not parse the token in its file (R2, R20). Reading the value in the agent gives a deployment without the
chart the same rule (R1).

The values schema accepts the two values only as R4 spells them, as it accepts the levels of `LOG_LEVEL` only in
lowercase, so every values file spells a value one way. A deployment without the chart sets the variable by hand, so
the agent compares the value without regard to case and reads an empty value as the default, and ADR-0107 R2 reads
every value from a list the same way (R3, R4).

Whoever installs the agent chooses the token that its recipients accept. The agent does not read the mode by which the
recipients accept tokens (ADR-0092 R15), and it cannot tell what its token file holds: the file may hold a token that
the recipients in `legacy` accept, such as the static token of a test stand whose stubs accept any token. So no value
that R3 accepts stops the start because of what the recipients accept. A wrong choice shows at the rollout where the
policy source or tenant-manager refuses the token: they answer 401, the policy pull or the translation of the default
tenant fails, and the agent stays not ready (R15; ADR-0091 R14). Where only a PIP, entitlements, or User Management
refuses it, the agent turns ready and denies the resources that depend on that recipient (R13).

The deployment puts the agent's token file in place before the container starts: the kubelet writes a projected volume,
and Docker binds a file. A file that is missing, unreadable, or empty at the start is therefore an error of the
deployment that no wait repairs, like a token for the API server that the agent cannot read (ADR-0104 R14). A Keycloak
that does not answer can recover, so the agent waits for it instead (R14, R20).

The client secret leaves the agent only in requests to the token endpoint of `client-credentials`. With `token-file` the
agent needs neither the endpoint nor the credentials, so the chart mounts no Secret and the Secret need not exist.
Switching `AUTHZ_OUTGOING_TOKEN_SOURCE` then takes one setting, also where an environment file lists every setting of
the agent (R20). A value that ADR-0107 R2 refuses still stops the start, because that check treats every agent variable
alike, and the operator learns of a mistyped token endpoint at once rather than when switching back to
`client-credentials`.

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

- **A1. Choose the token by `M2M_AUTH_MODE`.** Rejected by R1 and R2: the agent does not read `M2M_AUTH_MODE`
  (ADR-0092 R15), and an installation in `hybrid` could not choose when to start sending the token for `netcracker`.
- **A2. Let an unset value follow `M2M_AUTH_MODE`.** Rejected by R1: the setting would have a third state, and an
  operator could not tell from `values.yaml` which token the agent sends.
- **A3. Keep the value in the chart alone.** Rejected by R1: the agent has to run without the chart as well.
- **A4. Stop the start, and refuse to render, on a pair of `AUTHZ_OUTGOING_TOKEN_SOURCE` and `M2M_AUTH_MODE` that the
  recipients refuse, such as `client-credentials` in `k8s`.** Rejected by ADR-0092 R15: whether the agent starts does
  not depend on `M2M_AUTH_MODE`, with or without the chart, and a wrong choice fails the calls that carry the token
  (R13, R15). Earlier versions of R8 and R9 refused `client-credentials` in `k8s`, and before that `token-file` in
  `legacy`.
- **A5. Let a PIP declaration set these headers.** Rejected by R11: the token of a caller would reach an address from
  the policy configuration, and a PIP could answer for another tenant than the decision.
- **A6. Let a setting name the file that `token-file` reads.** Rejected by R20: a deployment puts the token at the path
  ADR-0094 names, as the chart's projected volume does, and a setting that the mount does not follow points the agent at
  a file that does not exist. An earlier version of this record had this setting.
- **A7. Choose the token with `KUBERNETES_M2M_ENABLED`.** Rejected by R2 and R17: the platform deprecates that parameter
  in favor of `M2M_AUTH_MODE`, and a value named after Kubernetes does not describe a token file that holds another
  token. An earlier version of this record made the agent read it.
- **A8. Name the values after an issuer, as `keycloak` and `kubernetes`, after a protocol, as `oauth2` and `oidc`, or
  after the platform's identity provider, as `identity-provider`.** Rejected by R2: the agent does not parse the token
  in its file, so it cannot name the issuer. A protocol name such as `oauth2` or `oidc` covers every grant of that
  protocol, while `client-credentials` names the one grant the agent uses, the client credentials grant of OAuth 2.0.
- **A9. Build the token endpoint from `IDENTITY_PROVIDER_URL` alone.** Rejected by R19: a Keycloak that serves its
  realms without `/auth` answers that endpoint with 404, and the agent stays not ready (R14).
- **A10. Refuse a set `AUTHZ_OUTGOING_TOKEN_URL` that ADR-0107 R2 accepts with `token-file`.** Rejected by R20:
  switching `AUTHZ_OUTGOING_TOKEN_SOURCE` would take two changes, and with `token-file` the agent sends the client
  secret nowhere either way.
- **A11. Stop the start only on a missing token file.** Rejected by R20: an empty or unreadable file is the same error
  of the deployment, and the agent would start without a token and stay not ready, with only warnings in its log.
- **A12. Send the token file whenever `AUTHZ_OUTGOING_TOKEN_URL` is empty, with no setting that chooses the token.**
  Rejected by R1 and R20: a token endpoint lost from a configuration would switch the agent to another token without a
  message, while with `client-credentials` an empty endpoint stops the start. An earlier version of the agent chose
  the token this way.
- **A13. Keep the prefix `AUTHZ_M2M_` of the earlier settings, as in `AUTHZ_M2M_TOKEN_URL`.** Rejected by R1 and R20:
  ADR-0092 defines an M2M token as a kind of token that the agent accepts, and `M2M_AUTH_MODE` covers both the tokens a
  service accepts and the tokens it sends, so a reader could take `AUTHZ_M2M_*` for settings of the tokens the agent
  accepts. With `token-file` the agent's token need not be an M2M token either.

## Consequences

Negative:

- An installation whose recipients accept only Kubernetes tokens, as in `k8s`, sets `AUTHZ_OUTGOING_TOKEN_SOURCE` to
  `token-file` itself (R2).
- No value of `AUTHZ_OUTGOING_TOKEN_SOURCE` that R3 accepts stops the start because of what the recipients accept. Where
  the recipients refuse the agent's token, such as the token for `netcracker` in `legacy` or the client credentials
  token in `k8s`, every call that carries it fails, and a failed policy pull or translation of the default tenant keeps
  the agent not ready through ADR-0091 R14 (R2, R15). Where only a PIP, entitlements, or User Management refuses it, the
  agent turns ready and denies the resources that depend on that recipient (R13).
- Outside Kubernetes nothing renews the agent's token file on its own. The agent reads the file again (R12), so a
  process that the operator runs can renew it. Without one, `token-file` serves only a token that outlives the run of
  the agent, such as the static token of a test stand. A deployment without Kubernetes that has neither a process that
  renews the file nor such a token uses `client-credentials` (R2, R12).
- A deployment that sets `KUBERNETES_M2M_ENABLED=true` and not `AUTHZ_OUTGOING_TOKEN_SOURCE` gets `client-credentials`,
  and needs the Secret `<SERVICE_NAME>-client-credentials`, until it sets `AUTHZ_OUTGOING_TOKEN_SOURCE` to `token-file`
  (R4, R17, R20).
- An agent without the chart that reads its token file with the token endpoint empty stops the start until it sets
  `AUTHZ_OUTGOING_TOKEN_SOURCE` to `token-file` (R1, R20).
- With `client-credentials`, an installation whose Keycloak serves its realms without `/auth` sets
  `AUTHZ_OUTGOING_TOKEN_URL`. Without it the agent stays not ready (R14, R19).
- A PIP that forwards the caller's `Authorization` or `Tenant` receives the agent's token and the tenant of the decision
  instead.
- With `token-file` the agent sends PIPs the content of its token file, such as the token for `netcracker`, in place
  of its client credentials token (R2).
