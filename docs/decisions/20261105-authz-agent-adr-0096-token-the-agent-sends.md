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
  2026-11-05.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  ADR-0092 R11, the tokens that the agent accepts, and ADR-0092 R15, which has the agent leave `M2M_AUTH_MODE` unread,
  as #345 rewrites them.
- [authz-agent-ADR-0093: Take the tenant of a decision from the verified user token, then from the request](20261029-authz-agent-adr-0093-tenant-of-a-decision.md):
  ADR-0093 R11, the call to tenant-manager, and ADR-0093 R7, the `Tenant` header of outgoing calls.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  the term token for `netcracker`, ADR-0094 R3, which mounts it when R2 of this record chooses it, and the Kubernetes
  tokens the agent accepts.
- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  ADR-0091 R14, the readiness conditions that the policy pull and the default tenant feed.
- [authz-agent-ADR-0105: Configure the two providers through the chart values](https://github.com/Netcracker/qubership-authz-agent/pull/332),
  proposed in #332: ADR-0105 R1, which has the chart leave `M2M_AUTH_MODE` unread.

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

We will choose the token the agent sends with the setting `AUTHZ_M2M_TOKEN_SOURCE`, which the agent reads itself:
`client-credentials`, the default, or `token-file`.

### Terms

- **The agent's client credentials token**: the token that the agent obtains with client credentials from the token
  endpoint in `AUTHZ_M2M_TOKEN_URL`.
- **The agent's token file**: `/var/run/secrets/tokens/netcracker/token`, the path of the token for `netcracker` of
  ADR-0094.
- **The agent's token**: the token that R2 has the agent present to the recipients of R10.
- **Stops the start**, **Kubernetes token**: as ADR-0091 defines them.
- **Token for `netcracker`**: as ADR-0094 defines it.

### Rules

#### The setting

- **R1** (`startup`). The agent reads `AUTHZ_M2M_TOKEN_SOURCE` from its environment, `client-credentials` by default.
- **R2** (`startup`). `client-credentials` sends the agent's client credentials token, and `token-file` sends the
  content of the agent's token file without the white space around it.
- **R3** (`startup`). The value is compared without regard to case, and an empty value means `client-credentials`, the
  default of R1. Any other value stops the start.
- **R4** (`chart`). The chart passes the value `AUTHZ_M2M_TOKEN_SOURCE` to the container under the same name,
  `client-credentials` by default. Its values schema accepts `client-credentials` and `token-file` alone.
- **R17** (`chart`). The chart does not read `KUBERNETES_M2M_ENABLED`, and its values schema accepts that key with any
  value.
- **R5** (`startup`). `client-credentials` takes the token endpoint from `AUTHZ_M2M_TOKEN_URL` and the client id and the
  client secret from the files that `AUTHZ_M2M_CLIENT_ID_FILE` and `AUTHZ_M2M_CLIENT_SECRET_FILE` name. An empty
  endpoint stops the start.
- **R6** (`startup`). With `token-file` the agent reads the agent's token file, and stops the start when that file is
  missing, cannot be read by the agent, is not a regular file once symbolic links are followed, or is empty or holds
  only white space. The agent does not parse the token in the file, so no other content of the file stops the start.
- **R7** (`startup`, `client`). With `client-credentials` the agent does not read the agent's token file. With
  `token-file` it sends no request to `AUTHZ_M2M_TOKEN_URL`, reads neither of the files that `AUTHZ_M2M_CLIENT_ID_FILE`
  and `AUTHZ_M2M_CLIENT_SECRET_FILE` name, and a set value of any of these three settings is no reason for it to stop
  the start.

#### What the chart mounts and passes

- **R18** (`chart`). With `client-credentials` the chart mounts the Secret `<SERVICE_NAME>-client-credentials`, passes
  `AUTHZ_M2M_CLIENT_ID_FILE` and `AUTHZ_M2M_CLIENT_SECRET_FILE` with the paths of the files of that Secret, and passes
  the token endpoint of R19. With `token-file` it mounts no such Secret, passes none of these three settings, and a set
  value `AUTHZ_M2M_TOKEN_URL` is no reason for it to refuse to render.
- **R19** (`chart`). With `client-credentials` the chart passes the value `AUTHZ_M2M_TOKEN_URL`, empty by default, to
  the container under the same name. In place of an empty value it passes `IDENTITY_PROVIDER_URL`, less one trailing
  `/`, followed by `/auth/realms/cloud-common/protocol/openid-connect/token`.

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
agent does not parse the token in its file (R2, R6). Reading the value in the agent gives a deployment without the
chart the same rule (R1).

Whoever installs the agent chooses the token that its recipients accept. The agent does not read the mode by which the
recipients accept tokens (ADR-0092 R15), and it cannot tell what its token file holds: the file may hold a token that
the recipients in `legacy` accept, such as the static token of a test stand whose stubs accept any token. So no value
that R3 accepts stops the start because of what the recipients accept, and a wrong choice shows at the rollout: the
recipients answer 401, the policy pull fails, and the agent stays not ready (R15; ADR-0091 R14).

The deployment puts the agent's token file in place before the container starts: the kubelet writes a projected volume,
and Docker binds a file. A file that is missing, unreadable, or empty at the start is therefore an error of the
deployment that no wait repairs, like the token for the API server in ADR-0094 R5. A Keycloak that does not answer can
recover, so the agent waits for it instead (R6, R14).

The client secret leaves the agent only in requests to the token endpoint of `client-credentials`. With `token-file` the
agent needs neither the endpoint nor the credentials, so the chart mounts no Secret and the Secret need not exist.
Switching `AUTHZ_M2M_TOKEN_SOURCE` then takes one setting, also where an environment file lists every setting of the
agent (R7, R18).

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
- **A4. Stop the start, and refuse to render, on a pair of `AUTHZ_M2M_TOKEN_SOURCE` and `M2M_AUTH_MODE` that the
  recipients refuse, such as `client-credentials` in `k8s`.** Rejected by ADR-0092 R15 and ADR-0105 R1: neither the
  agent nor the chart reads `M2M_AUTH_MODE`, and a wrong choice shows at the rollout (R15). Earlier versions of R8 and
  R9 refused `client-credentials` in `k8s`, and before that `token-file` in `legacy`.
- **A5. Let a PIP declaration set these headers.** Rejected by R11: the token of a caller would reach an address from
  the policy configuration, and a PIP could answer for another tenant than the decision.
- **A6. Let a setting name the file that `token-file` reads.** Rejected by R6: a deployment puts the token at the path
  ADR-0094 names, as the chart's projected volume does, and a setting that the mount does not follow points the agent at
  a file that does not exist. An earlier version of R6 had this setting.
- **A7. Choose the token with `KUBERNETES_M2M_ENABLED`.** Rejected by R2 and R17: the platform deprecates that parameter
  in favor of `M2M_AUTH_MODE`, and a value named after Kubernetes does not describe a token file that holds another
  token. An earlier version of this record made the agent read it.
- **A8. Name the values after an issuer, as `keycloak` and `kubernetes`, after a protocol, as `oauth2` and `oidc`, or
  after the platform's identity provider, as `identity-provider`.** Rejected by R2: the agent does not parse the token
  in its file, so it cannot name the issuer, and a protocol name does not tell the two ways apart.
- **A9. Build the token endpoint from `IDENTITY_PROVIDER_URL` alone.** Rejected by R19: a Keycloak that serves its
  realms without `/auth` answers that endpoint with 404, and the agent stays not ready (R14).
- **A10. Refuse a set `AUTHZ_M2M_TOKEN_URL` with `token-file`.** Rejected by R7 and R18: switching
  `AUTHZ_M2M_TOKEN_SOURCE` would take two changes, and with `token-file` the agent sends the client secret nowhere
  either way.
- **A11. Stop the start only on a missing token file.** Rejected by R6: an empty or unreadable file is the same error of
  the deployment, and the agent would start without a token and stay not ready, with only warnings in its log.

## Consequences

Negative:

- An installation whose recipients accept only Kubernetes tokens, as in `k8s`, sets `AUTHZ_M2M_TOKEN_SOURCE` to
  `token-file` itself (R2).
- No value of `AUTHZ_M2M_TOKEN_SOURCE` that R3 accepts stops the start because of what the recipients accept. Where the
  recipients refuse the agent's token, such as the token for `netcracker` in `legacy` or the client credentials token in
  `k8s`, every call that carries it fails, and a policy pull that fails keeps the agent not ready through ADR-0091 R14
  (R2, R15).
- A deployment that sets `KUBERNETES_M2M_ENABLED=true` and not `AUTHZ_M2M_TOKEN_SOURCE` gets `client-credentials`, and
  needs the Secret `<SERVICE_NAME>-client-credentials`, until it sets `AUTHZ_M2M_TOKEN_SOURCE` to `token-file` (R4,
  R17, R18).
- An agent without the chart that reads its token file with `AUTHZ_M2M_TOKEN_URL` empty stops the start until it sets
  `AUTHZ_M2M_TOKEN_SOURCE` to `token-file` (R1, R5).
- With `client-credentials`, an installation whose Keycloak serves its realms without `/auth` sets
  `AUTHZ_M2M_TOKEN_URL`. Without it the agent stays not ready (R14, R19).
- A PIP that forwards the caller's `Authorization` or `Tenant` receives the agent's token and the tenant of the decision
  instead.
- With `token-file` the agent sends PIPs the token for `netcracker` in place of its client credentials token (R2).
