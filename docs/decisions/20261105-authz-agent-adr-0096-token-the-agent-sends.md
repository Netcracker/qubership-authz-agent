# Choose the token the agent sends with a setting of its own

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record.
- The owner of the policy decision code (`vlsi`) returned the questionnaire of 2026-11-03 and reviewed this record on
  2026-11-05.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  ADR-0092 R11, the M2M modes, which decide what the agent accepts.
- [authz-agent-ADR-0093: Take the tenant of a decision from the verified user token, then from the request](20261029-authz-agent-adr-0093-tenant-of-a-decision.md):
  ADR-0093 R11, the call to tenant-manager, and ADR-0093 R7, the `Tenant` header of outgoing calls.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
    the term token for `netcracker`, and the Kubernetes tokens the agent accepts.
- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  ADR-0091 R14, the readiness conditions that the policy pull and the default tenant feed.

## Context

The agent presents one token on the policy pull and on calls to PIPs, entitlements, User Management, and
tenant-manager.

`KUBERNETES_M2M_ENABLED`, a boolean chart value, chooses between the agent's realm token and the token for `netcracker`,
and `helm-templates/authz-agent/values.yaml` sets it to `false`. The container does not read it: the choice follows from
whether the chart sets `AUTHZ_M2M_TOKEN_URL`, and the agent has to run without the chart as well. `M2M_AUTH_MODE` of
ADR-0092 decides which tokens the agent accepts. The services of an installation in `k8s` refuse a realm token, and in
`legacy` they refuse a token that the API server signed.

A PIP declaration can set headers today: `setHeaders` and `forwardHeaders` take precedence over the agent's token, and
`forwardHeaders` can forward the caller's `Authorization`.

## Decision

We will choose the token the agent sends with the boolean setting `KUBERNETES_M2M_ENABLED`, `false` by default.

### Terms

- **The agent's realm token**: the realm token that the agent obtains from the realm `cloud-common` with client
  credentials.
- **The agent's token**: the token the agent presents to the recipients of R10: the agent's realm token or the token for
  `netcracker` of ADR-0094.

### Rules

#### The setting

- **R1** (`startup`). The agent reads `KUBERNETES_M2M_ENABLED` from its environment, `false` by default.
- **R2** (`startup`). `true` sends the token for `netcracker`, and `false` sends the agent's realm token. The value
  has no third state, and `M2M_AUTH_MODE` does not change it.
- **R3** (`startup`). An empty value means `false`, as an unset one does, and the value is compared without regard to
  case. Any other value stops the start, as ADR-0092 R15 does for the mode.
- **R4** (`chart`). The chart passes the value of the same name to the container, `false` by default.
- **R5** (`startup`). `false` takes the token endpoint from `AUTHZ_M2M_TOKEN_URL`, and an empty endpoint stops the
  start.
- **R6** (`startup`). `true` reads the file in `AUTHZ_PAP_CLIENT_TOKEN_FILE`, `/var/run/secrets/tokens/netcracker/token`
  by default, and a missing file stops the start.
- **R7** (`startup`). With `false` the agent does not read that file.
- **R8** (`startup`). `false` in `k8s` and `true` in `legacy` stop the start with a message.
- **R9** (`chart`). The values schema refuses the same pairs, with a message that names both settings, and compares the
  mode without regard to case.

#### The recipients

- **R10** (`client`). The policy pull and the calls to PIPs, entitlements, User Management, and tenant-manager all carry
  the agent's token.
- **R11** (`client`). The agent sets `Authorization` and `Tenant` itself, and takes neither from `setHeaders` or
  `forwardHeaders` of a PIP declaration.

#### A call without a valid token

- **R12** (`client`). The agent keeps its refresh: with `true` it reads the file again, and with `false` it renews the
  agent's realm token before it expires.
- **R13** (`client`). Without a valid token only the call that needs it fails. For a PIP, entitlements, or User
  Management the value it would give is unknown, and the resources that depend on it are denied.
- **R14** (`startup`). The policy pull and the translation of the default tenant need the agent's token too, so the
  agent stays not ready at the start while its realm token cannot be fetched, through the conditions of ADR-0091 R14.
- **R15** (`client`). A 401 from a recipient is a failure of that recipient.
- **R16** (`client`). The agent does not retry with the other token.

### Justification

Accepting a kind of token and choosing which token to send are separate decisions, so `hybrid` can start sending the
token for `netcracker` on its own (R2). A boolean shows which token the agent sends. In `k8s` and in `legacy` only one
token is accepted by the services that receive it, so the agent and the schema stop the other pair at the start, and the
operator does not have to find it out from failing calls (R8, R9). Reading the value in the agent gives a deployment
without the chart the same rule (R1). A missing token file for `netcracker` is an error of the chart that no wait
repairs, like the token for the API server in ADR-0094 R5, while a Keycloak that does not answer can recover (R6, R14).

A PIP address comes from the policy configuration. A declaration that replaced the token could send a caller's token to
that address, and the recipient would see the caller and not the agent (R11).

The other token would rarely help, because the services of an installation accept what its mode allows, and a retry
would hide a token that the recipient refuses (R16).

### Alternatives considered

- **A1. Choose the token by `M2M_AUTH_MODE` alone.** Rejected by R2: the mode would decide both what the agent accepts
  and what it sends, so `hybrid` could not start sending the token for `netcracker` on its own.
- **A2. Let an unset value follow `M2M_AUTH_MODE`.** Rejected by R2: the value would have three states, and an operator
  could not tell from `values.yaml` which token the agent sends.
- **A3. Keep the value in the chart alone.** Rejected by R1: the agent has to run without the chart as well.
- **A4. Refuse only `false` in `k8s`.** Rejected by R8: `true` in `legacy` fails in the same way, and nobody needs that
  pair.
- **A5. Let a PIP declaration set these headers.** Rejected by R11: the token of a caller would reach an address from
  the policy configuration, and a PIP could answer for another tenant than the decision.

## Consequences

Negative:

- Switching an installation to `k8s`, or back to `legacy`, takes a second setting.
- A PIP that forwards the caller's `Authorization` or `Tenant` receives the agent's token and the tenant of the decision
  instead.
- In `k8s` the token sent to PIPs changes from a realm token to the token for `netcracker`.
