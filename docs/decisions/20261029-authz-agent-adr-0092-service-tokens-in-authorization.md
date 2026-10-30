# Accept only service tokens in Authorization on the check routes

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Date

#### Owner

kichasov

#### Participants and approvers

The project architect, who settled the token rules at two meetings on 2026-10-16 and in a questionnaire returned on
2026-10-19, and decided at a meeting on 2026-10-28 that `Authorization` carries only an M2M token. The architect
approves this record. The Netcracker/qubership-authz-agent maintainers (kichasov). Assumption: the approvers' GitHub
accounts are added when this record is reviewed.

#### Related ADRs

- [authz-agent-ADR-0091: Verify tokens in Go against the keys of trusted providers](20261029-authz-agent-adr-0091-verify-tokens-in-go.md):
  verifies the tokens whose kind this record checks, and starts the reload that a token with an unknown `kid`
  triggers.

## Context

A check route receives the caller's token in `Authorization` and, optionally, the user's token in `Incoming-Token`.
The current policies accept any valid token in `Authorization`, a user token included.

Services of an installation call each other with Keycloak tokens, and in some installations with Kubernetes service
account tokens. The platform runs the services of an installation in one of three M2M modes, set in `M2M_AUTH_MODE`:
`legacy`, `hybrid`, and `k8s`, `legacy` by default.

The parity goldens of #42 cover service accounts that carry the role `ROLE_M2M` and no `level`, and expect them to
skip the tenant check. Every client of the test stand has both the role and a service account, so the goldens cannot
tell the two apart. The `level` of `key-manager`, the match in any case, the role in any realm, and Kubernetes tokens
have no golden.

## Decision

We will accept on the check routes only a service token in `Authorization`, of a kind the M2M mode accepts.

### Service tokens

- An M2M token is a Keycloak token with a `level` of `m2m` or `key-manager` in any case, or with the role `ROLE_M2M`
  in any realm, or a Kubernetes service account token.
- The M2M mode decides which kinds `Authorization` accepts. This is the one definition of the modes:

  | `M2M_AUTH_MODE` | Accepted in `Authorization` |
  | --- | --- |
  | `legacy` | Keycloak M2M tokens |
  | `hybrid` | Keycloak M2M tokens and Kubernetes tokens |
  | `k8s` | Kubernetes tokens |

- In `legacy` the trusted providers file has no provider for the Kubernetes API server, so a Kubernetes token has a
  `kid` that no provider publishes. It triggers the reload of ADR-0091 and is refused with `TOKEN_KID_UNKNOWN`. In
  `k8s` a Keycloak token is refused with `TOKEN_NOT_M2M`.

### Requests

- `Authorization` is required on the check routes. A missing header is refused with `TOKEN_MISSING`, a header that is
  not `Bearer` with `TOKEN_SCHEME_INVALID`, and a token that fails verification with the code of ADR-0091. A user
  token, or a token of a kind the mode does not accept, is refused with `TOKEN_NOT_M2M`. Each is a 401 before OPA.
- A user token in `Incoming-Token` that fails verification does not end the request. The request reaches OPA with the
  code of the failure, and the policies deny it with 200.
- With `Authorization-Type: anonymous` the subject is the anonymous user, and a user token in `Incoming-Token` is
  ignored. Without that header the subject is the user token, or the service token when there is no user token.

### Justification

Only an M2M token in `Authorization` keeps the caller a known service. No business case needs a direct call with a
user token, and the architect revisits that when one does.

One table of modes keeps the records that depend on it from defining the modes again.

Alternatives considered:

- **Accept a user token in `Authorization` and check its `tenant-id` against the tenant of the request.** Rejected for
  now: no business case needs a direct call with a user token.

## Consequences

Positive:

- The caller of a check route is always a known service.

Negative:

- The parity goldens of #42 change their answer in three groups:
  - `check-resource-v1-outcome/caller-user-token/*`, 11 cases: a user token in `Authorization` gets 403 in five of
    them and 200 in six, and 401 `TOKEN_NOT_M2M` here;
  - `check-resource-v1-outcome/regular/ts69-bare-service/*`, 7 cases: the client-credentials token of a client with
    no `realm_access` and no `level` gets 200, and 401 `TOKEN_NOT_M2M` here, so a service that authenticates with
    client credentials but has no `ROLE_M2M` stops working;
  - `regular/r29gaps-anonymous-with-an-end-user-token-*`, 2 of 4 cases: with `Authorization-Type: anonymous` and an
    `Incoming-Token`, the goldens take the end user as the subject, and the subject is anonymous here.
- In `legacy` every Kubernetes token triggers a reload of every provider, at most once a minute per Pod, before it is
  refused.

Neutral:

- Open points, decided as above until answered:
  - whether a client-credentials token without `ROLE_M2M` and without `level` counts as a service token;
  - whether `Authorization-Type: anonymous` with an `Incoming-Token` takes the end user as the subject;
  - whether the providers file lists the Kubernetes API server in every mode, so that `legacy` refuses a Kubernetes
    token with `TOKEN_NOT_M2M` and without a reload.
