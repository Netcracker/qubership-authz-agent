# Accept any verified token in Authorization and limit a caller that is not M2M to its tenant

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record, with the answers it takes from the owner of the policy
  decision code on an unknown mode and on the mode outside Kubernetes, and with the 503 for keys that cannot be loaded.
- The owner of the policy decision code (`vlsi`) returned the questionnaire of 2026-11-03.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0080: Replace Envoy, the Lua filters, and the OPA container with one Go service that embeds OPA](20260907-authz-agent-adr-0080-single-go-service-with-embedded-opa.md):
  this record supersedes its statements on the decision log (R18, R19, R20): the agent emits it in process, with the
  event shape of the collector and the JWT signature redaction, and serves it through `GET /internal/v1/decision-logs`.
- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  verifies the tokens that this record accepts, and defines realm token, file token, and Kubernetes token.
- [authz-agent-ADR-0093: Take the tenant of a decision from the verified user token, then from the request](20261029-authz-agent-adr-0093-tenant-of-a-decision.md):
  ADR-0093 R1, the tenant that a caller that is not M2M is compared with.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
    the marked provider and the checks of a Kubernetes token.
- [authz-agent-ADR-0095: Refuse a check request before policy evaluation](20261029-authz-agent-adr-0095-refuse-before-policy-evaluation.md):
  ADR-0095 R2, the 503 for keys that cannot be loaded.

## Context

A check route receives the caller's token in `Authorization` and, optionally, the user's token in `Incoming-Token`.

Services of an installation call each other with realm tokens, and in some installations with Kubernetes service account
tokens. The platform runs the services of an installation in one of three M2M modes, set in `M2M_AUTH_MODE`: `legacy`,
`hybrid`, and `k8s`, `legacy` by default.

Some callers send a user token in `Authorization`, and some services authenticate with client credentials and carry
neither the role `ROLE_M2M` nor a `level`. The parity goldens of #42 cover both: `caller-user-token`, `ts69-service`,
and `ts69-bare-service`.

## Decision

We will accept on the check routes any verified token in `Authorization` of a kind the M2M mode accepts, and limit a
token that is not M2M to its own tenant.

### Terms

- **Check route**: `check/resource`, `check/resource/bulk/operations`, and `check/filter` under `/access/v1` and
  `/access/v2`, `check/resource/bulk` under `/access/v1`, and `check/resource/bulk/operations` under `/preview/v1` and
  `/preview/v2`.
- **M2M token**: a token that R6, R7, or R21 makes one.

### Rules

#### Requests

- **R1** (`handler`). `Authorization` is required on the check routes. A missing header gets 401 with `TOKEN_MISSING`,
  and a header that is not `Bearer` gets 401 with `TOKEN_SCHEME_INVALID`, both before policy evaluation.
- **R2** (`handler`). A token in `Authorization` that fails verification gets 401 before policy evaluation. The
  exception is `TOKEN_KEYS_UNAVAILABLE` of ADR-0091 R38, which gets the 503 of ADR-0095 R2.
- **R3** (`handler`). An M2M token in `Authorization` may name any tenant.
- **R4** (`handler`). A token in `Authorization` that is not M2M may reach only the tenant of its own non-empty
  `tenant-id` claim, or the default tenant when it has no such claim. Any other tenant gets 403 with
  `CALLER_TENANT_MISMATCH` before policy evaluation.
- **R5** (`handler`). The comparison of R4 uses the tenant of the decision of ADR-0093 R1, so that an `Incoming-Token`
  cannot move the caller out of its tenant.

#### M2M tokens

- **R6** (`verify`). A realm token is an M2M token when `realm_access.roles` holds `ROLE_M2M`, compared byte for byte.
- **R21** (`verify`). A realm token is an M2M token when `level` is `m2m` or `key-manager`, compared without regard to
  case.
- **R7** (`verify`). A Kubernetes token is an M2M token. ADR-0094 R16 refuses one whose `sub` does not start with
  `system:serviceaccount`.
- **R8** (`verify`). A file token is not an M2M token, because its claims are whatever that provider signs.
- **R9** (`verify`). The token verification computes this test once and returns the result, as ADR-0091 R54 states.
- **R10** (`handler`, `policy`). Every reader, `subject.isM2M` among them, reads that result.

#### M2M modes

- **R11** (`handler`). `M2M_AUTH_MODE` decides the kinds of token that `Authorization` accepts. This is the one
  definition of the modes:

  | `M2M_AUTH_MODE` | Accepted in `Authorization` |
  | --- | --- |
  | `legacy` | Realm tokens and file tokens |
  | `hybrid` | Realm tokens, file tokens, and Kubernetes tokens |
  | `k8s` | Kubernetes tokens |

- **R12** (`keys`). In `legacy` the agent has no marked provider, so a token that the API server signed is refused with
  `TOKEN_ISSUER_UNKNOWN`, and no key is loaded for it.
- **R13** (`handler`). In `k8s` a realm token or a file token in `Authorization` that passes verification gets 401 with
  `TOKEN_KIND_NOT_ALLOWED`. One that fails gets the code of that check.
- **R14** (`keys`). The agent loads the keys of realms and of providers in every mode, because `Incoming-Token` may
  still hold a realm token or a file token in `k8s`.
- **R15** (`startup`). The value of `M2M_AUTH_MODE` is compared without regard to case, and an empty value means
  `legacy`, as an unset one does. Any other value stops the start, with or without the chart.
- **R16** (`startup`). Outside Kubernetes the only mode is `legacy`, because there is no API server. In the other modes
  ADR-0094 R5 stops the start when the token for the API server is missing.

#### Other routes

- **R17** (`handler`). No route requires an M2M token.
- **R18** (`handler`). The agent drops its decision log and with it `/internal/v1/decision-logs`, its one service route.
  [Issue #223](https://github.com/Netcracker/qubership-authz-agent/issues/223) tracks how decisions are read.
- **R19** (`handler`). A client of `/internal/v1/decision-logs` gets the 404 of any unknown path.
- **R20** (`chart`). `AUTHZ_DECISION_LOG_PATH`, `AUTHZ_DECISION_LOG_SIZE_LIMIT`, `AUTHZ_DECISION_LOG_FILE`,
  `AUTHZ_DECISION_LOG_URL`, `AUTHZ_DECISION_LOG_HEADERS`, and the emptyDir of the chart go away with the decision log.

### Justification

A check route needs a verified caller, not a caller of a particular kind. The M2M test decides what a caller may reach
instead of whether it may call (R3, R4), so a service whose Keycloak client issues neither `ROLE_M2M` nor a `level`
keeps working and stays inside its own tenant. Computing the test once keeps the check of a caller and the policies from
disagreeing about one token (R9, R10).

`k8s` exists to check a migration: an installation switches it on and sees which services still call with a realm token
or a file token (R13). It is not planned for production.

One table of modes keeps the records that depend on it from defining the modes again (R11). The value is matched loosely
because a mode in another case or an empty value should not stop the start by accident, and the table has no value that
differs from another by case alone (R15).

The goldens `caller-user-token`, `ts69-service`, and `ts69-bare-service` keep their answers. The goldens of #42 tell the
broad M2M test from `level` alone, and `ts72-service` and `ts72-role-m2m` tell `ROLE_M2M` from a service account.

### Alternatives considered

- **A1. Accept only M2M tokens in `Authorization`.** Rejected by R11: 28 goldens would change their answer, and a
  service without `ROLE_M2M` or `level` would stop working with no way to see that in the goldens.
- **A2. Accept realm tokens and file tokens in `Authorization` in `k8s` too.** Rejected by R13: the mode could no longer
  show who still uses one.
- **A3. Compare the caller with the tenant the request names.** Rejected by R5: an `Incoming-Token` of another tenant
  would move the decision out of the caller's tenant, and a mismatch would get the refusal that ADR-0093 R9 does not
  make.

## Consequences

Negative:

- A client-credentials token without `ROLE_M2M` and without `level` is treated as a user token, so it reaches only its
  own or the default tenant.
- The decisions of a request cannot be downloaded from the agent. Issue #223 tracks how they are read.
- Comparing with the tenant of the decision changes the answer of two requests that no golden covers:
  - A caller that is not M2M and has no `tenant-id`, such as a client-credentials token without `ROLE_M2M`, forwards the
    `Incoming-Token` of a user of tenant T. Without that header it is the golden `no-claim-names-no-tenant`, 200 in the
    default tenant. Here the tenant of the decision is T, so the caller gets 403 `CALLER_TENANT_MISMATCH`.
  - A user of tenant A sends a token in `Authorization`, `tenant_id=B`, and an `Incoming-Token` with `tenant-id` A.
    Without that header it is the golden `claim-a-names-tenant-b`, 403. Here the decision is computed in A, with 200.

Follow-ups:

- When this record is accepted, the status of ADR-0080 names the statements it supersedes.
