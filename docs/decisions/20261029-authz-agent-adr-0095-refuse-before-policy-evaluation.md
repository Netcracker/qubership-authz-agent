# Refuse a check request before policy evaluation

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The owner of the policy decision code (`vlsi`) approves this record.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0080: Replace Envoy, the Lua filters, and the OPA container with one Go service that embeds OPA](20260907-authz-agent-adr-0080-single-go-service-with-embedded-opa.md):
  this record supersedes its statement that the check family keeps its legacy error bodies, for a 401 and a 403 (R6).
- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  the checks of a token, each with its reason code, and ADR-0091 R38, keys that could not be loaded.
- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  ADR-0092 R1 and R2, the refusals of a missing or wrong token, ADR-0092 R11, the kinds of token, and ADR-0092 R4, a
  caller outside its tenant.
- [authz-agent-ADR-0093: Take the tenant of a decision from the verified user token, then from the request](20261029-authz-agent-adr-0093-tenant-of-a-decision.md):
  ADR-0093 R1, the tenant that the steps of this record compare with.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  ADR-0094 R14, R16 to R18, and R25, the refusals of a Kubernetes token.

## Context

A check request carries a caller's token, optionally a user's token, and a tenant. ADR-0091 to ADR-0094 decide how each
is verified and what each may reach, and each of them can refuse the request. The tenant depends on the verified
`Incoming-Token`, and the check of a caller depends on the tenant, so the steps need one order.

## Decision

We will run the checks of a request in one order before policy evaluation, and refuse a request there with an empty body
and the reason code in the audit and a metric.

### Terms

- **Refusal**: the end of a check request before policy evaluation, with a status and a reason code of R16. A token can
  be refused without a refusal of the request, as R3 states.

### Rules

#### The steps before policy evaluation

- **R1** (`handler`). The agent runs these steps in this order:
  1. Read and verify the token in `Authorization`: ADR-0092 R1, the checks of ADR-0091 and ADR-0094, and then the kind
     of token of ADR-0092 R11.
  2. Verify the token in `Incoming-Token`.
  3. Take the tenant of the decision (ADR-0093 R1) and log a mismatch (ADR-0093 R8).
  4. Compare a caller that is not M2M with that tenant (ADR-0092 R4, R5).
  5. Choose the policies of that tenant and evaluate them.
- **R2** (`handler`). A refusal in step 1 is a 401, or a 503 for `TOKEN_KEYS_UNAVAILABLE`.
- **R3** (`handler`). A failure in step 2 does not end the request, and policy evaluation gets the reason code of the
  failure. The exception is `TOKEN_KEYS_UNAVAILABLE`, which ends the request with a 503, because the tenant of step 3
  cannot be known.
- **R4** (`handler`). A refusal in step 4 is a 403.
- **R5** (`handler`). In step 5 a tenant without data or with a rejected snapshot gets the deny of ADR-0093 R16 or R18
  from Go.

#### Refusals

- **R6** (`handler`). A refusal has an empty body.
- **R7** (`handler`). A 503 carries `Retry-After: 60`, the minute in which a source is not asked again.
- **R8** (`handler`). A 401 carries `WWW-Authenticate: Bearer` for `TOKEN_MISSING` and `TOKEN_SCHEME_INVALID`, and
  `WWW-Authenticate: Bearer error="invalid_token"` for every other code, as RFC 6750 requires. These reveal nothing
  beyond the status.
- **R9** (`handler`). Every refusal carries `X-Request-Id` in the response.
- **R10** (`handler`). The reason code goes to the audit and a metric, and an operator finds the event by that
  identifier.
- **R11** (`handler`). A refusal writes an audit record and a CEF event, within the limit of R12, and neither ever holds
  the token.
- **R12** (`handler`). Audit records and CEF events of refusals are rate-limited per client address and reason code, so
  a stream of invented tokens does not write one event per request. Past the limit no event is written, and the metric
  of R13 still counts the refusal.
- **R13** (`handler`). The metric counts every refusal, labeled by the reason code and never by the `iss` or the realm
  of an unverified token.
- **R17** (`handler`). An audit record or a CEF event names the source of a token only as ADR-0091 R74 allows.
- **R14** (`handler`). A refusal writes one line in the application log, which has no stack trace and is not an error.
- **R15** (`handler`). `api/openapi.yaml` drops the body of a 401 and documents the 403 and the 503.

#### The reason codes

- **R16** (`handler`). This table indexes every code of a refusal. The rule in a row states when the code applies:

  | Status | `reasonCode` | Rule |
  | --- | --- | --- |
  | 401 | `TOKEN_MISSING`, `TOKEN_SCHEME_INVALID` | ADR-0092 R1 |
  | 401 | `TOKEN_FORMAT_INVALID` | ADR-0091 R40 |
  | 401 | `TOKEN_ALG_NOT_ALLOWED` | ADR-0091 R41 |
  | 401 | `TOKEN_ISSUER_UNKNOWN` | ADR-0091 R5, R11 |
  | 401 | `TOKEN_KID_MISSING` | ADR-0091 R22 |
  | 401 | `TOKEN_KID_UNKNOWN` | ADR-0091 R23, R39 |
  | 401 | `TOKEN_SIGNATURE_INVALID` | ADR-0091 R43 |
  | 401 | `TOKEN_AUDIENCE_MISSING`, `TOKEN_AUDIENCE_INVALID` | ADR-0091 R50; ADR-0094 R14 |
  | 401 | `TOKEN_EXP_MISSING`, `TOKEN_EXPIRED`, `TOKEN_NOT_YET_VALID` | ADR-0091 R44, R45 |
  | 401 | `TOKEN_IAT_MISSING`, `TOKEN_IAT_INVALID` | ADR-0091 R46, R47, R48 |
  | 401 | `TOKEN_KIND_NOT_ALLOWED` | ADR-0092 R13 |
  | 401 | `TOKEN_NAMESPACE_NOT_ALLOWED` | ADR-0094 R25 |
  | 401 | `TOKEN_SUBJECT_INVALID` | ADR-0094 R16 |
  | 403 | `CALLER_TENANT_MISMATCH` | ADR-0092 R4 |
  | 503 | `TOKEN_KEYS_UNAVAILABLE` | ADR-0091 R37, R38, for either header |

### Justification

The order of the steps follows what each needs: the tenant depends on the verified `Incoming-Token`, and the check of a
caller depends on the tenant (R1).

An empty body gives a caller nothing to build on and nothing to format twice (R6). The reason stays where an operator
looks, under the `X-Request-Id` (R9, R10).

A code of its own for keys that could not be loaded keeps an outage of Keycloak from reading like an invented token. The
503 says that the fault is not the caller's token, and `Retry-After` keeps a client from adding traffic during the
outage (R2, R7). A user token whose keys cannot be loaded ends the request, because otherwise the same request would
move to another tenant for as long as the outage lasts (R3). A code of its own for a realm token or a file token in
`k8s` shows which services still call with one, which is what that mode is for.

### Alternatives considered

- **A1. Carry `reasonCode` in the response body.** Rejected by R6: a caller gains nothing it can act on, and the error
  would be formatted in two places.
- **A2. Report missing keys as `TOKEN_KID_UNKNOWN`.** Rejected by ADR-0091 R38: an outage of Keycloak would look like a
  token with an invented `kid`.
- **A3. Answer 401 for keys that cannot be loaded.** Rejected by R2: that is the status of a bad token. With an empty
  body a caller cannot tell the two apart, and a client that reacts to a 401 by fetching a new token and retrying adds
  traffic at the worst moment.
- **A4. Evaluate a request whose user token failed for that reason.** Rejected by R3: the decision would move to the
  tenant the request names or to the default tenant, and move back when the keys arrive.
- **A5. Report a realm token or a file token in `k8s` as `TOKEN_ISSUER_UNKNOWN`.** Rejected by ADR-0092 R13: a service
  that still has to migrate would look like a token of an unknown issuer.

## Consequences

Negative:

- A caller cannot tell from the response why it was refused, so its owner needs the operator or the logs.
- A request with a good token in `Authorization` fails with a 503 when the keys of its `Incoming-Token` cannot be
  loaded.

Follow-ups:

- When this record is accepted, the status of ADR-0080 names the statement it supersedes.
