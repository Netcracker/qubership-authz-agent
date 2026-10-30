# Pass the verified identity to OPA and refuse before OPA with a reason code

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Date

#### Owner

kichasov

#### Participants and approvers

The owner of the policy decision code, who chose on 2026-10-27 that Go passes ready fields, the values of TOKEN PIPs
among them, and that a refusal before OPA is logged as an event without a policy evaluation, and who proposed the
order of the steps before OPA. The owner of the policy decision code approves this record. The
Netcracker/qubership-authz-agent maintainers (kichasov). Assumption: the approvers' GitHub accounts are added when
this record is reviewed.

#### Related ADRs

- [authz-agent-ADR-0091: Verify tokens in Go against the keys of trusted providers](20261029-authz-agent-adr-0091-verify-tokens-in-go.md):
  the verification whose result this record passes, and the reason codes of a defective token.
- [authz-agent-ADR-0092: Accept only service tokens in Authorization on the check routes](20261029-authz-agent-adr-0092-service-tokens-in-authorization.md):
  which token is the subject, and the refusals of a missing or wrong token in `Authorization`.
- [authz-agent-ADR-0093: Take the tenant of a decision from the request](20261029-authz-agent-adr-0093-tenant-from-the-request.md):
  the tenant this record passes, and the check of the user token that runs before OPA.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  the refusal of a Kubernetes token from a namespace outside the installation.

## Context

From a verified token, `policies/identity.rego` builds a subject of `id`, `name`, `type`, `roles`, and `scopes`, and
`policies/pip.rego` reads the claim a TOKEN PIP names from the token payload. A TOKEN PIP is declared in the policy
configuration of a tenant. Go writes the decision log, and wraps every 401 it returns. The policies that read the
identity are expected to be replaced by a module generated from the policies later.

The policy language has `subject.isM2M`, which is true for a service account or a `level` of `m2m`. It is a different
test from the one that decides which tokens `Authorization` accepts.

## Decision

We will pass OPA the identity that Go computes, and refuse a request before OPA with a reason code.

### The steps before OPA

1. Take the tenant of the request, as ADR-0093 decides.
2. Choose the policies of that tenant.
3. Verify the tokens, as ADR-0091 decides, and apply ADR-0092. A refusal here is a 401.
4. Run the check of the user token of ADR-0093.
5. Build the subject, and compute the TOKEN PIP values from the PIP declarations of the tenant's policies.

### The identity OPA receives

Go computes and passes:

- the subject, with the `id`, `name`, `type`, `roles`, and `scopes` that `policies/identity.rego` builds today;
- the tenant of the request;
- the `level`;
- the id of the provider whose key verified the token;
- whether the request is anonymous;
- for a user token that failed, the `verify` code;
- the value and the state of every TOKEN PIP. Go reads the value from the verified token by the claim or the jsonPath
  the PIP declaration names and applies its `defaultValue`. The token payload itself is not passed.

TOKEN PIP values are computed for every request: they depend on the PIP declarations of the request's tenant, so the
same token gives other values under another tenant or after a change of the configuration.

The field layout is interim. The owner of the policy decision code changes `policies/identity.rego` to read these
fields, and the module that later replaces those policies need not keep the layout. Assumption: the field names and
their place in `input` are settled with that owner before the wiring change.

### Refusals and the decision log

The body of every refusal before OPA carries `reasonCode` next to `message`. These are all the codes:

| Status | `reasonCode` | When |
| --- | --- | --- |
| 401 | `TOKEN_MISSING`, `TOKEN_SCHEME_INVALID`, `TOKEN_NOT_M2M` | `Authorization` is missing, is not `Bearer`, or carries a token of a kind it does not accept (ADR-0092) |
| 401 | `TOKEN_FORMAT_INVALID`, `TOKEN_ALG_NOT_ALLOWED`, `TOKEN_KID_MISSING`, `TOKEN_KID_UNKNOWN`, `TOKEN_SIGNATURE_INVALID`, `TOKEN_AUDIENCE_MISSING`, `TOKEN_AUDIENCE_INVALID`, `TOKEN_EXP_MISSING`, `TOKEN_EXPIRED`, `TOKEN_NOT_YET_VALID`, `TOKEN_IAT_MISSING`, `TOKEN_IAT_INVALID` | The service token fails a check of ADR-0091 |
| 401 | `TOKEN_NAMESPACE_NOT_ALLOWED` | A Kubernetes token comes from a namespace outside the installation (ADR-0094) |
| 400 or 403 | `INCOMING_TENANT_MISMATCH` | The check of the user token refuses the request with its switch on (ADR-0093) |

With the decision log on, every request has an event, written by the code that writes the events today. A refusal
before OPA is an event without a policy evaluation. Every event carries the `reasonCode`, the provider id, the tenant
of the request, and the `X-Request-Id` of the request.

The agent sends PIPs the token it sends today; this record does not change it.

### Justification

The policies receive a fixed identity, the values of TOKEN PIPs included, and do not depend on how a claim is read.

The order follows what each step needs. TOKEN PIP values depend on the PIP declarations of the tenant, so the tenant
and its policies come first. The check of the user token needs the provider of a verified token, so it runs after
the verification.

The decision log and the error body keep one implementation each: Go already writes every event and wraps every 401,
so a refusal before OPA uses the same code.

Alternatives considered:

- **Pass the token payload to Rego.** Rejected: the policies would compute the subject and the TOKEN PIP values again,
  so the rules would still live in two places.
- **Cache the TOKEN PIP values with the verified token.** Rejected: the same token gives other values under another
  tenant or after a change of the configuration.

## Consequences

Positive:

- The policies read the identity, and the TOKEN PIP values arrive computed.
- A refusal before OPA has a reason code in the response and in the decision log.

Negative:

- The Go wiring and the change to `policies/identity.rego` have to land together.

Neutral:

- The decision log event gains the `reasonCode` and the provider id.
- Open points, decided as above until answered:
  - a service-account flag or a ready `isM2M` on the subject, kept apart from the test of ADR-0092;
  - the `userId` path, where the check of `VIEW_AS_ANOTHER_USER` runs as the caller and the decision for each user it
    looks up runs with a subject built from the answer of User Management, whose TOKEN PIPs are empty and get no
    `defaultValue`: whether this record describes both subjects or leaves the path out;
  - the status of `INCOMING_TENANT_MISMATCH`, which ADR-0093 leaves open.
