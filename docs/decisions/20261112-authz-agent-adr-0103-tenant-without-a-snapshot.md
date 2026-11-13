# Deny every request of a tenant without a published snapshot, and keep readiness on /ready

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

vlsi

#### Participants and approvers

- The owner of the policy decision code (`vlsi`) approves this record.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  ADR-0091 R17, the conditions that the 503 of `/ready` names, and ADR-0091 R18, liveness, which R4 and R5 build on.
- [authz-agent-ADR-0093: Take the tenant of a decision from the verified user token, then from the request](20261029-authz-agent-adr-0093-tenant-of-a-decision.md):
  the tenant of the decision, the default tenant and its translation (ADR-0093 R11), which ADR-0093 also answers for a
  request that needs the default tenant before the translation, and readiness (ADR-0093 R17, R19, R21). R1 here
  replaces ADR-0093 R16 and R18.
- [authz-agent-ADR-0095: Refuse a check request before policy evaluation](20261029-authz-agent-adr-0095-refuse-before-policy-evaluation.md):
  the refusals that come before the answer of R1, and ADR-0095 R5, which gives the same answer by citing ADR-0093 R16
  and R18.
- [authz-agent-ADR-0097: Answer as legacy access-control, and depart from it only to narrow access or by a recorded decision](20261107-authz-agent-adr-0097-departures-from-legacy.md):
  ADR-0097 R1, the legacy answer, which no golden records for a tenant without policies.
- [authz-agent-ADR-0100: Reject a tenant's candidate snapshot whole when it holds a form the agent cannot evaluate](20261107-authz-agent-adr-0100-forms-the-agent-cannot-evaluate.md):
  the candidate snapshot, a candidate rejected at the first pull, and ADR-0100 R6, what the public `/health` returns.

## Context

The agent decides a request with the snapshot of the tenant of the decision. A tenant can have no snapshot for three
reasons: the policy data does not name it, its candidate snapshot was rejected at the first pull after the start, or the
first pull after the start has not finished. ADR-0093 R16 answers the first case and ADR-0093 R18 the second, in
different words, and no rule answers the third.

The default tenant has a window of its own. Until tenant-manager translates its name (ADR-0093 R11), the agent does not
know the key of its policy data. That window comes from the agent's start rather than from the policy data, and
ADR-0093, which owns the default tenant and its translation, answers the requests that fall into it.

The goldens of the parity suite do not record how legacy answers for a tenant without policies.

Readiness and health are separate probes. In #205 `/ready` answers 503 until the first pull is accepted for every tenant
the policy source names and until the default tenant is translated, and `/health` answers 200 while the trusted
providers are loaded, whatever the state of the tenants. A liveness probe that failed for a tenant without a snapshot
would restart a process that is only waiting for its source.

## Decision

We will answer every request of a tenant without a published snapshot at once, with 200 and a denial of each resource,
and report the tenants without a snapshot in `/ready`, in the internal `/health`, and in a measurement, never in the
status of `/health`.

### Terms

- **Tenant without a snapshot**: a tenant of the decision for which the agent has no published snapshot, because the
  policy data does not name the tenant, because its candidate snapshot was rejected at the first pull after the start,
  or because the first pull after the start has not finished. A tenant that keeps an earlier snapshot after a rejected
  candidate (ADR-0093 R21) has a snapshot. While `AUTHZ_TENANT_MANAGER_URL` holds an address and the agent has not
  yet translated the name of the default tenant (ADR-0093 R11), the default tenant is not a tenant without a snapshot,
  because the agent cannot yet tell which snapshot is its own.

### Rules

#### The answer

- **R1** (`handler`). A request that passes the checks of ADR-0095 and whose tenant of the decision is a tenant without
  a snapshot gets status 200 and a denial of every resource, without waiting for a snapshot:
  1. `check/resource` answers `false`;
  2. each item of a bulk check answers `false`;
  3. bulk operations answer empty lists;
  4. `check/filter` answers `DENY`.
- **R2** (`handler`). The denial reason of each resource that R1 denies is `no policies are published for tenant
  <tenant>`, with the tenant of the decision in place of `<tenant>`, so that a log or a trace tells it from a policy
  denial.

#### Readiness and health

- **R4** (`startup`). The `/health` of the internal listener, like the public `/health`, is liveness under ADR-0091
  R18: its status does not change for a tenant without a snapshot or for a default tenant whose name is not translated
  yet, and it lists the tenants only in its body under R6.
- **R5** (`startup`). While no pull after the start has finished, the 503 of `/ready` names that reason, besides the
  conditions of ADR-0091 R17. `/ready` is served on the internal listener only.
- **R6** (`snapshot`). The `/health` of the internal listener lists each tenant that the policy source names, with
  whether it has a published snapshot. ADR-0100 R2 adds the reason of a rejected candidate.
- **R7** (`snapshot`). The agent exports the number of tenants that the policy source names and that have no published
  snapshot. The measurement answers whether some tenant is denied everything at this moment.

### Justification

A tenant without a snapshot has nothing that could allow a request, so the answer is a denial in every case. One rule
covers the three reasons a tenant can lack a snapshot, because a caller cannot tell them apart and the answer is the
same (R1). Answering at once keeps a request from holding a connection for as long as the pull takes, and the status
stays 200, so a caller does not retry a request that the next pull may not fix either (R1). The reason tells an
operator who reads a denial that no policy was evaluated (R2).

`/health` is the liveness probe. A restart does not give a tenant a snapshot, and with one broken tenant a liveness
probe that failed would restart every Pod and stop the other tenants as well (R4). Readiness is where a rollout waits,
and ADR-0093 decides when it waits. The message of `/ready` tells the operator what it waits for, and it names tenants,
so it stays on the internal listener, as ADR-0100 R6 keeps the public `/health` free of names (R5). The internal
`/health` shows the state of every tenant after the agent becomes ready, when `/ready` no longer reports it (R6), and a
measurement lets an operator alert on a tenant that is denied everything (R7).

### Alternatives considered

- **A1. Answer 503 to a request of a tenant without a snapshot, so that the caller retries.** Rejected by R1: a tenant
  that the policy data does not name never gets a snapshot, so the caller would retry forever, and a bulk caller would
  fail every item where a denial is enough.
- **A2. Hold the request until the first pull finishes.** Rejected by R1: the request would wait for as long as the
  policy source does not answer.
- **A4. Answer 503 on `/health` while a tenant has no snapshot.** Rejected by R4: the liveness probe would restart
  every Pod for one tenant's data.

## Consequences

Negative:

- A request in the window between the start and the first accepted pull is denied, where a request after it can be
  allowed. A client that calls the agent before it is ready, such as through a Service that does not wait for
  readiness, gets denials during that window.

Follow-ups:

- #205 exports `authz_agent_policy_tenants` with the label `snapshot="none"` for the tenants without a snapshot,
  which counts the tenants R7 names, and has no measurement for the wait on tenant-manager that ADR-0093 R12 asks for.
- When this record is accepted, ADR-0093 gains a line under Related ADRs that names R16 and R18 as replaced, and its
  R19 and R20 name their tenant, a tenant whose candidate snapshot was rejected at the first pull after the start,
  instead of pointing at R18. ADR-0095 gains a line that ADR-0103 R1 replaces the citation in its R5.
- The release notes of #205 state that the default `AUTHZ_TENANT_MANAGER_URL` keeps an installation without
  tenant-manager not ready until the variable is set empty.

## Open points

- **O1.** Whether a tenant without a snapshot gets the denial of R1 or 503, so that a client retries while the first
  pull runs. The owner of the policy decision code (`vlsi`) decides. The point affects R1.
- **O3.** Whether the agent needs a readiness endpoint for each tenant, and which members of the internal `/health`
  describe a tenant. The owner of the policy decision code (`vlsi`) decides. The point affects R5 and R6.
