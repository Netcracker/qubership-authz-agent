# Evaluate the condition and the predicates of a simplified policy with operation ALL on every operation

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

vlsi

#### Participants and approvers

- The owner of the policy decision code (`vlsi`) decided on 2026-10-21 to evaluate such a policy as legacy does, and
  approves this record.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0093: Take the tenant of a decision from the verified user token, then from the request](20261029-authz-agent-adr-0093-tenant-of-a-decision.md):
  ADR-0093 R19, readiness after a candidate rejected at the first pull.
- [authz-agent-ADR-0097: Answer as legacy access-control, and depart from it only to narrow access or by a recorded decision](20261107-authz-agent-adr-0097-departures-from-legacy.md):
  ADR-0097 R1, the legacy answer that this record restores.
- [authz-agent-ADR-0099: Answer check/filter with exactly the rows that a check of each row would allow](20261107-authz-agent-adr-0099-filter-as-a-check-of-each-row.md):
  the rows that the predicate of a rule gives in `check/filter`.
- [authz-agent-ADR-0100: Reject a tenant's candidate snapshot whole when it holds a form the agent cannot evaluate](20261107-authz-agent-adr-0100-forms-the-agent-cannot-evaluate.md):
  the candidate snapshot that R4 rejects, and ADR-0100 R7, the grants a tenant keeps after such a rejection.
- [authz-agent-ADR-0103: Deny every request of a tenant without a published snapshot, refuse the untranslated default tenant with 503, and keep readiness on /ready](20261112-authz-agent-adr-0103-tenant-without-a-snapshot.md):
  ADR-0103 R1, the answer to a tenant whose candidate was rejected at the first pull.

## Context

A simplified policy names a resource type, an operation, roles, and optionally a condition and filter predicates. The
operation `ALL` stands for every operation on the resource type.

Legacy evaluates the condition of such a policy on every operation, and returns its predicate in the filter of every
operation. The goldens of the parity suite in #42, under `test/parity/suite/testdata/golden/`, record it: with the
condition `resource.a == 'y'`, `READ` and `DELETE` answer `true` for a resource with `a` equal to `y` and `false` for
one with `a` equal to `n` (`check-resource-v1-outcome/isolated/oa1-operation-all-with-a-condition`), and a policy with
`"rsqlPredicate": "all==1"` gives that predicate in the filter of `READ` and of `LIST`
(`check-filter-v1-outcome/isolated/oa2-operation-all-with-a-predicate`).

The PAP of legacy stores a policy whose `component`, `resourceType`, and `operation` are all `ALL`, with no condition
and no predicates (`load-simplified-policies-v1/isolated/r29pap-global-policy-with-predicates-ok`), and refuses the same
policy with a predicate with 400 (`load-simplified-policies-v1/isolated/r29pap-global-policy-with-predicates-bad`). No
golden records how it answers `resourceType: ALL` with a condition, or with a `component` or an `operation` other than
`ALL`.

Legacy grants a policy whose `component`, `resourceType`, and `operation` are all `ALL`, with no condition and no
predicates, to a subject that holds its role. In the tenant suite of #42, tenant A holds such a policy for
`ROLE_MT_ADMIN`, and no other policy of either tenant names the resource type `PARITY_MT_ANY`. A user of tenant A with
that role gets `true` for `READ` on `PARITY_MT_ANY` (`check-resource-v1/tenant/t9b-tenant-a-admin-wildcard`), and a user
of tenant B with the same role, where tenant B holds no such policy, gets `false` (`t9a-tenant-b-admin-no-wildcard`).
The read of `r29pap-global-policy-with-predicates-ok` says nothing about the grant: its role, `ROLE_PARITY_R29_NOBODY`,
belongs to no user of the suite.

The agent on `main` takes a policy with `operation: ALL` or `resourceType: ALL` into the wildcard access-role fast path
of the load-testing plan of 2026-03-30, which grants its roles every operation without reading its condition or its
predicates. Issue #89 reports the wrong
allow: with `a` equal to `n`, legacy answers `false` and the agent answers `true`. The translator of #205 compiles a
simplified policy into the general form, where the index of the evaluator selects the policies of a subject's roles, so
the fast path no longer saves time.

## Decision

We will evaluate a simplified policy whose operation is `ALL` as a policy that names each operation of its resource
type, with its condition and its predicates, and grant nothing to its roles without them.

### Terms

- **Global policy**: a simplified policy whose `component`, `resourceType`, and `operation` are all `ALL`, and that has
  no condition and no predicate in any dialect.

### Rules

- **R1** (`translate`). A simplified policy whose operation is `ALL` applies to every operation on its resource type.
  For each operation, its roles and its condition decide whether it allows, as they decide for a simplified policy
  that names that operation.
- **R2** (`translate`). In `check/filter`, the predicates of a simplified policy whose operation is `ALL` give its rows
  for every operation on its resource type, as ADR-0099 states for the predicate of any rule.
- **R3** (`translate`). A global policy allows its roles every operation on every resource type.
- **R4** (`translate`). A candidate snapshot that holds a simplified policy with `resourceType: ALL` that is not a
  global policy is rejected, with an error that names the policy.

### Justification

Projects wrote their policies with `operation: ALL` against legacy, which evaluates the condition and returns the
predicate on every operation. Granting the roles without the condition allows resources that legacy denies, and
ADR-0097 R1 requires the legacy answer (R1, R2). A global policy has no condition to drop, and legacy grants it, as
`t9b-tenant-a-admin-wildcard` records for `READ` on a resource type no other policy names (R3).

The owner decided on 2026-10-21 that the agent rejects `resourceType: ALL` outside the global form. No golden records
legacy evaluating such a policy, so there is no legacy answer to reproduce, and rejecting the candidate keeps the agent
from inventing a meaning for the data (R4). O1 covers the forms no golden records.

### Alternatives considered

- **A1. Keep the wildcard access-role fast path, which grants the roles of a policy with `operation: ALL` or
  `resourceType: ALL` unconditionally.** Rejected by R1 and R2 for `operation: ALL`: the condition and the predicates
  are dropped, and the agent allows where legacy denies, as issue #89 shows. Rejected by R4 for `resourceType: ALL`
  outside the global form: the grant would give such a policy a meaning that no legacy answer records. This reverses the
  fast path of the load-testing plan of 2026-03-30.
- **A2. Read a policy with `resourceType: ALL` and a condition as a condition on every resource type.** Rejected by
  R4: no golden records a legacy answer for such a policy, so this meaning would be the agent's own.

## Consequences

Negative:

- A policy with `operation: ALL`, roles, and a condition or a predicate denies the resources and rows that its
  condition or its predicate excludes, which the agent of `main` allows. For the goldens
  `oa1-operation-all-with-a-condition/read-condition-false` and `delete-condition-false`, issue #89 records `true` on
  `main`; the answer here is `false`, as in legacy.
- An installation whose stored policy data holds `resourceType: ALL` outside the global form has its candidate
  snapshot rejected at the first pull after the upgrade. The tenant then has no snapshot, so ADR-0103 R1 denies its
  requests, and the agent stays not ready under ADR-0093 R19. A candidate rejected after the agent became ready leaves
  the previous snapshot in place, with the grants the new data revokes (ADR-0100 R7).

Follow-ups:

- #205 refuses such a policy at upload in `components/authz-policy-admin/validate.go`, and its translator has no check
  of R4 for policy data that arrives from the export.
- `docs/plans/20260330-load-testing-preparation-plan.md` cites ADR-0040, a record that is not in `docs/decisions/`, for
  the fast path that A1 rejects. The plan needs a line that this record replaces it. On #205,
  `test/svt/profiler/README.md` and the fixtures `test/svt/profiler/wildcard-*/data.json` still describe wildcard
  access under ADR-0040.
- A parity case of the global policy on an operation other than `READ`, and on a resource type that a policy of
  another role names, would record R3 beyond the one golden that records it now.
- Issue #89 also names a policy set uploaded in the regular form and marked `"type": "SIMPLIFIED"`, whose rule target
  is `true` (golden `r29structure-type-simplified-top/read-a-n`). Such a set is not a simplified policy, so ADR-0097 R1
  decides its answer, and this record does not cover it.

## Open points

- **O1.** Whether the PAP of legacy refuses `resourceType: ALL` with a condition, or with a `component` or an
  `operation` other than `ALL`. A golden of each form settles it. Where legacy accepts and evaluates a form, the owner
  of the policy decision code (`vlsi`) decides whether R4 still rejects it. The point affects R4.
