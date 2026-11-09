# Treat a value the agent could not read as unknown, and read each value once per request

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

vlsi

#### Participants and approvers

- The owner of the policy decision code (`vlsi`) set these principles on 2026-10-21 and approves this record.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0097: Answer as legacy access-control, and depart from it only to narrow access or by a recorded decision](20261107-authz-agent-adr-0097-departures-from-legacy.md):
  ADR-0097 R2 and R3, the departures this record makes, and ADR-0097 O1, which concerns R2 here.
- [authz-agent-ADR-0099: Answer check/filter with exactly the rows that a check of each row would allow](20261107-authz-agent-adr-0099-filter-as-a-check-of-each-row.md):
  the attributes of a resource in a filter, which are unknown values of this record, and the terms unknown target and
  node that can deny, which R11 uses.
- [authz-agent-ADR-0100: Reject a tenant's candidate snapshot whole when it holds a form the agent cannot evaluate](20261107-authz-agent-adr-0100-forms-the-agent-cannot-evaluate.md):
  ADR-0100 R4, a policy set that legacy never evaluates.

## Context

A decision reads values from sources outside the agent: PIPs, the permission scope service, User Management, and the
entitlements service. Any of them can fail. Legacy answers 500 to a request whose condition reads a failed PIP, so one
failed call fails a whole bulk request. Where a condition reads two sources, the legacy answer depends on which one it
read first, which ADR-0097 calls a defect of meaning.

The policy language has negation without a `not`: `!=`, `NOT IN`, `NOT CONTAINS`, `NOT MATCH`, a DENY rule under
`PERMIT_UNLESS_DENY` or `DENY_OVERRIDES`, and `subject denied`. Reading a failed value as `false` makes a DENY rule
inapplicable, and a deny list then lets the request through.

Legacy keeps the answers of a PIP declared cacheable between requests, so an answer can depend on an earlier request.

## Decision

We will evaluate a value the agent could not read as unknown in three-valued logic, allow only what does not depend on
it, answer 200, and read each value from its source at most once per request and never from an earlier request.

### Terms

- **Source**: a PIP, the permission scope service, User Management, or the entitlements service.
- **Source failure**: an outgoing call to a source that ends in a transport error, in the expiry of its timeout, at an
  open circuit breaker, or without a current agent token to present, or a response that R5 reads as a failure.
- **Unknown value**: a value that is one of these:
  1. the value of a source whose call ended in a source failure;
  2. a value of a PIP that the tenant's policy data does not declare;
  3. an attribute of the resource during `check/filter`;
  4. the result of `subject allowed` or `subject denied` over a decision that depends on an unknown value;
  5. the decision of a policy set that legacy never evaluates, as ADR-0100 defines it.
- **Key**: a source together with the request it sends: the URL, the method, the headers, and the body.

### Rules

#### Evaluation

- **R1** (`translate`). A condition is evaluated in Kleene's three-valued logic. A comparison with an unknown value is
  unknown, `AND` is false when any operand is false, and `OR` is true when any operand is true.
- **R2** (`translate`). A resource is allowed only if it is allowed for every value that each unknown value could take.
  Otherwise it is denied. R11 denies some resources that this rule alone would allow.
- **R3** (`handler`). A source failure never makes a check route answer 500. The answer is 200, and each resource gets
  its decision under R2. The exception is a subject whose token has no roles at all in a request with
  `obligations=true`, which gets 500 as in legacy.
- **R11** (`translate`). A rule whose condition is unknown under R1 because it reads a value whose source failed
  denies, whatever the effect of the rule and whatever the other rules and the combining algorithms give. It denies
  where the rule is applicable, and where its target, or the target of a policy or a set above it, is an unknown target
  of a node that can deny, as ADR-0099 defines both terms:
  1. `check/resource` denies the resource as a whole. A condition whose value R1 settles without the failed value,
     such as an `OR` with another true operand, gives no such denial.
  2. `check/filter` denies the rows on which the rule can apply and its condition can be unknown, which the predicate
     of the rule names, and admits the rows the tree allows minus those rows. Where a dialect cannot write those rows,
     the answer in that dialect is `DENY`. A condition that reads the failed value is unknown on every row of the
     predicate, even where another operand over the resource settles it on some rows.
- **R4** (`translate`). A resource denied under R2 because of an unknown value, or under R11, gets the denial reason
  `PIP resolution failed`, with the names of the sources that failed, and the agent writes a `WARN` line for it.

#### Reading a source

- **R5** (`client`). The agent reads each class of response of a source as legacy reads it, and a class that legacy
  reads as an error is a source failure. A class that legacy reads as a value is a source failure only where the
  contract of the source shows that the class means a failure: a golden of the source, or an answer of the team that
  owns it.
- **R6** (`client`). A 404 from the permission scope service is a source failure. Legacy reads it as an empty scope.
- **R7** (`client`). Every outgoing call to a source has a timeout.
- **R8** (`snapshot`). A policy set that reads a PIP the tenant's policy data does not declare is named in `/health`.
  Only the conditions that read that PIP get an unknown value.

#### Calls per request

- **R9** (`client`). Within one decision request, the agent sends each key at most once. The items of a bulk request
  share the calls, and User Management is called once per `userId`.
- **R10** (`client`). The agent keeps no value of a source from one decision request to the next, including the value of
  a PIP that legacy declares cacheable.

### Justification

Three-valued logic makes the answer independent of the order in which sources are read, which ADR-0097 R3 requires.
Reading a failed value as `false` would open a deny list, so an unknown value is neither true nor false (R1). An
allow that holds for every possible value of the unknown is safe to give, and any other is a denial (R2).

A failed source affects only the resources that read it. Answering 200 with a denial for those resources keeps a bulk
request useful for the rest, and the status no longer depends on whether a failed operand happened to be read (R3). The
named reason and the `WARN` line let an operator tell a failure from a policy denial (R4). The exception for a subject
without roles keeps legacy behavior until the path with obligations has an owner decision (O1).

Legacy denies a resource when an applicable rule's condition fails on a source, even where another rule allows it.
Projects rely on that denial, so the owner decided on 2026-11-09 to keep it (ADR-0097 R1). Whether the condition
depends on the failed value is settled by R1, so the order of operands still does not change the answer (R11). The filter
cannot tell on which rows another operand over the resource settles such a condition, so it denies every row the
predicate of the rule names, which keeps it no wider than `check/resource` (R11).

The agent changes how it reacts to a failure, not what a response means, so a source's answers keep the meaning legacy
gave them (R5). The permission scope service never returns 404 by its contract: a subject without assignments gets 200
with an empty list. A 404 therefore comes from something other than the service, and reading it as an empty scope
would hide the fault (R6). A call without a timeout can hold a request for as long as the source does not answer, so
every call has one, and its expiry is a failure like any other (R7). An undeclared PIP is a configuration error that lasts until someone fixes the data, so
`/health` shows it rather than only the reason of each denial (R8).

One call per key keeps a condition that reads a value twice consistent within a request, and keeps a bulk request from
calling a source once per item (R9). A value kept between requests can be stale and makes an answer depend on an earlier
request, and no source offers a way to invalidate it (R10).

### Alternatives considered

- **A1. Read a failed value as `false`.** Rejected by R1: a DENY rule that reads the value stops applying, and a deny
  list lets the request through.
- **A2. Let a failed value fail the decision of the resource whenever a condition reads it, as a strict built-in error
  does.** Rejected by R11 and by ADR-0097 R3: whether the failed value is read at all depends on the index, the order of clauses, and the evaluator's
  early exit, so `pipA OR pipB` would get different answers from equivalent modules.
- **A3. Answer 500 to a request that reads a failed source, as legacy does.** Rejected by R3: one failed call would fail
  every item of a bulk request.
- **A4. Keep the values of a cacheable PIP between requests, as legacy does.** Rejected by R10.
- **A5. Let a rule whose condition depends on a failed value deny only through the combining algorithm.** Rejected by
  R11: an allowing sibling under `PERMIT_OVERRIDES` would allow the resource, where legacy denies it.

## Consequences

Negative:

- A request that legacy answers with 500 because a source failed gets 200 and a denial of the resources that depend on
  the source.
- A parity case whose golden holds a value that legacy took from its cache gets a different answer from the agent.
- Without a cache between requests, a source gets one call per key per decision request, which is more calls than
  legacy sends for a cacheable PIP.
- A permission scope service that answers 404 makes the agent deny where legacy reads an empty scope.
- A resource that one rule allows is denied when the condition of another applicable rule depends on a failed source
  (R11), as in legacy.
- In `check/filter`, a condition such as `subject.x == 'v' OR resource.a == 'y'` with a failed `subject.x` denies the
  rows where `a` is `y` too, which `check/resource` allows (R11). The filter stays no wider than `check/resource`, as
  ADR-0099 requires.

## Open points

- **O1.** Whether a subject whose token has no roles gets 500 with `obligations=true`, as legacy answers, or 200 with a
  denial. The owner of the policy decision code (`vlsi`) decides when the path with obligations is designed. The point
  affects R3.
