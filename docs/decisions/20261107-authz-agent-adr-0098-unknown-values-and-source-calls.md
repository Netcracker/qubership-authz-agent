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

- [authz-agent-ADR-0090: Read the legacy configuration export through one strict reader](20261025-authz-agent-adr-0090-one-strict-reader-for-the-legacy-export.md):
  its rule 2, the PIPs and policy sets it isolates, whose values are unknown values here.
- [authz-agent-ADR-0097: Answer as legacy access-control, and depart from it only to narrow access or by a recorded decision](20261107-authz-agent-adr-0097-departures-from-legacy.md):
  ADR-0097 R2 and R3, the departures this record makes, and ADR-0097 R5, under which R12 names the
  departures that allow more.
- [authz-agent-ADR-0099: Answer check/filter with exactly the rows that a check of each row would allow](20261107-authz-agent-adr-0099-filter-as-a-check-of-each-row.md):
  the attributes of a resource in a filter, which are unknown values of this record, and the terms unknown target and
  node that can deny, which R11 uses.
- [authz-agent-ADR-0100: Reject a tenant's candidate snapshot whole when it holds a form the agent cannot evaluate](20261107-authz-agent-adr-0100-forms-the-agent-cannot-evaluate.md):
  ADR-0100 R4, a policy set that legacy never evaluates.

## Context

A decision reads values from sources outside the agent: PIPs, the permission scope service, User Management, and the
entitlements service. Any of them can fail, and legacy reacts by source. When a PIP that the condition of an applicable
rule reads fails, legacy answers 200 and denies the resource. Under `PERMIT_UNLESS_DENY` and `DENY_OVERRIDES` it
denies even where another rule allows it: the parity case `failed-pip-beside-allow-permit-unless-deny`, request
`failed-allow-beside-allow`, records `"decision": false`. Under the other two algorithms the answer depends on which
rule legacy evaluates first, and repeated recordings answered both ways. When the
User Management lookup fails, legacy answers 500 to the whole request, so one failed call fails every item of a bulk
request (`g72-ob-bulk-lookup-500`). It answers 500 as well when the permission scope service fails or returns a body it
cannot read. Where a condition reads two sources, the legacy answer depends on which one it read first, which ADR-0097
calls a defect of meaning.

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
  5. the decision of a policy set that legacy never evaluates, as ADR-0100 defines it;
  6. a value of a PIP that ADR-0090 rule 2 isolates;
  7. the decision of a policy set that ADR-0090 rule 2 isolates;
  8. the result of a comparison on which legacy fails with an exception, over a value that the source returned
     normally or an attribute of the resource, such as `IS EMPTY` or `IS NOT EMPTY` over a PIP body `null`, or an
     operator that legacy cannot apply to an attribute of the resource that is `null`.
- **Failed value**: an unknown value of item 1, 2, 6, or 8 of the list above. Items 4, 5, and 7 are unknown values that
  are not failed values: R2 alone decides a resource that depends on them.
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
- **R11** (`translate`). A rule whose condition is unknown under R1 because of a failed value denies, whatever
  the effect of the rule and whatever the other rules and the combining algorithms give. It denies where the rule is
  applicable, and also where its target, or the target of a policy or a set above it, is an unknown target
  of a node that can deny, as ADR-0099 defines both terms:
  1. `check/resource` denies the resource as a whole. A condition whose value R1 settles without the failed value,
     such as an `OR` with another true operand, gives no such denial.
  2. `check/filter` denies exactly the rows on which the rule can apply and its condition is unknown under R1, with the
     failed value unknown and each attribute of the resource taken from the row, and admits the rows the tree allows
     minus those rows. `subject.x == 'v' OR resource.a == 'y'` with a failed `subject.x` denies the rows where `a` is
     not `y`, and keeps the rows where `a` is `y`. Where a dialect cannot write the denied rows, that dialect gets
     `null`, and the answer follows ADR-0099 R5.
- **R4** (`translate`). A resource denied under R2 because of an unknown value, or under R11, gets the denial reason
  `PIP resolution failed`, with the names of the sources that failed, of the policy sets of item 5 or 7 whose
  decision it depends on, or of the operator and the operand of item 8.
- **R12** (`translate`). These departures can allow a resource that legacy denies, and they are departures that allow
  more under ADR-0097 R5:
  1. a condition whose value R1 settles without the failed value, such as `subject.x == 'v' OR resource.a == 'y'` with a
     failed `subject.x` and `a` equal to `y`, allows where legacy stops at the failed operand and denies (R11);
  2. a request that legacy fails with 500 because the User Management lookup or the permission scope service failed,
     or because it reaches a policy set that legacy never evaluates, gets 200, and each resource that does not depend
     on the failed source or the set gets its decision (R3 for a source failure, R2 for a set);
  3. a PIP value read afresh for each request can allow where legacy denies from a value it kept from an earlier
     request (R10);
  4. a request that legacy refuses with 400 because a loaded policy set reads a PIP that the domain does not declare,
     as the parity case `failed-pip-beside-allow-permit-unless-deny` describes, gets 200, and each resource whose
     conditions do not read that PIP gets its decision (R8).

#### Telemetry

- **R13** (`handler`). A decision request in which a source failure denied some resource writes one `WARN` line,
  whatever the number of resources it denied. The line names the failed sources and the kind of failure, and carries
  the request ID. Lines with the same source and kind of failure are rate-limited, so an outage writes a bounded number
  of lines whatever the traffic.
- **R14** (`client`). The agent counts the calls to sources by the kind of source and by outcome, where the outcome is
  success or the kind of failure. The counter answers how often each kind of source fails, and the failure rate of a
  kind is computable from it alone.

#### Reading a source

- **R5** (`client`). The agent reads each class of response of a source as legacy reads it, and a class that legacy
  reads as an error is a source failure. A class that legacy reads as a value is a source failure only where the
  contract of the source shows that the class means a failure: a golden of the source, a recorded answer of a released
  version of it, or an answer of the team that owns it.
- **R6** (`client`). A 404 from the permission scope service is a source failure. Legacy reads it as an empty scope.
- **R7** (`client`). Every outgoing call to a source has a timeout.
- **R8** (`snapshot`). A policy set that reads a PIP the tenant's policy data does not declare is named in the `/health`
  of the internal listener. Only the conditions that read that PIP get an unknown value. ADR-0100 R6 states what the
  `/health` of the public listener returns.

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
request useful for the rest, where legacy fails it with 500 when User Management or the permission scope service
fails, and the status no longer depends on whether a failed operand happened to be read (R3). The named reason lets a
caller tell a failure from a policy denial (R4). Each of these departures can give a resource that legacy denies, so
R12 names them as allowing more.

During an outage, every request that reads the failed source fails the same way. One line per request, with the rate
bounded per source and kind of failure, tells the operator which source failed without writing one line per denied
resource of a bulk request, and its request ID joins the failure to the request (R13). The counter answers whether to
wait or to call the team that runs the source (R14). The exception for a subject
without roles keeps legacy behavior until the path with obligations has an owner decision (O1).

Legacy denies a resource when an applicable rule's condition fails on a source, even where another rule allows it
under `PERMIT_UNLESS_DENY` or `DENY_OVERRIDES`, and the order of evaluation decides under the other two algorithms.
Projects rely on that denial, so the owner decided on 2026-11-09 to keep it (ADR-0097 R1). Whether the condition depends
on the failed value is settled by R1, so the order of operands still does not change the answer (R11). The filter denies
the rows on which `check/resource` would deny under R11, row by row, as ADR-0099 R1 requires. A policy set that legacy
never evaluates fails every request that reaches it in legacy. Here its decision is an unknown value, and R2 allows a
resource only where the answer does not depend on it, which R12 names as allowing more.

The owner decided on 2026-11-09 where R11 stops. A PIP that the tenant does not declare, or that the reader isolates,
is a fault that a condition reads in the same way as a failed call, so it is a failed value and R11 denies through it.
A set that legacy never evaluates, an isolated set, and `subject allowed` over a decision that depends on a failed value
are a nested decision that is unknown, so R2 decides them: a resource is allowed only where the answer does not depend
on that decision.

A comparison on which legacy throws, such as `IS EMPTY` over a PIP body `null`, drops the decision of the resource in
legacy as a failed PIP does, although the source answered normally. Reading it as `false` would let a `NOT` or a DENY
rule over it open access that legacy denies, so the owner decided on 2026-11-10 that its result is a failed value
(item 8), and R11 denies through it.

The agent changes how it reacts to a failure, not what a response means, so a source's answers keep the meaning legacy
gave them (R5). The permission scope service never returns 404 by its contract: its release of 2026-10-12, called with a
production identity provider, answers 200 with an empty list to a subject without assignments, in a group or not, and
answered no request with 404. A 404 therefore comes from something other than the service, and reading it as an empty
scope would hide the fault (R6). A call without a timeout can hold a request for as long as the source does not answer,
so every call has one, and its expiry is a failure like any other (R7). An undeclared PIP is a configuration error that
lasts until someone fixes the data, so `/health` shows it rather than only the reason of each denial (R8).

One call per key keeps a condition that reads a value twice consistent within a request, and keeps a bulk request from
calling a source once per item (R9). A value kept between requests can be stale and makes an answer depend on an earlier
request, and no source offers a way to invalidate it (R10).

### Alternatives considered

- **A1. Read a failed value as `false`.** Rejected by R1: a DENY rule that reads the value stops applying, and a deny
  list lets the request through.
- **A2. Let a failed value fail the decision of the resource whenever a condition reads it, as a strict built-in error
  does.** Rejected by R11 and by ADR-0097 R3: whether the failed value is read at all depends on the index, the order of
  clauses, and the evaluator's early exit, so `pipA OR pipB` would get different answers from equivalent modules.
- **A3. Answer 500 to the whole request when the User Management lookup or the permission scope service fails, as legacy
  does.** Rejected by R3: one failed call would fail every item of a bulk request.
- **A4. Keep the values of a cacheable PIP between requests, as legacy does.** Rejected by R10.
- **A5. Let a rule whose condition depends on a failed value deny only through the combining algorithm.** Rejected by
  R11: an allowing sibling under `PERMIT_UNLESS_DENY` would allow the resource, where legacy denies it
  (`failed-allow-beside-allow`).
- **A6. Write a `WARN` line for each denied resource.** Rejected by R13: a bulk request of 1000 items during an outage
  would write 1000 lines, at the rate of the traffic.

## Consequences

Negative:

- A request that legacy answers with 500 because the User Management lookup or the permission scope service failed gets
  200 and a denial of the resources that depend on the source (R12).
- A parity case whose golden holds a value that legacy took from its cache gets a different answer from the agent,
  which can allow more (R12).
- Without a cache between requests, a source gets one call per key per decision request, which is more calls than
  legacy sends for a cacheable PIP.
- A permission scope service that answers 404 makes the agent deny where legacy reads an empty scope.
- A resource that one rule allows is denied when the condition of another applicable rule depends on a failed source
  (R11), as in legacy under `PERMIT_UNLESS_DENY` and `DENY_OVERRIDES`.

Follow-ups:

- #205 reads a 404 from the permission scope service as an empty scope, which R6 makes a source failure.

## Open points

- **O1.** Whether a subject whose token has no roles gets 500 with `obligations=true`, as legacy answers, or 200 with a
  denial. The owner of the policy decision code (`vlsi`) decides when the path with obligations is designed. The point
  affects R3.
