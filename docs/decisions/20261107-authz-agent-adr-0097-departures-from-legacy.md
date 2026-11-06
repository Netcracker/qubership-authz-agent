# Answer as legacy access-control, and depart from it only to narrow access or by a recorded decision

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

vlsi

#### Participants and approvers

- The owner of the policy decision code (`vlsi`) set these principles on 2026-10-21 and approves this record.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0083: Compare operands as the Java values legacy reads, and a number by value](20261024-authz-agent-adr-0083-operands-as-java-values.md):
  how the agent reproduces a legacy comparison.
- [authz-agent-ADR-0090: Read the legacy configuration export through one strict reader](20261025-authz-agent-adr-0090-one-strict-reader-for-the-legacy-export.md):
  its rule 5, the differences from legacy at the boundary where the export is read.
- [authz-agent-ADR-0098: Treat a value the agent could not read as unknown, and read each value once per request](20261107-authz-agent-adr-0098-unknown-values-and-source-calls.md):
  the departure for a failed source.
- [authz-agent-ADR-0099: Answer check/filter with exactly the rows that a check of each row would allow](20261107-authz-agent-adr-0099-filter-as-a-check-of-each-row.md):
  the departures of `check/filter`, and the exceptions to R7 there.
- [authz-agent-ADR-0100: Reject a tenant's candidate snapshot whole when it holds a form the agent cannot evaluate](20261107-authz-agent-adr-0100-forms-the-agent-cannot-evaluate.md):
  the forms that legacy evaluates and the agent does not.

## Context

The agent replaces the PDP of legacy access-control. Projects wrote and tuned their policies against the answers of
legacy, and their applications append the text of a `check/filter` predicate to their own queries as legacy writes it.

The parity suite records the answers of a live access-control 6.1.6 as goldens and compares the agent with them. Some
recorded answers are defects: for the same policy data and the same request, the answer depends on the order in which
legacy evaluates the operands of a condition, or on which of two sources failed. The suite lists each case where the
agent answers differently in `test/parity/suite/accepted_divergences.go`, and each entry needs a decision that allows
the difference. Until now the policy for such decisions lived outside the repository, so an entry could not cite it.

## Decision

We will give the legacy answer by default, depart from it without a separate decision only to remove a defect of
meaning and only toward less access, and record every other departure in an ADR rule that a parity entry can cite.

### Terms

- **Legacy answer**: the HTTP status and the body that the PDP of access-control 6.1.6 returns for a request, as the
  goldens of the parity suite record it.
- **Departure**: a request for which the agent's status or body differs from the legacy answer.
- **Defect of meaning**: a legacy answer that, for policy data the legacy PAP accepts, has one of these properties:
  1. it changes when the operands of an `AND` or an `OR` are swapped;
  2. it depends on which of the sources a request reads failed, or in which order they failed;
  3. a `check/filter` answer admits a row that `check/resource` denies for that row.
- **Narrowing departure**: a departure where every resource the agent allows, legacy allows too, and every row the
  agent's filter admits, the legacy filter admits too.

### Rules

#### The default

- **R1** (`translate`). The agent gives the legacy answer to every request, except where R2 allows the departure or a
  rule of an ADR names it. A legacy behavior that allows access is kept until such a rule names it.

#### Departures without a separate decision

- **R2** (`translate`). A departure that removes a defect of meaning needs no ADR of its own, provided it is a narrowing
  departure. A departure that removes a defect of meaning and allows more than legacy is governed by R5.
- **R3** (`translate`). The answer does not depend on the order of the operands of an `AND` or an `OR`. The agent
  evaluates every operand that can change the result, and does not reproduce the point at which legacy stops evaluating
  a condition.

#### Departures that need a decision

- **R4** (`translate`). A departure that is not a narrowing departure, or that has a cause other than a defect of
  meaning, exists only where a rule of an ADR names it. Code that departs from the legacy answer without such a rule
  violates R1.
- **R5** (`translate`). A departure that allows a resource or a row that legacy denies is named in a rule of an ADR as
  allowing more, whatever its cause.
- **R6** (`translate`). A behavior legacy does not have, such as an input it does not read, a placeholder it does not
  substitute, or a check it does not make, is added only by a rule of an ADR.

#### The text of an answer

- **R7** (`translate`). The body of an answer matches the legacy answer byte for byte, including the escaping, the
  quotation marks, the URL encoding, and a mongodb predicate that is not valid JSON. A value from the policy data or the
  request is substituted into a predicate as legacy substitutes it, with no escaping of the agent's own. A departure
  under R2 or R4 changes the bytes that its change of meaning needs and no others.

#### The record of departures

- **R8** (`parity`). Every parity case that the agent answers differently from its golden has an entry in
  `test/parity/suite/accepted_divergences.go`, and the `Decision` of the entry names the ADR and the rule that allow the
  departure, as `ADR-0097 R3`. An entry without such a rule fails the suite.
- **R9** (`parity`). An entry whose agent answer allows a resource or a row that the golden denies is marked as allowing
  more (`AllowsMore`), and its `Decision` names a rule under R5.
- **R10** (`parity`). A golden stays as it was recorded when the agent departs from it. The agent's answer goes into
  the entry, never into the golden.

### Justification

A project that tuned its policies against legacy relies on today's denials as much as on its permissions, so the
default is the legacy answer, defects included (R1). A defect that allows access is still kept until someone decides to
remove it, because removing it can break a project that, knowingly or not, depends on it.

A defect of meaning is different: the same request gets different answers from equivalent policy data, so no project
can rely on any one of them. Removing it toward less access cannot open anything a project expects closed (R2). The
order of operands is the main case. In the agent, the order of clauses comes from the generated module and from the
evaluator's early exit, so reproducing the legacy order would make an answer change when the module is regenerated
(R3).

Every other departure changes an answer that a project could have relied on, so it needs a decision that a reviewer can
find and argue with (R4). A departure that allows more is the one that can open data, so it is named as such wherever it
is recorded, including when it follows from a rule about unknown values (R5, R9). New behavior is a departure too: a
policy that works only on the agent cannot move back to legacy (R6).

Applications append the predicate text to their queries and parse it as legacy writes it. Escaping a value, adding
brackets, or turning a mongodb predicate into valid JSON would change what the query matches, so the bytes stay. A
value with special characters that changes the structure of a predicate is the responsibility of the policy author, and
`customPredicate` is the safe form for such a value (R7).

The parity suite runs every case, including a departed one, and compares the agent with the recorded entry. Naming a
rule in each entry turns the list of entries into a list of decisions, and a reviewer of a new entry checks the rule
rather than a free-text reason (R8). The goldens are the evidence of what legacy did, so they are never edited to match
the agent (R10).

### Alternatives considered

- **A1. Fix every legacy defect the team finds, including those that allow less than intended.** Rejected by R1 and
  R4: a project whose policies rely on such a defect would lose access on migration with no decision anyone can point
  to.
- **A2. Reproduce the order in which legacy evaluates a condition.** Rejected by R3: the answer would depend on the
  order of clauses in the generated module.
- **A3. Escape substituted values, or write a mongodb predicate as valid JSON.** Rejected by R7: an application that
  appends or parses the predicate would get a different query.
- **A4. Accept a divergence with a free-text reason or a design note outside the ADRs.** Rejected by R8: the reason
  cannot be checked against a rule, and a note outside the records drifts from the code.

## Consequences

Negative:

- Legacy defects that allow access stay in the agent until an ADR names each of them.
- A predicate value with special characters can still change the structure of the predicate, as it does in legacy.
- A parity case whose legacy answer depends on the order of operands or on which source failed gets a different answer
  from the agent, and is listed in `accepted_divergences.go` with `ADR-0097 R3` or a rule of ADR-0098 or ADR-0099.

Follow-ups:

- The entries for `general-pip-dict` in `test/parity/suite/accepted_divergences.go` name
  `docs/parity/general-pip-dict-divergences.md`, which is not in the repository, and they allow what legacy denies. They
  need a rule under R5, or the agent gives the legacy answer there.
- The substitution of `${subject.isM2M}` in `requestAttributes`, which legacy does not perform, is a decision of the
  owner without a record. It needs an ADR rule under R6.

## Open points

- **O1.** ADR-0098 allows some requests that legacy does not. A condition such as `subject.x == 'v' OR resource.a == 'y'`
  with an unknown `subject.x` and a true right operand allows, where legacy denies because it stops at the failed
  operand; legacy allows the same request when the operands are swapped. A bulk request that reads a failed source gets
  500 from legacy, and the agent allows the items that do not depend on the source. The owner of the policy decision
  code (`vlsi`) decides whether such departures are narrowing departures under R2, or departures that allow more under
  R5. The point affects R2, R5, and R9.
- **O2.** The owner decided that the path that decides on behalf of a user reads the caller's token for a TOKEN PIP,
  where legacy reads nothing, and calls User Management at another address. Reading the caller's token can allow more
  than legacy, which R2 does not permit without a record. The owner of the policy decision code (`vlsi`) decides whether it
  gets an ADR rule under R5 or the legacy answer. The point affects R2 and R5.
