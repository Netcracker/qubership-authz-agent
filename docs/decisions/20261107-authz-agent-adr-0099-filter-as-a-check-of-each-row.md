# Answer check/filter with exactly the rows that a check of each row would allow

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

vlsi

#### Participants and approvers

- The owner of the policy decision code (`vlsi`) set this principle on 2026-10-21 and approves this record.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0097: Answer as legacy access-control, and depart from it only to narrow access or by a recorded decision](20261107-authz-agent-adr-0097-departures-from-legacy.md):
  ADR-0097 R7, the text of an answer, ADR-0097 R5, the departures that allow more, which R8 here names, and the third
  defect of meaning.
- [authz-agent-ADR-0098: Treat a value the agent could not read as unknown, and read each value once per request](20261107-authz-agent-adr-0098-unknown-values-and-source-calls.md):
  ADR-0098 R1, the three-valued logic that R3 and R9 here use for the attributes of a resource.

## Context

`check/filter` does not answer yes or no. It answers with a predicate that the application adds to its own query, in
the dialects a rule declares: `rsqlPredicate`, `sqlPredicate`, `mongodbPredicate`, `querydslPredicate`, and
`customPredicate`. The answer has two steps: the algebra of the filter chooses and combines the predicates of rules, and
each dialect turns the result into text.

Legacy builds the filter by rules of its own that do not follow the decision of `check/resource`. For some policy data
the legacy filter admits rows that `check/resource` denies for the same row: it returns the predicate of an ALLOW rule
alone where a DENY rule should subtract rows, and it writes the wrong opposite of some operators when it negates a DENY
predicate. ADR-0097 calls this a defect of meaning.

## Decision

We will build the answer of `check/filter` as the set of rows that `check/resource` would allow, row by row, taking the
predicate of each rule as its condition on the row, and narrow that set where a dialect cannot write it exactly.

### Terms

- **Row**: one resource that the application's query can return.
- **Predicate of a rule**: the condition on a row that the rule's template in a dialect states.
- **Allowed rows and denied rows of a node**: the rows for which a node of the policy tree, evaluated on that row,
  gives ALLOW and DENY. A node that gives neither on a row is not applicable to it.
- **All rows** and **no rows**: the two sets that need no predicate.
- **Node that can deny**: a DENY rule, a policy or a set with the algorithm `DENY_UNLESS_PERMIT`, or a policy or a set
  with a child that can deny. Any other node can only allow or not apply.
- **Unknown target**: a target that is neither true nor false, under ADR-0098 R1, on the request or on a row: it reads
  an attribute of the resource during `check/filter`, or a value whose source failed.

### Rules

#### The set of rows

- **R1** (`translate`). The rows that a `check/filter` answer admits are the rows that `check/resource` would allow for
  the same subject and operation, where the predicate of each rule is its condition on the row. R5, R6, and R9 are the
  exceptions.
- **R2** (`translate`). With A the allowed rows and D the denied rows of the children of a node, the node gets these
  sets:

  | Algorithm | Allowed rows | Denied rows |
  | --- | --- | --- |
  | `DENY_OVERRIDES` | ∪A ∖ ∪D | ∪D |
  | `PERMIT_OVERRIDES` | ∪A | ∪D ∖ ∪A |
  | `DENY_UNLESS_PERMIT` | ∪A | all rows except ∪A |
  | `PERMIT_UNLESS_DENY` | all rows except ∪D | ∪D |

- **R3** (`translate`). The target and the condition of a rule are evaluated with every attribute of the resource
  unknown. Where the target of the rule is not an unknown target, the three-valued result gives the rule its rows:

  | Result | Rule with a predicate | Rule without a predicate |
  | --- | --- | --- |
  | true | the rows of the predicate | all rows |
  | false | no rows | no rows |
  | unknown | the rows of the predicate | an ALLOW rule: no rows; a DENY rule: denied rows that are unknown |

  A rule with a predicate whose condition is false for the subject gives no rows, even where legacy returns its
  predicate. R9 gives its rows to a rule whose target is an unknown target.
- **R9** (`translate`). In `check/filter`, a rule, a policy, or a set whose target is an unknown target gets denied
  rows that are unknown and no allowed rows if it is a node that can deny, and is not applicable to any row otherwise,
  whatever made the target unknown.
- **R10** (`translate`). In `check/resource`, a rule, a policy, or a set whose target is an unknown target on the
  resource gives DENY if it is a node that can deny, and is not applicable otherwise.
- **R4** (`translate`). At the root, a row on which the tree is not applicable is denied. The answer is `DENY` when the
  allowed rows of the root are no rows, `ALLOW` when they are all rows, including a tree whose rules have no conditions,
  and `USE_FILTER_CONDITION` with the predicate text otherwise.

#### Narrowing

- **R5** (`translate`). Where a dialect cannot write a set of rows exactly, the answer admits fewer rows in that
  dialect, never more. A set of denied rows that is unknown makes the allowed rows of its parent no rows under
  `DENY_OVERRIDES` and `PERMIT_UNLESS_DENY`. A subtraction that a dialect cannot write gives that dialect `null`, and the
  answer is `DENY` when no dialect is left.
- **R6** (`translate`). A placeholder whose value the agent could not read makes the answer `DENY`, except in or below a
  rule, a policy, or a set whose target is an unknown target, where R9 gives that node its rows.

#### The text of a predicate

- **R7** (`translate`). The text of a predicate is the legacy text of ADR-0097 R7, with these changes of meaning:
  1. In mongodb, the agent always wraps a group of DENY predicates in `$and`.
  2. The negation of a DENY predicate writes the correct opposite of each operator: `$gt` becomes `$lte`, `<=` becomes
     `>`, and `=gt=` becomes `=le=`. Each pair that legacy already negates correctly, such as `$lt` and `$gte`, `$in`
     and `$nin`, `$eq` and `$ne`, or `=in=` and `=out=`, keeps its legacy text.
  3. A mongodb fragment that has no opposite operator, such as a bare value, is negated by wrapping it in `$nor`.

#### Departures that allow more

- **R8** (`parity`). These departures can admit rows that the legacy filter does not admit, and they are departures
  that allow more under ADR-0097 R5:
  1. a rule with a predicate whose condition is false for the subject gives no rows (R3), where legacy subtracts or adds
     its predicate;
  2. a tree whose rules have no conditions gets `ALLOW` (R4), where legacy answers `USE_FILTER_CONDITION` with a `null`
     predicate;
  3. the corrected negation of a DENY predicate (R7), where the legacy negation matches fewer rows.

### Justification

An application uses the filter instead of calling `check/resource` for each row, so the two answers have to agree.
Defining the filter as a check of each row makes that agreement the rule rather than a property to test case by case,
and settles each case that would otherwise need its own decision (R1). The algebra of sets is the algebra of the
combining algorithms, restated for rows (R2).

The attributes of a resource are unknown when the filter is built, which is the case ADR-0098 R1 handles. The part of a
condition that reads the subject is known, so a rule whose subject part is false gives nothing, and the predicate
describes the part that reads the resource (R3). A tree whose rules have no conditions allows every row, so its answer
is `ALLOW`, where legacy writes `USE_FILTER_CONDITION` with a `null` predicate, which an application cannot add to a query
(R4).

The filter must never admit a row that `check/resource` denies, so where a dialect cannot express the exact set, the
agent gives a smaller one (R5). A placeholder without a value would leave a predicate that matches the wrong rows (R6).

A node whose target is unknown either applies or does not, and ADR-0098 R2 allows a resource only if it is allowed
both ways. A node that can deny may deny when its target holds, so `check/resource` denies, and the filter gives the
node denied rows it cannot name, which R5 turns into a narrower answer (R9, R10). A node that cannot deny only allows or
does not apply, so reading it as not applicable denies nothing that it would allow both ways, and keeps the rows its
siblings allow. Legacy answers so as well (R9, R10). The rule is the same whatever made the target unknown, a resource
attribute in the filter or a failed source, because ADR-0098 R1 does not tell them apart.

The legacy text of a DENY group in mongodb and of some negated operators changes which rows the query matches, so these
are changes of meaning that ADR-0097 R7 allows. The pairs that legacy already writes correctly keep their text, because
an application may compare or parse it (R7).

Each of these departures agrees with `check/resource`, and still admits rows that a project may never have seen in a
legacy filter, so each is named as allowing more (R8).

### Alternatives considered

- **A1. Reproduce the legacy filter algebra.** Rejected by R1: the legacy filter admits rows that `check/resource`
  denies.
- **A2. Return the ALLOW predicate alone where a DENY subtraction cannot be written, as legacy does.** Rejected by R5:
  the answer would admit rows that `check/resource` denies.
- **A3. Keep the legacy negation of `$gt`, `<=`, and `=gt=`.** Rejected by R7: the negated predicate matches a row that
  the DENY rule denies.
- **A4. Leave every policy or set whose target reads the resource out of the filter, as legacy does.** Rejected by R9:
  under `DENY_OVERRIDES` a DENY policy left out lets its siblings admit rows that `check/resource` denies.
- **A5. Give unknown denied rows to every policy or set whose target reads the resource.** Rejected by R9: a policy of
  ALLOW rules alone under `DENY_OVERRIDES` would empty the rows its siblings allow, where `check/resource` and legacy
  allow them.
- **A6. Deny in `check/resource` for every rule, policy, or set whose target is unknown.** Rejected by R10: a policy of
  ALLOW rules alone would override the permissions of its siblings under `DENY_OVERRIDES`, although it cannot deny on
  any value of its target, and legacy treats it as not applicable.

## Consequences

Negative:

- Where a DENY subtraction cannot be written in a dialect, the agent answers `null` in that dialect or `DENY`, where
  legacy answers with a predicate that admits more rows.
- A DENY rule without a predicate next to a condition on the resource, under `DENY_OVERRIDES` or `PERMIT_UNLESS_DENY`,
  makes the answer `DENY`, where legacy returns the ALLOW predicate.
- A tree without conditions gets `ALLOW` where legacy answers `USE_FILTER_CONDITION` with a `null` predicate.
- A node that can deny and whose target reads the resource makes the answer `DENY` under a `DENY_OVERRIDES` or
  `PERMIT_UNLESS_DENY` parent (R9, R5), where legacy leaves the node out and returns the predicates of its siblings.

## Open points

- **O1.** Whether R5 may make the answer `DENY` for a DENY rule without a predicate next to a condition on the resource,
  as the second negative consequence states. The owner of the policy decision code (`vlsi`) confirms it against data on
  `check/filter` calls for resource types that use deny lists. The point affects R3 and R5.
