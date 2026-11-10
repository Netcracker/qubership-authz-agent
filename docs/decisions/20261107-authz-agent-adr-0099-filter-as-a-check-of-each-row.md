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
  ADR-0098 R1, the three-valued logic that R3 and R9 here use for the attributes of a resource, and ADR-0098 R11, the
  denial of a resource whose rule depends on a failed source.

## Context

`check/filter` does not answer yes or no. It answers with a predicate that the application adds to its own query, in
the dialects a rule declares: `rsqlPredicate`, `sqlPredicate`, `mongodbPredicate`, `predicate` for QueryDSL, and
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
- **Node that can deny**: a rule, a policy, or a set whose outcome, evaluated on this request with its own target taken
  as true, can be DENY under ADR-0098 R1 or R11. The values of the request are known, and in `check/filter` the
  attributes of the resource are unknown. A DENY rule whose condition is not false for the subject, and a policy or a
  set with the algorithm `DENY_UNLESS_PERMIT` whose children do not allow every row, are such nodes. A DENY rule whose
  condition is false for the subject, and a `DENY_UNLESS_PERMIT` node with a child that allows every row, are not. An
  ALLOW rule whose condition can stay unknown through a failed value is such a node under ADR-0098 R11, and so is a
  policy or a set with such a node among its children. Any other node can only allow or not apply.
- **Unknown target**: a target that is neither true nor false, under ADR-0098 R1, on the request or on a row: it reads
  an attribute of the resource during `check/filter`, or another unknown value of ADR-0098.

### Rules

#### The set of rows

- **R1** (`translate`). The rows that a `check/filter` answer admits are the rows that `check/resource` would allow for
  the same subject and operation, where the predicate of each rule is its condition on the row. R5, R6, R9, and R12 are
  the exceptions. ADR-0098 R11 gives the rows of a rule whose condition stays unknown through a failed value.
- **R2** (`translate`). With A the allowed rows and D the denied rows of the children of a node, the node gets these
  sets:

  | Algorithm | Allowed rows | Denied rows |
  | --- | --- | --- |
  | `DENY_OVERRIDES` | ∪A ∖ ∪D | ∪D |
  | `PERMIT_OVERRIDES` | ∪A | ∪D ∖ ∪A |
  | `DENY_UNLESS_PERMIT` | ∪A | all rows except ∪A |
  | `PERMIT_UNLESS_DENY` | all rows except ∪D | ∪D |

- **R3** (`translate`). The target and the condition of a rule are evaluated with every attribute of the resource
  unknown. Where the target of the rule is not an unknown target, and ADR-0098 R11 does not decide the rule, the
  three-valued result gives the rule its rows:

  | Result | Rule with a predicate | Rule without a predicate |
  | --- | --- | --- |
  | true | the rows of the predicate | all rows |
  | false | no rows | no rows |
  | unknown through an attribute of the resource | the rows of the predicate | an ALLOW rule: no rows; a DENY rule: denied rows that are unknown |
  | unknown through another unknown value of ADR-0098 | an ALLOW rule: no rows; a DENY rule: denied rows that are unknown | an ALLOW rule: no rows; a DENY rule: denied rows that are unknown |

  A rule with a predicate whose condition is false for the subject gives no rows, even where legacy returns its
  predicate. R9 gives its rows to a rule whose target is an unknown target, and ADR-0098 R11 to a rule whose condition
  stays unknown because of a failed value. A condition that holds a failed value and that R1 of ADR-0098 settles
  without it, such as an `OR` with a true operand, gets its row here.
- **R9** (`translate`). In `check/filter`, a rule, a policy, or a set whose target is an unknown target gets its rows
  as follows, whatever made the target unknown:
  1. a DENY rule with a predicate, whose condition is not false for the subject, keeps its predicate: it gets the rows
     of its predicate as denied rows and no allowed rows;
  2. any other node that can deny gets denied rows that are unknown and no allowed rows;
  3. a node that cannot deny is not applicable to any row.

  An ALLOW rule whose condition depends on a failed value denies under ADR-0098 R11. Such a rule, and a node with
  such a rule below it, are therefore nodes that can deny, in `check/filter` under this rule and in `check/resource`
  under R10.
- **R10** (`translate`). In `check/resource`, a rule, a policy, or a set whose target is an unknown target on the
  resource gives DENY if it is a node that can deny, and is not applicable otherwise.
- **R4** (`translate`). At the root, a row on which the tree is not applicable is denied. The answer is `DENY` when the
  allowed rows of the root are no rows, `ALLOW` when they are all rows, and `USE_FILTER_CONDITION` with the predicate
  text otherwise.

#### Narrowing

- **R5** (`translate`). Where a dialect cannot write a set of rows exactly, the answer admits fewer rows in that
  dialect, never more. A set of denied rows that is unknown makes the allowed rows of its parent no rows under
  `DENY_OVERRIDES` and `PERMIT_UNLESS_DENY`. A subtraction that a dialect cannot write gives that dialect `null`, and
  the answer is `DENY` when no dialect is left.
- **R6** (`translate`). A placeholder whose value the agent could not read makes the answer `DENY`, except in or below a
  rule, a policy, or a set whose target is an unknown target, where R9 gives that node its rows.
- **R12** (`translate`). The answer is `DENY` when the filter passes either of two bounds:
  1. Depth: the filter evaluates the children of a set deeper than level 8, where a set at the root of the tree is at
     level 1. A set counts when the filter evaluates its children: its target is true, or it is an unknown target that
     R9 evaluates. A set whose target is false does not count. A set with `iterate` counts as any other set. A tree of
     8 nested sets gets its text; a tree of 9 gets `DENY`.
  2. Size: the text of any dialect, or the compact JSON of `customFilterCondition`, is longer than 1 MiB, that is,
     1 048 576 bytes in UTF-8. Each text is measured on its own and in bytes, so a text in Cyrillic can pass the bound
     with fewer characters than that, and one dialect, such as mongodb, can pass it alone. Compact JSON has no space
     after `,` or `:`, and escaping that the JSON encoder adds to `<`, `>`, and `&` is not counted. A text of exactly
     1 MiB is returned; one byte more gives `DENY`. The agent may stop building a text as soon as a part of it passes
     the bound.

#### The text of a predicate

- **R7** (`translate`). The text of a predicate is the legacy text of ADR-0097 R7, with these changes of meaning:
  1. In mongodb, the agent always wraps a group of DENY predicates in `$and`.
  2. The negation of a DENY predicate writes the correct opposite of every operator, and keeps the legacy text wherever
     legacy writes the correct opposite, such as `=gt=` as `=le=`, `$lt` as `$gte`, or `=in=` as `=out=`. Where legacy
     writes a wrong one, the agent writes the correct one. The goldens of the parity suite record these: legacy leaves
     the mongodb `$gt` as `$gt` and writes `$lte` as `$gtee`, writes the RSQL `<=` and `>=` as `>==` and `<==`, and
     replaces an operator inside a quoted value as well, so `a>"x==y"` becomes `a<="x!=y"`. The agent negates `$gt` as
     `$lte`, `$lte` as `$gt`, `<=` as `>`, `>=` as `<`, and `a>"x==y"` as `a<="x==y"`. SQL and QueryDSL negate by
     wrapping, `NOT (...)` and `(...).not()`.
  3. A mongodb fragment that has no opposite operator, such as a bare value, is negated by wrapping it in `$nor`.
- **R11** (`translate`). The text of a predicate depends only on the rule's template in that dialect and on the values
  substituted into it under R7, not on the rule's condition. The agent does not check that a template selects the rows
  on which the condition holds, and adds no guard to a negated predicate for a case where the two can differ, such as
  a comparison that ignores case, a missing attribute, or a value of another type.

#### Departures that allow more

- **R8** (`parity`). These departures can admit rows that the legacy filter does not admit, and they are departures
  that allow more under ADR-0097 R5:
  1. a rule with a predicate whose condition is false for the subject gives no rows (R3), where legacy subtracts or adds
     its predicate;
  2. a tree whose allowed rows are all rows gets `ALLOW` (R4), where legacy answers `USE_FILTER_CONDITION` with every
     predicate `null`, as the parity case `deny-without-predicate-false-beside-a-predicate-under-permit-unless-deny`
     records;
  3. the corrected negation of a DENY predicate (R7), where the legacy negation selects other rows or is not a valid
     query.

### Justification

An application uses the filter instead of calling `check/resource` for each row, so the two answers have to agree.
Defining the filter as a check of each row makes that agreement the rule rather than a property to test case by case,
and settles each case that would otherwise need its own decision (R1). The algebra of sets is the algebra of the
combining algorithms, restated for rows (R2).

The attributes of a resource are unknown when the filter is built, which is the case ADR-0098 R1 handles. The part of a
condition that reads the subject is known, so a rule whose subject part is false gives nothing, and the predicate
describes the part that reads the resource (R3). A condition that a failed value leaves unknown is decided by ADR-0098
R11, because a predicate cannot describe the value that failed (R3). A tree that allows every row answers `ALLOW`, where
legacy sometimes writes `USE_FILTER_CONDITION` with every predicate `null`, which an application cannot add to a query
(R4).

The filter must never admit a row that `check/resource` denies, so where a dialect cannot express the exact set, the
agent gives a smaller one (R5). A placeholder without a value would leave a predicate that matches the wrong rows (R6).

Under R2 the allowed rows and the denied rows of a node both refer to both sets of each child. In nested sets that
alternate `PERMIT_OVERRIDES` and `DENY_OVERRIDES`, the parts the two sets share grow exponentially with depth. In memory
they can be shared, but no dialect can write a shared part once, so the exact text doubles at each level: 20 levels give
219 244 characters of RSQL, where legacy writes 421, and 25 levels do not finish in 8 seconds. The owner decided on
2026-11-10 to answer `DENY` past 8 levels and past 1 MiB of text. `DENY` admits fewer rows than R1 states, in the
direction R5 allows, and legacy has neither bound (R12).

A node whose target is unknown either applies or does not, and ADR-0098 R2 allows a resource only if it is allowed
both ways. A node that can deny may deny when its target holds, so `check/resource` denies, and the filter gives the
node denied rows it cannot name, which R5 turns into a narrower answer (R9, R10). A node that cannot deny only allows or
does not apply, so reading it as not applicable denies nothing that it would allow both ways, and keeps the rows its
siblings allow. Legacy answers so as well (R9, R10). The rule is the same whatever made the target unknown, a resource
attribute in the filter or a failed source, because ADR-0098 R1 does not tell them apart.

A DENY rule with a predicate already names the rows it denies, so under an unknown target the filter subtracts those
rows rather than every row. That denies each row `check/resource` denies through the rule, and also the rows where the
target does not hold (R9).

The legacy text of a DENY group in mongodb and of some negated operators changes which rows the query matches, so these
are changes of meaning that ADR-0097 R7 allows. The pairs that legacy already writes correctly keep their text, because
an application may compare or parse it (R7).

The author of a policy writes the condition and the template of a rule separately, in different languages, and they
are evaluated by different rules. `==` in a condition ignores case and converts types, and a comparison in SQL, RSQL,
or mongodb follows the collation and the column types of the application's store. The agent knows neither. A guard
such as `LOWER(...)` or `IS NOT NULL` would guess at the store, could keep the database from using an index, and
cannot be written in an RSQL dialect whose parser has no such operator. The author knows the store, so keeping the
template in step with the condition is the author's task (R11).

Each of these departures agrees with `check/resource`, and still admits rows that a project may never have seen in a
legacy filter, so each is named as allowing more (R8).

### Alternatives considered

- **A1. Reproduce the legacy filter algebra.** Rejected by R1: the legacy filter admits rows that `check/resource`
  denies.
- **A2. Return the ALLOW predicate alone where a DENY subtraction cannot be written, as legacy does.** Rejected by R5:
  the answer would admit rows that `check/resource` denies.
- **A3. Keep the legacy negation of `$gt`, `$lte`, `<=`, and `>=`.** Rejected by R7: the negated predicate selects the
  rows the DENY rule denies, or is not a valid query.
- **A4. Leave every policy or set whose target reads the resource out of the filter, as legacy does.** Rejected by R9:
  under `DENY_OVERRIDES` a DENY policy left out lets its siblings admit rows that `check/resource` denies.
- **A5. Give unknown denied rows to every policy or set whose target reads the resource.** Rejected by R9: a policy of
  ALLOW rules alone under `DENY_OVERRIDES` would empty the rows its siblings allow, where `check/resource` and legacy
  allow them.
- **A6. Deny in `check/resource` for every rule, policy, or set whose target is unknown.** Rejected by R10: a policy of
  ALLOW rules alone would override the permissions of its siblings under `DENY_OVERRIDES`, although it cannot deny on
  any value of its target, and legacy treats it as not applicable.
- **A7. Decide whether a node can deny from its effect and algorithm alone.** Rejected by R9 and R10: a DENY rule whose
  condition is false for the subject would deny where its outcome on the request is never DENY, and legacy treats it as
  not applicable.
- **A8. Guard the negation of a DENY predicate with `LOWER(...)`, `IS NOT NULL`, `$exists`, or `DENY` for a value of
  another type.** Rejected by R11: a guard guesses at the collation and the types of the store, and changes text that
  an application may compare or parse.
- **A9. Answer `null` in every dialect for a DENY predicate whose condition can differ from its template.** Rejected
  for its cost: almost every DENY predicate on a string qualifies, so deny lists would stop working in `check/filter`.
- **A10. Write the parts shared by the allowed and the denied rows once.** Rejected by R12: RSQL, SQL, QueryDSL, and
  mongodb have no way to name a part of a predicate and refer to it again.
- **A11. Build the exact text at any depth and size.** Rejected by R12: the text and the time to build it grow
  exponentially with the depth of alternating sets.

## Consequences

Negative:

- Where a DENY subtraction cannot be written in a dialect, the agent answers `null` in that dialect or `DENY`, where
  legacy answers with a predicate that admits more rows.
- A DENY rule without a predicate next to a condition on the resource, under `DENY_OVERRIDES` or `PERMIT_UNLESS_DENY`,
  makes the answer `DENY`, where legacy returns the ALLOW predicate.
- A tree whose allowed rows are all rows gets `ALLOW` where legacy answers `USE_FILTER_CONDITION` with every predicate
  `null` (R8).
- A node that can deny and whose target reads the resource makes the answer `DENY` under a `DENY_OVERRIDES` or
  `PERMIT_UNLESS_DENY` parent (R9, R5), where legacy leaves the node out and returns the predicates of its siblings.
- A tree that evaluates sets deeper than 8 levels, or whose text in any dialect passes 1 MiB, gets `DENY` (R12), where
  legacy, which has neither bound, answers with a predicate.
- Where the template of a DENY rule selects fewer rows than its condition denies, `check/filter` admits rows that
  `check/resource` denies, as legacy does (R11). With the condition `resource.segment == "VIP"` and the SQL template
  `segment = 'VIP'`, a row with `segment = 'vip'` appears in the list, and `check/resource` denies it because `==`
  ignores case. A value of another type, such as `5` against `"5"`, and, in mongodb, a document without the attribute
  differ in the same way.

Follow-ups:

- A warning at load time for a DENY rule whose template and condition visibly differ, such as a case-sensitive
  template for a `==` condition on a string, is left for a later change.

- `combine` in #205 keeps the denied rows of a node whole, where R2 subtracts its allowed rows. The answer is narrower
  than R1 states, which is safe, and the code changes to match R2.

## Open points

- **O1.** Whether R5 may make the answer `DENY` for a DENY rule without a predicate next to a condition on the resource,
  as the second negative consequence states. The owner of the policy decision code (`vlsi`) confirms it against data on
  `check/filter` calls for resource types that use deny lists. The point affects R3 and R5.
