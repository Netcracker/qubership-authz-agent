# Reject a tenant's candidate snapshot whole when it holds a form the agent cannot evaluate

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

vlsi

#### Participants and approvers

- The owner of the policy decision code (`vlsi`) set this principle on 2026-10-21 and approves this record.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0090: Read the legacy configuration export through one strict reader](20261025-authz-agent-adr-0090-one-strict-reader-for-the-legacy-export.md):
  the configuration that fails to load because legacy would not store it, and its rule 2, the sets it isolates, which
  ADR-0098 treats like a policy set that legacy never evaluates.
- [authz-agent-ADR-0093: Take the tenant of a decision from the verified user token, then from the request](20261029-authz-agent-adr-0093-tenant-of-a-decision.md):
  ADR-0093 R19 and R21, readiness and the snapshot a tenant keeps after its candidate is rejected.
- [authz-agent-ADR-0097: Answer as legacy access-control, and depart from it only to narrow access or by a recorded decision](20261107-authz-agent-adr-0097-departures-from-legacy.md):
  ADR-0097 R1, the legacy answer that a partial evaluation would break, ADR-0097 R4, under which R12 names the
  departures of a pattern that does not compile, and ADR-0097 R5, under which R7 and R12 name the departures that
  allow more.
- [authz-agent-ADR-0098: Treat a value the agent could not read as unknown, and read each value once per request](20261107-authz-agent-adr-0098-unknown-values-and-source-calls.md):
  the unknown values that a policy set legacy never evaluates gives, and item 7 of its unknown values, the decision of a
  node that R10 isolates.
- [authz-agent-ADR-0103: Deny every request of a tenant without a published snapshot, and keep readiness on /ready](20261112-authz-agent-adr-0103-tenant-without-a-snapshot.md):
  ADR-0103 R1, the answer to a tenant whose candidate was rejected at the first pull.

## Context

The agent translates each tenant's policy data into a module and publishes it as that tenant's snapshot. The goal is to
translate every form that legacy evaluates, and the missing forms are added one at a time. Until then a tenant can hold
a form the translator has no translation for, such as a jsonPath expression outside the supported subset.

Legacy also accepts policy data that it never evaluates: a policy set for which every request that reaches it gets 500,
whatever its sources answer. Such a set is a fault of the data, not of the agent.

A `MATCH` or `NOT MATCH` pattern stands for a regular expression, and the syntax of that expression was never
documented. Legacy compiles it with `java.util.regex`, and while a tenant's loaded policy data holds a pattern that
`java.util.regex` refuses, legacy answers 400 to every check of that tenant. Policy evaluation in the agent matches a
pattern in the RE2 syntax, the syntax of the Go package `regexp`, which refuses some expressions that Java accepts,
such as the backreference `(a)\1`.

## Decision

We will reject a tenant's candidate snapshot as a whole when it holds a form that legacy evaluates and the agent cannot,
keep a policy set that legacy itself never evaluates in the snapshot as a permanent source of unknown values, and
isolate the one node that holds a `MATCH` pattern that does not compile in the RE2 syntax.

### Terms

- **Candidate snapshot**: the module and the data that the agent builds from one pull of a tenant's policy data, before
  it publishes them.
- **Form the agent cannot evaluate**: a construct of the policy language that the legacy PDP evaluates and the agent's
  translator has no translation for. A pattern that does not compile is not such a form, whether legacy compiles it or
  not: R10 governs it.
- **Policy set that legacy never evaluates**: a policy set for which legacy answers 500 to every request that reaches
  it, whatever its sources answer. These are the sets whose `iterate` has one of these forms:
  1. a `foreach` other than `subject.permissionScope`, as in the parity case `r28reach-foreach-roles`;
  2. no `combiningAlgorithm`, as in the parity case `d2r46-8e8b10b0bb`;
  3. a `combiningAlgorithm` that legacy does not know. The PAP of 6.1.6 rejects such data with 400 (the parity case
     `rp46-head-iterate-algorithm-other`), so no golden records the PDP answer, the 500 is inferred, and the form
     reaches the agent only from data that an older PAP stored.

  An unknown `combiningAlgorithm` of a policy or a set itself, outside `iterate`, is not such a form: it fails the
  candidate under ADR-0090 rule 2, which reads the three forms above as such a set.

  A set that ADR-0090 rule 2 isolates is a fault of the export, not of this kind, and ADR-0098 gives its decision an
  unknown value as well.
- **Pattern that does not compile**: a `MATCH` or `NOT MATCH` pattern whose expression fails either compilation of R9,
  such as `a)|(b` or `(a)\1`.

### Rules

- **R1** (`snapshot`). A candidate snapshot that holds a form the agent cannot evaluate is rejected whole, and no part
  of it is published. The candidates of the other tenants are published as usual.
- **R2** (`snapshot`). A rejected candidate snapshot is reported by a `WARN` line and in the `/health` of the internal
  listener, each naming the tenant, the policy set, and the reason.
- **R3** (`translate`). A form the agent cannot evaluate fails the translation of the candidate snapshot with an error
  that names the policy set and the form. The translator does not replace the form with an undefined value, a skipped
  rule, or an unknown value.
- **R4** (`snapshot`). A policy set that legacy never evaluates does not reject the candidate snapshot. Its decision
  is an unknown value of ADR-0098, and the `/health` of the internal listener names the policy set.
- **R5** (`docs`). The documentation of each release lists the forms the agent cannot evaluate.
- **R6** (`handler`). The `/health` of the public listener returns the status and counts only. It names no tenant, no
  policy set, no reason, and no form.
- **R7** (`snapshot`). A tenant that keeps its previous snapshot under ADR-0093 R21 because a candidate was rejected,
  under R1, under ADR-0090 rule 2, under ADR-0102 R4, or for any other reason, keeps the grants that the rejected
  candidate revokes.
  This is a departure that allows more under ADR-0097 R5: legacy evaluates the new policy data and denies where the
  agent allows.
- **R8** (`snapshot`). For each tenant, the agent exports the time it last accepted a snapshot, whether its latest
  candidate was rejected, and the time the first of the current run of rejections arrived. The measurements answer how
  long a tenant has served a snapshot that its policy data has moved past.
- **R9** (`translate`). When the agent loads a tenant's policy data, it compiles the regular expression that each
  `MATCH` and `NOT MATCH` pattern stands for, after the wildcards of the pattern are expanded, in the RE2 syntax twice:
  once alone, and once inside the anchors that the agent adds around it. The first compilation fails for `a)|(b`, whose
  parentheses the anchors would balance. A `\Q` that no `\E` closes
  quotes the rest of the pattern, as in Java, and does not fail either compilation.
- **R10** (`translate`, `snapshot`). A pattern that does not compile isolates one node of the tenant's policy data and
  does not reject the candidate snapshot under R1. The isolated node is:
  1. the policy, where the pattern is in the target of the policy or in the target or the condition of one of its
     rules;
  2. the policy set, where the pattern is in the target of the set;
  3. the set of simplified policies, where the pattern is in the condition of one of its policies.

  A target that holds the pattern matches every request that reaches the isolated node. The decision of the isolated
  node is an unknown value of ADR-0098, item 7, in `check/resource` and in `check/filter` alike, and the tenant's other
  policies are evaluated as usual.
- **R11** (`snapshot`). A node isolated under R10 is reported by a `WARN` line when the policy data is loaded and under
  `failures` in the `/health` of the internal listener, each naming the tenant, the policy set, the policy where R10
  isolates a policy, the pattern, and the error of the compilation. A tenant whose only fault is such a node has its
  candidate snapshot published, and it counts toward readiness under ADR-0093 R19 as any published snapshot does.
- **R12** (`translate`). The RE2 syntax of R9 gives these departures from legacy. Items 2 and 3 can allow a resource or
  a row that legacy denies, and they are departures that allow more under ADR-0097 R5:
  1. a pattern that `java.util.regex` accepts and the RE2 syntax refuses, such as `(a)\1`, isolates its node under R10,
     where legacy evaluates the pattern;
  2. a check of a tenant whose policy data holds a pattern that `java.util.regex` refuses, which legacy answers with
     400, gets the answer that the other rules give instead of 400, and each resource and row gets its decision under
     R10 or, where the RE2 syntax accepts the pattern, from the pattern as the RE2 syntax reads it;
  3. a pattern that both syntaxes accept matches the strings that the RE2 syntax gives it, where legacy matches the
     strings that `java.util.regex` gives it.

### Justification

A tenant's policies work together: a deny list in one set limits what another set allows. Publishing a snapshot with a
part left out would give answers that are neither legacy answers nor narrowing departures, so the whole candidate waits
until the form is supported, and the tenant keeps the snapshot it had (R1, R3). The other tenants do not depend on that
data, so their updates go on (R1). A rejection is invisible in the answers of a tenant that keeps its old snapshot, so
the operator learns of it from the log and from `/health` (R2). The internal `/health` names tenants, policy sets, and
forms, which tell an outsider how access is organized, so the public listener shows only whether the agent is healthy
(R6).

The previous snapshot is the safer of two wrong answers, but it is still wrong after a revocation: a grant the new
data removes stays until the form is supported. That allows more than legacy, so it is named as such (R7), and an
operator sees from R8 how long each tenant has served its older policies, and alerts on it.

A policy set that legacy never evaluates fails in legacy too. Rejecting the tenant for it would stop every update of
that tenant over a fault that legacy users already live with, so the set stays as a failure that affects only the
requests that reach it (R4). The forms of such a set are known from the fields of `iterate` alone, so the translator
finds them without evaluating anything.

A pattern that does not compile is a fault of one string in one policy. Legacy answers 400 to every check of the
tenant for a pattern that Java refuses, and rejecting the candidate would stop every update of the tenant for that
string, so the agent isolates the smallest node that holds the pattern and leaves the rest of the tenant as it is
(R10). The decision of an isolated node is an unknown value, so ADR-0098 R2 allows a resource or a row under its
target only where every decision the node could give allows it, and the broken pattern allows nothing.
A target that holds the pattern matches every request, because a target the agent cannot evaluate must not hide the
failure from the requests it would have reached (R10). The tenant stays ready, so the operator learns of the fault from
the log and the internal `/health` (R11). The syntax of a pattern was never documented, so the agent takes the RE2
syntax that its policy evaluation uses, and names the departures that follow from it (R9, R12). The anchors would
balance the parentheses of `a)|(b` and give it a meaning its author did not write, so the expression is compiled
without them as well (R9).

A release may evaluate part of the language, provided the part it does not evaluate is published, so that a project can
check its policies before migration (R5).

### Alternatives considered

- **A1. Translate a form the agent cannot evaluate into an undefined value or an unknown value.** Rejected by R3: under
  a DENY rule an undefined value opens access, and an unknown value denies requests that legacy allows, with no signal
  that the policy is not supported.
- **A2. Quarantine the node of the tree that holds the form, and publish the rest.** Rejected by R1 for a form the
  agent cannot evaluate: the answers of the rest depend on the quarantined node. R10 takes this design for a pattern
  that does not compile, whose node gives an unknown value instead of being left out.
- **A3. Reject the tenant for a policy set that legacy never evaluates.** Rejected by R4.
- **A4. Reject the whole pull when one tenant's candidate is rejected.** Rejected by R1.
- **A5. Serve the internal `/health` on the public listener.** Rejected by R6.
- **A6. Reject the candidate snapshot of a tenant that holds a pattern that does not compile.** Rejected by R10.
- **A7. Answer 400 to every check of a tenant that holds a pattern that does not compile, as legacy does.** Rejected by
  R10 and R12.
- **A8. Check a pattern in the syntax of `java.util.regex`.** Rejected because it needs a port of `java.util.regex` to
  the agent, while the syntax of a pattern was never documented and policy evaluation matches a pattern in the RE2
  syntax (R9).

## Consequences

Negative:

- A tenant whose policy data gains a form the agent cannot evaluate keeps its previous policies until the agent
  supports the form, including grants that the new data revokes (R7).
- At the first pull after a start, that tenant has no snapshot, so ADR-0103 R1 denies its requests, and the agent
  stays not ready under ADR-0093 R19. An installation is therefore checked for forms the agent cannot evaluate before
  the agent replaces legacy there (R5).
- A node that R10 isolates gives an unknown value to every request that reaches it until its pattern is changed,
  including a pattern that legacy evaluates, such as `(a)\1` (R12).
- A check that legacy refuses with 400 because of a pattern that Java refuses gets decisions from the agent,
  and a pattern that both syntaxes accept matches as the RE2 syntax reads it (R12).
