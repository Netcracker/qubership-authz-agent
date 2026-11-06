# Read the legacy configuration export through one strict reader

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Date

2026-10-25

#### Owner

vlsi

#### Participants and approvers

The Netcracker/qubership-authz-agent maintainers. Assumption: the approvers' GitHub accounts are added when this record
is reviewed.

#### Related ADRs

- [authz-agent-ADR-0080: Replace Envoy, the Lua filters, and the OPA container with one Go service that embeds OPA](20260907-authz-agent-adr-0080-single-go-service-with-embedded-opa.md):
  the agent is one Go process, and this record fixes where that process reads its configuration.
- [authz-agent-ADR-0082: Evaluate jsonPath with our own Go package instead of a third-party library](20261023-authz-agent-adr-0082-own-jsonpath-evaluator.md):
  the semantics of a jsonPath, which the reader keeps as written.
- [authz-agent-ADR-0083: Compare operands as the Java values legacy reads, and a number by value](20261024-authz-agent-adr-0083-operands-as-java-values.md):
  the semantics of a value, which the reader keeps as written.

## Context

The agent takes its policies from the v3 configuration export of legacy access-control:
`GET /access/v3/config/policySets` and `GET /access/v3/config/pips`. The export reflects what the legacy PAP stored, and
the PAP enforces several properties before it stores anything:

- A PIP name is unique within a tenant. The key of a PIP declaration is the name and the tenant, and the domain is not
  part of it. The PAP rejects a second declaration of a name in another domain.
- Every element of a policy set tree has a non-empty `tenantId`, and the PAP sets it from the request tenant, not from
  the request body. A child set can only reference a parent of the same tenant, and the key of a set is its
  `policySetId` and its tenant.
- A rule stores its querydsl template in the field `predicate`. No version of legacy has a field `querydslPredicate`.
  A simplified policy carries only `rsqlPredicate` and `predicates.mongodbPredicate` in the simplified API; the rule
  legacy builds from it, which the export carries, has only `rsqlPredicate` and `mongodbPredicate`. The PAP ignores
  unknown fields instead of rejecting them.
- PAP 6.1.6 trims a condition and parses it before storing it, so `True` and `tRUE` are rejected and only `true`,
  `TRUE`, `false`, and `FALSE` are stored as constant conditions.

The export does not keep the first two properties when a tenant has customized a policy set or a PIP. Legacy writes a
customized element under the tenant that reads the export, not under the tenant that owns it. A reader can therefore see
two declarations of one PIP name in one tenant, two top-level sets of one tenant with one `policySetId`, and a policy or
a rule of another tenant inside a set. Serving `GET /access/v3/config/policySets` in that state also moves the other
tenant's policies into the reader's set with the same `policySetId`, and removing the customization does not move them
back. Nothing in the export tells the tenant's own element from the moved one.

The agent read the export in more than one place, and each reader solved these questions locally. The runtime reader
maps a rule's `querydslPredicate` and leaves `predicate` unmapped. In the production configuration corpus, about 525
rules carry a querydsl template in `predicate` and none carries `querydslPredicate`, so the filter returns no querydsl
condition for any of them. A rule like "the first declaration wins" for a repeated PIP name has no legacy behavior to
match either: legacy exports PIP declarations in hash order, so "first" has no stable meaning there.

## Decision

We will read the export in one place, `internal/policyir`, and nothing else in the agent will parse it. The reader
follows five rules.

1. **The export is the contract, field by field.** The reader accepts the fields legacy stores and no others. Each
   field that a decision reads is either mapped into the tree or listed in the tree's unsupported forms:

   - a policy set: `tenantId`, `policySetId`, `name`, `type`, `domain`, `component`, `status`, `target`,
     `combiningAlgorithm`, `iterate` with `foreach` and `combiningAlgorithm`, `policies`, `policySets`, and
     `externalId`;
   - a policy: `tenantId`, `policyId`, `name`, `target`, `combiningAlgorithm`, and `rules`;
   - a rule: `tenantId`, `ruleId`, `name`, `ruleType`, `target`, `condition`, `effect`, `rsqlPredicate`,
     `sqlPredicate`, `mongodbPredicate`, `predicate`, and `customPredicate` with `predicate` and `params`;
   - a PIP declaration: `tenantId`, `name`, `pipType`, `type`, `domain`, `url`, `httpMethod`, `header`, `claim`,
     `beanName`, `jsonPath`, `resourceType`, `defaultValue`, `headers`, `requestAttributes`, `productMapping`,
     `customMapping`, `cacheable`, and `cachePeriod`.

   A field legacy stores that no decision reads is known, and the reader skips it: `description` and `deprecated`
   everywhere, `uiTarget` on a set, a policy, and a rule, `previousStatus` on a set, and `uiCondition` on a rule. The
   agent defines no input field of its own, except fields that an ADR adds as an explicit extension of the contract
   (today the PIP request and response extension); that ADR lists them, and they are never inferred. Changing either
   list takes a change to this record. The reader drops an unknown key, as the PAP does, and lists it in
   `Export.Dropped`.
2. **Legacy invariants are checked once, when the export is read.** A top-level set or a PIP declaration without a
   usable `tenantId` belongs to no tree and is reported in `Export.Orphans`. A nested element without `tenantId` takes
   the tenant of its top-level set. Where the export breaks the tenant properties above, the reader isolates the
   damaged element, and the tenant keeps the rest of its tree. A top-level set that holds an element of another tenant,
   or whose `policySetId` the tenant has more than once, becomes an isolated set: it fails every request under its
   target and holds nothing else. A PIP name the tenant declares more than once becomes an isolated declaration, which
   a condition reads as a failed PIP. Each isolation is listed in `Export.Dropped`. An element the reader cannot read,
   such as one with an unknown combining algorithm, fails the tenant's candidate snapshot (`Export.Failed`) and keeps
   the previous snapshot. The Rego generator and the evaluator rely on these invariants and carry no fallback rule
   such as "the first declaration wins".
3. **Text is normalized once, in the reader.** A whole condition equal to `true` or `false`, ignoring ASCII case and
   the characters up to U+0020 around it, which Java's `String.trim` removes, becomes a constant node. Every other
   condition is parsed into the tree. The Rego generator never reads the text of a condition. The legacy PDP compares
   the text before trimming it, so trimming is a difference from legacy and is recorded under rule 5: PAP 6.1.6
   stores the trimmed text, but an older PAP stored it as written.
4. **The reader carries no semantics.** It keeps values, paths, and absent fields as written. What they mean belongs to
   ADR-0082 for jsonPath, ADR-0083 for values, and the Rego generator for everything else, such as an absent combining
   algorithm or an effect other than `ALLOW` and `DENY`.
5. **Every difference from legacy at this boundary is documented.** Where the reader is stricter or narrower than
   legacy, the doc comment of `FromRegular`, or of the tree node the difference produces, states what the reader does
   and what legacy does, and a test pins what the reader does.

### Justification

The PAP's storage keeps the invariants of rule 2, and the export breaks them only where a tenant has a customization.
Isolating the damaged element confines that defect to the requests the element can affect. Without the checks, each
consumer of the tree needs its own answer for a duplicate name or a foreign tenant, and those answers drift apart.

We considered four alternatives:

- **A lenient reader with fallback rules in each consumer.** This is how the readers grew. It produced a field that
  legacy never writes and lost the field that production configurations use.
- **Reproducing legacy on a damaged export.** For a repeated PIP name, the legacy PDP library uses the first
  declaration in hash order, which is an accident of the implementation and cannot be reproduced or tested. For a set
  that holds another tenant's policy, legacy evaluates that policy in the tenant that read the export.
- **Failing the tenant on a damaged export.** A customization in one tenant would then stop every request of another
  tenant.
- **Rejecting unknown fields.** Legacy ignores them, and an export from a newer legacy version could add a field that
  changes nothing for the agent. Dropping the field and listing it keeps the snapshot loadable and the drop visible.

## Consequences

- The runtime reader maps a rule's `predicate` to the querydsl dialect, and the filter returns the querydsl condition of
  the production rules that carry one. The reader of simplified policies, the policy admin stub, and the parity
  fixtures stop using `querydslPredicate`.
- `internal/policyir` drops the field `querydslPredicate` and the unsupported finding for it. It isolates a repeated PIP
  name and a damaged top-level set as rule 2 says, instead of dropping the second declaration or failing the tenant.
  It keeps reporting a top-level set or a PIP
  declaration without a usable tenant in `Export.Orphans`; legacy never exports one, so only a hand-made input reaches
  that path. It lists every unknown key it drops in `Export.Dropped`, maps `externalId`, `cacheable`, and
  `cachePeriod` as written, and trims a constant condition as rule 3 says.
- A configuration that legacy would not store fails to load in the agent. The failure names the tenant and the element,
  and the tenant keeps its previous snapshot. A damaged export, which legacy does produce, loads with the damaged
  elements isolated.
- New questions about legacy input go to rule 1 or rule 2 first. A question gets a local rule only if legacy really
  stores the input.
- The runtime reader `internal/acconfig` is replaced by `internal/policyir` once the Rego generator reads the tree.
  Until then, the runtime reader follows rule 1 for predicate fields.
