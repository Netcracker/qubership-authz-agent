# Suite Fixture Pack

Expanded simplified-policy / PIP fixtures for the parity test suite
(fixture-pack slice of
[20260414-access-control-parity-test-suite-task.md](../../../../../../../docs/handovers/done/20260414-access-control-parity-test-suite-task.md)).

These fixtures are **additive** to the smoke baseline under
[`../../smoke/`](../../smoke/). `ParitySuite.SetupSuite` seeds the
smoke simplified fixtures first and this suite pack second, preserving the
legacy ordering that the old compose seeding script used. The suite pack uses
**distinct** `resourceType` names under the `PARITY_SUITE_*` prefix so there
is no locator collision per **D-L** of the handover. No fixture in this
directory overwrites or shadows a Step 2 smoke row.

## Grammar constraints

The legacy simplified-policy input DTO (from the internal access-control source
repository) has **only** these predicate-carrying fields:

- `condition` — an ABAC-expression AST string parsed by the ABAC expression
  grammar (`AbacExpression.g4` in the internal policy-decision-point module).
- `rsqlPredicate` — an RSQL template string, optionally containing
  `${subject.<alias>}` placeholders that the engine substitutes at render
  time.

There is **no** `sqlPredicate` / `mongodbPredicate` input. The
`sqlFilterCondition` / `mongodbFilterCondition` fields that the parity
response carries are populated by a different code path (full-policy /
XACML) that simplified-policies do not reach. Step 3 therefore splits the
fixture pack across two channels:

- this `suite/` directory for simplified-policy and simplified-PIP payloads;
- `../regular/parity-suite-full.json` for the small regular-policy subset
  that needs `predicate` / `mongodbPredicate` / `sqlPredicate`.

## CLANG spellings that parse cleanly

Verified against legacy test data from the internal access-control source
repository (`access-control-policy-decision-point/src/test/resources`):

- String equality: `resource.field == 'value'` (single quotes only).
- Numeric equality / relational: `resource.amount == 5`, `resource.amount >= 100`, `resource.amount < 1000`.
- Inequality: `resource.field != 'value'`.
- Set containment: `resource.tags CONTAINS 'red'`, `resource.tags CONTAINS ANY 'red', 'blue'` (no parens around list).
- Negation: `resource.tags NOT CONTAINS 'red'`, `resource.tags NOT CONTAINS ANY 'red', 'blue'`.
- Subset: `resource.tags IS SUBSET subject.parityTags` (legacy's "contains all" form).
- Null: `resource.ownerId IS NULL`, `resource.ownerId IS NOT NULL`.
- Emptiness: `subject.parityAllowed IS EMPTY`, `subject.parityAllowed IS NOT EMPTY`.
- Combinators: `A AND B`, `A OR B`, `NOT A` — all uppercase, space-separated.

Pattern the fixtures reuse for subject-attribute-to-resource comparison:
`resource.id IN subject.parityAllowed` and `resource.id == subject.parityCurrent`.

## File layout

| File | Kind | Purpose |
| ------ | ------ | --------- |
| `ols-multi-role.json` | simplified policies | Two pure-OLS rows on the same `(resourceType, operation)` locator but different roles — one for `ROLE_PARITY_READER`, one for `ROLE_PARITY_REVIEWER`. Drives AGG rows 61/62. |
| `rls-token-pip.json` | simplified policies | RLS row whose `condition` reads `subject.parityDepartment` (a TOKEN PIP bound to the `department` JWT claim). |
| `rls-header-pip.json` | simplified policies | RLS row whose `condition` reads `subject.parityHeaderAttr` (a HEADER PIP bound to the `x-parity-pip-attribute` custom header). |
| `rls-general-dict.json` | simplified policies | RLS row whose `condition` reads direct leaf aliases extracted from a dict-returning GENERAL PIP (`subject.parityMetaDepartment`, `subject.parityMetaMaxAmount`). |
| `rls-general-scalar.json` | simplified policies | RLS row whose `rsqlPredicate` uses `${subject.parityStatusScalar}` template substitution from a scalar-string GENERAL PIP. Drives SUB row 68. |
| `rls-agg-two-predicates.json` | simplified policies | Two RLS rows with distinct `rsqlPredicate` templates on the same `(resourceType, operation, role)` locator. Drives AGG row 63 (predicate-union). |
| `rls-agg-ols-plus-rls.json` | simplified policies | One OLS row + one RLS row on the same locator. Drives AGG row 64 (OLS + RLS combining). |
| `rls-allow.json` | simplified policies | Pure-OLS row on `PARITY_SUITE_FILTER` without predicates. Drives row 21 (calcResult=ALLOW baseline on check/filter). |
| `clang-string-equality.json` | simplified policies | CLANG row 49: `resource.category == 'PARITY_GOLD'`. |
| `clang-number-relational.json` | simplified policies | CLANG row 50: `resource.amount >= 100 AND resource.amount < 1000`. |
| `clang-boolean-or.json` | simplified policies | CLANG row 52: `resource.priority == 'HIGH' OR resource.escalated == true`. |
| `clang-in-literal.json` | simplified policies | CLANG row 54: `resource.status IN 'OPEN', 'PENDING', 'REVIEW'`. |
| `clang-contains-any.json` | simplified policies | CLANG row 56: `resource.tags CONTAINS ANY 'red', 'blue'`. |
| `clang-null.json` | simplified policies | CLANG row 58: `resource.ownerId IS NOT NULL`. |
| `suite-pips.json` | simplified PIPs | TOKEN / HEADER / GENERAL PIP declarations the RLS rows above bind against. Includes leaf aliases for dict-return GENERAL PIPs and scalar/list aliases for the SUB / CLANG / filter slices. |
| `../regular/parity-suite-full.json` | regular policy set | Full-policy fixtures for PSUITE row 22 and SUB rows 71/72/73, imported via the legacy PAP `policySets/externalId` channel. |

## Seed channel

[`test/parity/suite/seed.go`](../../../../seed.go) is the active seed helper.
`SetupSuite` feeds it an embedded `fs.FS` rooted at
`testdata/fixtures/`, and the helper:

1. bulk-loads the smoke simplified PIPs,
2. bulk-loads the suite simplified PIPs,
3. bulk-loads the smoke simplified policies,
4. bulk-loads the suite simplified policies,
5. imports every file under `../regular/` via
   `PUT /access/v1/policySets/externalId/{externalId}`.

This preserves the old compose seed ordering while making the `go test`
binary self-contained.

Dict-return GENERAL PIP note: legacy simplified-policy validation resolves
only direct PIP aliases in condition strings, as implemented by
`ConditionTransformer.ConditionVisitor.getPolicyInformationPoint(...)`.
That means a condition like `subject.parityMeta.department` is rejected at
PUT time with `subject.parityMeta.department PIP doesn't exist`. The suite
therefore models dict-return coverage through multiple leaf aliases
(`subject.parityMetaDepartment`, `subject.parityMetaMaxAmount`,
`subject.parityMetaIds`) extracted from the same mocked JSON object via
`jsonPath`, which is explicitly supported by the legacy PIP docs.

Prohibited-header note: the legacy PAP rejects HEADER PIP declarations on
`tenant` / `authorization`, so row 48 does **not** model the behavior through
a dedicated PIP. Instead the Go suite verifies `HeadersFilter` parity by
comparing an OLS-baseline request with caller-supplied prohibited headers
against the same request with those headers absent.
