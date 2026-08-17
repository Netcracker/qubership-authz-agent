# Regular Policy Fixtures

This directory holds the small parity-suite slice that must use the legacy
full-policy import channel (`PUT /access/v1/policySets/externalId/{externalId}`)
instead of the simplified-policy channel.

These files are imported by
[`test/parity/suite/seed.go`](../../../../seed.go) during
`ParitySuite.SetupSuite` rather than by a compose-side shell script.

Why it exists:

- Simplified policies accept only `condition` and `rsqlPredicate`.
- Parity rows that need `predicate`, `mongodbPredicate`, or `sqlPredicate`
  must therefore go through the regular-policy PAP surface.

Current coverage:

- `parity-suite-full.json`
  Covers the remaining Step 3 cases that need non-simplified predicate fields:
  `PSUITE-6-use-filter-incoming` plus SUB rows 71/72/73.
