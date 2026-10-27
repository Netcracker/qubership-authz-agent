# Agent instructions

Create an issue with a type (`gh issue create --type Bug|Feature|Task`), not a `bug` or `enhancement` label.

The Rego in `policies/` interprets simplified policies at run time and is maintenance-only until a translator from policies to Rego replaces it. Do not review it or report defects in it, and change it only to keep the existing tests passing.

Tests: Go `testing` as engine and assertions in the root module, `test/integration/pipstub`, and `test/integration/tenantmanager` (no testify, no go-cmp); `test/integration/testify` is on testify, and `test/parity/suite` is on testify with go-cmp for its comparisons. Mutation: go-mutesting, through `make mutation-diff`.

Before you open a pull request that changes Go code outside `test/`, commit the change and run `make mutation-diff`. It lists every mutant on a line the branch changed that no test kills, and fails when there is one. For each survivor:

- If it changes behavior the code promises, add or strengthen a test through the unit's interface, not a test that pins the mutated line.
- If it changes nothing a caller can observe, it is equivalent: say why in the pull request description.
- If you cannot tell, list it in the pull request description as unresolved.

Report the counts the run prints and the outcome of each survivor in the pull request description. Do not add `mutator-disable` comments to production code.
