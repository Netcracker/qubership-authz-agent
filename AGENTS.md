# Agent instructions

Create an issue with a type (`gh issue create --type Bug|Feature|Task`), not a `bug` or `enhancement` label.

The Rego in `policies/` interprets simplified policies at run time and is maintenance-only until a translator from policies to Rego replaces it. Do not review it or report defects in it, and change it only to keep the existing tests passing.

Tests: Go `testing` from the standard library, with `testing/synctest` for code that waits on goroutines or timers. testify is used only in `test/integration/testify` and `test/parity/suite`, and go-cmp only in `test/parity/suite`; new tests elsewhere use neither. Mutation: mutago, through `make mutation-diff`.

Before you open a pull request that changes Go code outside `test/`, run `git fetch origin` and `make mutation-diff`. It lists every mutant on a line the branch changed that no test kills, and fails when there is one. It reads the working tree, so uncommitted changes to tracked files count; commit a new file, or add it with `git add -N`, for it to count.

The base of the diff is the merge base of `HEAD` and `origin/main`. When the pull request targets another branch, pass that branch as the base: `make mutation-diff MUTATION_BASE=origin/<target-branch>`. `MUTATION_BASE` takes any branch, tag, or commit, and the run uses its merge base with `HEAD`, so passing the target branch is enough even after it has moved on.

For each survivor:

- If it changes behavior the code promises, add or strengthen a test through the unit's interface, not a test that pins the mutated line.
- If it changes nothing a caller can observe, it is equivalent: say why in the pull request description.
- If you cannot tell, list it in the pull request description as unresolved.

Report the counts the run prints and the outcome of each survivor in the pull request description. Do not add `mutator-disable` comments to production code.
