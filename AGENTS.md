# Agent instructions

Create an issue with a type (`gh issue create --type Bug|Feature|Task`), not a `bug` or `enhancement` label.

The Rego in `policies/` interprets simplified policies at run time and is maintenance-only until a translator from policies to Rego replaces it. Do not review it or report defects in it, and change it only to keep the existing tests passing.

For a fixed policy set, time and memory per request stay linear, up to a sort's log factor, in untrusted bytes from the
caller and PIPs. Reading a byte once per nesting level or per item of another array or object breaks that unless a limit
keeps it linear. Cost should stay polynomial in policy size. Input too big or too deep fails its request or load, not
the process. The Rego in `policies/` stays exempt.

A production installation serves at most 3 tenants and up to 10000 policies, a subject holds up to 1200 permissions, and
a bulk request carries 20 to 50 items. A request, bulk included, has a budget of 5 ms. Size designs, limits, and caches
for these numbers. In a review, leave out a cost that appears only beyond them, such as the start time of an
installation with 100 tenants. This covers cost only: a correctness defect, such as one tenant reading the policies of
another, stays in scope. A count that a caller or a PIP controls, such as the items of a bulk request, the bytes of a
PIP response, the tenants that requests name, or the realms in `iss` claims, needs a bound at any size.

Tests: Go `testing` from the standard library, with `testing/synctest` for code that waits on goroutines or timers. testify is used only in `test/integration/testify`, `test/parity/suite`, and `test/suitecheck`, and go-cmp only in `test/parity/suite`; new tests elsewhere use neither. Mutation: mutago, through `make mutation-diff`.

For a branch that changes Go code outside `test/`, run `make mutation-diff` after `git fetch` and act on the report it prints. Do not run mutago with `--update-baseline`.

It mutates the lines changed since the merge base with `MUTATION_BASE`, `origin/main` by default. When the base of the pull request is another branch, as for a stacked pull request, or when `origin` is a fork, pass the base branch of the upstream repository, such as `MUTATION_BASE=upstream/main`.
