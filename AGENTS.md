# Agent instructions

Create an issue with a type (`gh issue create --type Bug|Feature|Task`), not a `bug` or `enhancement` label.

The Rego in `policies/` interprets simplified policies at run time and is maintenance-only until a translator from policies to Rego replaces it. Do not review it or report defects in it, and change it only to keep the existing tests passing.

For a fixed policy set, time and memory per request stay linear, up to a sort's log factor, in untrusted bytes from the
caller and PIPs. Reading a byte once per nesting level or per item of another array or object breaks that unless a limit
keeps it linear. Cost should stay polynomial in policy size. Input too big or too deep fails its request or load, not
the process. The Rego in `policies/` stays exempt.

Tests: Go `testing` from the standard library, with `testing/synctest` for code that waits on goroutines or timers. testify is used only in `test/integration/testify` and `test/parity/suite`, and go-cmp only in `test/parity/suite`; new tests elsewhere use neither. Mutation: mutago, through `make mutation-diff`.

For a branch that changes Go code outside `test/`:

- Run `make mutation-diff` after `git fetch`. It mutates the lines changed since the merge base with `MUTATION_BASE`, `origin/main` by default. When the base of the pull request is another branch, as for a stacked pull request, or when `origin` is a fork, pass the base branch of the upstream repository, such as `MUTATION_BASE=upstream/main`.
- For each survivor it lists, also in `mutago-agentic.json`, add a test through the unit's interface, not one that asserts on the implementation of the mutated line, or say in the pull request description why the mutant is equivalent. Quote the summary line there, and list as unresolved each errored mutant and each survivor you cannot tell is equivalent.
- Do not run mutago with `--update-baseline`.
- When the run fails without listing a survivor, ends with the warning that no test was shown able to fail on the changed files, or the branch changes a file behind a build tag, follow "Mutation testing of a change" in README.md.
