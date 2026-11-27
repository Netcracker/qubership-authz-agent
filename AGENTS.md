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

Tests: Go `testing` from the standard library, with `testing/synctest` for code that waits on goroutines or timers. testify is used only in `test/integration/testify` and `test/parity/suite`, and go-cmp only in `test/parity/suite`; new tests elsewhere use neither. Mutation: mutago, through `make mutation-diff`.

For a branch that changes Go code outside `test/`, run `make mutation-diff` after `git fetch` and act on the report it prints. Do not run mutago with `--update-baseline`.

It mutates the lines changed since the merge base with `MUTATION_BASE`, `origin/main` by default. When the base of the pull request is another branch, as for a stacked pull request, or when `origin` is a fork, pass the base branch of the upstream repository, such as `MUTATION_BASE=upstream/main`.

## Design choices

The preferences below apply by default to a design, to code, to an ADR you write or update, and to a review. A
requirement, an ADR, another rule of this file, or compatibility with legacy access-control as
ADR-0097 in [#226](https://github.com/Netcracker/qubership-authz-agent/pull/226) defines it outranks them, and a shape
that one of these prescribes is not a defect under this section. Where a rule you write or change in an ADR departs from
them, the record says why. A choice that no rule of [the decision records](docs/decisions/README.md) states is left to
the implementer, and these preferences guide it.

Prefer a convention of Kubernetes, Helm, or OIDC, a widely used library, or a built-in mechanism over code written for
authz-agent.

Name a setting so that a security engineer or an SRE understands it without the source code: the term that the standard
or the widely used identity providers use (`issuer`, `audience`, JWKS, the JWT claim name), or the setting's effect
where no such term exists. A setting that applies to every token issuer takes a name that fits Kubernetes service
account tokens, Keycloak, and GCP, AWS, and Azure identity tokens alike: `issuer`, not `keycloakRealm`. A setting that
exists for one provider only, such as the realms of a Keycloak, may carry that provider's name.

Model a configuration or an API so that an invalid value or combination cannot be written. Prefer one enum with a closed
set of values over several boolean flags that must agree, and type and parse a setting that holds an integer as an
integer, not as a string. Where the format cannot rule a value or combination out, the fail-fast rule below decides
where it is rejected.

Fail fast: report a defect in the code, the configuration, or a policy at the earliest point that can detect it. The
points, from earliest, are compilation, the chart's values schema, the install or the start of the agent, the load of
the policies, and only last the first request that needs the setting. A check that the chart runs does not replace the
check at the start, because the agent also runs without the chart. Name the setting or the policy in the error. A defect
in this sense is one that the text of the code, the configuration, or a policy shows by itself, such as a malformed URL.
A dependency that does not answer, or answers without the data, such as a JWKS endpoint, an absent realm, or the policy
source, is not one: the agent keeps running, and its liveness does not depend on that dependency
([ADR-0091 R18](docs/decisions/20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md)).

Prefer one general rule over a list of special cases, so that an operator can predict the behavior from the
configuration. When fixing a defect, name its class in words that also describe a second input, and make the fix and its
test cover that input too. A defect that no other input can reach, such as a typo in a message, is fixed where it was
reported.
