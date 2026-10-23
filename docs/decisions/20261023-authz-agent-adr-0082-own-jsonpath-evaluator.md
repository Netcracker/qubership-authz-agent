# Evaluate jsonPath with our own Go package instead of a third-party library

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Date

#### Owner

vlsi

#### Participants and approvers

The Netcracker/qubership-authz-agent maintainers. Assumption: the approvers' GitHub accounts are added when this record
is reviewed.

#### Related ADRs

- [authz-agent-ADR-0080: Replace Envoy, the Lua filters, and the OPA container with one Go service that embeds OPA](20260907-authz-agent-adr-0080-single-go-service-with-embedded-opa.md):
  the agent is one Go process. A jsonPath evaluator has to run inside it, in Go.

## Context

Policies written for legacy access-control use jsonPath in three places:

- the `jsonPath` of a GENERAL PIP declaration, which selects a value from the PIP response;
- the `claim` of a TOKEN PIP declaration, which selects a value from the token, as in `$.realm_access.roles`;
- a resource attribute in a condition or a target, such as `resource.items[?(@.role == 'owner')].userId[*]`.

Legacy access-control does not evaluate these paths itself. It drops the `resource.` prefix and passes the rest to
Jayway JsonPath 2.9.0 or 2.10.0 in its default configuration (the json-smart provider, no options). Around the library
it adds its own rules: a path that Jayway does not find makes the attribute absent, and a list becomes a set. The agent
has to answer as legacy does, so the reference is Jayway together with these rules, not a jsonPath standard.

The first release supports the subset of jsonPath that the parity goldens record (PR #42): `.key`, `['key']`, `..key`,
`[n]`, `[n,m]`, `[a:b]`, `[*]`, the filter `[?(...)]` with `==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `nin`, `subsetof`,
`anyof`, `noneof`, `size`, `empty`, `=~`, `&&`, `||`, and the trailing functions `.length()`, `.min()`, `.max()`,
`.avg()`, `.sum()`, `.first()`, `.last()`, `.keys()`. A path outside the subset is reported as unsupported. Full Jayway
compatibility is the goal of a later step, one path form at a time.

The parity goldens show behavior that belongs to Jayway or to the legacy rules around it, and that RFC 9535 and most
libraries do not share:

- A filter compares a number with a quoted literal by value (`'5.0' == 5` holds), compares numbers as `BigDecimal`,
  and selects an element without the key for `!=` and `nin`.
- A filter applied to a single object tests the object itself.
- `[*]` applied to an object returns the member values.
- The answer distinguishes a missing key, a key under `null` or `{}`, and an index past the end of a list, because
  legacy reaches each of them through a different Jayway exception.

Real project configurations also use forms that several libraries do not parse: `$.[*].id`, a claim with a hyphen that
Jayway reads as `$.user-id`, an index written after a dot (`$.roles.1`), `null` as a filter literal
(`@.groups == null`), and a regular expression with a flag (`@.name =~ /admin.*/i`).

We compared seven Go libraries with Jayway 2.9.0 on the same inputs: `github.com/ohler55/ojg/jp`,
`github.com/theory/jsonpath`, `github.com/AsaiYusuke/jsonpath/v2`, `github.com/spyzhov/ajson`,
`github.com/bhmj/jsonslice`, `github.com/PaesslerAG/jsonpath`, and `github.com/oliveagle/jsonpath`. The inputs were the
258 queries of [json-path-comparison](https://github.com/cburgmer/json-path-comparison) and 88 cases of legacy behavior
from the agent's tests. `k8s.io/client-go/util/jsonpath` and `github.com/vmware-labs/yaml-jsonpath` were left out: the
first implements the kubectl dialect and brings in all of client-go, the second works on YAML nodes.

| Library | Answers equal to Jayway, of 258 | Legacy cases passed, of 88 |
| --- | --- | --- |
| `theory/jsonpath` (RFC 9535) | 168 | 41 |
| `ohler55/ojg/jp` | 164 | 47 |
| `AsaiYusuke/jsonpath/v2` | 162 | 31 |
| `bhmj/jsonslice` | 151 | 46 |
| `spyzhov/ajson` | 150 | 41 |
| `PaesslerAG/jsonpath` | 150 | 18 |
| `oliveagle/jsonpath` | 77 | 17 |

None of the libraries claims Jayway compatibility. None parses `nin`, `subsetof`, `anyof`, `noneof`, or `size` in a
filter. None accepts `.min()`, `.sum()`, or `.keys()` at the end of a path. Only `bhmj/jsonslice` returns a value for
`.length()`, and for a string it counts bytes.

## Decision

We will evaluate jsonPath with our own Go package in the agent, `internal/jsonpath`, and take no third-party jsonPath
library as a runtime dependency.

- The package parses the path and evaluates it over the agent's value model, which keeps every number as its exact
  decimal text and keeps the order of object members.
- The release supports the subset listed in the Context. A path outside it fails to compile with an unsupported-path
  error, so the policy that holds it is refused before it runs.
- Each further Jayway form is added as its own change, with cases that run against Jayway.
- A differential test runs the package and Jayway JsonPath on the JVM over the same inputs. The test needs a JVM and the
  Jayway jars only on the machine that runs it. It is not part of the default `go test ./...`.

### Justification

The behavior that has to match sits in the core of a jsonPath library: the syntax of the filter and the way the filter
compares values. Neither can be changed from outside the libraries we compared. The filter operators of
`ohler55/ojg/jp` are unexported package variables. `theory/jsonpath` registers only function extensions in RFC 9535
syntax, and an infix operator such as `nin` is not one of them. A wrapper around a library would need its own path
tokenizer for the forms the library rejects, a step-by-step walk to tell a missing key from a key under `null` and from
an index past the end, its own trailing functions, and its own filter language. What remains for the library is `.key`,
`[n]`, `[*]`, and `..key`, which are the simplest part of the evaluator.

The best library, `ohler55/ojg/jp`, fails 41 of the 88 legacy cases. Nineteen of them are trailing functions and twenty
are in the filter: the operators it does not parse, the comparison of a number with a string, the flag `/i`, and a
filter applied to a single object. The package written for the first release passes all 88.

Alternatives considered:

- **Use `github.com/ohler55/ojg/jp` and wrap it.** It is the most active candidate, it has no dependencies, and it
  exposes the parsed path. Rejected for the reasons above: the wrapper would contain the whole filter language, and the
  library would still reject `$.[*]`, a key with a hyphen, and `/i`.
- **Use `github.com/theory/jsonpath`.** It implements RFC 9535 strictly. Rejected: legacy follows Jayway, and the two
  dialects differ in the filter syntax and in what a filter over an object selects.
- **Fork a library and change its filter.** Rejected: the fork would carry the same amount of our code, inside a
  structure designed for a different dialect, and every upstream release would need a merge.
- **Call Jayway itself, in a JVM next to the agent.** Rejected: the agent is one Go process (ADR-0080), it has to run
  without Kubernetes, and a decision has a budget of 5 ms, which a call to another process per jsonPath would consume.

## Consequences

Positive:

- The agent answers the legacy cases exactly, including numbers outside the `float64` range and the distinction between
  a missing key, a `null` parent, and an index past the end.
- The agent has no jsonPath dependency to upgrade, audit, or patch.
- The differential test makes compatibility measurable: each new form is accepted when its answers match Jayway's.

Negative:

- We maintain a parser and an evaluator, about 900 lines of Go plus tests, and we own their bugs.
- Regular expressions run on Go's RE2 engine, not on `java.util.regex`. A pattern that uses lookaround or a
  backreference is reported as unsupported, not evaluated differently.
- The differential test needs a JVM and the Jayway jars. The json-path-comparison queries are under GPL-3.0, so the
  test reads them from a local checkout and is skipped without one. They are not copied into this repository.

Neutral:

- In four places, the behavior the agent's tests describe differs from plain Jayway, and no golden confirms either
  side yet: `.length()` of a string (Jayway returns `null`), `\d`, `\w`, and `\s` in a regular expression (Java matches
  ASCII only by default), an index too large for an `int` (Jayway rejects the path), and a document number outside the
  `double` range in a filter. Goldens for these decide what the package does; the choice of evaluator does not.
