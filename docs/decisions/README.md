# Architecture decision records

The records in this directory state what the agent must do and why. Records from ADR-0091 on use numbered rules, so that
a person or an agent can check a change against each rule. Earlier records are prose and stay as they were accepted.

## Read a record with numbered rules

- **Terms** define the words the rules depend on. A term keeps one meaning in every record. ADR-0091 defines the words
  for tokens, providers, and keys that the other records share.
- **R1, R2** are the rules. Outside its record, cite a rule with its record, as `ADR-0091 R7`, because each record
  numbers its own rules. A number is never reused, so a rule added later can sit out of order under its topic.
- **A1, A2** are rejected alternatives, each with the rule that rejects it. Code that implements one violates the
  record.
- **O1, O2** are open points: questions a record does not settle yet. A record with an open point cannot be accepted.
- **Negative** consequences are costs the decision accepts, so they are not defects.

A rule names the layer where its check runs, or two layers, in parentheses:

| Layer | Holds | Code |
| --- | --- | --- |
| `keys` | The trusted providers file, reading and holding signing keys | `internal/token/keys` |
| `verify` | The check of one token and its result | `internal/token/verify` |
| `namespaces` | The topology file and the allowed namespaces | `internal/token/namespaces` |
| `handler` | Each request before policy evaluation, and the responses of the check routes | `components/authz-agent/internal/server`, `api/openapi.yaml` |
| `startup` | Settings read at start, readiness, and liveness | `components/authz-agent/internal/` packages, `main.go`, `config.go`, and the settings table under `## Configuration` in `components/authz-agent/README.md` |
| `client` | Outgoing calls, the policy pull, and the agent's token | `components/authz-agent/internal/{m2m,pull}`, `internal/pips` |
| `policy` | The policies and the input they read | `policies/` |
| `chart` | The Helm chart and its values schema | `helm-templates/authz-agent` |
| `image` | The image of the agent, its base, and its entrypoint | `build/authz-agent` |
| `docker` | The Compose example and the page for running the agent under Docker | `deploy/docker` |
| `ci` | The workflows that build, release, and test the agent | `.github/workflows`, `.qubership/docker.cfg` |

A layer says where to look first. Another layer may meet a rule, provided the behavior the rule states holds.

A record with status `Proposed` is the intended design, and a change is checked against each one whose rules it touches.
An accepted record binds the code on `main`, and a statement a `Proposed` record replaces stays in force for code that
no change has moved to that record.

Anything no rule states is the implementer's choice.

## Name the rules of a change

A pull request that changes code under a record says which rules it covers, in its description:

```text
Implements: ADR-0092 R6, R8; ADR-0091 R54.
Defers: ADR-0091 R38 to #208; ADR-0095 R2 to the wiring change.
```

`Defers` names the pull request or the change that will bring the rule. A deferred rule takes the alternatives it
rejects with it, so a change that defers ADR-0091 R21 does not violate ADR-0091 A3.

## Check a change

1. Read the `Implements` and `Defers` lines. They are claims, so they guide the check and settle only the deferred
   rules.
2. Walk every rule of the layers the change touches, named or not. A missing line shows in no diff, so this walk finds
   the rule a change forgot.
3. Give each rule one verdict, and group the rows by root cause in the report, because one defect can break several
   rules.

| Verdict | Meaning |
| --- | --- |
| Conforms | The code meets the rule. |
| Violates | The change touches the rule and does not meet it. Code that implements a rejected alternative counts too. |
| Deferred | The change names the rule under `Defers`. |
| Not touched | The change does not touch the rule. |
| Cannot tell | The rule does not decide the case, or an open point covers it. |

A change touches a rule when it adds or changes code that runs in the case the rule describes, or names the rule under
`Implements`. A defect in unchanged code that the change only moves or calls is not touched, and the report names it
apart.

Where two verdicts could apply, `Deferred` wins over the others, and `Cannot tell` wins over `Violates`.
