# Divergences in PIP answers and filter templates

## Status

Accepted. The suite applies the decisions below as entries of `acceptedDivergences` in
[`test/parity/suite/accepted_divergences.go`](../../test/parity/suite/accepted_divergences.go). Each entry has the
agent's answer under `test/parity/suite/testdata/accepted-divergences/<golden key>.json`; a case passes when the agent
answers as the golden or exactly as that file. The suite runs regular policy set cases against access-control only,
so the entry for the filter template takes effect once those cases run against the agent.

## A PIP answer that is not JSON

A PIP answer with status 200 or 204 and a body of zero bytes is an empty answer: the agent reads the PIP as `null`.

A PIP answer with status 200 whose body is not empty and is not one JSON value, such as the text `v` or an HTML page of
a proxy, fails the PIP. The agent treats it as any other failed call: a comparison that reads the PIP has an unknown
value, a `DENY` rule over it applies, and the denial names the PIP. Legacy reads such an answer as `null`.

| Condition, with the PIP answering the text `v` | `resource.a` | Legacy | Agent |
| --- | --- | --- | --- |
| `subject.x IS NULL OR resource.a == 'y'` | `n` | allows | denies |
| `subject.x IS NULL OR resource.a == 'y'` | `y` | allows | allows |
| `subject.x == 'v' OR resource.a == 'y'` | `n` | denies | denies |

A body that is not JSON is a fault of the PIP or of something between the agent and the PIP, not an answer that the
attribute has no value. Reading it as `null` lets a `DENY` rule over the PIP stay silent and lets `IS NULL` grant
access because a service failed.

Case: `isolated/q15-a-text-body-is-null/true-value` of `check-resource-v1-outcome`, from
`test/parity/suite/testdata/cases/round15/questions.json`. The other `q15-a-text-body-*` cases answer the same in both.

## Placeholders in a filter template

The agent fills the placeholders of a predicate template, such as `${subject.parityIdiomGen}` in the `rsqlPredicate`
`a=in=(${subject.parityIdiomGen})`, in one pass. A value goes into the filter text as its source returned it: when a PIP
returns `["${subject.id}"]`, the filter is `a=in=("${subject.id}")`. Legacy substitutes the placeholders in the
substituted value again and returns the subject's id in its place.

A second pass lets the value a PIP returns choose which attribute of the subject reaches the filter.
Filling once keeps every value as its source returned it.

The templates of `id44-template-1` (`a==$${subject.parityIdiomGen}`) and `id44-template-2`
(`a==${subject.parityIdiomNone:-d}`) answer the same in both.

Case: `regular/id44-template-0/filter` of `check-filter-v1-outcome`, from
`test/parity/suite/testdata/cases/round44/idioms-conditions.json`. Until regular cases run against the agent, the
agent's unit test `TestAPlaceholderValueIsWrittenAsTheSourceReturnedIt` checks this behavior.
