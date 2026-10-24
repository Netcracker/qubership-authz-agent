# Compare operands as the Java values legacy reads, and a number by value

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

- [authz-agent-ADR-0082: Evaluate jsonPath with our own Go package instead of a third-party library](20261023-authz-agent-adr-0082-own-jsonpath-evaluator.md):
  the same document model, `internal/jsonvalue`, keeps the text of every number, from which this record reads the value.

## Context

Rego generated from a legacy policy compares value records built by `internal/legacyvalue`, not raw JSON. Each operator
needs a rule for what an operand is, and the parity goldens pin most of those rules:

- `==` compares two operands by `String.valueOf` ignoring case. A number from the request prints as its digits when it
  is an integer and as `Double.toString` otherwise, so `5.0 == 5` is false and `1e400 == 'Infinity'` is true
  (`r28reach-num-infinity-text`).
- A number literal of a condition prints as `BigDecimal.toString`, so `5.50` does not equal the value `5.5` and `05`
  equals `5` (`sp44-literals-num-fraction-trailing-zero-or`, `x17-number-leading-zero`). An element of a list literal
  prints as written, so `05` there does not equal `5` (`sp44-literals-ln-elem-leading-zero-or`).
- `<`, `<=`, `>`, and `>=` read a string as `new BigDecimal(String)` does (`x16-number-string-*`), and `1e400 > 5` is
  false (`r28reach-num-greater`). So `"5.0" <= 5` and `"5.0" >= 5` hold while `"5.0" == 5` does not.
- `MATCH` over a number ends the rule (`vm-match-*`).

These goldens are consistent with one assumption: legacy reads the request with Jackson in its default configuration,
an integer as `Integer`, `Long`, or `BigInteger` and any other number as `Double`, and each operator works on the
`String.valueOf` text of that object. No golden yet tells this reading apart from one that orders numbers by the
document's text: `0.300000000000000010 > 0.3` and `1e-400 > 0` are asked in PDP round 67.

A first version of the record mixed the two readings. Its key for `==` came from the `Double`, and its number for `<`
from the document's text, so `0.300000000000000010` was equal to `0.3` and greater than it at once.

Comparing a number by text makes equality depend on how a client formats its JSON. `5.50` does not equal `5.5`,
`5.0` does not equal `5`, `"5.0"` does not equal `5`, and `{"a": 1}` does not equal `{"a": 1.0}` under `Map.equals`. A
policy author who writes `5.50` means the number 5.5. A number prints in many forms (`5`, `5.0`, `5.00`), while a string
that holds a number reads as one value.

## Decision

We will read every operand once into the Java value legacy holds, and define every operator over that value. Equality
with a number is the one exception: we will compare a number with a number or a string by value, where legacy compares
their texts.

The value of an operand:

- a number from a document is its digits when it is an integer and its `Double` otherwise, so `1e-400` is `0.0` and
  `1e400` is `Infinity`;
- a number literal of a condition is a `BigDecimal`, and an element of a list literal is the number its text reads as;
- a string, a boolean, a list, and an object are themselves.

The operators:

- `==` between two numbers holds when `new BigDecimal(String.valueOf(v))` of each compares equal. This holds inside
  lists and objects too, so `{"a": 1}` equals `{"a": 1.0}`.
- `==` between a number and a string holds when `new BigDecimal` reads the string and the two values compare equal, so
  `"5.0"` equals `5`. A string that `new BigDecimal` refuses, such as `"abc"` or `"Infinity"`, equals no number.
- `==` between any other two operands, two strings included, compares their `String.valueOf` texts ignoring case, as
  legacy does: `"5.0"` does not equal `"5"`.
- `<`, `<=`, `>`, and `>=` compare `new BigDecimal(String.valueOf(v))` of each operand, and are false where either side
  is not a number `BigDecimal` reads, such as `Infinity`.
- `MATCH` tests a string, and ends the rule for any other operand.

In the record, `ck` is the `String.valueOf` text, `k` is its folded form, `n` is the number `new BigDecimal(ck)` reads,
and the key `o` of an object keys each number by its `n`. The record holds no other text of a number. A string has an
`n` wherever `new BigDecimal` reads it, so generated code compares a number with a string by `n` alone.

### Justification

- One reading per source, with operators defined over it, leaves no special case per operator. The overflow case
  needs no rule of its own, because `Infinity` is a text `BigDecimal` refuses, and the key and the number of one record
  cannot disagree.
- Two numbers compared by value match what a policy author writes. JSON serializers differ on whether 5 prints as `5`
  or `5.0`, and a decision should not change with the serializer.
- A string compared with a number by value makes `==` agree with `<` and `>`, which read the string as a number
  already. Reading a string as a number gives one value, where printing a number gives one of several texts. SQL
  databases and JavaScript's `==` also convert the string to a number in this comparison. A value a HEADER PIP
  returns is always a string, and it now compares with a number literal by value.
- Comparing two strings by value was rejected: `"007"` would equal `"7"`, and identifiers are strings. Two numeric
  strings therefore keep the legacy gap where `"5.0" <= "5"` and `"5.0" >= "5"` hold and `"5.0" == "5"` does not.
- Falling back to text for a string `new BigDecimal` refuses was rejected. It differs from the strict rule only for
  `1e400 == 'Infinity'`, which holds in legacy because `Double.toString` prints an overflow as `Infinity`.
- Reading only ASCII digits in a string was rejected. `new BigDecimal` reads digits of any script, and a second reader
  for `==` would let it disagree with `<` on such a string.
- Repeating legacy exactly was rejected: `5.50` against `5.5` and `5` against `5.0` would then depend on formatting.
- Reading only the literals as a `Double` was rejected. It makes `5.50` equal `5.5` and keeps `5` unequal to `5.0`,
  which depends on formatting just the same.
- Reading every number from the document's text exactly was rejected: it makes `1e400 > 5` true and
  `1e400 == 'Infinity'` false, and the goldens pin both the other way.

## Consequences

- These pairs are equal: `5.50` and `5.5`, `5`, `5.0`, and `5e0`, `05` and `5` in a list literal, `"5.0"` and `5`,
  `{"a": 1}` and `{"a": 1.0}`, `[1]` and `[1.0]`, and `0.0` and `-0.0`.
- These pairs differ: `{"a": 1}` and `{"a": "1"}`, because `Map.equals` compares a member's type, `"5.0"` and `"5"`,
  and `1e400` and `"Infinity"`.
- A number with more digits than a `Double` holds is the `Double` under every operator: `0.300000000000000010` equals
  `0.3` and is not greater than it, and `1e-400` is `0`.
- A number beyond the `Double` range has no `n`. It orders against nothing, and equals another such number of the same
  sign.
- The agent gives a different answer from legacy wherever a golden compares a number with a number or a string of
  another spelling. A replay of the executable specification counts 64 such answers. Two numbers account for 35, among
  them `c1-number-literal/float`, `vn2-*`, `vm-*-decimal-integral`, and the `sp44` and `sp46` trailing-zero and
  leading-zero cases. A number and a string account for 27, among them `vm-*-decimal-string`, `vt1-*`,
  `x16-decimal-text-*`, and the `sp46` HEADER and GENERAL string cases. `r28reach-num-infinity-text` and
  `r28reach-num-negative-infinity-text` account for the last 2. The parity suite has to record them as known
  differences.
- If round 67 shows that legacy orders numbers by the document's text, the reading in this record is revised for every
  operator at once, not patched for `<`.
