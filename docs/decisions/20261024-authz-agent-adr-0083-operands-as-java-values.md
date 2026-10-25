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

- `==` compares two scalars by `String.valueOf` ignoring case. A number from the request prints as its digits when it
  is an integer and as `Double.toString` otherwise, so `5.0 == 5` is false and `1e400 == 'Infinity'` is true
  (`r28reach-num-infinity-text`).
- A number literal of a condition prints as `BigDecimal.toString`, so `5.50` does not equal the value `5.5` and `05`
  equals `5` (`sp44-literals-num-fraction-trailing-zero-or`, `x17-number-leading-zero`). An element of a list literal
  prints as written, so `05` there does not equal `5` (`sp44-literals-ln-elem-leading-zero-or`).
- `<`, `<=`, `>`, and `>=` read a string as `new BigDecimal(String)` does (`x16-number-string-*`), and `1e400 > 5` is
  false (`r28reach-num-greater`). So `"5.0" <= 5` and `"5.0" >= 5` hold while `"5.0" == 5` does not.
- `==` between a list or an object and a string compares the string with the Java text of the structure, `[v, w]` or
  `{k=v}`, ignoring case (`x17-eq-structure-as-text-*`, `q19-list-equals-its-printed-text`). Its JSON text does not
  match (`x17-eq-structure-as-json-*`).
- `==` between two lists or two objects holds for an equal pair (`p15-eq-resource-resource`, `v16-eq-049`). Legacy
  reads a resource attribute with Jayway JsonPath and copies a list it selects into a `java.util.HashSet`, so two such
  lists compare as `Set.equals` and two objects as `Map.equals`, each element with its type and case. A list inside an
  element or a member stays a Jayway list, which compares in order. No golden yet compares two structures that differ
  only in order, repeats, type, or case, and none shows how legacy reads a list from the subject or from a PIP.
- `MATCH` over a number ends the rule (`vm-match-*`).

These goldens are consistent with one assumption: legacy reads the request with Jackson in its default configuration,
an integer as `Integer`, `Long`, or `BigInteger` and any other number as `Double`, and each operator works on that
object: on its `String.valueOf` text, except `==` between two lists or two objects. No golden yet tells this reading
apart from one that orders numbers by the document's text: `0.300000000000000010 > 0.3` and `1e-400 > 0` are asked in
PDP round 67.

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
- a list read from a document is the set of its elements, and a list inside an element or a member stays a list. The
  agent reads a list of the subject or of a PIP response the same way as a list of the resource;
- a string, a boolean, and an object are themselves.

The operators:

- `==` between two numbers holds when `new BigDecimal(String.valueOf(v))` of each compares equal.
- `==` between a number and a string holds when `new BigDecimal` reads the string and the two values compare equal, so
  `"5.0"` equals `5`. A string that `new BigDecimal` refuses, such as `"abc"` or `"Infinity"`, equals no number.
- `==` between two lists or two objects compares them as `Set.equals` and `Map.equals` do: the elements of a list in
  any order and without repeats, the members of an object in any order, each element with its type, and each string
  and key with its case. So `[1, 2]` equals `[2, 1]` and `[1, 1]` equals `[1]`, while `{"a": 1}` differs from
  `{"a": "1"}`, and `["X"]` from `["x"]`. A list inside an element or a member compares in order, as `List.equals`
  does. A number inside compares with a number by value, where Java's `Integer` does not equal a `Double`: this is the
  number exception, so `{"a": 1}` equals `{"a": 1.0}` and `[1]` equals `[1.0]`. A number inside never equals a
  string.
- `==` between a list or an object and a string compares the Java text of the structure with the string, ignoring
  case, as legacy does.
- `==` between any other two operands, two strings included, compares their `String.valueOf` texts ignoring case, as
  legacy does: `"5.0"` does not equal `"5"`.
- `<`, `<=`, `>`, and `>=` compare `new BigDecimal(String.valueOf(v))` of each operand, and are false where either side
  is not a number `BigDecimal` reads, such as `Infinity`.
- `MATCH` tests a string, and ends the rule for any other operand.

In the record, `ck` is the `String.valueOf` text, `k` is its folded form, the number is the one `new BigDecimal(ck)`
reads, and the key `o` of a list or an object keys each number inside by its value. The record holds no other text of a
number. A string has a number wherever `new BigDecimal` reads it, so generated code compares a number with a string by
that number alone. The record writes the number as `n` where Rego's own operators compare it exactly, and otherwise
sets `nl` for `nc.decimal.compare`.

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
  `{"a": 1}` and `{"a": 1.0}`, `[1]` and `[1.0]`, `[1, 2]` and `[2, 1]`, `[1, 1]` and `[1]`, and `0.0` and `-0.0`.
- These pairs differ: `{"a": 1}` and `{"a": "1"}`, and `["X"]` and `["x"]`, because a list or an object compares each
  element with its type and case; `{"a": [1, 2]}` and `{"a": [2, 1]}`, because a list inside a member compares in
  order; `"5.0"` and `"5"`; and `1e400` and `"Infinity"`.
- `==` is not transitive. `"5.0"` equals `5` and `5` equals `"5.00"`, but `"5.0"` does not equal `"5.00"`, because two
  strings compare by text. `[5]` equals `[5.0]` and `[5.0]` equals the string `"[5.0]"`, but `[5]` does not, because a
  list compares with a string by its Java text. Likewise `[1, 1]` equals `[1]` and `[1]` equals `"[1]"`, but `[1, 1]`
  does not equal `"[1]"`. Code that groups operands by equality, such as a rule index, cannot treat `==` as an
  equivalence.
- A string equals a number wherever `new BigDecimal` reads it as the same value, so `"+5"` and `"٥"` equal `5`, where
  legacy compares the texts. A string keeps every digit it holds while a number from a document is a `Double`, so
  `"0.300000000000000010"` does not equal the number `0.300000000000000010`, which is `0.3`.
- A number with more digits than a `Double` holds is the `Double` under every operator: `0.300000000000000010` equals
  `0.3` and is not greater than it, and `1e-400` is `0`.
- A number beyond the `Double` range prints as `Infinity`, which `BigDecimal` refuses. It orders against nothing, and
  equals another such number of the same sign.
- The agent gives a different answer from legacy wherever a golden compares a number with a number or a string of
  another spelling. A replay of the executable specification counts 64 such answers. Two numbers account for 35, among
  them `c1-number-literal/float`, `vn2-*`, `vm-*-decimal-integral`, and the `sp44` and `sp46` trailing-zero and
  leading-zero cases. A number and a string account for 27, among them `vm-*-decimal-string`, `vt1-*`,
  `x16-decimal-text-*`, and the `sp46` HEADER and GENERAL string cases. `r28reach-num-infinity-text` and
  `r28reach-num-negative-infinity-text` account for the last 2. The parity suite has to record them as known
  differences.
- The set, type, and case rule for two lists or two objects follows how legacy reads a resource attribute, not a
  golden. A golden that shows legacy comparing them by text or in order revises that rule.
- The Java text of a list that a structure compares with a string keeps the document's order and repeats, where the
  text of a `HashSet` follows its hash order and drops repeats. The agent does not reproduce that text: `[2, 1]`
  equals `"[2, 1]"` and `[1, 1]` equals `"[1, 1]"`, where legacy prints `[1, 2]` and `[1]`. The parity suite has to
  record a golden that depends on that text as a known difference.
- If round 67 shows that legacy orders numbers by the document's text, the reading in this record is revised for every
  operator at once, not patched for `<`.
