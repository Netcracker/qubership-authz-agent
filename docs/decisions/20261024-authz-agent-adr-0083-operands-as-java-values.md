# Compare two values by one rule in every operator: a number by value, any other scalar by its text ignoring case

## Status

Accepted

<!-- markdownlint-disable-next-line MD001 -->
#### Date

2026-11-12

#### Owner

vlsi

#### Participants and approvers

- The owner of the policy decision code (`vlsi`) approves the rules and the departures they name.
- The Netcracker/qubership-authz-agent maintainers.

#### Related ADRs

- [authz-agent-ADR-0082: Evaluate jsonPath with our own Go package instead of a third-party library](20261023-authz-agent-adr-0082-own-jsonpath-evaluator.md):
  the same document model, `internal/jsonvalue`, keeps the text of every number, from which R1 reads its value.
- ADR-0097, "Answer as legacy access-control, and depart from it only to narrow access or by a recorded decision",
  proposed in Netcracker/qubership-authz-agent#226: its R4 and R5 require the departures of this record to be named by
  numbered rules, and its R6 governs a new form of the condition language.

## Context

Rego generated from a legacy policy compares value records built by `internal/legacyvalue`, not raw JSON. A condition
compares two values in ten operators: `==`, `!=`, `IN`, `NOT IN`, `CONTAINS`, `NOT CONTAINS`, `CONTAINS ANY`,
`NOT CONTAINS ANY`, `IS SUBSET`, and `IS NOT SUBSET`. The goldens of legacy access-control 6.1.6 show how legacy reads
an operand and three different equalities behind those operators:

- `==`, `IN`, `CONTAINS`, and `CONTAINS ANY` compare two scalars by their `String.valueOf` text ignoring case. A
  number from the request prints as its digits when it is an integer and as `Double.toString` otherwise, so `5.0 == 5`
  is false, `5 == '5'` is true, and `1e400 == 'Infinity'` is true (`r28reach-num-infinity-text`).
- A number literal of a condition prints as `BigDecimal.toString`, so `5.50` does not equal the value `5.5` and `05`
  equals `5` (`sp44-literals-num-fraction-trailing-zero-or`, `x17-number-leading-zero`). An element of a list literal
  prints as written, so `05` there does not equal `5` (`sp44-literals-ln-elem-leading-zero-or`).
- `IS SUBSET` compares with case (`vm-is-subset-strings-alone/upper-case-string`). When a resource attribute or a PIP
  is on its right, an element that is not a string equals nothing, so `5 IS SUBSET resource.y` is false for `y = 5`
  (`v16-is-subset-119`, `k18-is-subset-003`).
- Two lists or two objects compare as `Set.equals` and `Map.equals` over the values Jackson reads: a list of a
  resource attribute in any order and without repeats, a list inside an element or a member in order, each string
  with its case, and a number never equal to a string (`p15-eq-resource-resource`, `v16-eq-049`, `ol69-case-eq`,
  `on67-number-text-eq`).
- `==` between a list or an object and a string compares the string with the Java text of the structure, `[v, w]` or
  `{k=v}`, ignoring case (`x17-eq-structure-as-text-*`, `q19-list-equals-its-printed-text`). Its JSON text does not
  match (`x17-eq-structure-as-json-*`).
- `<`, `<=`, `>`, and `>=` read a string as `new BigDecimal(String)` does (`x16-number-string-*`), and `1e400 > 5` is
  false (`r28reach-num-greater`). So `"5.0" <= 5` and `"5.0" >= 5` hold while `"5.0" == 5` does not.
- `MATCH` tests a string against a pattern with case, and over a number ends the rule (`vm-match-*`).

These goldens agree with one reading: legacy reads the request with Jackson in its default configuration, an integer
as `Integer`, `Long`, or `BigInteger` and any other number as `Double`. Round 67 tells this reading apart from one by
the text of the document: `0.300000000000000010 > 0.3` and `1e-400 > 0` are false and `0.300000000000000010 == 0.3` is
true (`on67-rel-gt-near`, `on67-rel-gt-underflow`, `on67-eq-near`).

Comparing a number by text makes equality depend on how a client formats its JSON: `5.50` does not equal `5.5`, and
`"5.0"` does not equal `5`. Applying a fix to `==` alone leaves the three equalities in place: `resource.b CONTAINS
'5.0'` would hold for `b = [5]` while `["5.0"] IS SUBSET resource.b` would not, and inside a nested list `"X"` would
differ from `"x"`. A policy author could not tell from two values alone whether they are equal.

Equality cannot be one key per scalar without comparing two strings by value. That makes `"007"` equal `"7"`, and
identifiers are strings: the conditions of the projects' policy data hold several thousand comparisons of one
attribute with another, almost all of them `IN` and `CONTAINS ANY` over lists of identifiers.

## Decision

We will compare two scalars by one rule wherever a condition compares them: a number with a number, or with a string
that `BigDecimal` reads, by value, and any other two scalars by their text ignoring case. Every other reading of an
operand stays as legacy reads it.

### Terms

- **Scalar**: a string, a number, or a boolean. `null` is not a scalar.
- **Numeric string**: a string that `new BigDecimal(String)` of Java 21 reads without an exception: a sign, digits of
  any script, a point, and an exponent, with no character beyond the Basic Multilingual Plane and a scale within the
  range of `int`. `"Infinity"` and `"abc"` are not numeric strings.
- **Comparing operator**: `==`, `!=`, `IN`, `NOT IN`, `CONTAINS`, `NOT CONTAINS`, `CONTAINS ANY`, `NOT CONTAINS ANY`,
  `IS SUBSET`, and `IS NOT SUBSET`.
- **Text of a scalar**: a string itself; `true` or `false` for a boolean.
- **Ignoring case**: as `String.equalsIgnoreCase` of Java compares two texts.

### Rules

#### The value of a number

- **R1** (`translate`). The value of a number from the request, a resource, the subject, or a PIP is its digits when
  it is an integer and its `Double` otherwise, so `1e-400` is `0` and `1e400` is beyond the range of a `Double`. The
  value of a number literal, and of a number in a list literal, is the `BigDecimal` of its own text.

#### Two scalars

- **R2** (`translate`). Two numbers are equal when their values are equal: `5`, `5.0`, and `5e0` are equal, and so
  are `5.50` and `5.5`. A number beyond the range of a `Double` equals only a number beyond the range with the same
  sign.
- **R3** (`translate`). A number and a string are equal when the string is a numeric string whose value equals the
  value of the number: `"5.0"` equals `5`. A string that is not a numeric string equals no number.
- **R4** (`translate`). Two scalars that R2 and R3 do not cover, that is two strings, two booleans, or a string and a
  boolean, are equal when their texts are equal ignoring case: `"abc"` equals `"ABC"`, `true` equals `"TRUE"`, and
  `"5.0"` does not equal `"5"`. A boolean never equals a number.

#### Where the rule applies

- **R5** (`translate`). Every comparing operator decides whether two scalars are equal by R2, R3, and R4 and by no
  other test, whichever side each scalar is on, and whether it is a literal, an element of a list literal, a resource
  attribute, a subject attribute, a PIP value, or an element or a member of a list or an object at any depth.
- **R6** (`translate`). Two lists, or two objects, are equal when their elements or members are equal pairwise by R5
  and R6. A list of the resource, the subject, or a PIP that is an operand of `==` or `!=` compares as a set: in any
  order, with repeats ignored. A list inside an element or a member compares in order. An object compares its members
  by name, with case. `null` inside a list or an object equals `null`.
- **R7** (`translate`). `IS SUBSET` holds when its left operand has at least one element and each element of it
  equals some element of its right operand by R5. The elements of a resource attribute, a subject attribute, or a PIP
  value on the right are candidates in the same way as the elements of a list literal. An object on the right equals
  no element.

#### Comparisons that are not equality

- **R8** (`translate`). A list or an object and a string are equal under a comparing operator when the string equals
  the Java text of the list or the object, such as `[v, w]` or `{k=v}`, ignoring case. The text lists the elements of
  a list in the order and with the repeats of the document.
- **R9** (`translate`). `<`, `<=`, `>`, and `>=` compare the values of a number or a numeric string on each side, and
  are false where either side is neither, or is a number beyond the range of a `Double`.
- **R10** (`translate`). `MATCH` and `NOT MATCH` test the text of a string against the pattern with case, and end the
  rule for an operand that is not a string. No comparing operator compares two strings with case.

### Justification

- One rule for two scalars lets a reader decide whether two values are equal without knowing the operator, the side,
  or the depth. The goldens of rounds 16, 17, 18, 67, and 69 show that legacy has three equalities, and their parity
  cannot be kept without keeping the cases in which `CONTAINS` and `IS SUBSET` disagree about the same pair (R5, R6,
  R7).
- Two numbers compared by value match what a policy author writes. JSON serializers differ on whether 5 prints as `5`
  or `5.0`, and a decision should not change with the serializer (R2).
- A string compared with a number by value makes `==` agree with `<` and `>`, which read the string as a number
  already. Reading a string as a number gives one value, where printing a number gives one of several texts. SQL
  databases and the `==` of JavaScript also convert the string to a number in this comparison. A value a HEADER PIP
  returns is always a string, and it compares with a number literal by value (R3, R9).
- Two strings compare by text because identifiers are strings: `"007"` and `"7"`, `"1.0"` and `"1.00"` name different
  things (R4).
- Case is ignored because legacy ignores it in `==`, `IN`, `CONTAINS`, and `CONTAINS ANY`, which hold almost every
  comparison in the projects' policy data, and in the resource type, the roles, and the operation. `IS SUBSET` is the
  one comparing operator that keeps case, and its other quirks show that this is not a designed choice: it also finds
  `5` absent from `[5]` when the list is an attribute (R4, R5, R10).
- An attribute or a PIP on the right of `IS SUBSET` is a list of candidates like a literal, because the author writes
  the same condition either way (R7).
- Reading every operand once, as legacy reads it, leaves no special case per operator. A number beyond the range of a
  `Double` needs no rule of its own in `==`, because `Infinity` is not a numeric string (R1, R3).

### Alternatives considered

- **A1. One key per scalar: a numeric string by its value against any scalar.** Rejected by R4: `"007"` would equal
  `"7"`, and `"+5"` would equal `"5"`. It would make equality transitive and let the generator give each scalar one
  token instead of two.
- **A2. A number never equals a string.** Rejected by R3: `5 == '5'` holds in legacy, and a HEADER PIP value would
  equal no number literal. It changes the answer to 158 goldens.
- **A3. Compare two lists or two objects as `Set.equals` and `Map.equals`, with case and type.** Rejected by R6:
  `5 == "5"` would hold while `[5] == ["5"]` does not. It keeps 12 answers of legacy.
- **A4. Keep `IS SUBSET` with case, and an attribute or a PIP on its right as one value.** Rejected by R5 and R7:
  `["5.0"] IS SUBSET resource.b` would stay false for `b = [5]` while `resource.b CONTAINS '5.0'` holds.
- **A5. A comparing operator, or a new form of `==`, that compares two strings with case.** Rejected by R10: no golden
  and no condition of the projects' policy data asks for it, and a new form needs a rule of its own under ADR-0097 R6
  and the support of the policy administration point.
- **A6. Fall back to text for a string that `new BigDecimal` refuses.** Rejected by R3. It differs from the rule only
  for `1e400 == 'Infinity'`, which holds in legacy because `Double.toString` prints an overflow as `Infinity`.
- **A7. Read only ASCII digits in a string.** Rejected by R3 and R9: `new BigDecimal` reads digits of any script, and
  a second reader for `==` would let it disagree with `<` on such a string.
- **A8. Repeat legacy exactly.** Rejected by R2 and R3: `5.50` against `5.5` and `5` against `5.0` would then depend
  on formatting.
- **A9. Read only the literals as a `Double`.** Rejected by R1 and R2. It makes `5.50` equal `5.5` and keeps `5`
  unequal to `5.0`, which depends on formatting just the same.
- **A10. Read every number from the text of the document exactly.** Rejected by R1: it makes `1e400 > 5` true and
  `1e400 == 'Infinity'` false, and the goldens pin both the other way.

## Consequences

Negative:

- The condition language has no equality with case. `MATCH` is the only test with case, and it compares a string
  exactly only when the pattern holds none of `*`, `?`, `(`, `)`, and `.`, which match more than themselves, and none
  of `[`, `]`, `{`, `}`, `+`, `^`, `$`, `|`, and `\`, which keep their meaning in a regular expression.
- Equality is not transitive. `"5.0"` equals `5` and `5` equals `"5.00"`, but `"5.0"` does not equal `"5.00"`.
  `"5.0" <= "5"` and `"5.0" >= "5"` hold while `"5.0" == "5"` does not. `[5]` equals `[5.0]` and `[5.0]` equals the
  string `"[5.0]"`, but `[5]` does not, because a list compares with a string by its Java text. Likewise `[1, 1]`
  equals `[1]` and `[1]` equals `"[1]"`, but `[1, 1]` does not equal `"[1]"`. Code that groups operands by equality,
  such as a rule index, cannot treat it as an equivalence, and two lists or two objects cannot be reduced to one key:
  the generated code compares them member by member.
- Looking up a nested list or object among the elements of a list takes time that grows with the product of their
  numbers when the elements write one number in several ways, since a number matches every string of its value. The
  agent fails a request, as it fails a body nested too deep, when a value a comparison reads would need a lookup of more
  than 16 groups of such elements and elements it must scan. A GENERAL or FILTERED PIP, the entitlements service, or the
  permission scope whose answer is over the limit reads as a source that failed. Lists whose elements write their
  numbers alike stay far below the limit.
- These pairs are equal: `5.50` and `5.5`; `5`, `5.0`, and `5e0`; `05` and `5` in a list literal; `"5.0"` and `5`;
  `"+5"`, `"٥"`, and `5`; `0.0` and `-0.0`; `{"a": 1}` and `{"a": 1.0}`; `{"a": 1}` and `{"a": "1"}`; `["X"]` and
  `["x"]`; `[1, 2]` and `[2, 1]`; `[1, 1]` and `[1]`.
- These pairs differ: `"5.0"` and `"5"`; `{"a": [1, 2]}` and `{"a": [2, 1]}`, because a list inside a member compares
  in order; `1e400` and `"Infinity"`; `"0.300000000000000010"` and the number `0.300000000000000010`, which is the
  `Double` `0.3`.
- A number with more digits than a `Double` holds is the `Double` under every operator: `0.300000000000000010` equals
  `0.3` and is not greater than it, and `1e-400` is `0`. A number beyond the range orders against nothing.
- The Java text of a list that R8 compares with a string keeps the order and repeats of the document, where legacy
  prints a `HashSet` in hash order and without repeats: `[2, 1]` equals `"[2, 1]"` and `[1, 1]` equals `"[1, 1]"`,
  where legacy prints `[1, 2]` and `[1]`.
- The agent answers unlike legacy wherever a golden compares a number with a number or a string of another spelling.
  A replay of the executable specification counts 64 such answers. Two numbers account for 35, among them
  `c1-number-literal/float`, `vn2-*`, `vm-*-decimal-integral`, and the `sp44` and `sp46` trailing-zero and
  leading-zero cases. A number and a string account for 27, among them `vm-*-decimal-string`, `vt1-*`,
  `x16-decimal-text-*`, and the `sp46` HEADER and GENERAL string cases. `r28reach-num-infinity-text` and
  `r28reach-num-negative-infinity-text` account for the last 2.
- The agent answers 55 more goldens unlike legacy. 30 of them allow what legacy denies, and ADR-0097 R5 requires each
  of them to be named:
  - R6, 12 goldens: `ol69-case-eq` and `-ne`, `on67-string-case-eq` and `-ne`, `ol69-number-text-eq` and `-ne`,
    `ol69-member-text-number-eq` and `-ne`, `on67-number-text-eq` and `-ne`, `on67-list-number-text-eq` and `-ne`.
    The `-eq` cases allow more.
  - R4 and R5 in `IS SUBSET`, 7 goldens: `vm-is-subset-strings-alone/upper-case-string`,
    `vm-is-not-subset-strings-alone/upper-case-string`, `h17-is-subset-004/p01`, `h17-is-not-subset-006/p01`,
    `v17-is-subset-038/p01`, `v17-is-not-subset-041/p01`, and `v16-is-subset-119/p01`. The `IS SUBSET` cases allow
    more.
  - R7, 36 goldens: `v16-is-subset-119` (9 requests), `v16-is-not-subset-003` (10 requests), `k18-is-subset-003`,
    `-004`, `-007`, `k18-is-not-subset-012`, `-018`, `g17-is-subset-033`, `g17-is-not-subset-036`,
    `q18-five-list-body-on-the-right-of-is-subset` (2 requests), `q17-string-true-is-subset-of-a-true-body`
    (2 requests), `r16-residual-002`, `r18-residual-016`, `h16-is-subset-010`, `h16-is-not-subset-000`, and
    `c21-018835` (2 requests). 20 of them allow more.
- An installation that relies on `IS SUBSET` with case, or on an attribute or a PIP on its right holding numbers or
  booleans that match nothing, gets more grants on upgrade.

Follow-ups:

- The documentation of the condition language states that no comparison keeps case and that `MATCH` is the test with
  case.
- The executable specification sets its `agent` profile to these rules and accepts the 55 goldens.
- The text of the link to this record in ADR-0097 takes the new title when ADR-0097 is merged.
