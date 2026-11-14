"""Writes the translator case files next to this script: python3 generate.py.

These cases were first written in Go; the files hold the same cases, request for request, so the goldens recorded
then still apply. Each file is one test function of the parity suite, in the format case_files_test.go reads:

  match-dialect.json    which wildcard dialect MATCH speaks on a path
  value-semantics.json  how equality, membership, and the relational operators treat a value whose JSON type or
                        written form is not the literal's

TestTranslatorPolicySetCases stays in Go: two of its cases upload two sets under two external ids, and a case file
uploads one.

A number in a resource keeps the spelling it is written with here, 5.00 and 5e0 included, because the suite sends it
as written and the answer may depend on the spelling.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

def read_duplicates():
    """The ids of duplicates.tsv: cases left out because a kept case holds exactly what each of them holds."""
    with open(os.path.join(HERE, "duplicates.tsv")) as f:
        return {line.split("\t")[0] for line in f if line.strip() and not line.startswith("#")}


DUPLICATES = read_duplicates()
DUPLICATES_NOTE = " The cases listed in duplicates.tsv are left out: a kept case exercises exactly what each of them does."
LEFT_OUT = set()



class Num:
    """A JSON number written exactly as text, such as 5.00 or 1e2, which a Python float would respell."""

    def __init__(self, text):
        float(text)
        self.text = text

    def marker(self):
        return "@@number:" + self.text + "@@"


def _with_markers(value):
    if isinstance(value, Num):
        return value.marker()
    if isinstance(value, dict):
        return {k: _with_markers(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_with_markers(v) for v in value]
    return value


class File:
    """The cases of one file."""

    def __init__(self, name, about, prefix):
        self.name, self.about, self.prefix, self.cases = name, about, prefix, []

    def add(self, case, resource_type):
        """Adds case under resource_type, the resource type its goldens were recorded with."""
        assert all(c["id"] != case["id"] for c in self.cases), case["id"]
        self.cases.append({"id": case["id"], "resourceType": resource_type,
                           **{k: v for k, v in case.items() if k != "id"}})

    def write(self):
        cases = [c for c in self.cases if c["id"] not in DUPLICATES]
        LEFT_OUT.update(c["id"] for c in self.cases if c["id"] in DUPLICATES)
        about = self.about + (DUPLICATES_NOTE if len(cases) < len(self.cases) else "")
        doc = {"about": about, "resourceTypePrefix": self.prefix, "pins": {}, "pips": {},
               "cases": _with_markers(cases)}
        text = json.dumps(doc, indent=1, ensure_ascii=False)
        while "\"@@number:" in text:
            start = text.index("\"@@number:")
            end = text.index("@@\"", start) + 3
            text = text[:start] + text[start + len("\"@@number:"):end - 3] + text[end:]
        with open(os.path.join(HERE, self.name + ".json"), "w") as f:
            f.write(text + "\n")


def isolated(cid, condition, requests, about=None):
    case = {"id": cid}
    if about:
        case["about"] = about
    case["condition"] = condition
    case["requests"] = requests
    return case


def req(name, resource):
    return {"name": name, "resource": resource}


def match_dialect():
    f = File("match-dialect",
             "Which wildcard dialect MATCH speaks on a path. The agent's own condition parser accepts every pattern "
             "here and hands it on as a string, and four answers are recorded for the operator: "
             "x5-match-unquoted-wildcard has ab* matching abc, not matching xabc and not matching ABC, so MATCH is "
             "anchored and case-sensitive; a2-match-attribute-pattern has a pattern taken from an attribute answering "
             "false; and x34-regex-literal has /ab.*/ answering false even for a value the regex describes. Nothing "
             "before these cases says what a metacharacter does to a path separator. Every case sends a URI the "
             "pattern should select and a URI it should not, so a pattern access-control accepts and never evaluates "
             "shows as a column of false answers rather than as a dialect. md7-pattern-without-a-metacharacter is the "
             "control for the whole file: its pattern carries no metacharacter, so a false answer on uri-equal means "
             "the attribute path or the operand order is wrong and no other answer in the file means anything.",
             "PARITY_SUITE_MATCH_")

    def case(cid, rt, pattern, requests, about=None):
        rid = "match-" + cid.split("-", 1)[0]
        f.add(isolated(cid, "resource.uri MATCH " + pattern,
                       [req(name, {"id": rid, "uri": uri}) for name, uri in requests], about),
              "PARITY_SUITE_MATCH_" + rt)

    case("md1-star-between-segments", "MD1", "/v1/*/items", [
        ("one-segment-in-between", "/v1/a/items"),
        ("two-segments-in-between", "/v1/a/b/items"),
        ("no-segment-in-between", "/v1/items"),
        ("last-segment-differs", "/v1/a/other"),
    ], "One star between two separators: whether it stands for exactly one segment, for any number of them, or for "
       "any run of characters including the separator.")
    case("md2-star-inside-a-segment", "MD2", "/v1/it*", [
        ("rest-of-the-same-segment", "/v1/items"),
        ("a-further-segment", "/v1/items/1"),
        ("another-prefix", "/v1/xtems"),
    ], "One star inside a segment: whether it stops at the next separator.")
    case("md3-double-star-between-segments", "MD3", "/v1/**/items", [
        ("one-segment-in-between", "/v1/a/items"),
        ("two-segments-in-between", "/v1/a/b/items"),
        ("no-segment-in-between", "/v1/items"),
        ("last-segment-differs", "/v1/a/other"),
    ], "A double star that is not the last element of the pattern.")
    case("md4-double-star-at-the-end", "MD4", "/v1/items/**", [
        ("one-segment-below", "/v1/items/1"),
        ("two-segments-below", "/v1/items/1/tags"),
        ("nothing-below", "/v1/items"),
        ("separator-and-nothing-below", "/v1/items/"),
    ], "A trailing double star against zero segments, in both spellings of a URI that stops at the prefix.")
    case("md5-question-mark", "MD5", "/v1/item?", [
        ("one-character", "/v1/items"),
        ("two-characters", "/v1/itemss"),
        ("no-character", "/v1/item"),
    ], "The single-character wildcard, on one character, two, and none.")
    case("md6-trailing-separator-in-the-pattern", "MD6", "/v1/items/", [
        ("uri-with-the-separator", "/v1/items/"),
        ("uri-without-the-separator", "/v1/items"),
    ], "A separator at the end of the pattern. The pattern also has the shape x34-regex-literal records as accepted "
       "and always false, a value between two slashes, so two false answers here are equally explained by the "
       "trailing separator and by that reading. md7 does not separate the two, because its pattern has no trailing "
       "slash to drop.")
    case("md7-pattern-without-a-metacharacter", "MD7", "/v1/items", [
        ("uri-equal", "/v1/items"),
        ("uri-with-a-trailing-separator", "/v1/items/"),
        ("uri-with-a-query-string", "/v1/items?x=1"),
        ("uri-with-a-longer-path", "/v1/items/1"),
        ("uri-with-a-prefix", "/api/v1/items"),
    ], "A pattern with no metacharacter at all: the control for the file, and the case that decides whether such a "
       "pattern is equality. The four other requests ask what equality would have to ignore: a separator "
       "at the end of the URI, a query string, a longer path, and a prefix.")
    case("md8-doubled-separator", "MD8", "/v1//items", [
        ("uri-with-both-separators", "/v1//items"),
        ("uri-with-one-separator", "/v1/items"),
    ], "An empty segment in the pattern, against a URI that has one and a URI that does not.")
    case("md9-star-before-a-query-string", "MD9", "/v1/items*", [
        ("uri-with-a-query-string", "/v1/items?x=1"),
        ("uri-without-a-query-string", "/v1/items"),
        ("another-path-with-a-query-string", "/v1/other?x=1"),
    ], "A trailing star against a query string: whether the query is part of the value the pattern sees.")
    case("md10-percent-encoded-separator", "MD10", "/v1/*", [
        ("one-segment", "/v1/a"),
        ("percent-encoded-separator", "/v1/a%2Fb"),
        ("literal-separator", "/v1/a/b"),
    ], "A percent-encoded separator inside one segment, beside the decoded form of the same path. If the two "
       "answers differ, the pattern is matched against the decoded value.")
    case("md11-uppercase-in-the-pattern", "MD11", "/V1/Items", [
        ("uri-in-the-same-case", "/V1/Items"),
        ("uri-in-lower-case", "/v1/items"),
    ], "Case on a path. x5 records ab* against ABC as false, which settles the direction where the pattern is "
       "lower-case; this case asks the other direction.")
    case("md12-brace-placeholder", "MD12", "/v1/{id}/items", [
        ("a-segment-in-place-of-the-placeholder", "/v1/42/items"),
        ("the-braces-themselves", "/v1/{id}/items"),
    ], "A brace placeholder, the spelling a path template uses: whether MATCH reads it as a wildcard or as four "
       "literal characters.")
    case("md13-parentheses", "MD13", "/v1/()/items", [
        ("one-character-segment", "/v1/a/items"),
        ("longer-segment", "/v1/abc/items"),
        ("empty-segment", "/v1//items"),
        ("two-segments", "/v1/a/b/items"),
        ("the-parentheses-themselves", "/v1/()/items"),
    ], "A pair of parentheses as a metacharacter, one or more characters within a segment, or as the two literal "
       "characters.")
    case("md14-star-over-characters-outside-a-uri", "MD14", "/v1/*", [
        ("dot", "/v1/a.b"),
        ("space", "/v1/a b"),
        ("angle-bracket", "/v1/a<b"),
        ("non-ascii-letters", "/v1/яблоко"),
        ("double-quote", "/v1/a\"b"),
    ], "Which characters a star covers within a segment: the dot is the control, and the others sit outside every "
       "class of URI characters a matcher may pick.")
    case("md15-two-question-marks", "MD15", "/v1/??", [
        ("two-characters", "/v1/ab"),
        ("one-character", "/v1/a"),
        ("three-characters", "/v1/abc"),
    ])
    return f


def value_semantics():
    f = File("value-semantics",
             "How equality and membership treat a value that is not a string in the case the literal is written in. "
             "The agent's own condition parser accepts every condition here, and no earlier golden records the "
             "answers. Two recorded answers look like they disagree about numbers, and the vn cases are written to "
             "settle them rather than to add a third: c1-number-literal/float records resource.n == 5 as false for "
             "the attribute 5.0, and c11-decimal-number-equals/trailing-zero records resource.n == 5.5 as true for "
             "the attribute 5.50. One rule explains both: parse the attribute to a double, then compare the string "
             "forms; 5.50 renders as \"5.5\" and equals the literal, while 5.0 renders as \"5.0\" and does not equal "
             "\"5\". vn1/two-decimal-places (5.00), vn1/exponent (5e0) and vn5 (1e2 against the literal 100) tell "
             "that reading from the one where the literal's own form picks the comparison: under the "
             "double-then-string rule all three are true, and under the second only the ones whose literal is "
             "written the same way. vn2, a fractional literal against an integer attribute, and vn4, the negated "
             "side, carry the remaining columns. Each case carries the request a working operator answers true, "
             "because a condition access-control accepts and never evaluates answers false to every request; "
             "resource['x'] and MATCH against an attribute are already recorded as behaving that way (j7, a2).",
             "PARITY_SUITE_VAL_")

    def case(cid, rt, condition, attribute, requests, about=None):
        rid = "val-" + cid.split("-", 1)[0]
        f.add(isolated(cid, condition, [req(name, {"id": rid, attribute: value}) for name, value in requests],
                       about),
              "PARITY_SUITE_VAL_" + rt)

    numbers = ("Numbers. c1 records the integer literal against 5, \"5\" and 5.0; the vn1 to vn3 cases carry the "
               "forms it left out, and each repeats an answer c1 or c11 already has as its control.")
    case("vn1-integer-literal-against-written-decimals", "VN1", "resource.n == 5", "n", [
        ("integer", 5),
        ("one-decimal-place-as-a-string", "5.0"),
        ("two-decimal-places", Num("5.00")),
        ("exponent", Num("5e0")),
    ], numbers)
    case("vn2-fractional-literal-against-an-integer", "VN2", "resource.n == 5.0", "n", [
        ("one-decimal-place", Num("5.0")),
        ("integer", 5),
        ("two-decimal-places", Num("5.00")),
        ("integer-as-a-string", "5"),
        ("one-decimal-place-as-a-string", "5.0"),
    ], numbers)
    case("vn3-fractional-literal-against-longer-decimals", "VN3", "resource.n == 5.5", "n", [
        ("one-decimal-place", Num("5.5")),
        ("two-decimal-places-as-a-string", "5.50"),
        ("four-decimal-places", Num("5.5000")),
    ], numbers)
    case("vn4-integer-literal-negated", "VN4", "resource.n != 5", "n", [
        ("integer", 5),
        ("one-decimal-place", Num("5.0")),
        ("integer-as-a-string", "5"),
        ("another-integer", 6),
    ], "The negated side of the same rule, which the translator has to project the same way and which no recorded "
       "case covers.")
    case("vn5-exponent-against-a-plain-integer", "VN5", "resource.n == 100", "n", [
        ("plain-integer", 100),
        ("exponent", Num("1e2")),
        ("exponent-as-a-string", "1e2"),
    ])
    case("vn6-integer-past-float-precision", "VN6", "resource.n == 9007199254740992", "n", [
        ("exact", 9007199254740992),
        ("neighbour-above", 9007199254740993),
        ("exact-as-a-string", "9007199254740992"),
    ], "c2 records the literal 9007199254740993 as unequal to its neighbor below, so equality survives the first "
       "integer a float64 cannot hold. This is the same pair with the literal on the other side, which a comparison "
       "that rounds one operand only would answer differently.")
    case("vn7-relational-over-a-non-number", "VN7", "resource.n > 5", "n", [
        ("numeric-string-above", "10"),
        ("non-numeric-string", "abc"),
        ("boolean", True),
        ("null", None),
        ("collection", [6]),
    ], "Relational operators compare numerically, so the string \"10\" is greater than 5 (c3, in the round 2 "
       "semantics cases). These are the operands where a numeric comparison has no value to work with, each sent on "
       "its own so that one refusal does not mask the next. numeric-string-above is the control.")
    case("vn8-relational-over-negative-strings", "VN8", "resource.n > -5", "n", [
        ("negative-string-above", "-4"),
        ("negative-string-below", "-10"),
    ])

    case("vc1-long-s-against-ascii-s", "VC1", "resource.x == 's'", "x", [
        ("ascii-lower-case", "s"),
        ("ascii-upper-case", "S"),
        ("long-s", "ſ"),
    ], "Case outside ASCII. Two strings differing only in ASCII case are equal (c5-string-equals-other-case, in the "
       "round 2 semantics cases), and that leaves two readings: the comparison ignores case, or both operands are "
       "lower-cased first. vc1 separates them, because the long s upper-cases to S and lower-cases to itself. vc2 "
       "and vc3 add the pairs whose two cases are not the same length and whose lower case carries a combining "
       "mark.")
    case("vc2-sharp-s-against-a-pair-of-s", "VC2", "resource.x == 'ss'", "x", [
        ("lower-case-pair", "ss"),
        ("upper-case-pair", "SS"),
        ("sharp-s", "ß"),
    ])
    case("vc3-dotted-and-dotless-i", "VC3", "resource.x == 'i'", "x", [
        ("ascii-lower-case", "i"),
        ("ascii-upper-case", "I"),
        ("capital-i-with-dot-above", "İ"),
        ("dotless-lower-case-i", "ı"),
    ])
    case("vc4-cyrillic-case", "VC4", "resource.x == 'я'", "x", [
        ("lower-case", "я"),
        ("upper-case", "Я"),
    ])
    case("vc5-cyrillic-case-under-in", "VC5", "resource.x IN 'я', 'other'", "x", [
        ("lower-case", "я"),
        ("upper-case", "Я"),
    ])
    case("vc6-cyrillic-case-under-contains", "VC6", "resource.tags CONTAINS 'я'", "tags", [
        ("lower-case-element", ["я"]),
        ("upper-case-element", ["Я"]),
    ])

    case("vt1-number-against-a-string-literal", "VT1", "resource.n == '5'", "n", [
        ("string", "5"),
        ("number", 5),
        ("number-with-a-decimal-place", Num("5.0")),
    ], "Operands whose JSON type is not the literal's.")
    case("vt2-boolean-against-an-upper-case-string-literal", "VT2", "resource.b == 'TRUE'", "b", [
        ("string-in-the-same-case", "TRUE"),
        ("string-in-lower-case", "true"),
        ("boolean-true", True),
        ("boolean-false", False),
    ], "A boolean equals its own string form, and two strings equal each other across ASCII case; this case asks "
       "whether the two rules compose.")
    case("vt3-contains-over-elements-in-another-case", "VT3", "resource.tags CONTAINS 'RED'", "tags", [
        ("element-in-the-same-case", ["RED"]),
        ("element-in-lower-case", ["red"]),
    ])
    case("vt4-contains-over-numbers", "VT4", "resource.ns CONTAINS 5", "ns", [
        ("number-element", [5]),
        ("string-element", ["5"]),
        ("element-with-a-decimal-place", [Num("5.0")]),
    ])
    case("vt5-contains-over-an-object", "VT5", "resource.o CONTAINS 'k'", "o", [
        ("a-collection-holding-the-value", ["k"]),
        ("an-object-with-the-value-as-a-key", {"k": "v"}),
        ("an-object-with-the-value-as-a-value", {"v": "k"}),
    ], "Whether CONTAINS over an object reads its keys, its values, or neither. Both object requests can be false at "
       "once, so the control is a-collection-holding-the-value: CONTAINS over a collection holding the value is "
       "recorded as true (l5), and a false answer there means the attribute path rather than the object.")
    case("vt6-in-a-list-of-mixed-types", "VT6", "resource.x IN 'a', 5, TRUE", "x", [
        ("the-string-member", "a"),
        ("the-number-member", 5),
        ("the-boolean-member", True),
        ("no-member", "b"),
    ], "A list literal whose members have three different types. l8 records a number list; this case adds the mixed "
       "one, and asks which member each attribute finds.")
    return f


for build in (match_dialect, value_semantics):
    build().write()

unmatched = DUPLICATES - LEFT_OUT
assert not unmatched, f"duplicates.tsv names cases no file adds: {sorted(unmatched)}"
