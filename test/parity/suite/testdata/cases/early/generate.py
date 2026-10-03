"""Writes the early case files next to this script: python3 generate.py.

These cases were the first the parity suite asked, written in Go; these files hold the same cases, request for request,
so the goldens recorded then still apply. Each file is one test function of the parity suite, in the format
case_files_test.go reads:

  isolated-policy.json          operator forms, attribute paths, subject attributes, literals, whitespace,
                                declarations, and policy shapes whose acceptance by the PAP was not established
  isolated-condition-form.json  forms the agent's own condition parser accepts and no other golden records
  regular-policy-set.json       how access-control evaluates regular policy sets, up to the nested-set filter

TestRegularPolicySetCases runs regular-policy-set.json and then four cases kept in Go, in the order they were recorded:
filter-set-beside-simplified-policy uploads a simplified policy beside its set, inactive-set comes between it and the
next two, and reupload-replaces-sets and two-external-ids-allow-and-deny upload two set lists. A case file uploads one
set list and no simplified policy. TestLoadSimplifiedPoliciesConditionSyntax stays in Go because it uploads each
condition alone into a domain of its own with one PUT, without the PIP upload of the isolated runner, and records the
status under condition-syntax/ rather than isolated/. TestRound16CustomizationUnderIterateCases stays in Go because it
files its goldens under the case id rather than regular/, reads the v3 export before and after the import, and waits
out the scope PIP's cache before the case.

A number in a resource keeps the spelling it is written with here, 5.0 and 5.50 included, because the suite sends it
as written and the answer may depend on the spelling.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PIP_MOCK = "http://pip-mock:8090/api/v1/pip"
READER_TARGET = "subject.roles CONTAINS 'ROLE_PARITY_READER'"
ISOLATED_PREFIX = "PARITY_SUITE_ISO_"
REGULAR_PREFIX = "PARITY_SUITE_REG_"
SET_TARGET = "resourceType == '{{resourceType}}'"


class Num:
    """A JSON number written exactly as text, such as 5.0 or 5.50, which a Python float would respell."""

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


def upper(text):
    return text.upper().replace("-", "_")


class File:
    """The cases of one file and the PIPs and pins they name."""

    def __init__(self, name, about, prefix, pips=None, pins=None):
        self.name, self.about, self.prefix = name, about, prefix
        self.pips, self.pins, self.cases = pips or {}, pins or {}, []

    def add(self, case, resource_type=None):
        """Adds case, keeping resource_type where the id does not derive it."""
        assert all(c["id"] != case["id"] for c in self.cases), case["id"]
        assert all(p in self.pips for p in case.get("pips", ())), case["id"]
        if resource_type is not None and resource_type != self.prefix + upper(case["id"]):
            case = {"id": case["id"], "resourceType": resource_type, **{k: v for k, v in case.items() if k != "id"}}
        self.cases.append(case)

    def write(self):
        doc = {"about": self.about, "resourceTypePrefix": self.prefix, "pins": self.pins, "pips": self.pips,
               "cases": _with_markers(self.cases)}
        text = json.dumps(doc, indent=1, ensure_ascii=False)
        while "\"@@number:" in text:
            start = text.index("\"@@number:")
            end = text.index("@@\"", start) + 3
            text = text[:start] + text[start + len("\"@@number:"):end - 3] + text[end:]
        with open(os.path.join(HERE, self.name + ".json"), "w") as f:
            f.write(text + "\n")


def isolated(cid, condition, requests, pips=(), about=None, **extra):
    case = {"id": cid}
    if about:
        case["about"] = about
    if condition:
        case["condition"] = condition
    if pips:
        case["pips"] = list(pips)
    case.update(extra)
    case["requests"] = requests
    return case


def req(name, resource=None, **extra):
    r = {"name": name}
    r.update(extra)
    if resource is not None:
        r["resource"] = resource
    return r


def iso(f, letter, cid, condition, requests, about=None, **extra):
    """Adds an isolated case whose resource type is PARITY_SUITE_ISO_<letter> and whose resources have id iso-<letter>."""
    rid = "iso-" + letter.lower()
    reqs = [req(name, {"id": rid, **fields} if isinstance(fields, dict) else fields, **opts)
            for name, fields, *rest in requests for opts in [rest[0] if rest else {}]]
    f.add(isolated(cid, condition, reqs, about=about, **extra), ISOLATED_PREFIX + letter)


def isolated_policy():
    f = File("isolated-policy",
             "Operator forms, attribute paths, subject attributes, literals, whitespace, declarations, and policy "
             "shapes whose acceptance by the PAP is not established. Each case is one simplified policy uploaded "
             "alone into PARITY_ISOLATED, so a form the PAP refuses records its upload status and sends no request.",
             ISOLATED_PREFIX,
             pips={
                 "no-header": {
                     "name": "subject.parityNoHeader", "type": "UUID", "pipType": "HEADER",
                     "header": "x-parity-no-such-header", "cacheable": False,
                 },
             })
    iso(f, "J1", "j1-nested-path-neq", "resource.o.x != 'v'", [
        ("parent-absent", {}),
        ("parent-empty-object", {"o": {}}),
        ("parent-null", {"o": None}),
        ("leaf-differs", {"o": {"x": "w"}}),
    ])
    iso(f, "J5", "j5-array-index", "resource.list[0] == 'a'", [
        ("first-element-matches", {"list": ["a", "b"]}),
        ("array-absent", {}),
    ])
    iso(f, "J6", "j6-array-wildcard-path", "resource.items[*].id CONTAINS 'a'", [
        ("an-item-has-the-id", {"items": [{"id": "a"}, {"id": "b"}]}),
    ])
    iso(f, "J7", "j7-bracket-path", "resource['x'] == 'v'", [("attribute-matches", {"x": "v"})])
    iso(f, "J8", "j8-hyphen-in-key", "resource.a-b == 'v'", [("hyphenated-key-matches", {"a-b": "v"})])
    iso(f, "C1", "c1-number-literal", "resource.n == 5", [
        ("integer", {"n": 5}),
        ("string", {"n": "5"}),
        ("float", {"n": Num("5.0")}),
    ])
    iso(f, "C2", "c2-number-precision", "resource.n == 9007199254740993", [
        ("neighbour-below", {"n": Num("9007199254740992")}),
        ("exact", {"n": Num("9007199254740993")}),
    ], about="9007199254740993 is the first integer a double cannot hold, so a comparison through a double cannot tell "
             "it from 9007199254740992.")
    iso(f, "C7", "c7-equals-empty-string", "resource.x == ''", [
        ("attribute-empty", {"x": ""}),
        ("attribute-absent", {}),
    ])
    iso(f, "L3", "l3-in-resource-collection", "resource.x IN resource.list", [
        ("value-in-collection", {"x": "a", "list": ["a"]}),
        ("collection-absent", {"x": "a"}),
    ])
    iso(f, "L4", "l4-subset-of-literal-list", "resource.list IS SUBSET 'a', 'b'", [
        ("empty-collection", {"list": []}),
        ("foreign-element", {"list": ["c"]}),
    ])
    iso(f, "L5", "l5-contains-literal", "resource.tags CONTAINS 'red'", [
        ("collection-with-value", {"tags": ["red"]}),
        ("scalar-equal-to-value", {"tags": "red"}),
        ("string-containing-value", {"tags": "bred"}),
    ])
    iso(f, "L8", "l8-number-list-in", "resource.n IN 1, 2", [
        ("number", {"n": 1}),
        ("string-number", {"n": "1"}),
    ])
    iso(f, "L9", "l9-is-not-empty", "resource.x IS NOT EMPTY", [
        ("attribute-absent", {}),
        ("empty-string", {"x": ""}),
        ("empty-collection", {"x": []}),
    ])
    iso(f, "A1", "a1-attribute-equals-attribute", "resource.x == resource.y", [
        ("both-equal", {"x": "v", "y": "v"}),
        ("right-absent", {"x": "v"}),
    ])
    iso(f, "A2", "a2-match-attribute-pattern", "resource.x MATCH resource.p", [
        ("pattern-matches", {"x": "abc", "p": "ab*"}),
    ])
    no_header_about = ("subject.parityNoHeader is a HEADER PIP with no defaultValue, a declaration no seeded fixture "
                       "has made the PAP accept.")
    iso(f, "H1", "h1-header-pip-no-value-neq", "subject.parityNoHeader != 'x'", [
        ("header-absent", {}),
        ("header-other-value", {}, {"headers": {"x-parity-no-such-header": "y"}}),
        ("header-equal-value", {}, {"headers": {"x-parity-no-such-header": "x"}}),
    ], about=no_header_about, pips=["no-header"])
    iso(f, "H2", "h2-header-pip-no-value-is-null", "subject.parityNoHeader IS NULL", [
        ("header-absent", {}),
        ("header-sent", {}, {"headers": {"x-parity-no-such-header": "y"}}),
    ], about=no_header_about, pips=["no-header"])
    iso(f, "U1", "u1-subject-roles-contains", "subject.roles CONTAINS 'ROLE_PARITY_READER'", [("reader", {})])
    iso(f, "U2", "u2-subject-roles-other-case", "subject.roles CONTAINS 'role_parity_reader'", [("reader", {})])
    iso(f, "U3", "u3-subject-service-account-is-null", "subject.serviceAccount IS NULL", [("reader", {})])
    iso(f, "U4", "u4-subject-type", "subject.type == 'USER'", [("reader", {})])
    iso(f, "U5", "u5-subject-name", "subject.name == 'parity-reader'", [("reader", {})])
    iso(f, "U6", "u6-subject-id-is-not-null", "subject.id IS NOT NULL", [("reader", {})])
    iso(f, "U7", "u7-has-access", "subject allowed 'READ' on resource", [("reader", {})])
    iso(f, "O1", "o1-operation-operand", "operation == 'READ'", [("read", {})])
    iso(f, "O2", "o2-resource-type-operand", "resourceType == 'PARITY_SUITE_ISO_O2'", [("own-type", {})])
    iso(f, "R5", "r5-bare-resource-operand", "resource == 'abc'", [("resource-string", "abc")],
        about="The resource is the string abc rather than an object.")
    iso(f, "X1", "x1-literal-on-the-left", "'v' == resource.x", [("attribute-matches", {"x": "v"})])
    iso(f, "X2", "x2-equals-keyword", "resource.x EQUALS 'v'", [("attribute-matches", {"x": "v"})])
    iso(f, "X3", "x3-not-equals-keyword", "resource.x NOT EQUALS 'v'", [("attribute-differs", {"x": "w"})])
    iso(f, "X4", "x4-greater-or-equal-words", "resource.n GREATER THAN OR EQUAL TO 5", [("boundary", {"n": 5})])
    iso(f, "X5", "x5-match-unquoted-wildcard", "resource.x MATCH ab*", [
        ("prefix-matches", {"x": "abc"}),
        ("match-inside", {"x": "xabc"}),
        ("prefix-other-case", {"x": "ABC"}),
    ])
    iso(f, "X6", "x6-match-quoted-wildcard", "resource.x MATCH 'ab*'", [("prefix-matches", {"x": "abc"})])
    iso(f, "X9", "x9-boolean-literal-uppercase", "resource.b == TRUE", [("attribute-true", {"b": True})])
    iso(f, "X10", "x10-condition-literal-true", "TRUE", [("any-resource", {})])
    iso(f, "X11", "x11-keyword-inside-string", "resource.x == 'a AND b'", [("attribute-matches", {"x": "a AND b"})])
    iso(f, "X12", "x12-list-without-spaces", "resource.x IN 'a','b'", [("second-element", {"x": "b"})])
    iso(f, "X13", "x13-comma-inside-list-string", "resource.x IN 'a,b'", [
        ("part-before-comma", {"x": "a"}),
        ("whole-string", {"x": "a,b"}),
    ])
    iso(f, "X14", "x14-leading-space", " resource.x == 'v'", [("attribute-matches", {"x": "v"})])
    iso(f, "X15", "x15-trailing-space", "resource.x == 'v' ", [("attribute-matches", {"x": "v"})])
    iso(f, "X16", "x16-tab-between-tokens", "resource.x ==\t'v'", [("attribute-matches", {"x": "v"})])
    iso(f, "X17", "x17-number-leading-zero", "resource.n == 05", [("number-five", {"n": 5})])
    iso(f, "X19", "x19-undeclared-subject-attribute", "subject.parityUndeclared == 'x'", [("reader", {})],
        about="The condition reads a subject attribute that no PIP of the domain declares, on purpose.")
    f.add(isolated("x20-undeclared-placeholder", None, [req("filter", operation="LIST", filter=True)],
                   about="A policy on LIST with no condition and an rsqlPredicate whose placeholder names a subject "
                         "attribute that no PIP of the domain declares, on purpose.",
                   operation="LIST", policy={"rsqlPredicate": "owner==${subject.parityUndeclared}"}),
          ISOLATED_PREFIX + "X20")
    iso(f, "X24", "x24-lowercase-is-null", "resource.x is null", [("attribute-absent", {})])
    iso(f, "X25", "x25-double-quoted-string", "resource.x == \"v\"", [("attribute-matches", {"x": "v"})])
    iso(f, "X26", "x26-null-literal", "resource.x != null", [
        ("attribute-present", {"x": "w"}),
        ("attribute-absent", {}),
    ])
    f.add(isolated("x28-policy-resource-type-lowercase", None, [
        req("request-uppercase", {"id": "iso-x28"}, type="PARITY_SUITE_ISO_X28"),
        req("request-lowercase", {"id": "iso-x28"}, type="parity_suite_iso_x28"),
    ], about="The policy names its resource type in lower case, with no condition; the requests name it in either "
             "case."), "parity_suite_iso_x28")
    iso(f, "X29", "x29-policy-role-lowercase", None, [("reader", {})],
        about="The policy grants role_parity_reader, the reader's role in lower case, with no condition.",
        roles=["role_parity_reader"])
    f.add(isolated("x30-policy-operation-all", None, [
        req("read", {"id": "iso-x30"}, operation="READ"),
        req("delete", {"id": "iso-x30"}, operation="DELETE"),
    ], about="A policy on operation ALL with no condition.", operation="ALL"), ISOLATED_PREFIX + "X30")
    iso(f, "X31", "x31-policy-without-roles", None, [("reader", {})],
        about="A policy with an empty role list and no condition.", roles=[])
    return f


def isolated_condition_form():
    f = File("isolated-condition-form",
             "Forms the agent's own condition parser (internal/simplifiedpolicies/parser.go) accepts and no golden "
             "records: the negated operators NOT MATCH, IS NOT SUBSET and NOT CONTAINS ANY, the denied form of the "
             "access operator, the word forms GREATER THAN, LESS THAN and the two spellings of LESS THAN OR EQUAL TO, "
             "the single equals sign, the /…/ regex literal, and FALSE as a whole condition. It adds what no case "
             "sends at all: subject.scopes, subject.permissions in a condition and the MAPPING PIP that grants one, "
             "the FILTERED pipType, signed and fractional literals, and JSON Path beyond the plain and bracketed "
             "paths of isolated-policy.json. Each case asks two things: whether the PAP accepts the form, and what "
             "access-control decides once it has. A refusal settles the first and leaves the second open. Where the "
             "second question is reachable, the case sends two requests that a working operator tells apart, because "
             "a form the PAP accepts and the evaluator ignores answers false to both; resource['x'] and MATCH against "
             "an attribute are already recorded as behaving that way (j7, a2). Both pinned routes return a "
             "collection holding the value the h cases compare against, so a false decision there means the form "
             "was ignored rather than that the PIP returned nothing.",
             ISOLATED_PREFIX,
             pins={
                 "/api/v1/pip/iso-filtered": {"statusCode": 200, "body": ["red", "blue"]},
                 "/api/v1/pip/iso-list": {"statusCode": 200, "body": ["red", "blue"]},
             },
             pips={
                 "filtered": {
                     "name": "subject.parityFilteredList", "url": PIP_MOCK + "/iso-filtered", "httpMethod": "POST",
                     "pipType": "FILTERED", "requestAttributes": {"resourceType": "PARITY_SUITE_ISO_H3"},
                     "cacheable": False,
                 },
                 "list": {
                     "name": "subject.parityList", "url": PIP_MOCK + "/iso-list", "httpMethod": "POST",
                     "pipType": "GENERAL", "requestAttributes": {"resourceType": "PARITY_SUITE_ISO_H5"},
                     "cacheable": False,
                 },
                 "permissions": {
                     "name": "subject.permissions.PARITY", "type": "UUID", "pipType": "MAPPING", "cacheable": False,
                     "customMapping": {"subject.roles": {"ROLE_PARITY_READER": ["parity_permission"]}},
                 },
             })

    negation = ("CONTAINS, MATCH and IS SUBSET are recorded; their negated forms are not. The case sends the null "
                "value that separates NOT IN from NOT CONTAINS in the round 2 semantics cases, where n1 is true and "
                "n2 is false.")
    iso(f, "M1", "m1-not-match", "resource.x NOT MATCH ab*", [
        ("pattern-matches", {"x": "abc"}),
        ("pattern-does-not-match", {"x": "zzz"}),
        ("attribute-null", {"x": None}),
    ], about=negation)
    iso(f, "M2", "m2-not-contains-any", "resource.tags NOT CONTAINS ANY 'red', 'blue'", [
        ("one-element-shared", {"tags": ["red"]}),
        ("no-element-shared", {"tags": ["green"]}),
        ("attribute-null", {"tags": None}),
    ], about=negation)
    iso(f, "M3", "m3-is-not-subset", "resource.list IS NOT SUBSET 'a', 'b'", [
        ("every-element-listed", {"list": ["a"]}),
        ("foreign-element", {"list": ["c"]}),
        ("empty-collection", {"list": []}),
        ("attribute-null", {"list": None}),
    ], about=negation + " IS SUBSET is false for an empty collection (l4), where set theory makes it true, so the "
                        "empty case decides whether the two operators are complements.")

    subject = ("subject.permissionScope is recorded as refused (g8b), and subject.isM2M was refused on access-control "
               "5.13 and is accepted as a whole condition on 6.1.6 (g8a). subject.scopes appears in no other case; "
               "subject.permissions only as the target of a regular policy set, which the PAP accepts and which is "
               "false for a reader with no permission assigned. IS EMPTY shows whether the attribute resolves in a "
               "condition at all; CONTAINS shows what it holds on this stand.")
    iso(f, "U8", "u8-subject-scopes-is-empty", "subject.scopes IS EMPTY", [("reader", {})], about=subject)
    iso(f, "U9", "u9-subject-scopes-contains", "subject.scopes CONTAINS 'profile'", [("reader", {})], about=subject)
    unassigned = subject + (" The parity users carry no assigned permission, so u10 and u11 record the negative "
                            "answers; pm1 is u11's positive half.")
    iso(f, "U10", "u10-subject-permissions-is-empty", "subject.permissions IS EMPTY", [("reader", {})],
        about=unassigned)
    iso(f, "U11", "u11-subject-permissions-contains", "subject.permissions CONTAINS 'parity_permission'",
        [("reader", {})], about=unassigned)

    iso(f, "PM1", "pm1-mapping-pip-merged-list", "subject.permissions CONTAINS 'parity_permission'", [("reader", {})],
        about="u11 with the permission granted by subject.permissions.PARITY, a MAPPING PIP that grants "
              "parity_permission to ROLE_PARITY_READER. A PIP of this shape is how access-control assigns permissions "
              "to a role outside the simplified policies: it declares the mapping inline, and every "
              "subject.permissions.<suffix> PIP the tenant holds is merged into one subject.permissions list on the "
              "subject. The real export carries \"cacheable\": true; this declaration keeps the false every accepted "
              "fixture under testdata/fixtures uses, so that pm3 cannot be answered by a cache. The upload status "
              "also answers whether the PAP takes a MAPPING PIP at all.",
        pips=["permissions"])
    iso(f, "PM2", "pm2-mapping-pip-suffixed-reference", "subject.permissions.PARITY CONTAINS 'parity_permission'",
        [("reader", {})],
        about="Whether a policy can read one mapping PIP by its own name, or only the merged list pm1 reads.",
        pips=["permissions"])
    iso(f, "PM3", "pm3-mapping-pip-after-declaration-removed", "subject.permissions CONTAINS 'parity_permission'",
        [("reader", {})],
        about="pm1's question with the declaration withdrawn: the upload of each case replaces the domain's PIPs, so "
              "by now PARITY_ISOLATED holds none. A false answer scopes the mapping to the declaration that carried "
              "it; a true one means it outlived that declaration, and the permission granted here is visible to "
              "every case of the tenant that reads subject.permissions. permission-policy-target records false for "
              "the same permission and the same role, so a true answer here is worth checking against that golden "
              "after the run. The case reads what pm1 uploaded and has to run after it, which the order of the "
              "cases gives it.")
    iso(f, "U12", "u12-subject-denied", "subject denied 'READ' on resource", [("reader", {})],
        about="The access operator has a denied form as well as the allowed form recorded in u7, which the PAP "
              "accepts and which is false on this stand because no entitlement source backs it.")

    words = ("Only GREATER THAN OR EQUAL TO is recorded (x4), and the parser takes OR EQUALS TO as well as OR EQUAL "
             "TO. The case sends the boundary and its neighbor, so a form the evaluator maps to a different operator "
             "is visible.")
    for letter, cid, condition, neighbor, value in (
        ("W1", "w1-greater-than-words", "resource.n GREATER THAN 5", "above-boundary", 6),
        ("W2", "w2-less-than-words", "resource.n LESS THAN 5", "below-boundary", 4),
        ("W3", "w3-less-than-or-equal-words", "resource.n LESS THAN OR EQUAL TO 5", "above-boundary", 6),
        ("W4", "w4-greater-than-or-equals-to-words", "resource.n GREATER THAN OR EQUALS TO 5", "below-boundary", 4),
        ("W5", "w5-less-than-or-equals-to-words", "resource.n LESS THAN OR EQUALS TO 5", "above-boundary", 6),
    ):
        iso(f, letter, cid, condition, [("boundary", {"n": 5}), (neighbor, {"n": value})], about=words)

    iso(f, "X32", "x32-single-equal-sign", "resource.x = 'v'", [
        ("attribute-matches", {"x": "v"}),
        ("attribute-differs", {"x": "w"}),
    ], about="EQUALS and == are recorded (x2, x1), and the single equals sign the parser also accepts is not.")
    iso(f, "X33", "x33-condition-literal-false", "FALSE", [("any-resource", {})],
        about="TRUE as a whole condition is recorded (x10), and FALSE is not.")
    iso(f, "X34", "x34-regex-literal", "resource.x MATCH /ab.*/", [
        ("pattern-matches", {"x": "abc"}),
        ("pattern-does-not-match", {"x": "zzz"}),
    ], about="The parser reads /…/ as a regex literal and hands it on as a plain string. MATCH with an unquoted "
             "wildcard is recorded (x5) and with a quoted one is refused (x6), so this is the third spelling.")

    numbers = ("Equality compares through the string form, so 5.0 does not equal 5 (c1); the relational operators "
               "compare numerically, so the string \"10\" is greater than 5 (c3, in the round 2 semantics cases, where "
               "a string comparison would answer false). No other case puts a sign or a fraction in the literal "
               "itself.")
    iso(f, "C10", "c10-negative-number-equals", "resource.n == -5", [
        ("exact", {"n": Num("-5")}),
        ("same-magnitude-positive", {"n": Num("5")}),
    ], about=numbers)
    iso(f, "C11", "c11-decimal-number-equals", "resource.n == 5.5", [
        ("exact", {"n": Num("5.5")}),
        ("string", {"n": "5.5"}),
        ("trailing-zero", {"n": Num("5.50")}),
    ], about=numbers)
    iso(f, "C12", "c12-greater-than-negative", "resource.n > -5", [
        ("above-boundary", {"n": Num("-4")}),
        ("below-boundary", {"n": Num("-10")}),
    ], about=numbers)

    jsonpath = ("resource.list[0] and resource.items[*].id both work (j5, j6), while resource['x'] is accepted and "
                "answers false (j7). The case pairs a resource the path selects with one it does not, so that an "
                "accepted path nobody evaluates reads as two false answers.")
    iso(f, "J9", "j9-jsonpath-filter-expression", "resource.items[?(@.type=='a')].id CONTAINS 'x'", [
        ("selected-item-has-the-id", {"items": [{"type": "a", "id": "x"}, {"type": "b", "id": "y"}]}),
        ("the-id-is-on-the-other-item", {"items": [{"type": "a", "id": "y"}, {"type": "b", "id": "x"}]}),
    ], about=jsonpath)
    iso(f, "J10", "j10-jsonpath-recursive-descent", "resource..code CONTAINS 'x'", [
        ("nested-code", {"o": {"code": "x"}}),
        ("no-code-anywhere", {"o": {"other": "x"}}),
    ], about=jsonpath)

    filtered = ("The FILTERED PIP. The agent drops the pipType on the pull path (internal/acconfig/convert.go) and "
                "refuses it on the mount path (internal/pips/validate.go), and neither the type nor the condition "
                "form that passes it an argument appears in any fixture. The three h cases separate the two: whether "
                "the declaration is accepted, whether the form is accepted on a PIP that has the type, and whether "
                "the form is accepted on one that does not. subject.parityFilteredList declares a FILTERED PIP with "
                "the fields of an accepted GENERAL one, so that a refusal is about the pipType rather than about a "
                "field the declaration left out; no fixture has made the PAP accept this pipType and the field set "
                "it requires is unknown, so the case records the upload status. subject.parityList is a GENERAL PIP "
                "returning a collection, shaped like the accepted declarations under testdata/fixtures, so that h5 "
                "measures the FILTERED condition form against a pipType the PAP is known to take.")
    iso(f, "H3", "h3-filtered-pip-plain-reference", "subject.parityFilteredList CONTAINS 'red'", [("reader", {})],
        about=filtered, pips=["filtered"])
    iso(f, "H4", "h4-filtered-pip-filtered-form", "subject.parityFilteredList FILTERED 'red' CONTAINS 'red'",
        [("reader", {})], about=filtered, pips=["filtered"])
    iso(f, "H5", "h5-filtered-form-on-general-pip", "subject.parityList FILTERED 'red' CONTAINS 'red'",
        [("reader", {})], about=filtered, pips=["list"])
    return f


def rule(key, target, condition, effect, predicates=None):
    r = {"key": key, "target": target, "condition": condition, "effect": effect}
    if predicates:
        r["predicates"] = predicates
    return r


def policy(key, algorithm, *rules, target=READER_TARGET):
    p = {"key": key, "target": target}
    if algorithm:
        p["algorithm"] = algorithm
    p["rules"] = list(rules)
    return p


def set_(key, algorithm, *policies, target=SET_TARGET, sets=None):
    s = {"key": key, "target": target}
    if algorithm:
        s["algorithm"] = algorithm
    s["policies"] = list(policies)
    if sets:
        s["sets"] = sets
    return s


def regular(cid, sets, requests, about=None):
    case = {"id": cid}
    if about:
        case["about"] = about
    case["sets"] = sets
    case["requests"] = requests
    return case


def regular_policy_set():
    f = File("regular-policy-set",
             "How access-control evaluates regular policy sets: the nested policy set, policy, and rule format with "
             "targets, combining algorithms, ALLOW and DENY effects, and four predicate kinds. The agent loads "
             "simplified policies only, so the cases record access-control's answers as the behavior an evaluator "
             "of regular sets has to reproduce, and run on the legacy profile only. Each case records the status of "
             "its upload and, when it was accepted, the status and the answer of every request. The resource types "
             "are the case's own, and the sets are emptied when the test ends. TestRegularPolicySetCases runs four "
             "more cases in Go after these: a set beside a simplified policy in a filter, an inactive set, a second "
             "upload under the same external id, and two external ids for one resource type.",
             REGULAR_PREFIX)

    algorithm_about = ("One case per combining algorithm name, used at both the set and the policy level. Each "
                       "operation meets a different mix of rules: READ an ALLOW before a DENY, UPDATE a DENY before "
                       "an ALLOW, DELETE a DENY alone, CREATE no rule, APPROVE an ALLOW whose condition reads a "
                       "missing attribute beside an ALLOW, REJECT such a DENY beside an ALLOW. The absent and unknown "
                       "names record what the PAP does without a valid algorithm.")
    resource = {"id": "reg-alg"}
    for key, name in (
        ("deny-unless-permit", "DENY_UNLESS_PERMIT"),
        ("permit-unless-deny", "PERMIT_UNLESS_DENY"),
        ("deny-overrides", "DENY_OVERRIDES"),
        ("permit-overrides", "PERMIT_OVERRIDES"),
        ("first-applicable", "FIRST_APPLICABLE"),
        ("only-one-applicable", "ONLY_ONE_APPLICABLE"),
        ("ordered-deny-overrides", "ORDERED_DENY_OVERRIDES"),
        ("ordered-permit-overrides", "ORDERED_PERMIT_OVERRIDES"),
        ("absent", ""),
        ("unknown", "PARITY_NO_SUCH_ALGORITHM"),
    ):
        f.add(regular("algorithm-" + key, [set_("set", name, policy(
            "reader", name,
            rule("read-allow", "operation == 'READ'", "true", "ALLOW"),
            rule("read-deny", "operation == 'READ'", "true", "DENY"),
            rule("update-deny", "operation == 'UPDATE'", "true", "DENY"),
            rule("update-allow", "operation == 'UPDATE'", "true", "ALLOW"),
            rule("delete-deny", "operation == 'DELETE'", "true", "DENY"),
            rule("approve-allow-missing-attribute", "operation == 'APPROVE'", "resource.x == 'v'", "ALLOW"),
            rule("approve-allow", "operation == 'APPROVE'", "true", "ALLOW"),
            rule("reject-deny-missing-attribute", "operation == 'REJECT'", "resource.x == 'v'", "DENY"),
            rule("reject-allow", "operation == 'REJECT'", "true", "ALLOW"),
        ))], [
            req("read-allow-then-deny", resource, operation="READ"),
            req("update-deny-then-allow", resource, operation="UPDATE"),
            req("delete-deny-alone", resource, operation="DELETE"),
            req("create-no-rule", resource, operation="CREATE"),
            req("approve-failed-allow-beside-allow", resource, operation="APPROVE"),
            req("reject-failed-deny-beside-allow", resource, operation="REJECT"),
        ], about=algorithm_about))

    for key, name in (("permit-overrides", "PERMIT_OVERRIDES"), ("deny-unless-permit", "DENY_UNLESS_PERMIT")):
        f.add(regular("nested-outer-deny-inner-allow-" + key, [set_(
            "outer", name,
            policy("outer-reader", "DENY_UNLESS_PERMIT", rule("outer-read-deny", "operation == 'READ'", "true", "DENY")),
            sets=[set_("inner", "DENY_UNLESS_PERMIT",
                       policy("inner-reader", "DENY_UNLESS_PERMIT",
                              rule("inner-read-allow", "operation == 'READ'", "true", "ALLOW")))],
        )], [req("read", {"id": "reg-nested"})],
            about="A DENY in the outer set against an ALLOW in a nested set, under two outer algorithms."))

    missing = ("A missing attribute in the target of a set, a policy, or a rule, beside a sibling at the same level "
               "that allows when resource.s is 'y'.")
    f.add(regular("missing-attribute-in-set-target", [
        set_("reads-missing", "DENY_UNLESS_PERMIT",
             policy("reader", "DENY_UNLESS_PERMIT", rule("read-allow", "operation == 'READ'", "true", "ALLOW")),
             target=SET_TARGET + " AND resource.x == 'v'"),
        set_("sibling", "DENY_UNLESS_PERMIT",
             policy("reader", "DENY_UNLESS_PERMIT",
                    rule("read-allow-when-s", "operation == 'READ'", "resource.s == 'y'", "ALLOW"))),
    ], [
        req("sibling-allows", {"id": "reg-set-target", "s": "y"}),
        req("both-attributes-present", {"id": "reg-set-target", "x": "v", "s": "n"}),
    ], about=missing + " Both policies are built from the key reader, so they carry one policyId, and the recorded "
                       "400 is as likely the shared id as the target; TestRound7SetTargetRefusalCases separates the "
                       "two, and the fixture stays as recorded."))
    f.add(regular("missing-attribute-in-policy-target", [set_(
        "set", "DENY_UNLESS_PERMIT",
        policy("reads-missing", "DENY_UNLESS_PERMIT", rule("read-allow", "operation == 'READ'", "true", "ALLOW"),
               target=READER_TARGET + " AND resource.x == 'v'"),
        policy("sibling", "DENY_UNLESS_PERMIT",
               rule("read-allow-when-s", "operation == 'READ'", "resource.s == 'y'", "ALLOW")),
    )], [req("sibling-allows", {"id": "reg-policy-target", "s": "y"})], about=missing))
    f.add(regular("missing-attribute-in-rule-target", [set_(
        "set", "DENY_UNLESS_PERMIT",
        policy("reader", "DENY_UNLESS_PERMIT",
               rule("reads-missing", "operation == 'READ' AND resource.x == 'v'", "true", "ALLOW"),
               rule("sibling", "operation == 'READ'", "resource.s == 'y'", "ALLOW")),
    )], [req("sibling-allows", {"id": "reg-rule-target", "s": "y"})], about=missing))

    f.add(regular("deny-target-false-against-condition-false", [set_(
        "set", "PERMIT_UNLESS_DENY",
        policy("reader", "PERMIT_UNLESS_DENY",
               rule("read-deny-condition", "operation == 'READ'", "resource.flag == 'on'", "DENY"),
               rule("update-deny-target", "operation == 'UPDATE' AND resource.flag == 'on'", "true", "DENY")),
    )], [
        req("read-condition-false", {"id": "reg-tc", "flag": "off"}, operation="READ"),
        req("update-target-false", {"id": "reg-tc", "flag": "off"}, operation="UPDATE"),
    ], about="A DENY rule whose target is false against one whose condition is false, under PERMIT_UNLESS_DENY: "
             "whether the two count as not applicable alike."))

    f.add(regular("two-deny-lists-in-one-set", [set_(
        "set", "DENY_UNLESS_PERMIT",
        policy("denies-alpha", "PERMIT_UNLESS_DENY",
               rule("alpha", "operation == 'READ'", "resource.area == 'alpha'", "DENY"),
               rule("alpha-shared", "operation == 'READ'", "resource.area == 'shared'", "DENY")),
        policy("denies-beta", "PERMIT_UNLESS_DENY",
               rule("beta", "operation == 'READ'", "resource.area == 'beta'", "DENY"),
               rule("beta-shared", "operation == 'READ'", "resource.area == 'shared'", "DENY")),
    )], [
        req("denied-by-the-alpha-list", {"id": "reg-two-lists", "area": "alpha"}),
        req("denied-by-the-beta-list", {"id": "reg-two-lists", "area": "beta"}),
        req("denied-by-both-lists", {"id": "reg-two-lists", "area": "shared"}),
        req("denied-by-neither-list", {"id": "reg-two-lists", "area": "open"}),
    ], about="Two PERMIT_UNLESS_DENY policies with deny lists of their own under one DENY_UNLESS_PERMIT set. Product "
             "policies ship that shape for a service whose endpoints are open except for a few, and split the "
             "exceptions over two policies. Each policy permits whatever its own list does not deny, so a set that "
             "takes the permit of either one lets the second policy cancel the first policy's denial. The alpha and "
             "beta requests record that; shared, denied by both lists, and open, denied by neither, fix the other "
             "two columns. one-deny-list-in-one-set is the control."))
    f.add(regular("one-deny-list-in-one-set", [set_(
        "set", "DENY_UNLESS_PERMIT",
        policy("denies-both", "PERMIT_UNLESS_DENY",
               rule("alpha", "operation == 'READ'", "resource.area == 'alpha'", "DENY"),
               rule("beta", "operation == 'READ'", "resource.area == 'beta'", "DENY"),
               rule("shared", "operation == 'READ'", "resource.area == 'shared'", "DENY")),
    )], [
        req("denied-by-the-single-list", {"id": "reg-one-list", "area": "alpha"}),
        req("denied-by-no-entry", {"id": "reg-one-list", "area": "open"}),
    ], about="The control for two-deny-lists-in-one-set: the same deny list in one policy. Here alpha meets a single "
             "PERMIT_UNLESS_DENY verdict with nothing to combine it with, so a request the two-policy case answers "
             "differently is answered by the set level rather than by the rules."))

    styles = "A policy or rule style that simplified policies do not produce."
    f.add(regular("permission-policy-target", [set_(
        "set", "DENY_UNLESS_PERMIT",
        policy("permission", "DENY_UNLESS_PERMIT", rule("read-allow", "operation == 'READ'", "true", "ALLOW"),
               target="subject.permissions CONTAINS 'parity_permission'"),
    )], [req("reader-without-permission", {"id": "reg-permission"})], about=styles))
    f.add(regular("bare-resource-condition", [set_(
        "set", "DENY_UNLESS_PERMIT",
        policy("reader", "DENY_UNLESS_PERMIT",
               rule("show-element", "operation == 'SHOW'", "resource == 'parity:ui:element'", "ALLOW")),
    )], [
        req("matching-element", "parity:ui:element", operation="SHOW"),
        req("other-element", "parity:ui:other", operation="SHOW"),
    ], about=styles))
    f.add(regular("method-name-operation", [set_(
        "set", "DENY_UNLESS_PERMIT",
        policy("reader", "DENY_UNLESS_PERMIT",
               rule("method", "operation == 'ParityController.getThing'", "true", "ALLOW")),
    )], [
        req("same-name", {"id": "reg-method"}, operation="ParityController.getThing"),
        req("other-case", {"id": "reg-method"}, operation="paritycontroller.getthing"),
    ], about=styles))

    def all_kinds(field):
        return {
            "predicate": "${resourceType}." + field + ".eq(\"1\")",
            "rsqlPredicate": field + "==1",
            "sqlPredicate": field + "=1",
            "mongodbPredicate": "{ \"" + field + "\": 1 }",
        }

    filters = ("Filters: how the predicates of several rules, of a DENY rule, of a rule whose condition is false, "
               "and of nested sets combine.")
    f.add(regular("filter-two-allow-rules", [set_(
        "set", "DENY_UNLESS_PERMIT",
        policy("reader", "DENY_UNLESS_PERMIT",
               rule("first", "operation == 'LIST'", "true", "ALLOW", all_kinds("a")),
               rule("second", "operation == 'LIST'", "true", "ALLOW", all_kinds("b"))),
    )], [req("filter", filter=True)], about=filters))
    f.add(regular("filter-allow-and-deny-rules", [set_(
        "set", "DENY_UNLESS_PERMIT",
        policy("reader", "DENY_UNLESS_PERMIT",
               rule("allow", "operation == 'LIST'", "true", "ALLOW", {"rsqlPredicate": "a==1"}),
               rule("deny", "operation == 'LIST'", "true", "DENY", {"rsqlPredicate": "b==2"})),
    )], [req("filter", filter=True)], about=filters))
    f.add(regular("filter-allow-rule-condition-false", [set_(
        "set", "DENY_UNLESS_PERMIT",
        policy("reader", "DENY_UNLESS_PERMIT",
               rule("condition-false", "operation == 'LIST'", "false", "ALLOW", {"rsqlPredicate": "a==1"}),
               rule("condition-true", "operation == 'LIST'", "true", "ALLOW", {"rsqlPredicate": "b==2"})),
    )], [req("filter", filter=True)], about=filters))
    f.add(regular("filter-nested-sets", [set_(
        "outer", "DENY_UNLESS_PERMIT",
        policy("outer-reader", "DENY_UNLESS_PERMIT",
               rule("outer-list", "operation == 'LIST'", "true", "ALLOW", {"rsqlPredicate": "outer==1"})),
        sets=[set_("inner", "DENY_UNLESS_PERMIT",
                   policy("inner-reader", "DENY_UNLESS_PERMIT",
                          rule("inner-list", "operation == 'LIST'", "true", "ALLOW", {"rsqlPredicate": "inner==1"})))],
    )], [req("filter", filter=True)], about=filters))
    return f


if __name__ == "__main__":
    for build in (isolated_policy, isolated_condition_form, regular_policy_set):
        build().write()
