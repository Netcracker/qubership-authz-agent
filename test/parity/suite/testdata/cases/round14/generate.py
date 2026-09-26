"""Writes the round 14 case files next to this script: python3 generate.py.

Each file is one test function of the parity suite, recorded on a stand of its own, in the format case_files_test.go
reads. The cases ask for forms of the condition language no golden has recorded yet:

  operand-kind.json  what value or state each kind of operand gives, on the left and on the right
  right-state.json   the right operand in each special state under every binary operator
  value.json         every operator over resource.x of many JSON types against literals of several types
  syntax.json        operand pairs the PAP may refuse, and lexical forms of operators and literals
  jsonpath.json      jsonPath forms beyond a key, [n] and [?(@.k == 'v')]
  target.json        a failed PIP, an absent attribute, and subject.permissionScope outside iterate in each target

A condition whose id ends in -alone is the comparison by itself; one ending in -or stands on the left of
OR resource.a == 'y', so that true tells a false comparison from a rule the comparison ended.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
READER = {"id": "00000000-0000-0000-0000-000000000101", "name": "parity-reader", "type": "USER"}
READER_TARGET = "subject.roles CONTAINS 'ROLE_PARITY_READER'"


def general_pip(name, route):
    return {"name": name, "url": "http://pip-mock:8090" + route, "httpMethod": "POST", "pipType": "GENERAL",
            "requestAttributes": {"case": name}, "cacheable": False}


ROUTES = {"string": "/api/v1/pip/r14-string", "list": "/api/v1/pip/r14-list",
          "nullbody": "/api/v1/pip/r14-null-body", "failing": "/api/v1/pip/r14-failing"}
PINS = {
    "string": {"statusCode": 200, "body": "v"},
    "list": {"statusCode": 200, "body": ["v", "w"]},
    "nullbody": {"statusCode": 200, "bodyRaw": "null"},
    "failing": {"statusCode": 500, "body": {"error": "parity round 14 case"}},
}
PIPS = {
    "noheader": {"name": "subject.parityNoHeader", "type": "UUID", "pipType": "HEADER",
                 "header": "x-parity-no-such-header", "cacheable": False},
    "string": general_pip("subject.parityR14String", ROUTES["string"]),
    "list": general_pip("subject.parityR14List", ROUTES["list"]),
    "nullbody": general_pip("subject.parityR14NullBody", ROUTES["nullbody"]),
    "failing": general_pip("subject.parityR14Failing", ROUTES["failing"]),
    "m2m": general_pip("subject.isM2M", ROUTES["string"]),
    "token": {"name": "subject.parityR14Department", "type": "UUID", "pipType": "TOKEN", "claim": "department",
              "cacheable": False},
    "tokenlist": {"name": "subject.parityR14Roles", "type": "UUID", "pipType": "TOKEN",
                  "claim": "$.realm_access.roles", "cacheable": False},
    "scope": {"name": "subject.permissionScope", "pipType": "PERMISSION_SCOPE", "url": "http://pip-mock:8090",
              "cacheable": False, "cachePeriod": 1},
}
ROUTE_OF_PIP = {"string": "string", "list": "list", "nullbody": "nullbody", "failing": "failing", "m2m": "string"}


class Group:
    """The cases of one file."""

    def __init__(self, name, pips, about):
        self.name, self.pips, self.about, self.cases = name, pips, about, []

    def add(self, cid, cond, requests, pips=(), about=None):
        self._append({"id": cid, "about": about, "condition": cond, "pips": list(pips), "requests": requests})

    def add_sets(self, cid, sets, requests, pips=(), about=None):
        self._append({"id": cid, "about": about, "pips": list(pips), "sets": sets, "requests": requests})

    def _append(self, case):
        assert all(c["id"] != case["id"] for c in self.cases), case["id"]
        assert all(p in self.pips for p in case["pips"]), case["id"]
        for key in ("about", "pips"):
            if not case[key]:
                del case[key]
        self.cases.append(case)

    def write(self):
        pins = {ROUTES[ROUTE_OF_PIP[k]]: PINS[ROUTE_OF_PIP[k]] for k in self.pips if k in ROUTE_OF_PIP}
        doc = {"about": self.about, "resourceTypePrefix": "PARITY_SUITE_R14_", "pins": pins, "pips": {k: PIPS[k] for k in self.pips},
               "cases": self.cases}
        with open(os.path.join(HERE, self.name + ".json"), "w") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
            f.write("\n")


def req(name, **res):
    return {"name": name, "resource": res}


def deny_rule_tree(condition):
    """A PERMIT_UNLESS_DENY set of one PERMIT_UNLESS_DENY policy whose one DENY rule has condition."""
    return [{"key": "set", "target": "resourceType == '{{resourceType}}'", "algorithm": "PERMIT_UNLESS_DENY",
             "policies": [{"key": "reader", "target": READER_TARGET, "algorithm": "PERMIT_UNLESS_DENY",
                           "rules": [{"key": "deny", "target": "true", "condition": condition, "effect": "DENY"}]}]}]


# ---------------------------------------------------------------------------------------------------------------
# ok: operand kinds
# ---------------------------------------------------------------------------------------------------------------
ok = Group("operand-kind", ["string", "token", "list", "tokenlist"], (
    "What value or state each kind of operand gives: subject.id, name, type, and serviceAccount, resourceType, the "
    "whole resource, literals, GENERAL and TOKEN PIPs, subject.roles and scopes, and lists from a GENERAL and a TOKEN "
    "PIP. Each kind stands on the left of every operator it may stand on and on the right of the comparison, "
    "membership, and containment operators. The request carries in x the value the operand is expected to give."))
SINGLE = [  # (slug, operand, value it should give, pips)
    ("subject-id", "subject.id", READER["id"], ()),
    ("subject-name", "subject.name", READER["name"], ()),
    ("subject-type", "subject.type", READER["type"], ()),
    ("general-string", "subject.parityR14String", "v", ("string",)),
    ("token-claim", "subject.parityR14Department", "finance", ("token",)),
]
for slug, o, v, pips in SINGLE:
    pre = v[:3]
    for form, cond in [
        ("equals", f"{o} == '{v}'"), ("not-equals", f"{o} != '{v}'"), ("equals-other", f"{o} == 'zz'"),
        ("is-null", f"{o} IS NULL"), ("is-not-null", f"{o} IS NOT NULL"), ("match", f"{o} MATCH {pre}*"),
        ("in", f"{o} IN '{v}', 'zz'"), ("not-in", f"{o} NOT IN '{v}', 'zz'"), ("greater-than", f"{o} > 5"),
        ("on-the-right", f"resource.x == {o}"), ("on-the-right-not-equals", f"resource.x != {o}"),
        ("on-the-right-of-less-than", f"resource.x < {o}"), ("literal-on-the-left", f"'{v}' == {o}"),
    ] + ([("on-the-right-of-in", f"resource.x IN {o}"), ("on-the-right-of-not-in", f"resource.x NOT IN {o}")]
         if pips else []):
        ok.add(f"ok-{slug}-{form}", cond, [req("probe", id="r14", x=v, a="y")], pips)
# subject.serviceAccount gives null for a user
for form, cond in [("is-null", "subject.serviceAccount IS NULL"), ("is-not-null", "subject.serviceAccount IS NOT NULL"),
                   ("equals-or", "subject.serviceAccount == 'v' OR resource.a == 'y'"),
                   ("not-equals", "subject.serviceAccount != 'v'"),
                   ("on-the-right-or", "resource.x == subject.serviceAccount OR resource.a == 'y'")]:
    ok.add(f"ok-subject-service-account-{form}", cond, [req("probe", id="r14", x="v", a="y")])
# resourceType: its value is the case's own resource type
for form, tmpl in [("equals", "resourceType == '{rt}'"), ("equals-lower-case", "resourceType == '{rtl}'"),
                   ("match", "resourceType MATCH PARITY_SUITE_R14_*"), ("in", "resourceType IN '{rt}', 'zz'"),
                   ("on-the-right", "resource.x == resourceType"), ("literal-on-the-left", "'{rt}' == resourceType"),
                   ("is-null", "resourceType IS NULL")]:
    ok.add(f"ok-resource-type-{form}", tmpl.format(rt="{{resourceType}}", rtl="{{resourceTypeLowerCase}}"),
           [req("probe", id="r14", x="{{resourceType}}", a="y")])
# resource: the whole resource object
for form, cond in [("is-null", "resource IS NULL"), ("is-not-null", "resource IS NOT NULL"),
                   ("equals-or", "resource == 'v' OR resource.a == 'y'"),
                   ("not-equals-or", "resource != 'v' OR resource.a == 'y'"),
                   ("greater-than-or", "resource > 5 OR resource.a == 'y'"),
                   ("in-or", "resource IN 'v', 'w' OR resource.a == 'y'"),
                   ("on-the-right-or", "resource.x == resource OR resource.a == 'y'")]:
    ok.add(f"ok-whole-resource-{form}", cond, [req("probe", id="r14", x="v", a="y")])
# literals on the left of every operator that allows them
for form, cond in [("string-equals", "'v' == resource.x"), ("string-not-equals", "'v' != resource.x"),
                   ("number-less-than", "4 < resource.n"), ("number-greater-than", "6 > resource.n"),
                   ("string-in", "'v' IN resource.l"), ("string-not-in", "'v' NOT IN resource.l"),
                   ("string-is-null", "'v' IS NULL"), ("string-is-not-null", "'v' IS NOT NULL"),
                   ("two-literals-less-than", "4 < 5"), ("two-strings-less-than", "'a' < 'b'"),
                   ("number-equals-string", "5 == resource.x")]:
    ok.add(f"ok-literal-{form}", cond, [req("probe", id="r14", x="v", n=5, l=["v", "w"], a="y")])
# multi-valued operands
MULTI = [
    ("subject-roles", "subject.roles", "ROLE_PARITY_READER", "ROLE_PARITY_OTHER", ()),
    ("subject-scopes", "subject.scopes", "openid", "zz", ()),
    ("general-list", "subject.parityR14List", "v", "w", ("list",)),
    ("token-list", "subject.parityR14Roles", "ROLE_PARITY_READER", "zz", ("tokenlist",)),
]
for slug, o, v1, v2, pips in MULTI:
    for form, cond in [
        ("contains", f"{o} CONTAINS '{v1}'"), ("not-contains", f"{o} NOT CONTAINS '{v1}'"),
        ("contains-other", f"{o} CONTAINS 'zz'"), ("contains-any", f"{o} CONTAINS ANY '{v1}', 'zz'"),
        ("not-contains-any", f"{o} NOT CONTAINS ANY 'zz', 'yy'"), ("is-subset", f"{o} IS SUBSET '{v1}', '{v2}', 'zz'"),
        ("is-not-subset", f"{o} IS NOT SUBSET 'zz'"), ("is-empty", f"{o} IS EMPTY"),
        ("is-not-empty", f"{o} IS NOT EMPTY"), ("in-on-the-right", f"resource.x IN {o}"),
        ("contains-any-on-the-right", f"resource.l CONTAINS ANY {o}"),
        ("is-subset-on-the-right", f"resource.l IS SUBSET {o}"), ("contains-on-the-right", f"resource.l CONTAINS {o}"),
        ("not-in-on-the-right", f"resource.x NOT IN {o}"), ("not-contains-on-the-right", f"resource.l NOT CONTAINS {o}"),
        ("equals-on-the-right", f"resource.x == {o}"), ("not-equals-on-the-right", f"resource.x != {o}"),
    ]:
        ok.add(f"ok-{slug}-{form}", cond, [req("probe", id="r14", x=v1, l=[v1], a="y")], pips)

# ---------------------------------------------------------------------------------------------------------------
# rs: the right operand in a special state
# ---------------------------------------------------------------------------------------------------------------
rs = Group("right-state", ["noheader", "nullbody", "failing"], (
    "What every binary operator gives when its right operand is an absent key, null, [], an empty JSON Path selection, "
    "an index past the end, a HEADER PIP without its header, a GENERAL PIP whose body is null, or a GENERAL PIP that "
    "answers 500. The prefixes ra, rx, re, rs, ro, rh, rn and rf name those states in that order. A case ending in "
    "-alone is the comparison by itself; one ending in -or stands on the left of OR resource.a == 'y', so true tells a "
    "false comparison from a rule the comparison ended. The r14-*-in-a-deny-rule-* cases tell an ended rule from a "
    "failed answer."))
OPS = [("equals", "=="), ("not-equals", "!="), ("less-than", "<"), ("less-or-equal", "<="), ("greater-than", ">"),
       ("greater-or-equal", ">="), ("in", "IN"), ("not-in", "NOT IN"), ("contains", "CONTAINS"),
       ("not-contains", "NOT CONTAINS"), ("contains-any", "CONTAINS ANY"), ("not-contains-any", "NOT CONTAINS ANY"),
       ("is-subset", "IS SUBSET"), ("is-not-subset", "IS NOT SUBSET"), ("match", "MATCH"), ("not-match", "NOT MATCH")]
LEFT = {"==": "resource.v", "!=": "resource.v", "IN": "resource.v", "NOT IN": "resource.v", "MATCH": "resource.v",
        "NOT MATCH": "resource.v", "<": "resource.n", "<=": "resource.n", ">": "resource.n", ">=": "resource.n"}
STATES = [  # (prefix, right operand, extra resource fields, pips)
    ("ra", "resource.x", {}, ()),
    ("rx", "resource.x", {"x": None}, ()),
    ("re", "resource.x", {"x": []}, ()),
    ("rs", "resource.items[?(@.type=='zzz')].id", {"items": [{"type": "a", "id": "q"}]}, ()),
    ("ro", "resource.list[5]", {"list": ["a"]}, ()),
    ("rh", "subject.parityNoHeader", {}, ("noheader",)),
    ("rn", "subject.parityR14NullBody", {}, ("nullbody",)),
    ("rf", "subject.parityR14Failing", {}, ("failing",)),
]
for pfx, right, extra, pips in STATES:
    for slug, op in OPS:
        left = LEFT.get(op, "resource.l")
        for form, cond in [("alone", f"{left} {op} {right}"), ("or", f"{left} {op} {right} OR resource.a == 'y'")]:
            cid = f"{pfx}-{slug}-{form}"
            rs.add(cid, cond, [req("probe", id="r14-" + cid, v="v", n=5, l=["v"], a="y", **extra)], pips)
# a null body under IS NOT EMPTY on the left of a true OR; an earlier round asked it alone
rs.add("cn-is-not-empty-or", "subject.parityR14NullBody IS NOT EMPTY OR resource.a == 'y'",
       [req("probe", id="r14-cn-is-not-empty-or", a="y")], ("nullbody",),
       "IS NOT EMPTY over a GENERAL PIP whose body is null, beside a true OR: true says the operand was false, false "
       "that it ended the rule. Round 13 asked the operator alone (cn-is-not-empty-alone), where both read false.")

# An absent key, an index past the end, and a failed PIP on the right read false in both forms whether they end the
# rule or fail the answer, so each also goes into a DENY rule under PERMIT_UNLESS_DENY. Read with the -alone case of
# the same comparison, which says whether it could be true: true here says the rule ended alone, false that the answer
# failed or the comparison held.
for state, right in [("absent-key", "resource.x"), ("index-past-the-end", "resource.list[5]"),
                     ("failing-pip", "subject.parityR14Failing")]:
    for slug, op in OPS:
        cid = f"r14-{state}-on-the-right-in-a-deny-rule-{slug}"
        rs.add_sets(cid, deny_rule_tree(f"{LEFT.get(op, 'resource.l')} {op} {right}"),
                    [req("read", id="r14-right-state", v="v", n=5, l=["v"], list=["a"])], ("failing",),
                    "The only DENY rule of a PERMIT_UNLESS_DENY policy: true says the comparison ended its rule alone, "
                    "false that it failed the answer or held; the -alone case of the same comparison says whether it "
                    "could hold.")

# ---------------------------------------------------------------------------------------------------------------
# vm: value types
# ---------------------------------------------------------------------------------------------------------------
vm = Group("value", [], (
    "What every operator gives over resource.x of each JSON type against literals of several types: strings in several "
    "spellings, integers, a negative, decimals including the JSON number 5.0, booleans, lists of strings, integers, "
    "mixed and nested values, an object, and a list of objects. Each condition runs alone and on the left of "
    "OR resource.a == 'y', and each request names the value it sends."))
VALUES = [  # (request name, JSON value of resource.x); decimal-integral is written as 5.0, not 5
    ("string", "v"), ("upper-case-string", "V"), ("numeric-string", "5"), ("decimal-string", "5.0"),
    ("empty-string", ""), ("integer", 5), ("other-integer", 6), ("negative", -5), ("decimal", 5.5),
    ("decimal-integral", 5.0), ("true", True), ("false", False), ("string-list", ["v", "w"]),
    ("integer-list", [5, 6]), ("mixed-list", ["v", 5]), ("nested-list", [["v"]]), ("object", {"k": "v"}),
    ("object-list", [{"k": "v"}]),
]
VM = [  # (slug, operator, right side)
    ("equals-string", "==", "'v'"), ("equals-integer", "==", "5"), ("equals-decimal", "==", "5.5"),
    ("equals-negative", "==", "-5"), ("equals-true", "==", "true"),
    ("not-equals-string", "!=", "'v'"), ("not-equals-integer", "!=", "5"),
    ("less-than-integer", "<", "6"), ("less-than-decimal", "<", "5.6"), ("less-than-string", "<", "'6'"),
    ("greater-or-equal-integer", ">=", "5"), ("greater-or-equal-decimal", ">=", "5.5"),
    ("greater-or-equal-string", ">=", "'5'"), ("less-or-equal-integer", "<=", "5"),
    ("greater-than-integer", ">", "4"),
    ("in-strings", "IN", "'v', 'w'"), ("in-numbers", "IN", "5, 6"), ("not-in-strings", "NOT IN", "'v', 'w'"),
    ("contains-string", "CONTAINS", "'v'"), ("contains-integer", "CONTAINS", "5"),
    ("not-contains-string", "NOT CONTAINS", "'v'"),
    ("contains-any-strings", "CONTAINS ANY", "'v', 'z'"), ("contains-any-numbers", "CONTAINS ANY", "5, 7"),
    ("not-contains-any-strings", "NOT CONTAINS ANY", "'v', 'z'"),
    ("is-subset-strings", "IS SUBSET", "'v', 'w', 'z'"), ("is-subset-numbers", "IS SUBSET", "5, 6, 7"),
    ("is-not-subset-strings", "IS NOT SUBSET", "'v', 'w', 'z'"),
    ("match", "MATCH", "v*"), ("not-match", "NOT MATCH", "v*"),
    ("is-null", "IS NULL", None), ("is-not-null", "IS NOT NULL", None),
    ("is-empty", "IS EMPTY", None), ("is-not-empty", "IS NOT EMPTY", None),
]
for slug, op, right in VM:
    base = f"resource.x {op}" + (f" {right}" if right is not None else "")
    for form, cond in [("alone", base), ("or", base + " OR resource.a == 'y'")]:
        cid = f"vm-{slug}-{form}"
        vm.add(cid, cond, [req(n, id="r14-" + cid, x=v, a="y") for n, v in VALUES])

# ---------------------------------------------------------------------------------------------------------------
# sx: operand pairs the PAP may refuse, and lexical forms
# ---------------------------------------------------------------------------------------------------------------
gr = Group("syntax", ["string", "m2m"], (
    "Which operand pairs and lexical forms the PAP accepts: operands of a kind an operator may not take, true and false "
    "beside a connective, subject.isM2M alone, and the spellings of operators, numbers, booleans, strings, lists and "
    "attribute names. A form the PAP accepts is checked once, so its golden says how it evaluates."))
PROBE = [req("probe", id="r14", x="v", n=5, b=True, l=["v"], a="y")]
FORBIDDEN = [
    ("roles-equals", "subject.roles == 'ROLE_PARITY_READER'"),
    ("roles-on-the-right-of-equals", "resource.x == subject.roles"),
    ("two-literals-equal", "'v' == 'v'"),
    ("roles-greater-than", "subject.roles > 5"),
    ("roles-is-null", "subject.roles IS NULL"),
    ("subject-id-is-empty", "subject.id IS EMPTY"),
    ("literal-is-empty", "'v' IS EMPTY"),
    ("resource-type-is-empty", "resourceType IS EMPTY"),
    ("subject-id-contains", "subject.id CONTAINS 'v'"),
    ("literal-contains", "'v' CONTAINS 'v'"),
    ("roles-on-the-right-of-contains", "resource.l CONTAINS subject.roles"),
    ("subject-id-contains-any", "subject.id CONTAINS ANY 'v', 'w'"),
    ("subject-id-on-the-right-of-contains-any", "resource.l CONTAINS ANY subject.id"),
    ("literal-is-subset", "'v' IS SUBSET 'v', 'w'"),
    ("roles-match", "subject.roles MATCH ROLE*"),
    ("literal-match", "'v' MATCH v*"),
    ("pip-on-the-right-of-match", "resource.x MATCH subject.parityR14String"),
    ("roles-in", "subject.roles IN 'ROLE_PARITY_READER'"),
    ("subject-id-on-the-right-of-in", "resource.x IN subject.id"),
    ("literal-on-the-right-of-in-alone", "resource.x IN 'v'"),
    ("true-or", "true OR resource.a == 'y'"),
    ("and-true", "resource.a == 'y' AND true"),
    ("true-and-false", "true AND false"),
    ("whole-true-lower-case", "true"),
    ("whole-true-upper-case", "TRUE"),
    ("whole-false-upper-case", "FALSE"),
    ("is-m2m-alone", "subject.isM2M"),
    ("is-m2m-beside-or", "subject.isM2M OR resource.a == 'y'"),
]
for slug, cond in FORBIDDEN:
    gr.add(f"sx-{slug}", cond, PROBE, ("string",) if "parityR14String" in cond else ())
# subject.isM2M may stand alone as a condition; with a PIP of that name declared, only a rule on the name refuses it
for slug, cond in [("is-m2m-declared-alone", "subject.isM2M"), ("is-m2m-declared-beside-or", "subject.isM2M OR resource.a == 'y'")]:
    gr.add(f"sx-{slug}", cond, PROBE, ("m2m",),
           "subject.isM2M alone is a condition, and a PIP of that name is declared, so a refusal can only come from a "
           "rule on the name itself.")
LEXICAL = [
    ("equals-word", "resource.x EQUALS 'v'"), ("not-equals-words", "resource.x NOT EQUALS 'v'"),
    ("greater-or-equal-words", "resource.n GREATER THAN OR EQUAL TO 5"),
    ("less-or-equal-words", "resource.n LESS THAN OR EQUAL TO 5"),
    ("single-equals", "resource.x = 'v'"),
    ("leading-zeros", "resource.n == 005"), ("negative-leading-zero", "resource.n == -05"),
    ("negative-decimal", "resource.n > -0.5"), ("small-negative-decimal", "resource.n > -0.001"),
    ("negative-zero", "resource.n > -0.0"),
    ("exponent", "resource.n == 5e0"), ("decimal-without-integer-part", "resource.n > .5"),
    ("trailing-dot", "resource.n == 5."),
    ("boolean-upper-case", "resource.b == TRUE"), ("boolean-lower-case", "resource.b == true"),
    ("boolean-mixed-case", "resource.b == True"), ("boolean-as-string", "resource.b == 'true'"),
    ("empty-string-literal", "resource.x != ''"), ("doubled-quote", "resource.x == 'it''s'"),
    ("list-without-spaces", "resource.x IN 'v','w'"), ("list-with-spaces-before-commas", "resource.x IN 'v' , 'w'"),
    ("numbers-list-without-spaces", "resource.n IN 5,6"),
    ("bare-path", "x == 'v'"), ("bare-nested-path", "l[0] == 'v'"),
    ("attribute-with-digits", "resource.x1 IS NULL"), ("attribute-with-dash", "resource.x-y IS NULL"),
    ("attribute-with-underscore", "resource.x_y IS NULL"),
]
for slug, cond in LEXICAL:
    gr.add(f"sx-{slug}", cond, PROBE)

# ---------------------------------------------------------------------------------------------------------------
# jp: jsonPath
# ---------------------------------------------------------------------------------------------------------------
jp = Group("jsonpath", [], (
    "Which JSON Path forms the PAP accepts in an attribute and what they select: negative indexes, slices, unions, "
    "wildcards, recursive descent, filters with comparisons, existence, &&, ||, in and =~, functions, bracketed keys, "
    "and the root $. Each condition runs alone and on the left of OR resource.a == 'y', over one resource."))
DOC = {"list": ["a", "b", "c"], "items": [{"type": "a", "id": "q", "n": 1}, {"type": "b", "id": "r", "n": 3}],
       "o": {"k": {"id": "s"}}}
PATHS = [
    ("negative-index", "resource.list[-1] == 'c'"),
    ("negative-index-past-the-start", "resource.list[-5] IS NULL"),
    ("slice", "resource.list[0:2] CONTAINS 'b'"),
    ("slice-open-end", "resource.list[1:] CONTAINS 'c'"),
    ("union-of-indexes", "resource.list[0,2] CONTAINS 'c'"),
    ("wildcard", "resource.items[*].id CONTAINS 'r'"),
    ("recursive-descent", "resource..id CONTAINS 's'"),
    ("filter-greater-than", "resource.items[?(@.n > 2)].id CONTAINS 'r'"),
    ("filter-not-equals", "resource.items[?(@.type != 'a')].id CONTAINS 'r'"),
    ("filter-exists", "resource.items[?(@.n)].id CONTAINS 'q'"),
    ("filter-and", "resource.items[?(@.type == 'a' && @.n > 0)].id CONTAINS 'q'"),
    ("filter-or", "resource.items[?(@.type == 'z' || @.n > 2)].id CONTAINS 'r'"),
    ("filter-on-a-number-selecting-one", "resource.items[?(@.n == 3)].id == 'r'"),
    ("filter-in", "resource.items[?(@.type in ['a'])].id CONTAINS 'q'"),
    ("filter-regex", "resource.items[?(@.type =~ /a/)].id CONTAINS 'q'"),
    ("function-length", "resource.list.length() == 3"),
    ("bracket-key", "resource['list'][0] == 'a'"),
    ("bracket-key-inside", "resource.o['k'].id == 's'"),
    ("dollar-root", "$.list[0] == 'a'"),
    ("index-then-key", "resource.items[1].id == 'r'"),
    ("filter-with-spaces", "resource.items[?(@.type == 'b')].id == 'r'"),
    ("wildcard-compared-with-equals", "resource.list[*] == 'a'"),
]
for slug, cond in PATHS:
    for form, c in [("alone", cond), ("or", cond + " OR resource.a == 'y'")]:
        cid = f"jp-{slug}-{form}"
        jp.add(cid, c, [req("probe", id="r14-" + cid, a="y", **DOC)])


# ---------------------------------------------------------------------------------------------------------------
# target: what a target that cannot be read gives. Earlier rounds recorded an absent attribute in rule and policy
# targets and the scope read in a policy target; here every level sits in one tree with a nested set, beside a control.
# ---------------------------------------------------------------------------------------------------------------
tg = Group("target", ["failing", "scope"], (
    "What a target gives that reads a failed GENERAL PIP, an absent attribute, or subject.permissionScope outside "
    "iterate, at the rule, the policy, and a nested set, in check/resource and in the filter. Every node of a -deny case "
    "is under PERMIT_UNLESS_DENY, so check/resource is true when the target does not apply; every node of an -allow case "
    "is under DENY_UNLESS_PERMIT, so it is true only when the target holds or the node permits. The readable cases are "
    "the control: their target holds."))
TROUBLES = [("failing-pip", "subject.parityR14Failing == 'v'"), ("missing-attribute", "resource.zz == 'v'"),
            ("scope-outside-iterate", "subject.permissionScope.region IS EMPTY"),
            ("readable", "resource.a == 'y'")]  # the control: a target that holds
# With a DENY rule every node is under PERMIT_UNLESS_DENY: a target that does not apply leaves nothing to deny and
# check/resource is true, while a target that holds, a node that denies, and a failed answer give false. With an
# ALLOW rule every node is under DENY_UNLESS_PERMIT, and only a target that holds, or a node that permits, gives true.
for effect, alg in [("DENY", "PERMIT_UNLESS_DENY"), ("ALLOW", "DENY_UNLESS_PERMIT")]:
    for level in ("rule", "policy", "set"):
        for trouble, expr in TROUBLES:
            rule = {"key": "decide", "target": expr if level == "rule" else "true", "condition": "true",
                    "effect": effect}
            policy = {"key": "decides", "target": READER_TARGET + (" AND " + expr if level == "policy" else ""),
                      "algorithm": alg, "rules": [rule]}
            nested = {"key": "nested", "target": expr if level == "set" else "true", "algorithm": alg,
                      "policies": [policy]}
            outer = {"key": "outer", "target": "resourceType == '{{resourceType}}'", "algorithm": alg,
                     "policies": [], "sets": [nested]}
            tg.add_sets(f"r14-{trouble}-in-a-{level}-target-{effect.lower()}", [outer],
                        [req("read", id="r14-target", a="y"), {"name": "filter", "filter": True}],
                        ("failing", "scope"),
                        "The control: the target holds, so check/resource is false under DENY and true under ALLOW."
                        if trouble == "readable" else None)

if __name__ == "__main__":
    groups = [ok, rs, vm, gr, jp, tg]
    for g in groups:
        g.write()
    for g in groups:
        print(f"{g.name}.json: {len(g.cases)} cases, {sum(len(c['requests']) for c in g.cases)} requests")
