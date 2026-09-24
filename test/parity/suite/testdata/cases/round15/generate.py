"""Writes the round 15 case files next to this script: python3 generate.py.

Round 15 asks every operand pair the PAP may accept that no golden has evaluated yet. pairs.tsv lists them, one line
per operator, left operand kind and right operand kind. Round 14 showed that the kind of an operand can change the
answer beyond the value it gives (the whole resource under >, a list on the right of ==, a string body of a GENERAL
PIP), so every pair gets a probe of its own instead of a sample per class.

Each pair is one case, or two when its operands are both fixed text, with the condition
<pair> OR resource.a == 'y' and two requests:

  true-value   a is 'n', and the operands are given values under which the comparison should hold, so the answer is
               the comparison itself;
  false-value  a is 'y', and the values are ones under which the comparison should not hold, so true tells a false
               comparison from a rule the comparison ended.

candidates() lists the values tried for a pair; choices.tsv names, per pair, the candidate each request uses, picked
so that the recorded answers predict true-value to hold and false-value not to, where some candidate allows it. A pair
without a line there uses its first candidate for both.

questions.json and entitlement-targets.json ask the forms round 14 left open; questions() and entitlement_targets()
say what each group asks. The operand kinds and the text each one is written as:

  res:path      resource.x (left), resource.y (right)
  res:nested    resource.o.x, resource.o.y
  res:jsonpath  resource.items[0].x where one value is expected, resource.items[*].x where a collection is
  resource      the whole resource
  resourceType  resourceType
  operation     operation; the PAP refuses it in a condition, so these pairs stand in the rule target of a regular set
  lit:*         a string, number or boolean literal; list:* a literal list on the right
  subj.*        subject.id, name, type, serviceAccount, roles, scopes, permissions (a MAPPING PIP), and
                subject.permissionScope.region, which stands in a set that iterates over one grant of region r1
  ent           subject.entitledResources.of('PARITY_R15_ENT').as('Owner'); the test function pins the entitlements
  pip           a TOKEN PIP over the department claim where one value is expected, a HEADER PIP whose header the
                request sends where a collection is
  pattern       a MATCH pattern
"""
import csv
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
READER_ID = "00000000-0000-0000-0000-000000000101"
READER_TARGET = "subject.roles CONTAINS 'ROLE_PARITY_READER'"
HEADER = "x-parity-r15-list"
ENT = "subject.entitledResources.of('PARITY_R15_ENT').as('Owner')"
ENT_IDS = ["e1", "e2"]
PERMISSIONS = ["PARITY_R15_READ", "PARITY_R15_WRITE"]
SCOPE_ROUTE = f"/api/v1/permission-scope/user/{READER_ID}/policies"

PIPS = {
    "token": {"name": "subject.parityR15Department", "type": "UUID", "pipType": "TOKEN", "claim": "department",
              "cacheable": False},
    "header": {"name": "subject.parityR15List", "type": "UUID", "pipType": "HEADER", "header": HEADER,
               "cacheable": False},
    "mapping": {"name": "subject.permissions.PARITY_R15", "type": "UUID", "pipType": "MAPPING", "cacheable": False,
                "customMapping": {"subject.roles": {"ROLE_PARITY_READER": PERMISSIONS}}},
    "scope": {"name": "subject.permissionScope", "pipType": "PERMISSION_SCOPE", "url": "http://pip-mock:8090",
              "cacheable": False, "cachePeriod": 1},
}
PINS = {SCOPE_ROUTE: {"statusCode": 200, "body": {"permissionScope": [{
    "id": READER_ID, "isInherited": False, "name": "parity-reader", "type": "USER",
    "policies": [{"scopeItems": [{"key": "region", "values": [{"id": "r1"}]}]}]}]}}}

# The value each fixed operand gives the reader, as the goldens recorded it.
FIXED = {
    "subj.id": READER_ID, "subj.name": "parity-reader", "subj.type": "USER", "subj.serviceAccount": None,
    "subj.roles": ["ROLE_PARITY_READER"], "subj.scopes": ["openid", "profile", "email"], "subj.permissions": PERMISSIONS,
    "ent": ENT_IDS, "subj.permissionScope": ["r1"], "resourceType": "{{resourceType}}", "operation": "READ",
}
TEXT = {"subj.id": "subject.id", "subj.name": "subject.name", "subj.type": "subject.type",
        "subj.serviceAccount": "subject.serviceAccount", "subj.roles": "subject.roles", "subj.scopes": "subject.scopes",
        "subj.permissions": "subject.permissions", "ent": ENT, "subj.permissionScope": "subject.permissionScope.region",
        "resourceType": "resourceType", "operation": "operation", "resource": "resource"}
POOL = ["v", "V", 5, "5", 5.5, True, ["v", "w"], [5, 6], {"k": "v"}]
FILES = [("eq", ("EQ", "NE")), ("rel", ("LT", "LE", "GT", "GE")), ("in", ("IN", "NOT_IN")),
         ("contains", ("CONTAINS", "NOT_CONTAINS")), ("any", ("CONTAINS_ANY", "NOT_CONTAINS_ANY")),
         ("subset", ("IS_SUBSET", "IS_NOT_SUBSET")), ("match", ("MATCH", "NOT_MATCH")),
         ("unary", ("IS_NULL", "IS_NOT_NULL", "IS_EMPTY", "IS_NOT_EMPTY"))]
WORDS = {"EQ": "==", "NE": "!=", "LT": "<", "LE": "<=", "GT": ">", "GE": ">=", "IS_NULL": "IS NULL",
         "IS_NOT_NULL": "IS NOT NULL", "IS_EMPTY": "IS EMPTY", "IS_NOT_EMPTY": "IS NOT EMPTY", "IN": "IN",
         "NOT_IN": "NOT IN", "CONTAINS": "CONTAINS", "NOT_CONTAINS": "NOT CONTAINS", "CONTAINS_ANY": "CONTAINS ANY",
         "NOT_CONTAINS_ANY": "NOT CONTAINS ANY", "IS_SUBSET": "IS SUBSET", "IS_NOT_SUBSET": "IS NOT SUBSET",
         "MATCH": "MATCH", "NOT_MATCH": "NOT MATCH"}
LEFT_MULTI = {"IS_EMPTY", "IS_NOT_EMPTY", "CONTAINS", "NOT_CONTAINS", "CONTAINS_ANY", "NOT_CONTAINS_ANY", "IS_SUBSET",
              "IS_NOT_SUBSET"}
RIGHT_MULTI = {"IN", "NOT_IN", "CONTAINS_ANY", "NOT_CONTAINS_ANY", "IS_SUBSET", "IS_NOT_SUBSET"}


def read_pairs():
    with open(os.path.join(HERE, "pairs.tsv")) as f:
        return [tuple(row) for row in csv.reader(f, delimiter="\t") if row and not row[0].startswith("#")]


def read_choices():
    path = os.path.join(HERE, "choices.tsv")
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return {row[0]: (int(row[1]), int(row[2])) for row in csv.reader(f, delimiter="\t") if row}


def slug(kind):
    return kind.replace(":", "-").replace(".", "-").replace("_", "-").lower()


def case_id(op, left, right):
    return "p15-" + "-".join([op.lower().replace("_", "-"), slug(left), slug(right)])


def lit(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return "'" + str(v) + "'"


def scalars(v):
    """The scalars a value holds: the value itself, or the elements of a list."""
    return [x for x in (v if isinstance(v, list) else [v]) if not isinstance(x, (list, dict))]


class Side:
    """One operand of a candidate: its text, and what the request must carry for it to give value."""

    def __init__(self, text, value, res=None, headers=None, pips=(), scope=False, target=False):
        self.text, self.value, self.res, self.headers = text, value, res or {}, headers or {}
        self.pips, self.scope, self.target = list(pips), scope, target


def variable(kind, side, multi, value):
    """A side whose value the request chooses."""
    key = "x" if side == "left" else "y"
    if kind == "res:path":
        return Side(f"resource.{key}", value, {key: value})
    if kind == "res:nested":
        return Side(f"resource.o.{key}", value, {"o": {key: value}})
    if kind == "res:jsonpath":
        if multi:
            items = [{key: e} for e in (value if isinstance(value, list) else [value])]
            return Side(f"resource.items[*].{key}", value, {"items": items})
        return Side(f"resource.items[0].{key}", value, {"items": [{key: value}]})
    if kind == "pip" and multi:
        text = ",".join(str(e) for e in (value if isinstance(value, list) else [value]))
        return Side("subject.parityR15List", value, headers={HEADER: text}, pips=["header"])
    raise AssertionError(kind)


def fixed(kind, side, multi):
    if kind == "pip":
        return Side("subject.parityR15Department", "finance", pips=["token"])
    if kind == "resource":
        return Side("resource", "the resource")
    s = Side(TEXT[kind], FIXED[kind])
    if kind == "subj.permissions":
        s.pips = ["mapping"]
    if kind == "subj.permissionScope":
        s.scope, s.pips = True, ["scope"]
    if kind == "operation":
        s.target = True
    return s


def literal(kind, near):
    """Literal texts to try for a literal kind, the values the other side gives first."""
    seen, out = set(), []

    def add(v):
        t = lit(v)
        if t not in seen:
            seen.add(t)
            out.append(Side(t, v))
    near = [x for x in near if x is not None]
    near = near + _neighbors(near)
    if kind == "lit:str":
        for v in near + ["v", "zz"]:
            if not isinstance(v, bool):
                add(str(v))
    elif kind == "lit:num":
        for v in near + [5, 6]:
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                add(v)
            elif isinstance(v, str) and v.lstrip("-").isdigit():
                add(int(v))
    elif kind == "lit:bool":
        add(True)
        add(False)
    elif kind in ("list:str", "list:num"):
        pool = [v for v in near + (["v", "w"] if kind == "list:str" else [5, 6])
                if (isinstance(v, str)) == (kind == "list:str") and not isinstance(v, bool)]
        for v in pool:
            text = f"{lit(v)}, {lit('zz') if kind == 'list:str' else 7}"
            if text not in seen:
                seen.add(text)
                out.append(Side(text, [v]))
    elif kind == "pattern":
        for v in near + ["v"]:
            if isinstance(v, str) and v and "{" not in v:
                t = v[:3] + "*"
                if t not in seen:
                    seen.add(t)
                    out.append(Side(t, t))
    return out


VARIABLE = {"res:path", "res:nested", "res:jsonpath"}


def is_variable(kind, multi):
    return kind in VARIABLE or (kind == "pip" and multi)


def is_literal(kind):
    return kind.startswith("lit:") or kind.startswith("list:") or kind == "pattern"


def candidates(op, left, right):
    """Every (left side, right side) tried for the pair, in a fixed order."""
    lm, rm = op in LEFT_MULTI, op in RIGHT_MULTI
    if right == "-":
        if is_variable(left, lm):
            return [(variable(left, "left", lm, v), None) for v in _pool(lm) + [[], None, ""]]
        if is_literal(left):
            return [(s, None) for s in literal(left, [])]
        return [(fixed(left, "left", lm), None)]
    out = []
    if not is_variable(left, lm) and not is_literal(left):
        ls = fixed(left, "left", lm)
        near = scalars(ls.value) + ([ls.value] if isinstance(ls.value, list) else [])
        if is_variable(right, rm):
            out = [(ls, variable(right, "right", rm, v)) for v in _near_pool(near, rm)]
        elif is_literal(right):
            out = [(ls, r) for r in literal(right, scalars(ls.value))]
        else:
            out = [(ls, fixed(right, "right", rm))]
    elif not is_variable(right, rm) and not is_literal(right):
        rs = fixed(right, "right", rm)
        near = scalars(rs.value) + ([rs.value] if isinstance(rs.value, list) else [])
        if is_variable(left, lm):
            out = [(variable(left, "left", lm, v), rs) for v in _near_pool(near, lm)]
        else:
            out = [(ls, rs) for ls in literal(left, scalars(rs.value))]
    elif is_variable(left, lm) and is_variable(right, rm):
        for v in _pool(lm):
            for w in _pair_values(v, rm):
                out.append((variable(left, "left", lm, v), variable(right, "right", rm, w)))
    elif is_variable(left, lm):
        for v in _pool(lm):
            for r in literal(right, scalars(v)):
                out.append((variable(left, "left", lm, v), r))
    elif is_variable(right, rm):
        for ls in literal(left, []):
            for w in _near_pool(scalars(ls.value), rm):
                out.append((ls, variable(right, "right", rm, w)))
    else:
        for ls in literal(left, []):
            for r in literal(right, scalars(ls.value)):
                out.append((ls, r))
    return out


def _neighbors(near):
    """Numbers one below and one above each number, so that <, <=, > and >= have a value that holds."""
    out = []
    for x in near:
        if isinstance(x, (int, float)) and not isinstance(x, bool):
            out += [x - 1, x + 1]
        elif isinstance(x, str) and x.lstrip("-").isdigit():
            out += [str(int(x) - 1), str(int(x) + 1)]
    return out


def _near_pool(near, multi=False):
    """Values to try for a variable side next to a side that gives near; lists first where a collection is expected."""
    out = []
    lists = [[x, "zz"] for x in near if not isinstance(x, (list, dict))]
    order = lists + near + _neighbors(near) if multi else near + _neighbors(near) + lists
    for v in order + POOL:
        if v not in out:
            out.append(v)
    return out


def _pool(multi):
    """POOL, lists first where a collection is expected."""
    return sorted(POOL, key=lambda v: not isinstance(v, list)) if multi else POOL


def _pair_values(v, multi=False):
    """Values to try on the right next to v on the left; lists first where a collection is expected."""
    out = [v, "zz"]
    out += _neighbors([v])
    if not isinstance(v, (list, dict)):
        out = ([[v, "zz"]] + out) if multi else (out + [[v, "zz"]])
    elif isinstance(v, list):
        out += [v[0], v[:1]]
    return out


def expression(op, ls, rs):
    return f"{ls.text} {WORDS[op]}" + ("" if rs is None else f" {rs.text}")


def build(op, left, right, cand, a):
    """(condition, resource, headers, pips, scope, target) of one candidate with resource.a = a."""
    ls, rs = cand
    sides = [ls] + ([rs] if rs else [])
    res = {"id": "r15", "a": a}
    for s in sides:
        for k, v in s.res.items():
            # both sides may write into resource.o or resource.items: merge, element by element for items
            if k == "o" and k in res:
                res[k] = dict(res[k], **v)
            elif k == "items" and k in res:
                old = res[k]
                res[k] = [dict(old[i] if i < len(old) else {}, **(v[i] if i < len(v) else {}))
                          for i in range(max(len(old), len(v)))]
            else:
                res[k] = v
    headers = {}
    for s in sides:
        headers.update(s.headers)
    pips = sorted({p for s in sides for p in s.pips})
    return (f"{expression(op, ls, rs)} OR resource.a == 'y'", res, headers, pips,
            any(s.scope for s in sides), any(s.target for s in sides))


def regular_sets(cond, scope, target):
    rule = {"key": "decide", "target": cond if target else "true", "condition": "true" if target else cond,
            "effect": "ALLOW"}
    policy = {"key": "reader", "target": READER_TARGET, "algorithm": "DENY_UNLESS_PERMIT", "rules": [rule]}
    s = {"key": "set", "target": "resourceType == '{{resourceType}}'", "algorithm": "DENY_UNLESS_PERMIT",
         "policies": [policy]}
    if scope:
        s["iterate"] = {"foreach": "subject.permissionScope", "algorithm": "DENY_UNLESS_PERMIT"}
    return [s]


def request(name, res, headers):
    r = {"name": name, "resource": res}
    if headers:
        r["headers"] = headers
    return r


def cases_for(op, left, right, choice):
    cands = candidates(op, left, right)
    assert cands, (op, left, right)
    t, f = choice if choice else (0, 0)
    t, f = min(t, len(cands) - 1), min(f, len(cands) - 1)
    bt = build(op, left, right, cands[t], "n")
    bf = build(op, left, right, cands[f], "y")
    cid = case_id(op, left, right)
    if bt[0] == bf[0]:
        groups = [(cid, bt, [request("true-value", bt[1], bt[2]), request("false-value", bf[1], bf[2])])]
    else:
        groups = [(cid + "-true-value", bt, [request("probe", bt[1], bt[2])]),
                  (cid + "-false-value", bf, [request("probe", bf[1], bf[2])])]
    out = []
    for gid, b, reqs in groups:
        cond, _, _, _, scope, target = b
        pips = sorted({p for _, bb, _ in groups for p in bb[3]})
        c = {"id": gid, "pips": pips, "requests": reqs}
        if scope or target:
            c["sets"] = regular_sets(cond, scope, target)
        else:
            c["condition"] = cond
        if not c["pips"]:
            del c["pips"]
        out.append(c)
    return out


# ---------------------------------------------------------------------------------------------------------------
# Questions: the forms round 14 left open, one group per question
# ---------------------------------------------------------------------------------------------------------------
Q_ROUTES = {"nullbody": "/api/v1/pip/r15-null-body", "glist": "/api/v1/pip/r15-list", "object": "/api/v1/pip/r15-object",
            "text": "/api/v1/pip/r15-text", "single": "/api/v1/pip/r15-single", "failing": "/api/v1/pip/r15-failing"}
Q_PINS = {
    "nullbody": {"statusCode": 200, "bodyRaw": "null"},
    "glist": {"statusCode": 200, "body": ["v", "w"]},
    "object": {"statusCode": 200, "body": {"k": "v"}},
    "text": {"statusCode": 200, "bodyRaw": "v"},
    "single": {"statusCode": 200, "body": ["v"]},
    "failing": {"statusCode": 500, "body": {"error": "parity round 15 case"}},
}
Q_PIP_NAMES = {"nullbody": "subject.parityR15NullBody", "glist": "subject.parityR15GeneralList",
               "object": "subject.parityR15Object", "text": "subject.parityR15Text", "single": "subject.parityR15Single",
               "failing": "subject.parityR15Failing"}


def general_pip(key):
    return {"name": Q_PIP_NAMES[key], "url": "http://pip-mock:8090" + Q_ROUTES[key], "httpMethod": "POST",
            "pipType": "GENERAL", "requestAttributes": {"case": Q_PIP_NAMES[key]}, "cacheable": False}


def deny_rule_sets(condition):
    """A PERMIT_UNLESS_DENY set and policy whose one DENY rule has condition: true when the rule does not apply,
    false when it denies or when the decision fails."""
    return [{"key": "set", "target": "resourceType == '{{resourceType}}'", "algorithm": "PERMIT_UNLESS_DENY",
             "policies": [{"key": "reader", "target": READER_TARGET, "algorithm": "PERMIT_UNLESS_DENY",
                           "rules": [{"key": "deny", "target": "true", "condition": condition, "effect": "DENY"}]}]}]


def q(cid, requests, condition=None, sets=None, pips=(), about=None):
    c = {"id": cid}
    if about:
        c["about"] = about
    if pips:
        c["pips"] = list(pips)
    if sets is not None:
        c["sets"] = sets
    else:
        c["condition"] = condition
    c["requests"] = requests
    return c


def rq(name, subject=None, headers=None, **res):
    r = {"name": name, "resource": dict({"id": "r15"}, **res)}
    if headers:
        r["headers"] = headers
    if subject:
        r["subject"] = subject
    return r


def questions():
    out = []
    # R15-1: an ended rule or a failed decision, told apart by a DENY rule with no allowing neighbor
    for op in ("IN", "NOT IN"):
        s = op.lower().replace(" ", "-")
        out.append(q(f"q15-null-on-the-right-of-{s}-in-a-deny-rule", [rq("read", v="v", x=None)],
                     sets=deny_rule_sets(f"resource.v {op} resource.x")))
    for op in ("CONTAINS ANY", "NOT CONTAINS ANY"):
        s = op.lower().replace(" ", "-")
        out.append(q(f"q15-null-body-on-the-right-of-{s}-in-a-deny-rule", [rq("read", l=["v"])],
                     sets=deny_rule_sets(f"resource.l {op} subject.parityR15NullBody"), pips=["nullbody"]))
    for op in ("MATCH", "NOT MATCH"):
        s = op.lower().replace(" ", "-")
        out.append(q(f"q15-{s}-over-a-non-string-in-a-deny-rule",
                     [rq("integer", x=5), rq("boolean", x=True), rq("list", x=["v"]), rq("object", x={"k": "v"})],
                     sets=deny_rule_sets(f"resource.x {op} v*")))
    # R15-2: a list of two values on the right of ==, !=, CONTAINS and NOT CONTAINS, from three sources
    sources = [("general", "subject.parityR15GeneralList", ["glist"], {}, {}),
               ("attribute", "resource.l2", [], {"l2": ["v", "w"]}, {}),
               ("header", "subject.parityR15List", ["header"], {}, {HEADER: "v,w"})]
    for src, text, pips, res, headers in sources:
        for op, left, lval in (("==", "resource.v", "v"), ("!=", "resource.v", "v"),
                               ("CONTAINS", "resource.l", ["v"]), ("NOT CONTAINS", "resource.l", ["v"])):
            s = {"==": "equals", "!=": "not-equals", "CONTAINS": "contains", "NOT CONTAINS": "not-contains"}[op]
            key = left.split(".")[1]
            out.append(q(f"q15-{src}-list-on-the-right-of-{s}-or", [rq("probe", headers=headers, a="y", **{key: lval}, **res)],
                         condition=f"{left} {op} {text} OR resource.a == 'y'", pips=pips))
            out.append(q(f"q15-{src}-list-on-the-right-of-{s}-in-a-deny-rule",
                         [rq("read", headers=headers, **{key: lval}, **res)],
                         sets=deny_rule_sets(f"{left} {op} {text}"), pips=pips))
    # R15-4: several groups of a nested set, and of a top-level set, beside a sibling predicate
    def allow(key, predicate):
        return {"key": key, "target": READER_TARGET, "algorithm": "DENY_UNLESS_PERMIT", "rules": [
            {"key": key + "-list", "target": "operation == 'LIST'", "condition": "true", "effect": "ALLOW",
             "predicates": {"rsqlPredicate": predicate}}]}
    typed = "resourceType == '{{resourceType}}'"
    out.append(q("q15-groups-of-a-nested-set-beside-a-predicate", [{"name": "filter", "filter": True}], sets=[
        {"key": "outer", "target": typed, "algorithm": "DENY_UNLESS_PERMIT", "policies": [allow("allowed", "allowed==1")],
         "sets": [{"key": "nested", "target": "true", "algorithm": "DENY_UNLESS_PERMIT",
                   "policies": [allow("a", "a==1"), allow("b", "b==2")]}]}]))
    out.append(q("q15-groups-of-a-top-level-set-beside-a-predicate", [{"name": "filter", "filter": True}], sets=[
        {"key": "first", "target": typed, "algorithm": "DENY_UNLESS_PERMIT", "policies": [allow("a", "a==1"), allow("b", "b==2")]},
        {"key": "second", "target": typed, "algorithm": "DENY_UNLESS_PERMIT", "policies": [allow("allowed", "allowed==1")]}]))
    # R15-5: subject.isM2M beside a connective, for the reader and for the service account alone
    for form, cond in (("or", "subject.isM2M OR resource.a == 'zz'"), ("and", "subject.isM2M AND resource.a == 'y'")):
        out.append(q(f"q15-is-m2m-{form}", [rq("reader", a="y"), rq("service-account", subject="m2m", a="y")], sets=[
            {"key": "set", "target": typed, "algorithm": "DENY_UNLESS_PERMIT", "policies": [
                {"key": "any-subject", "target": "true", "algorithm": "DENY_UNLESS_PERMIT", "rules": [
                    {"key": "decide", "target": "true", "condition": cond, "effect": "ALLOW"}]}]}]))
    # R15-6: an attribute on the right of MATCH, over a value equal to the attribute's path text
    out.append(q("q15-match-over-the-path-text", [rq("path-text", v="resource.x", x="zz"), rq("value", v="zz", x="zz")],
                 condition="resource.v MATCH resource.x"))
    out.append(q("q15-match-over-a-wildcard-path-text", [rq("path-text", v="resource.q", q="zz")],
                 condition="resource.v MATCH resource.*"))
    # R15-7: a GENERAL body that is an object, a text body, and a one-element list
    for key, what in (("object", "an-object-body"), ("text", "a-text-body"), ("single", "a-one-element-list-body")):
        name = Q_PIP_NAMES[key]
        for form, cond in (("equals", f"{name} == 'v'"), ("is-null", f"{name} IS NULL"),
                           ("contains", f"{name} CONTAINS 'v'")):
            out.append(q(f"q15-{what}-{form}", [rq("true-value", a="n"), rq("false-value", a="y")],
                         condition=f"{cond} OR resource.a == 'y'", pips=[key]))
    # R15-8: the whole resource under <, CONTAINS, IS EMPTY and NOT IN
    for form, cond in (("literal-less-than", "5 < resource"), ("contains", "resource CONTAINS 'v'"),
                       ("is-empty", "resource IS EMPTY"), ("not-in", "resource NOT IN 'v', 'w'")):
        out.append(q(f"q15-whole-resource-{form}", [rq("true-value", a="n"), rq("false-value", a="y")],
                     condition=f"{cond} OR resource.a == 'y'"))
    # R15-9: numbers
    for form, cond, n in (("negative-zero-integer", "resource.n == -0", 0), ("negative-double-zero", "resource.n == -00", 0),
                          ("negative-decimal-with-zero-fraction", "resource.n == -5.0", -5.0),
                          ("negative-decimal-with-a-trailing-zero", "resource.n > -0.50", 0),
                          ("zero-decimal", "resource.n == 0.0", 0.0), ("leading-zero-decimal", "resource.n == 00.5", 0.5)):
        out.append(q(f"q15-number-{form}", [rq("probe", n=n)], condition=cond))
    # R15-10: JSON Path beyond round 14
    items = [{"type": "ab", "id": "q", "n": 1, "tags": ["x"]}, {"type": "b", "id": "r", "n": 3, "tags": ["y", "z"]}]
    for form, cond in (
            ("regex-partial-match", "resource.items[?(@.type =~ /a/)].id CONTAINS 'q'"),
            ("function-min", "resource.nums.min() == 1"), ("function-max", "resource.nums.max() == 3"),
            ("function-avg", "resource.nums.avg() == 2"), ("function-sum", "resource.nums.sum() == 6"),
            ("function-first", "resource.list.first() == 'a'"), ("function-last", "resource.list.last() == 'c'"),
            ("function-keys", "resource.o.keys() CONTAINS 'k'"),
            ("filter-nin", "resource.items[?(@.type nin ['ab'])].id CONTAINS 'r'"),
            ("filter-subsetof", "resource.items[?(@.tags subsetof ['x', 'w'])].id CONTAINS 'q'"),
            ("filter-anyof", "resource.items[?(@.tags anyof ['z'])].id CONTAINS 'r'"),
            ("filter-noneof", "resource.items[?(@.tags noneof ['x'])].id CONTAINS 'r'"),
            ("filter-size", "resource.items[?(@.tags size 2)].id CONTAINS 'r'"),
            ("filter-empty", "resource.items[?(@.tags empty false)].id CONTAINS 'q'"),
            ("filter-less-or-equal", "resource.items[?(@.n <= 1)].id CONTAINS 'q'"),
            ("filter-greater-or-equal", "resource.items[?(@.n >= 3)].id CONTAINS 'r'"),
            ("nested-filter", "resource.items[?(@.tags[?(@ == 'z')])].id CONTAINS 'r'")):
        out.append(q(f"q15-jsonpath-{form}", [rq("probe", items=items, nums=[1, 2, 3], list=["a", "b", "c"], o={"k": 1})],
                     condition=cond))
    return out


def entitlement_targets():
    """R15-3 with the entitlements service failing: an entitlements read and a nested decision in each target."""
    out = []
    ent_read = f"{ENT} CONTAINS 'e1'"
    for level in ("rule", "policy", "set"):
        for what, expr in (("entitlements", ent_read), ("nested-decision", "subject allowed 'LIST' on resource")):
            rule = {"key": "deny", "target": expr if level == "rule" else "true", "condition": "true", "effect": "DENY"}
            policy = {"key": "reader", "target": expr if level == "policy" else READER_TARGET,
                      "algorithm": "PERMIT_UNLESS_DENY", "rules": [rule]}
            nested = {"key": "nested", "target": expr if level == "set" else "true", "algorithm": "PERMIT_UNLESS_DENY",
                      "policies": [policy]}
            sets = [{"key": "outer", "target": "resourceType == '{{resourceType}}'", "algorithm": "PERMIT_UNLESS_DENY",
                     "policies": [], "sets": [nested]}]
            pips = []
            if what == "nested-decision":
                # LIST is allowed only by a rule that reads a failing GENERAL PIP
                sets.append({"key": "list", "target": "resourceType == '{{resourceType}}'",
                             "algorithm": "DENY_UNLESS_PERMIT", "policies": [
                                 {"key": "lister", "target": READER_TARGET, "algorithm": "DENY_UNLESS_PERMIT", "rules": [
                                     {"key": "list", "target": "operation == 'LIST'",
                                      "condition": "subject.parityR15Failing == 'v'", "effect": "ALLOW"}]}]})
                pips = ["failing"]
            out.append(q(f"q15-failing-{what}-in-a-{level}-target", [rq("read")], sets=sets, pips=pips))
    return out


def write_questions(name, cases, about):
    used = sorted({p for c in cases for p in c.get("pips", [])})
    pips = {k: (PIPS[k] if k in PIPS else general_pip(k)) for k in used}
    pins = {Q_ROUTES[k]: Q_PINS[k] for k in used if k in Q_ROUTES}
    doc = {"about": about, "resourceTypePrefix": "PARITY_SUITE_R15_", "pins": pins, "pips": pips, "cases": cases}
    with open(os.path.join(HERE, name + ".json"), "w") as f:
        json.dump(doc, f, indent=1, ensure_ascii=False)
        f.write("\n")


def main():
    write_questions("questions", questions(), (
        "The forms round 14 left open: whether a rule ends or the decision fails for four right-hand states and for "
        "MATCH over a non-string; a list of two values on the right of ==, !=, CONTAINS and NOT CONTAINS from three "
        "sources; filter groups of a nested and a top-level set beside a sibling predicate; subject.isM2M beside a "
        "connective; an attribute on the right of MATCH over its own path text; GENERAL bodies that are an object, "
        "text, or a one-element list; the whole resource in more positions; number spellings; JSON Path forms."))
    write_questions("entitlement-targets", entitlement_targets(), (
        "An entitlements read and a nested decision that fails, in a rule, policy, and set target, with every node "
        "under PERMIT_UNLESS_DENY and a DENY rule: 400 means the PAP refuses the form, true that the node does not "
        "apply, false that the decision fails. The test function pins the entitlements service to answer 500."))
    pairs, choices = read_pairs(), read_choices()
    for name, ops in FILES:
        cases = []
        for op, left, right in pairs:
            if op in ops:
                cases += cases_for(op, left, right, choices.get(case_id(op, left, right)))
        used = sorted({p for c in cases for p in c.get("pips", [])})
        doc = {"about": (
            f"Every operand pair of {', '.join(WORDS[o] for o in ops)} the PAP may accept that no earlier golden "
            "evaluated. Each condition is <pair> OR resource.a == 'y': true-value sends a = 'n' and values under "
            "which the comparison should hold, false-value sends a = 'y' and values under which it should not."),
            "resourceTypePrefix": "PARITY_SUITE_R15_", "pins": PINS if "scope" in used else {},
            "pips": {k: PIPS[k] for k in used}, "cases": cases}
        with open(os.path.join(HERE, f"pairs-{name}.json"), "w") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
            f.write("\n")


if __name__ == "__main__":
    main()
