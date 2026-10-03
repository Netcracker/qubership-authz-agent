"""Writes the round 11 case files next to this script: python3 generate.py.

Round 11 was first written in Go; these files hold the same cases, request for request, so the goldens recorded
then still apply. Each file is one test function of the parity suite, in the format case_files_test.go reads:

  absent-key-probe.json               !=, NOT IN, NOT CONTAINS and > over an absent resource key, left of an OR
  null-probe.json                     eight operators over a resource attribute that is null, left of an OR
  empty-collection.json               operators over an empty array, an empty selection, an index past the end
  null-body-probe.json                IS EMPTY over a GENERAL PIP whose body is the JSON literal null
  null-literal-and-right-operand.json the literal null left of ==, an absent key right of ==
  declared-name.json                  a PIP named subject.isM2M, and a MAPPING PIP named subject.permissions
  filter-node.json                    check/filter over a set nested in a DENY_OVERRIDES set, and two set algorithms
  scope-outside-iterate.json          subject.permissionScope.<key> in a set that does not iterate

A case id ending in -control is the probe's control: the operand under question on the right of
resource.a == 'y' OR, where it is true whatever the operand does, so a false control means the fixture is broken.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PIP_MOCK = "http://pip-mock:8090/api/v1/pip"
READER_TARGET = "subject.roles CONTAINS 'ROLE_PARITY_READER'"
ISOLATED_PREFIX = "PARITY_SUITE_R11_"
REGULAR_PREFIX = "PARITY_SUITE_REG_"
OWN_FUNCTION = (" The cases live in their own test function so that a recording run can be filtered to them and leave "
                "every golden already committed alone.")


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
               "cases": self.cases}
        with open(os.path.join(HERE, self.name + ".json"), "w") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
            f.write("\n")


def isolated(cid, condition, requests, pips=(), about=None):
    case = {"id": cid}
    if about:
        case["about"] = about
    if condition:
        case["condition"] = condition
    if pips:
        case["pips"] = list(pips)
    case["requests"] = requests
    return case


def or_probe_pair(f, key, operand, requests, pips=()):
    """The probe puts operand on the left of an OR whose right operand is true; the control swaps them."""
    rt = ISOLATED_PREFIX + upper(key)
    f.add(isolated(key, operand + " OR resource.a == 'y'", requests, pips), rt)
    f.add(isolated(key + "-control", "resource.a == 'y' OR " + operand, requests, pips), rt + "_CTL")


def req(name, resource=None, **extra):
    r = {"name": name}
    r.update(extra)
    if resource is not None:
        r["resource"] = resource
    return r


def absent_key_probe():
    f = File("absent-key-probe",
             "Whether !=, NOT IN, NOT CONTAINS and > over an absent resource key end the rule or are false. Each is "
             "recorded alone (s2b, s3, s4, s5), where a false operand and an ended rule both answer false; on the "
             "left of an OR the absent key is recorded for ==, IS NOT NULL, IS EMPTY, IS NOT EMPTY, NOT MATCH, NOT "
             "CONTAINS ANY and IS NOT SUBSET only (s10, s12a, nn1-nn5). Each operator goes through a probe and its "
             "control against a resource without x and with a = y: a true probe means the operand is false and OR "
             "went on, a false one means the operand ended the rule." + OWN_FUNCTION,
             ISOLATED_PREFIX)
    requests = [req("x-absent", {"id": "r11-absent", "a": "y"})]
    for key, operand in (("ak-not-equals", "resource.x != 'v'"), ("ak-not-in", "resource.x NOT IN 'v', 'w'"),
                         ("ak-not-contains", "resource.x NOT CONTAINS 'v'"), ("ak-greater-than", "resource.x > 5")):
        or_probe_pair(f, key, operand, requests)
    return f


def null_probe():
    f = File("null-probe",
             "Whether ==, <, <=, >=, IS EMPTY, NOT CONTAINS, NOT CONTAINS ANY and NOT MATCH over a resource attribute "
             "that is null are false or end the rule. Each is recorded alone (s1c, nl1, nl6, nl2, n4, n2, m2, m1), "
             "where both answer false. Of the relational operators only > is recorded on the left of an OR (n3). "
             "CONTAINS, CONTAINS ANY and MATCH end the rule over null on the left of an OR (nc-*), so their "
             "negations may too. Each operator goes through a probe and its control against a resource whose x is "
             "null and whose a is y." + OWN_FUNCTION,
             ISOLATED_PREFIX)
    requests = [req("x-null", {"id": "r11-null", "x": None, "a": "y"})]
    for key, operand in (
        ("nx-equals", "resource.x == 'v'"), ("nx-less-than", "resource.x < 5"),
        ("nx-less-or-equal", "resource.x <= 5"), ("nx-greater-or-equal", "resource.x >= 5"),
        ("nx-is-empty", "resource.x IS EMPTY"), ("nx-not-contains", "resource.x NOT CONTAINS 'v'"),
        ("nx-not-contains-any", "resource.x NOT CONTAINS ANY 'v', 'w'"), ("nx-not-match", "resource.x NOT MATCH v*"),
    ):
        or_probe_pair(f, key, operand, requests)
    return f


def empty_collection():
    f = File("empty-collection",
             "What ==, !=, IS NOT EMPTY and IS SUBSET answer over an empty resource array, what NOT CONTAINS answers "
             "over a JSON Path that selects nothing, and whether IS EMPTY over an index past the end is false or ends "
             "the rule. Over an array of one value == is false and != true (pa-*), and over an empty one they are "
             "recorded nowhere; IS NOT EMPTY and IS SUBSET over [] are recorded alone (l9, l4). NOT CONTAINS over an "
             "empty selection is recorded on the left of an OR only (np1), which tells a value from an ended rule "
             "but not true from false. IS EMPTY over resource.list[5] is recorded alone (np3). == and != are asked "
             "alone and through a probe and its control, the others through one of the two, each against a resource "
             "with a = y." + OWN_FUNCTION,
             ISOLATED_PREFIX)
    empty_array = [req("x-empty-array", {"id": "r11-empty", "x": [], "a": "y"})]
    for key, operand in (("ea-equals", "resource.x == 'v'"), ("ea-not-equals", "resource.x != 'v'")):
        f.add(isolated(key + "-alone", operand, empty_array))
    for key, operand in (("ea-equals", "resource.x == 'v'"), ("ea-not-equals", "resource.x != 'v'"),
                         ("ea-is-not-empty", "resource.x IS NOT EMPTY"),
                         ("ea-is-subset", "resource.x IS SUBSET 'v', 'w'")):
        or_probe_pair(f, key, operand, empty_array)
    f.add(isolated("sel-not-contains-alone", "resource.items[?(@.type=='zzz')].id NOT CONTAINS 'v'", [
        req("nothing-selected", {"id": "r11-selection", "items": [{"type": "a", "id": "x"}]}),
    ], about="The path selects the id of every item of type zzz from items holding one element of another type, so "
             "the selection is empty."))
    or_probe_pair(f, "oob-is-empty", "resource.list[5] IS EMPTY",
                  [req("index-past-the-end", {"id": "r11-index", "list": ["a"], "a": "y"})])
    return f


def null_body_probe():
    route = "/api/v1/pip/r11-null-body"
    f = File("null-body-probe",
             "Whether IS EMPTY over a GENERAL PIP whose body is the JSON literal null is false or ends the rule. "
             "nb-null-body-is-empty records it alone, false. The PIP answers null at a route of its own, as in "
             "nb-null-body-*, and the condition goes through a probe and its control with resource.a y." + OWN_FUNCTION,
             ISOLATED_PREFIX,
             pips={"nullbody": {"name": "subject.parityR11NullBody", "url": PIP_MOCK + "/r11-null-body",
                                "httpMethod": "POST", "pipType": "GENERAL",
                                "requestAttributes": {"case": "r11-null-body"}, "cacheable": False}},
             pins={route: {"statusCode": 200, "bodyRaw": "null"}})
    or_probe_pair(f, "pn-null-body-is-empty", "subject.parityR11NullBody IS EMPTY",
                  [req("reader", {"id": "r11-null-body", "a": "y"})], ["nullbody"])
    return f


def null_literal_and_right_operand():
    f = File("null-literal-and-right-operand",
             "Whether the literal null on the left of == is a null value or ends the rule, and whether an absent "
             "resource key on the right of == is a false operand or ends the rule. null IS NULL and null IS NOT NULL "
             "are recorded (dn-*), and neither tells the two readings apart, since a null value and an absent key "
             "answer those two operators alike. The literal null on the right of != ends the rule (df2). "
             "a1/right-absent records the absent key on the right alone. Each goes through a probe and its control "
             "against a resource with v = v, no x, and a = y." + OWN_FUNCTION,
             ISOLATED_PREFIX)
    requests = [req("x-absent", {"id": "r11-right", "v": "v", "a": "y"})]
    for key, operand in (("lr-null-literal-equals", "null == 'v'"),
                         ("lr-absent-key-on-the-right", "resource.v == resource.x")):
        or_probe_pair(f, key, operand, requests)
    return f


def declared_name():
    header = "x-parity-r11-is-m2m"

    def header_pip(name):
        return {"name": name, "type": "UUID", "pipType": "HEADER", "header": header, "cacheable": False}

    def mapping_pip(name, permission):
        return {"name": name, "type": "UUID", "pipType": "MAPPING", "cacheable": False,
                "customMapping": {"subject.roles": {"ROLE_PARITY_READER": [permission]}}}

    f = File("declared-name",
             "Whether the PAP refuses subject.isM2M in a condition by its name or because nothing declares it, and "
             "whether it refuses a MAPPING PIP named subject.permissions with no suffix. "
             "rule-condition-subject-is-m2m, in a regular set, and g8a-subject-is-m2m, a bare subject.isM2M in a "
             "simplified policy, record the refusal of an undeclared subject.isM2M, which either reason produces; pm1 "
             "records a MAPPING PIP with a suffix, and a declaration without one is recorded nowhere. Each case reads "
             "what it declares, with the header x-parity-r11-is-m2m set to yes where it reads the header." + OWN_FUNCTION,
             ISOLATED_PREFIX,
             pips={
                 "ism2m": header_pip("subject.isM2M"),
                 "othername": header_pip("subject.parityR11IsM2M"),
                 "unsuffixed": mapping_pip("subject.permissions", "parity_r11_unsuffixed"),
                 "suffixed": mapping_pip("subject.permissions.PARITY_R11", "parity_r11_suffixed"),
             })
    header_yes = [req("header-yes", {"id": "r11-is-m2m"}, headers={header: "yes"})]
    f.add(isolated("dm-is-m2m-declared", "subject.isM2M == 'yes'", header_yes, ["ism2m"],
                   about="Declares a HEADER PIP named subject.isM2M and reads it."))
    f.add(isolated("dm-is-m2m-undeclared", "subject.isM2M == 'yes'", header_yes,
                   about="A control: the same condition with nothing declared."))
    f.add(isolated("dm-same-pip-under-another-name", "subject.parityR11IsM2M == 'yes'", header_yes, ["othername"],
                   about="A control: the same HEADER PIP under a name of its own."))
    reader = [req("reader", {"id": "r11-mapping"})]
    f.add(isolated("um-unsuffixed-mapping", "subject.permissions CONTAINS 'parity_r11_unsuffixed'", reader,
                   ["unsuffixed"],
                   about="Declares a MAPPING PIP named subject.permissions, granting the permission to the reader's "
                         "role, and reads the permission."))
    f.add(isolated("um-suffixed-mapping", "subject.permissions CONTAINS 'parity_r11_suffixed'", reader, ["suffixed"],
                   about="The control of um-unsuffixed-mapping: the same declaration named "
                         "subject.permissions.PARITY_R11."))
    return f


def rule(key, target, condition, effect, predicates=None):
    r = {"key": key, "target": target, "condition": condition, "effect": effect}
    if predicates:
        r["predicates"] = predicates
    return r


def policy(key, algorithm, *rules, target=READER_TARGET):
    return {"key": key, "target": target, "algorithm": algorithm, "rules": list(rules)}


def regular(cid, sets, requests, pips=(), about=None):
    case = {"id": cid}
    if about:
        case["about"] = about
    if pips:
        case["pips"] = list(pips)
    case["sets"] = sets
    case["requests"] = requests
    return case


ALGORITHMS = (("deny-unless-permit", "DENY_UNLESS_PERMIT"), ("permit-unless-deny", "PERMIT_UNLESS_DENY"),
              ("deny-overrides", "DENY_OVERRIDES"), ("permit-overrides", "PERMIT_OVERRIDES"))
FALSE_SUBJECT = "subject.roles CONTAINS 'ROLE_PARITY_NOBODY'"
FILTER_REQUESTS = [req("filter", filter=True), req("check-list", {"id": "r9-filter"}, operation="LIST")]


def predicate_policy():
    return policy("with-a-predicate", "DENY_UNLESS_PERMIT",
                  rule("list-with-a-predicate", "operation == 'LIST'", "true", "ALLOW", {"rsqlPredicate": "allowed==1"}))


def update_only_policy():
    return policy("update-only", "DENY_UNLESS_PERMIT", rule("update-allow", "operation == 'UPDATE'", "true", "ALLOW"))


def nested_set_case(cid, nested, requests, about):
    """A DENY_OVERRIDES set of the predicate policy and nested."""
    return regular(cid, [{"key": "outer", "target": "resourceType == '{{resourceType}}'", "algorithm": "DENY_OVERRIDES",
                          "policies": [predicate_policy()], "sets": [nested]}], requests, about=about)


def filter_node():
    f = File("filter-node",
             "What check/filter answers for a set nested in a DENY_OVERRIDES set beside a policy with an ALLOW "
             "predicate, when the nested set denies or does not apply in a way the filter has not been asked about; "
             "and for a policy with an ALLOW predicate beside a policy without a LIST rule, under the two set "
             "algorithms no earlier case asks it under. Every case sends the filter on LIST and check/resource on "
             "LIST." + OWN_FUNCTION + " Legacy profile only, like every regular case.",
             REGULAR_PREFIX)
    f.add(nested_set_case(
        "fn-nested-set-target-reads-the-resource",
        {"key": "nested", "target": "resource.x == 'a'", "algorithm": "DENY_UNLESS_PERMIT", "policies": [
            policy("nested-allows", "DENY_UNLESS_PERMIT", rule("nested-list-allow", "operation == 'LIST'", "true",
                                                               "ALLOW"))]},
        [req("filter", filter=True),
         req("check-list-without-x", {"id": "r11-filter"}, operation="LIST"),
         req("check-list-with-x-a", {"id": "r11-filter", "x": "a"}, operation="LIST")],
        "Nests a set whose target reads resource.x. A target that reads the resource is recorded to deny a filter "
        "alone (set-target-reads-*/filter), where a node that denies and a node that does not apply give the same "
        "DENY; beside the predicate policy under DENY_OVERRIDES, a node that denies takes the whole answer and a "
        "node that does not apply leaves allowed==1. check/resource without x and with x = a are the controls."))
    for key, algorithm in ALGORITHMS:
        f.add(nested_set_case(
            "fn-nested-set-without-an-applicable-policy-under-" + key,
            {"key": "nested", "target": "true", "algorithm": algorithm, "policies": [
                policy("for-nobody", "DENY_UNLESS_PERMIT",
                       rule("for-nobody-list-allow", "operation == 'LIST'", "true", "ALLOW"), target=FALSE_SUBJECT)]},
            FILTER_REQUESTS,
            "Nests a set under " + algorithm + " whose one policy targets a role nobody holds. What a set whose "
            "policies all do not apply contributes to a filter is recorded nowhere; the answer is DENY, allowed==1, "
            "or ALLOW depending on whether the nested set denies, does not apply, or permits."))
    for key, algorithm in (("permit-overrides", "PERMIT_OVERRIDES"), ("permit-unless-deny", "PERMIT_UNLESS_DENY")):
        f.add(regular(
            "fn-" + key + "-set-with-a-policy-without-a-list-rule",
            [{"key": "set", "target": "resourceType == '{{resourceType}}'", "algorithm": algorithm,
              "policies": [predicate_policy(), update_only_policy()]}],
            FILTER_REQUESTS,
            about="deny-overrides-set-with-a-policy-without-a-list-rule under " + algorithm + ": a policy with an "
                  "ALLOW predicate on LIST beside a DENY_UNLESS_PERMIT policy with a rule on UPDATE alone, which "
                  "denies LIST. Under DENY_OVERRIDES that deny takes the filter (DENY); under DENY_UNLESS_PERMIT a "
                  "deny beside a predicate is dropped (deny-in-one-policy-beside-a-predicate-in-another). "
                  "PERMIT_OVERRIDES and PERMIT_UNLESS_DENY are recorded nowhere."))
    return f


def scope_outside_iterate():
    reader_id = "00000000-0000-0000-0000-000000000101"
    route = "/api/v1/permission-scope/user/" + reader_id + "/policies"
    grants = [{"scopeItems": [{"key": "region", "values": [{"id": region}]}]} for region in ("r1", "r2")]
    f = File("scope-outside-iterate",
             "What subject.permissionScope.<key> resolves to in a set that does not iterate. "
             "scope-read-outside-iterate records CONTAINS over it, false with a resource value and with a literal "
             "alike, which an absent attribute, a null, and an empty list all produce (nn1, n4, nc-contains). IS "
             "EMPTY on READ is true over an empty list only. On UPDATE it stands on the left of an OR whose right "
             "operand holds: true over a null or an empty list, false over an absent attribute, which ends the rule "
             "(nn1). IS NULL on PROBE is true over each of the three. The scope service answers two grants, region r1 "
             "and region r2, as in the iterate binding cases. All three rules read the scope, so a false on each does "
             "not show that the policy is reached; TestRound12ScopeOutsideIterateControlCases adds a rule that reads "
             "none. The first request waits out the cachePeriod of the declaration, as permission-scope-wire does, so "
             "that a scope an earlier function cached is not served." + OWN_FUNCTION + " Legacy profile only.",
             REGULAR_PREFIX,
             pips={"scope": {"name": "subject.permissionScope", "pipType": "PERMISSION_SCOPE",
                             "url": "http://pip-mock:8090", "cacheable": False, "cachePeriod": 1}},
             pins={route: {"statusCode": 200, "body": {"permissionScope": [
                 {"id": reader_id, "isInherited": False, "name": "parity-reader", "policies": grants,
                  "type": "USER"}]}}})
    resource = {"id": "r11-scope-outside"}
    f.add(regular("scope-is-empty-outside-iterate", [{
        "key": "set", "target": "resourceType == '{{resourceType}}'", "algorithm": "DENY_UNLESS_PERMIT",
        "policies": [policy(
            "scoped", "DENY_UNLESS_PERMIT",
            rule("region-is-empty", "operation == 'READ'", "subject.permissionScope.region IS EMPTY", "ALLOW"),
            rule("region-is-empty-or-true", "operation == 'UPDATE'",
                 "subject.permissionScope.region IS EMPTY OR resource.a == 'y'", "ALLOW"),
            rule("region-is-null", "operation == 'PROBE'", "subject.permissionScope.region IS NULL", "ALLOW"))]}],
        [req("read-under-is-empty", resource, pauseMs=2000),
         req("update-under-is-empty-or-true", {"id": "r11-scope-outside", "a": "y"}, operation="UPDATE"),
         req("probe-under-is-null", resource, operation="PROBE")],
        pips=["scope"]))
    return f


for build in (absent_key_probe, null_probe, empty_collection, null_body_probe, null_literal_and_right_operand,
              declared_name, filter_node, scope_outside_iterate):
    build().write()
