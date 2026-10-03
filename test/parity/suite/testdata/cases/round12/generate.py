"""Writes the round 12 case files next to this script: python3 generate.py.

Round 12 was first written in Go; these files hold the same cases, request for request, so the goldens recorded
then still apply. Each file is one test function of the parity suite, in the format case_files_test.go reads:

  scope-outside-iterate-control.json  whether a scope read outside iterate ends its rule or leaves the policy unreached
  not-applicable-filter.json          check/filter over a PERMIT_UNLESS_DENY set with no applicable policy, and an
                                      unrestricted ALLOW beside a predicate under DENY_OVERRIDES

TestRound12IterateNodeInAFilterCases stays in Go: it pins the scope service to another answer before each case.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
READER_TARGET = "subject.roles CONTAINS 'ROLE_PARITY_READER'"
REGULAR_PREFIX = "PARITY_SUITE_REG_"
FALSE_SUBJECT = "subject.roles CONTAINS 'ROLE_PARITY_NOBODY'"
READER_ID = "00000000-0000-0000-0000-000000000101"
SCOPE_ROUTE = "/api/v1/permission-scope/user/" + READER_ID + "/policies"


class File:
    """The cases of one file and the PIPs and pins they name."""

    def __init__(self, name, about, prefix, pips=None, pins=None):
        self.name, self.about, self.prefix = name, about, prefix
        self.pips, self.pins, self.cases = pips or {}, pins or {}, []

    def add(self, case):
        assert all(c["id"] != case["id"] for c in self.cases), case["id"]
        assert all(p in self.pips for p in case.get("pips", ())), case["id"]
        self.cases.append(case)

    def write(self):
        doc = {"about": self.about, "resourceTypePrefix": self.prefix, "pins": self.pins, "pips": self.pips,
               "cases": self.cases}
        with open(os.path.join(HERE, self.name + ".json"), "w") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
            f.write("\n")


def req(name, resource=None, **extra):
    r = {"name": name}
    r.update(extra)
    if resource is not None:
        r["resource"] = resource
    return r


def rule(key, target, condition, effect, predicates=None):
    r = {"key": key, "target": target, "condition": condition, "effect": effect}
    if predicates:
        r["predicates"] = predicates
    return r


def policy(key, algorithm, *rules, target=READER_TARGET):
    return {"key": key, "target": target, "algorithm": algorithm, "rules": list(rules)}


def one_set(algorithm, *policies):
    return [{"key": "set", "target": "resourceType == '{{resourceType}}'", "algorithm": algorithm,
             "policies": list(policies)}]


def regular(cid, sets, requests, about=None, pips=()):
    case = {"id": cid}
    if about:
        case["about"] = about
    if pips:
        case["pips"] = list(pips)
    case["sets"] = sets
    case["requests"] = requests
    return case


def scope_body(*regions):
    """The scope service's answer for parity-reader: one grant of one region per value in regions."""
    return {"permissionScope": [{
        "type": "USER", "id": READER_ID, "name": "parity-reader", "isInherited": False,
        "policies": [{"scopeItems": [{"key": "region", "values": [{"id": region}]}]} for region in regions],
    }]}


# The scope declaration of permission-scope-wire. The PAP answers it with cacheable true and keeps a scope for
# cachePeriod seconds, so a case that waits two seconds before its first request reads the scope pinned here rather
# than one an earlier function left in the cache.
SCOPE_PIP = {"name": "subject.permissionScope", "pipType": "PERMISSION_SCOPE", "url": "http://pip-mock:8090",
             "cacheable": False, "cachePeriod": 1}


def scope_outside_iterate_control():
    f = File("scope-outside-iterate-control",
             "Whether a read of subject.permissionScope outside iterate ends the rule that reads it, or leaves every "
             "rule of its policy unreached. scope-is-empty-outside-iterate answers false for all three of its rules, "
             "the IS NULL rule included, and both explanations produce that. The one case here is the set of "
             "scope-is-empty-outside-iterate with three more rules in the same policy, and the scope service answers "
             "the same two grants, regions r1 and r2. Legacy profile only.",
             REGULAR_PREFIX, pips={"scope": SCOPE_PIP}, pins={SCOPE_ROUTE: {"statusCode": 200,
                                                                         "body": scope_body("r1", "r2")}})
    resource = {"id": "r11-scope-outside"}
    f.add(regular(
        "scope-outside-iterate-beside-a-control",
        one_set("DENY_UNLESS_PERMIT", policy(
            "scoped", "DENY_UNLESS_PERMIT",
            rule("region-is-empty", "operation == 'READ'", "subject.permissionScope.region IS EMPTY", "ALLOW"),
            rule("region-is-empty-or-true", "operation == 'UPDATE'",
                 "subject.permissionScope.region IS EMPTY OR resource.a == 'y'", "ALLOW"),
            rule("region-is-null", "operation == 'PROBE'", "subject.permissionScope.region IS NULL", "ALLOW"),
            rule("control-without-scope", "operation == 'CONTROL'", "true", "ALLOW"),
            rule("mixed-region-is-empty", "operation == 'MIXED'", "subject.permissionScope.region IS EMPTY", "ALLOW"),
            rule("mixed-true", "operation == 'MIXED'", "true", "ALLOW"))),
        [req("read-under-is-empty", resource, pauseMs=2000),
         req("update-under-is-empty-or-true", {"id": "r11-scope-outside", "a": "y"}, operation="UPDATE"),
         req("probe-under-is-null", resource, operation="PROBE"),
         req("control-without-scope", resource, operation="CONTROL"),
         req("scope-read-beside-a-true-rule", resource, operation="MIXED")],
        about="The first three requests repeat those of scope-is-empty-outside-iterate against this upload, the first "
              "after a wait that outlives the scope's cachePeriod. control-without-scope sends CONTROL, whose one "
              "rule has the condition true and reads no scope: true says the policy is reached on a request that "
              "reads no scope, false says the rules of the policy are not reached. scope-read-beside-a-true-rule "
              "sends MIXED, whose two rules are IS EMPTY over the scope key and the condition true: true says the "
              "scope read ends its own rule alone, false says it ends the policy or the whole answer, as a failed "
              "GENERAL PIP does.",
        pips=["scope"]))
    return f


FILTER_REQUESTS = [req("filter", filter=True), req("check-list", {"id": "r9-filter"}, operation="LIST")]


def predicate_policy():
    return policy("with-a-predicate", "DENY_UNLESS_PERMIT",
                  rule("list-with-a-predicate", "operation == 'LIST'", "true", "ALLOW", {"rsqlPredicate": "allowed==1"}))


def allows_list_policy():
    return policy("allows-list", "DENY_UNLESS_PERMIT", rule("list-allow", "operation == 'LIST'", "true", "ALLOW"))


def not_applicable_filter():
    f = File("not-applicable-filter",
             "What check/filter answers for a PERMIT_UNLESS_DENY set none of whose policies applies, and for an ALLOW "
             "without a predicate beside a predicate under DENY_OVERRIDES. "
             "fn-nested-set-without-an-applicable-policy-under-permit-unless-deny nests such a set beside the "
             "allowed==1 policy under DENY_OVERRIDES and answers allowed==1. Two readings produce that: A, the set "
             "does not apply in a filter, although it permits in check/resource (algorithm-permit-unless-deny); B, "
             "the set gives ALLOW, and an ALLOW beside a predicate under DENY_OVERRIDES keeps the predicate. The "
             "control of the predicate policy alone is deny-overrides-set-with-the-predicate-policy-alone in "
             "round9/filter-algebra.json. Every case sends the filter on LIST and check/resource on LIST. Legacy "
             "profile only, like every case with sets.",
             REGULAR_PREFIX)
    f.add(regular(
        "permit-unless-deny-set-without-an-applicable-policy",
        one_set("PERMIT_UNLESS_DENY", policy(
            "for-nobody", "DENY_UNLESS_PERMIT",
            rule("for-nobody-list-allow", "operation == 'LIST'", "true", "ALLOW"), target=FALSE_SUBJECT)),
        FILTER_REQUESTS,
        about="The set alone, its one policy targeting a role nobody holds: the filter is DENY under A and ALLOW under "
              "B, and check/resource is true under both."))
    f.add(regular(
        "deny-overrides-set-with-an-unrestricted-allow-beside-a-predicate",
        one_set("DENY_OVERRIDES", predicate_policy(), allows_list_policy()),
        FILTER_REQUESTS,
        about="The allowed==1 policy beside a policy that allows LIST with no predicate: the filter is ALLOW under A "
              "and allowed==1 under B."))
    f.add(regular(
        "deny-overrides-set-with-the-unrestricted-allow-alone",
        one_set("DENY_OVERRIDES", allows_list_policy()),
        FILTER_REQUESTS,
        about="Control: the policy without a predicate alone, ALLOW under both readings, which shows that it lifts "
              "the filter on its own."))
    return f


for build in (scope_outside_iterate_control, not_applicable_filter):
    build().write()
