"""Writes the round 13 case files next to this script: python3 generate.py.

Round 13 was first written in Go; these files hold the same cases, request for request, so the goldens recorded
then still apply. Each file is one test function of the parity suite, in the format case_files_test.go reads:

  scope-outside-iterate.json        where the failure of a subject.permissionScope read outside iterate ends
  filter.json                       an ALLOW without a predicate beside a predicate, and a nested set none of whose
                                    policies applies, in check/filter
  pap-syntax.json                   a literal left over after a comparison, and an attribute as a list element
  cells.json                        every operator over every operand state no golden fixes
  failing-pip-in-a-deny-rule.json   a GENERAL PIP that answers 500 under every operator in a DENY rule

TestRound13IterateCases stays in Go: it re-pins the scope service between three runs of its cases.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
READER_TARGET = "subject.roles CONTAINS 'ROLE_PARITY_READER'"
FALSE_SUBJECT = "subject.roles CONTAINS 'ROLE_PARITY_NOBODY'"
ISOLATED_PREFIX = "PARITY_SUITE_R13_"
REGULAR_PREFIX = "PARITY_SUITE_REG_"
READER_SUBJECT_ID = "00000000-0000-0000-0000-000000000101"
SCOPE_ROUTE = "/api/v1/permission-scope/user/" + READER_SUBJECT_ID + "/policies"
NULL_ROUTE = "/api/v1/pip/r13-null-body"
FAILING_ROUTE = "/api/v1/pip/r13-failing"
FAILING_ANSWER = {"statusCode": 500, "body": {"error": "parity round 13 cell case"}}


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


def isolated(cid, condition, requests, pips=(), about=None):
    case = {"id": cid}
    if about:
        case["about"] = about
    case["condition"] = condition
    if pips:
        case["pips"] = list(pips)
    case["requests"] = requests
    return case


def regular(cid, sets, requests, pips=(), about=None):
    case = {"id": cid}
    if about:
        case["about"] = about
    if pips:
        case["pips"] = list(pips)
    case["sets"] = sets
    case["requests"] = requests
    return case


def rule(key, target, condition, effect, predicates=None):
    r = {"key": key, "target": target, "condition": condition, "effect": effect}
    if predicates:
        r["predicates"] = predicates
    return r


def policy(key, algorithm, *rules, target=READER_TARGET):
    return {"key": key, "target": target, "algorithm": algorithm, "rules": list(rules)}


def one_set(algorithm, *policies, key="set", sets=None):
    s = {"key": key, "target": "resourceType == '{{resourceType}}'", "algorithm": algorithm,
         "policies": list(policies)}
    if sets:
        s["sets"] = sets
    return [s]


def general_pip(name, route):
    """A GENERAL PIP named name that reads route on pip-mock."""
    return {"name": name, "url": "http://pip-mock:8090" + route, "httpMethod": "POST", "pipType": "GENERAL",
            "requestAttributes": {"case": name}, "cacheable": False}


# subject.permissionScope read from the scope service. cacheable is written false and is not honoured: the PAP
# answers with cacheable true and a cachePeriod, so the period is one second, and the first request of a file
# that pins the service waits two seconds, so that no scope another function cached reaches it.
SCOPE_PIP = {"name": "subject.permissionScope", "pipType": "PERMISSION_SCOPE", "url": "http://pip-mock:8090",
             "cacheable": False, "cachePeriod": 1}


def scope_body(*grants):
    """The scope service's answer for parity-reader: one policy per grant, one scope item per key."""
    return {"statusCode": 200, "body": {"permissionScope": [{
        "id": READER_SUBJECT_ID, "isInherited": False, "name": "parity-reader", "type": "USER",
        "policies": [{"scopeItems": [{"key": k, "values": [{"id": v} for v in values]}
                                     for k, values in grant.items()]} for grant in grants]}]}}


FILTER_REQUESTS = [req("filter", filter=True), req("check-list", {"id": "r9-filter"}, operation="LIST")]


def allow_with_predicate(key, rsql):
    return rule(key, "operation == 'LIST'", "true", "ALLOW", {"rsqlPredicate": rsql})


def predicate_policy():
    return policy("with-a-predicate", "DENY_UNLESS_PERMIT", allow_with_predicate("list-with-a-predicate", "allowed==1"))


def scope_outside_iterate():
    f = File("scope-outside-iterate",
             "Where the failure of a subject.permissionScope read outside iterate ends. Round 12 showed it ends more "
             "than its own rule, and the one case that tells how much, scope-read-beside-a-true-rule, answers per "
             "stand. In each case here no second rule applies to the request, so no rule can decide before the read "
             "and the answer does not depend on the order. The scope service is pinned to two grants, region r1 and "
             "region r2. The first request waits out the cachePeriod of the declaration, as permission-scope-wire "
             "does, so that a scope an earlier function cached is not served.",
             REGULAR_PREFIX, pips={"scope": SCOPE_PIP}, pins={SCOPE_ROUTE: scope_body({"region": ["r1"]},
                                                                                     {"region": ["r2"]})})
    f.add(regular(
        "r13-scope-outside-iterate-in-a-deny-rule",
        one_set("PERMIT_UNLESS_DENY", policy(
            "scoped", "PERMIT_UNLESS_DENY",
            rule("read-deny-under-is-empty", "operation == 'READ'", "subject.permissionScope.region IS EMPTY", "DENY"),
            rule("control-deny-without-scope", "operation == 'CONTROL'", "resource.a == 'y'", "DENY"))),
        [req("read-under-is-empty", {"id": "r13-scope-deny"}, pauseMs=2000),
         req("control-without-scope", {"id": "r13-scope-deny", "a": "z"}, operation="CONTROL")],
        ["scope"],
        about="A PERMIT_UNLESS_DENY policy whose DENY rule reads the scope: check/resource is true if the read ends "
              "the rule alone, and false if it ends the answer. control-without-scope is its control, a DENY rule on "
              "another operation that does not apply, so the policy permits."))
    for key, algorithm, effect, about in (
        ("deny-unless-permit", "DENY_UNLESS_PERMIT", "ALLOW",
         "Reads the scope in the policy target, beside the role, over an ALLOW rule; the permit-unless-deny case "
         "does the same over a DENY rule. A target that holds gives true here and false there, a target that does "
         "not apply gives false and true, and a read that ends the answer gives false twice."),
        ("permit-unless-deny", "PERMIT_UNLESS_DENY", "DENY", None),
    ):
        f.add(regular(
            "r13-scope-outside-iterate-in-a-policy-target-under-" + key,
            one_set(algorithm, policy("scoped", algorithm, rule("any", "true", "true", effect),
                                      target=READER_TARGET + " AND subject.permissionScope.region IS NULL")),
            [req("read", {"id": "r13-scope-target"})], ["scope"], about=about))
    f.add(regular(
        "r13-scope-placeholder-outside-iterate",
        one_set("DENY_UNLESS_PERMIT", policy("scoped", "DENY_UNLESS_PERMIT", allow_with_predicate(
            "list-in-granted-regions", "region=in=(${subject.permissionScope.region})"))),
        FILTER_REQUESTS, ["scope"],
        about="Renders the scope key into the predicate of a set that does not iterate, with no other rule on LIST: "
              "DENY says the placeholder denies the filter, a predicate says what it renders to."))
    f.add(regular(
        "r13-scope-condition-outside-iterate-beside-a-predicate",
        one_set("DENY_UNLESS_PERMIT", predicate_policy(), policy(
            "scoped", "DENY_UNLESS_PERMIT",
            rule("list-under-is-empty", "operation == 'LIST'", "subject.permissionScope.region IS EMPTY", "ALLOW"))),
        [req("filter", filter=True)], ["scope"],
        about="Reads the scope key in the condition of a rule without a predicate, beside the allowed==1 policy: DENY "
              "says the read denies the whole filter, allowed==1 that the rule drops out. It sends the filter alone, "
              "since check/resource there has a permitting rule beside the read and answers per stand."))
    return f


ALGORITHMS = ("DENY_UNLESS_PERMIT", "DENY_OVERRIDES", "PERMIT_OVERRIDES", "PERMIT_UNLESS_DENY")


def key_of(algorithm):
    return algorithm.lower().replace("_", "-")


def allows_list():
    return policy("allows-list", "DENY_UNLESS_PERMIT", rule("list-allow", "operation == 'LIST'", "true", "ALLOW"))


def for_nobody_set(key, algorithm):
    """A set under algorithm whose one policy targets a role nobody holds, so none of its policies applies."""
    return {"key": key, "target": "true", "algorithm": algorithm, "policies": [
        policy(key + "-for-nobody", "DENY_UNLESS_PERMIT",
               rule(key + "-for-nobody-list-allow", "operation == 'LIST'", "true", "ALLOW"), target=FALSE_SUBJECT)]}


def filter_cases():
    f = File("filter",
             "What an ALLOW without a predicate does to a predicate beside it in check/filter, and what a set none of "
             "whose policies applies gives the set above it. Round 12 showed that under DENY_OVERRIDES the predicate "
             "stays beside such an ALLOW (r12 deny-overrides-set-with-an-unrestricted-allow-beside-a-predicate), while "
             "under DENY_UNLESS_PERMIT the ALLOW lifts it (r10 deny-list-without-predicate-beside-a-predicate), and "
             "that a PERMIT_UNLESS_DENY set with no policy that applies gives ALLOW. Every case sends the filter on "
             "LIST and check/resource on LIST.",
             REGULAR_PREFIX)
    for algorithm in ("PERMIT_OVERRIDES", "PERMIT_UNLESS_DENY"):
        key = key_of(algorithm)
        f.add(regular("r13-" + key + "-set-with-an-unrestricted-allow-beside-a-predicate",
                      one_set(algorithm, predicate_policy(), allows_list()), FILTER_REQUESTS,
                      about="ALLOW if the ALLOW without a predicate lifts the filter, allowed==1 if the predicate "
                            "stays. The -alone case is the control."))
        f.add(regular("r13-" + key + "-set-with-the-unrestricted-allow-alone",
                      one_set(algorithm, allows_list()), FILTER_REQUESTS))
    for algorithm in ALGORITHMS:
        about = None
        if algorithm == "DENY_UNLESS_PERMIT":
            about = ("A set none of whose policies applies, nested as the only child of a DENY_UNLESS_PERMIT set: DENY "
                     "says the nested set does not apply, ALLOW that it permits. The round 11 cases "
                     "fn-nested-set-without-an-applicable-policy-under-* put the set beside allowed==1 under "
                     "DENY_OVERRIDES, where the two give one answer. This row is the control, DENY by round 11; the "
                     "PERMIT_UNLESS_DENY row says whether that set still gives ALLOW when nested, which "
                     "r13-deny-unless-permit-set-with-a-nested-allow-beside-a-predicate needs.")
        f.add(regular("r13-only-child-" + key_of(algorithm) + "-set-without-an-applicable-policy",
                      one_set("DENY_UNLESS_PERMIT", key="outer", sets=[for_nobody_set("nested", algorithm)]),
                      FILTER_REQUESTS, about=about))
    f.add(regular(
        "r13-deny-unless-permit-set-with-a-nested-allow-beside-a-predicate",
        one_set("DENY_UNLESS_PERMIT", predicate_policy(), key="outer",
                sets=[for_nobody_set("nested", "PERMIT_UNLESS_DENY")]),
        FILTER_REQUESTS,
        about="The PERMIT_UNLESS_DENY set with no policy that applies, beside the allowed==1 policy under "
              "DENY_UNLESS_PERMIT: ALLOW if the ALLOW of a nested set lifts the predicate as a policy's ALLOW does, "
              "allowed==1 if it does not or if the nested set does not apply, which the PERMIT_UNLESS_DENY "
              "only-child row tells apart."))
    f.add(regular(
        "r13-deny-overrides-set-with-an-unrestricted-allow-beside-a-deny-predicate",
        one_set("DENY_OVERRIDES", allows_list(), policy(
            "with-a-deny-predicate", "DENY_OVERRIDES",
            rule("list-deny-with-a-predicate", "operation == 'LIST'", "true", "DENY", {"rsqlPredicate": "blocked==1"}))),
        FILTER_REQUESTS,
        about="The ALLOW without a predicate beside a DENY rule with the predicate blocked==1 under DENY_OVERRIDES: "
              "ALLOW if the ALLOW lifts a negated predicate, the negation of blocked==1 if it stays."))
    return f


def pap_syntax():
    f = File("pap-syntax",
             "Whether the PAP accepts a condition with a literal left over after a complete comparison, and a list "
             "whose second element is an attribute rather than a literal. No golden records either form. Each upload "
             "is recorded with its status, and an accepted one also with the answer to READ.",
             ISOLATED_PREFIX)
    resource = {"id": "r13-syntax", "a": "y", "x": "a", "y": "b"}
    f.add(isolated("ps-trailing-literal", "resource.a == 'y' 'z'", [req("read", resource)]))
    f.add(isolated("ps-attribute-in-a-list", "resource.x IN 'a', resource.y", [req("read", resource)]))
    return f


# The operators of the cells, keyed as the case ids name them.
OPERATORS = (
    ("equals", "== 'v'"), ("not-equals", "!= 'v'"), ("less-than", "< 5"), ("less-or-equal", "<= 5"),
    ("greater-than", "> 5"), ("greater-or-equal", ">= 5"), ("is-null", "IS NULL"), ("is-not-null", "IS NOT NULL"),
    ("is-empty", "IS EMPTY"), ("is-not-empty", "IS NOT EMPTY"), ("in", "IN 'v', 'w'"), ("not-in", "NOT IN 'v', 'w'"),
    ("contains", "CONTAINS 'v'"), ("not-contains", "NOT CONTAINS 'v'"), ("contains-any", "CONTAINS ANY 'v', 'w'"),
    ("not-contains-any", "NOT CONTAINS ANY 'v', 'w'"), ("is-subset", "IS SUBSET 'v', 'w'"),
    ("is-not-subset", "IS NOT SUBSET 'v', 'w'"), ("match", "MATCH v*"), ("not-match", "NOT MATCH v*"),
)
OPERATOR = dict(OPERATORS)
OR_TRUE = " OR resource.a == 'y'"

# Per operand state: the id prefix, the operand, what the resource carries beside id and a, the PIPs it reads, and
# the cells asked, as <operator>-alone or <operator>-or.
CELL_STATES = (
    ("ABSENT", "ca", "resource.x", {}, (), (
        "contains-any-alone", "contains-any-or", "contains-or", "greater-or-equal-alone", "greater-or-equal-or",
        "in-alone", "in-or", "is-subset-alone", "is-subset-or", "less-or-equal-alone", "less-or-equal-or",
        "less-than-alone", "less-than-or", "match-or")),
    ("NULL", "cx", "resource.x", {"x": None}, (), ("is-not-null-or",)),
    ("EMPTY_COLL", "ce", "resource.x", {"x": []}, (), (
        "contains-any-alone", "contains-any-or", "contains-or", "greater-or-equal-alone", "greater-or-equal-or",
        "greater-than-alone", "greater-than-or", "in-alone", "in-or", "less-or-equal-alone", "less-or-equal-or",
        "less-than-alone", "less-than-or", "match-alone", "match-or", "not-contains-alone", "not-contains-any-alone",
        "not-in-alone", "not-match-alone", "not-match-or")),
    ("EMPTY_SEL", "cs", "resource.items[?(@.type=='zzz')].id", {"items": [{"type": "a", "id": "q"}]}, (), (
        "contains-any-alone", "contains-any-or", "contains-or", "equals-alone", "equals-or", "greater-or-equal-alone",
        "greater-or-equal-or", "greater-than-alone", "greater-than-or", "in-alone", "in-or", "is-not-empty-alone",
        "is-not-empty-or", "is-not-null-alone", "is-not-null-or", "is-not-subset-alone", "is-null-alone",
        "is-subset-alone", "is-subset-or", "less-or-equal-alone", "less-or-equal-or", "less-than-alone",
        "less-than-or", "match-alone", "match-or", "not-contains-any-alone", "not-equals-alone", "not-in-alone",
        "not-match-alone", "not-match-or")),
    ("INDEX_OOB", "co", "resource.list[5]", {"list": ["a"]}, (), (
        "contains-alone", "contains-any-alone", "contains-any-or", "contains-or", "equals-alone", "equals-or",
        "greater-or-equal-alone", "greater-or-equal-or", "greater-than-alone", "greater-than-or", "in-alone", "in-or",
        "is-not-empty-alone", "is-not-empty-or", "is-not-null-alone", "is-not-null-or", "is-not-subset-alone",
        "is-not-subset-or", "is-null-alone", "is-subset-alone", "is-subset-or", "less-or-equal-alone",
        "less-or-equal-or", "less-than-alone", "less-than-or", "match-alone", "match-or", "not-contains-any-alone",
        "not-contains-any-or", "not-equals-alone", "not-equals-or", "not-in-alone", "not-in-or", "not-match-alone",
        "not-match-or")),
    ("PIP_EMPTY", "ch", "subject.parityNoHeader", {}, ("noheader",), (
        "greater-or-equal-alone", "greater-or-equal-or", "greater-than-alone", "greater-than-or",
        "less-or-equal-alone", "less-or-equal-or")),
    ("PIP_NULL", "cn", "subject.parityR13NullBody", {}, ("nullbody",), (
        "contains-alone", "contains-any-alone", "contains-any-or", "contains-or", "equals-alone", "equals-or",
        "greater-or-equal-alone", "greater-or-equal-or", "greater-than-alone", "greater-than-or", "in-alone", "in-or",
        "is-not-empty-alone", "is-not-null-alone", "is-not-null-or", "is-not-subset-alone", "is-subset-alone",
        "is-subset-or", "less-or-equal-alone", "less-or-equal-or", "less-than-alone", "less-than-or", "match-alone",
        "match-or", "not-contains-alone", "not-contains-any-alone", "not-contains-any-or", "not-contains-or",
        "not-in-alone", "not-match-alone", "not-match-or")),
    # Every operator alone here; every operator on the left of the true OR is added after all states.
    ("ERROR", "cf", "subject.parityR13Failing", {}, ("failing",), (
        "contains-alone", "contains-any-alone", "equals-alone", "greater-or-equal-alone", "greater-than-alone",
        "in-alone", "is-empty-alone", "is-not-empty-alone", "is-not-null-alone", "is-not-subset-alone",
        "is-null-alone", "is-subset-alone", "less-or-equal-alone", "less-than-alone", "match-alone",
        "not-contains-alone", "not-contains-any-alone", "not-in-alone", "not-match-alone")),
)


def cells():
    f = File("cells",
             "What each operator answers over each operand state, in the cells of the operator-by-state table that no "
             "golden fixes: those where a recorded case cannot tell a false operand from a true one, or from an ended "
             "rule, and those no case reaches. Every condition is one simplified policy on READ, sent once. A case id "
             "ending in -alone is the operator by itself, so true tells a true operand from a false one or an ended "
             "rule; one ending in -or stands on the left of OR resource.a == 'y', so true tells a false operand from an "
             "ended rule. The id prefix names the operand state: ca- resource.x, which the resource does not carry; "
             "cx- resource.x is null; ce- resource.x is []; cs- resource.items[?(@.type=='zzz')].id over items none of "
             "which has that type; co- resource.list[5] over a list of one element; ch- subject.parityNoHeader, a "
             "HEADER PIP whose header the request does not carry; cn- a GENERAL PIP whose body is the JSON literal "
             "null; cf- a GENERAL PIP that answers 500. The two GENERAL PIPs are pinned at routes of their own, as "
             "nb-null-body-* does. A GENERAL PIP that answers 500 fails the whole answer rather than one operand "
             "(rf-*), and over a single policy an operand that is false, a rule that ends, and an answer that fails "
             "all read false. So every operator is also asked over that PIP on the left of the true OR, as "
             "cf-<operator>-or: true says the operand was evaluated, false that the rule ended or the answer failed; "
             "failing-pip-in-a-deny-rule.json tells those two apart.",
             ISOLATED_PREFIX,
             pips={
                 "noheader": {"name": "subject.parityNoHeader", "type": "UUID", "pipType": "HEADER",
                              "header": "x-parity-no-such-header", "cacheable": False},
                 "nullbody": general_pip("subject.parityR13NullBody", NULL_ROUTE),
                 "failing": general_pip("subject.parityR13Failing", FAILING_ROUTE),
             },
             pins={NULL_ROUTE: {"statusCode": 200, "bodyRaw": "null"}, FAILING_ROUTE: FAILING_ANSWER})

    def add(cid, condition, extra, pips):
        f.add(isolated(cid, condition, [req("probe", {"id": "r13-" + cid, "a": "y", **extra})], pips))

    for _, prefix, operand, extra, pips, keys in CELL_STATES:
        for key in keys:
            operator, form = key.rsplit("-", 1)
            add(prefix + "-" + key, operand + " " + OPERATOR[operator] + (OR_TRUE if form == "or" else ""), extra,
                pips)
    for operator, text in OPERATORS:
        add("cf-" + operator + "-or", "subject.parityR13Failing " + text + OR_TRUE, {}, ("failing",))
    return f


def failing_pip_in_a_deny_rule():
    f = File("failing-pip-in-a-deny-rule",
             "Whether a GENERAL PIP that answers 500 ends only the rule that reads it or the whole answer, under every "
             "operator. Each case is a DENY rule over that PIP in a PERMIT_UNLESS_DENY policy, with no other rule: "
             "true says the operand is false or the rule ended alone, false that the operand holds or the answer "
             "failed. Beside cf-<operator>-alone and cf-<operator>-or of cells.json the three answers name the "
             "outcome.",
             REGULAR_PREFIX, pips={"failing": general_pip("subject.parityR13Failing", FAILING_ROUTE)},
             pins={FAILING_ROUTE: FAILING_ANSWER})
    for operator, text in OPERATORS:
        f.add(regular(
            "r13-failing-pip-in-a-deny-rule-" + operator,
            one_set("PERMIT_UNLESS_DENY", policy("reader", "PERMIT_UNLESS_DENY",
                                                 rule("deny", "true", "subject.parityR13Failing " + text, "DENY"))),
            [req("read", {"id": "r13-failing-pip"})], ["failing"]))
    return f


for build in (scope_outside_iterate, filter_cases, pap_syntax, cells, failing_pip_in_a_deny_rule):
    build().write()
