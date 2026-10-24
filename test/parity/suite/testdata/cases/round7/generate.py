"""Writes the round 7 case files next to this script: python3 generate.py.

Round 7 was first written in Go; these files hold the same cases, request for request, so the goldens recorded
then still apply. Each file is one test function of the parity suite, in the format case_files_test.go reads:

  failed-pip-beside-allow.json  a rule reading a GENERAL PIP that failed, beside a rule of its policy that allows
  set-target-refusal.json       whether missing-attribute-in-set-target was refused for its target or its shared id
  filter.json                   a rule without a predicate in check/filter, and a filter request with no operation

TestRound7IteratePermitOverridesCases and TestRound7PIPCacheCases stay in Go: they file their goldens outside regular/
and isolated/, and TestRound7PIPCacheCases waits a time measured from the moment it re-pinned pip-mock, which a fixed
pauseMs does not reproduce.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PIP_MOCK = "http://pip-mock:8090/api/v1/pip"
READER_TARGET = "subject.roles CONTAINS 'ROLE_PARITY_READER'"
REGULAR_PREFIX = "PARITY_SUITE_REG_"


def upper(text):
    return text.upper().replace("-", "_")


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


def one_set(key, target, algorithm, *policies):
    return {"key": key, "target": target, "algorithm": algorithm, "policies": list(policies)}


def regular(cid, sets, requests, pips=(), reads_routes=None, about=None):
    case = {"id": cid}
    if about:
        case["about"] = about
    if pips:
        case["pips"] = list(pips)
    if reads_routes:
        case["readsRoutes"] = reads_routes
    case["sets"] = sets
    case["requests"] = requests
    return case


RT_TARGET = "resourceType == '{{resourceType}}'"


def failed_pip_beside_allow():
    # The two algorithms under which a permit is not terminal, with the suffix that makes the PIP names and the
    # pip-mock paths of their case its own.
    algorithms = (("permit-unless-deny", "PERMIT_UNLESS_DENY", "PermitUnlessDeny"),
                  ("deny-overrides", "DENY_OVERRIDES", "DenyOverrides"))
    pips, pins = {}, {}
    for key, _, suffix in algorithms:
        rt = REGULAR_PREFIX + upper("failed-pip-beside-allow-" + key)
        for kind in ("broken", "gone", "live"):
            pip = {"name": "subject.parityTranslator" + kind.capitalize() + suffix,
                   "url": PIP_MOCK + "/translator-" + kind + "-" + key, "httpMethod": "POST", "pipType": "GENERAL",
                   "requestAttributes": {"resourceType": rt}, "cacheable": False}
            if kind == "live":
                # The live PIP reads $.value out of the body, so its condition compares a value, not an object.
                pip.update({"type": "JSON", "jsonPath": "$.value"})
            pips[kind + "-" + key] = pip
        route = "/api/v1/pip/translator-{}-" + key
        pins[route.format("broken")] = {"statusCode": 500, "body": {"error": "parity failed-pip case"}}
        pins[route.format("gone")] = {"statusCode": 404, "body": {"error": "parity failed-pip case"}}
        pins[route.format("live")] = {"statusCode": 200, "body": {"value": "v"}}
    f = File("failed-pip-beside-allow",
             "A rule whose condition reads a GENERAL PIP that failed, beside a rule of the same policy that allows. "
             "approve-failed-allow-beside-allow records this shape with a missing resource key and answers true under "
             "all four algorithms: an unresolvable value makes one rule inapplicable and leaves its neighbor alone. A "
             "failed PIP is the other way an operand fails to resolve, and whether the two are the same event decides "
             "whether an evaluator can drop the abort altogether. The cases run under PERMIT_UNLESS_DENY and "
             "DENY_OVERRIDES, the two algorithms under which a permit is not terminal, so every rule of the policy is "
             "evaluated whatever order the stand takes them in. Under DENY_UNLESS_PERMIT and PERMIT_OVERRIDES the "
             "first permitting rule ends the policy, the rule reading the failed PIP is evaluated only when the stand "
             "orders it first, and five recording runs on fresh stands answered the same request both ways, so those "
             "two algorithms have no answer to record. READ is an ALLOW reading the PIP answering 500 beside an ALLOW, "
             "UPDATE the same with 404, DELETE a DENY reading the 500 beside an ALLOW, and PROBE the rule reading the "
             "live PIP alone: the control that the declarations and pip-mock work, so a case where every answer is "
             "false is not explained by pip-mock being unreachable or the declarations being dropped. Each case reads "
             "PIPs of its own, named and routed after its algorithm, and fails unless pip-mock received a call on each "
             "of its three routes, so a PIP answer that outlived the case that fetched it could not be mistaken for a "
             "fresh one; TestRound7PIPCacheCases rules that out for cacheable false. Every case declares all six PIPs, "
             "because an upload of the domain replaces its declarations while the sets of the earlier case are still "
             "loaded, and a loaded set that reads a PIP the domain no longer declares makes access-control refuse every "
             "check with 400.",
             REGULAR_PREFIX, pips=pips, pins=pins)
    resource = {"id": "tr-failed-pip"}
    for key, algorithm, suffix in algorithms:
        def name(kind):
            return "subject.parityTranslator" + kind + suffix
        f.add(regular(
            "failed-pip-beside-allow-" + key,
            [one_set("set", RT_TARGET, algorithm, policy(
                "reader", algorithm,
                rule("read-allow-reads-the-broken-pip", "operation == 'READ'", name("Broken") + " != 'x'", "ALLOW"),
                rule("read-allow", "operation == 'READ'", "true", "ALLOW"),
                rule("update-allow-reads-the-gone-pip", "operation == 'UPDATE'", name("Gone") + " != 'x'", "ALLOW"),
                rule("update-allow", "operation == 'UPDATE'", "true", "ALLOW"),
                rule("delete-deny-reads-the-broken-pip", "operation == 'DELETE'", name("Broken") + " != 'x'", "DENY"),
                rule("delete-allow", "operation == 'DELETE'", "true", "ALLOW"),
                rule("probe-allow-reads-the-live-pip", "operation == 'PROBE'", name("Live") + " == 'v'", "ALLOW")))],
            [req("failed-allow-beside-allow", resource, operation="READ"),
             req("missing-allow-beside-allow", resource, operation="UPDATE"),
             req("failed-deny-beside-allow", resource, operation="DELETE"),
             req("live-pip-alone", resource, operation="PROBE")],
            pips=list(pips),
            reads_routes=["/api/v1/pip/translator-" + kind + "-" + key for kind in ("broken", "gone", "live")]))
    return f


def set_target_refusal():
    f = File("set-target-refusal",
             "Whether the recorded refusal of missing-attribute-in-set-target came from the set target that reads "
             "resource.x, or from the fixture beside it. missing-attribute-in-set-target uploads two sets whose "
             "policies share one policyId, since both are built from the key reader, and records 400; "
             "set-target-reads-unknown-attribute uploads the same target with two policy ids and records 200. The two "
             "cases here separate the two differences.",
             REGULAR_PREFIX)
    f.add(regular(
        "set-target-reads-missing-attribute-with-distinct-policy-ids",
        [one_set("reads-missing", "resourceType == '{{resourceType}}' AND resource.x == 'v'", "DENY_UNLESS_PERMIT",
                 policy("reader", "DENY_UNLESS_PERMIT", rule("read-allow", "operation == 'READ'", "true", "ALLOW"))),
         one_set("sibling", RT_TARGET, "DENY_UNLESS_PERMIT",
                 policy("sibling-reader", "DENY_UNLESS_PERMIT",
                        rule("read-allow-when-s", "operation == 'READ'", "resource.s == 'y'", "ALLOW")))],
        [req("sibling-allows", {"id": "reg-set-target", "s": "y"}),
         req("both-attributes-present", {"id": "reg-set-target", "x": "v", "s": "n"})],
        about="missing-attribute-in-set-target with the sibling policy under a key of its own, so the policy ids differ "
              "and the target is the only thing left to refuse. The requests are the recorded case's, read against "
              "the sibling set."))
    f.add(regular(
        "two-sets-whose-policies-share-one-id",
        [one_set("first", RT_TARGET, "DENY_UNLESS_PERMIT",
                 policy("reader", "DENY_UNLESS_PERMIT", rule("first-read-allow", "operation == 'READ'", "true", "ALLOW"))),
         one_set("second", RT_TARGET, "DENY_UNLESS_PERMIT",
                 policy("reader", "DENY_UNLESS_PERMIT",
                        rule("second-probe-allow", "operation == 'PROBE'", "true", "ALLOW")))],
        [req("read-under-the-first-set", {"id": "reg-shared-policy-id"}, operation="READ"),
         req("probe-under-the-second-set", {"id": "reg-shared-policy-id"}, operation="PROBE")],
        about="Two sets whose targets name the resource type alone and whose policies share one policyId, so the "
              "shared id is the only thing left to refuse. The two requests, one per set, are probes that a set the "
              "PAP accepted answers true."))
    return f


def filter_cases():
    f = File("filter",
             "What check/filter does with a rule that has no predicate and a condition it can evaluate without a "
             "resource, and which operation a filter request with no operation parameter is answered for. "
             "filter-rule-with-a-condition-and-no-predicate records DENY for a rule whose condition reads resource.x, "
             "and a filter request carries no resource, so that recording does not separate a rule without a "
             "predicate being left out of the filter from a condition that could not be evaluated. Each condition "
             "case also sends check/resource for the same operation. The cases live in their own test function so "
             "that a recording run can be filtered to them and leave every golden already committed alone. Legacy "
             "profile only, like every case with sets.",
             REGULAR_PREFIX)
    for key, condition, resource, about in (
        ("subject", READER_TARGET, {"id": "reg-filter-cond"},
         "The rule's condition reads the subject's roles, which the filter request can evaluate: ALLOW means the "
         "rule takes part in the filter and lifts it when its condition holds, DENY that a rule without a predicate "
         "is left out whatever its condition."),
        ("resource", "resource.x == 'v'", {"id": "reg-filter-cond", "x": "v"},
         "The control: the recorded resource condition, run on the same stand."),
    ):
        f.add(regular("filter-rule-with-a-" + key + "-condition-and-no-predicate", [one_set(
            "set", RT_TARGET, "DENY_UNLESS_PERMIT", policy(
                "reader", "DENY_UNLESS_PERMIT", rule("list-under-a-condition", "operation == 'LIST'", condition,
                                                     "ALLOW")))],
            [req("filter", filter=True), req("check-list-condition-true", resource, operation="LIST")], about=about))
    f.add(regular("filter-without-an-operation-and-no-rule-on-read", [one_set(
        "set", RT_TARGET, "DENY_UNLESS_PERMIT", policy(
            "reader", "DENY_UNLESS_PERMIT",
            rule("update", "operation == 'UPDATE'", "true", "ALLOW", {"rsqlPredicate": "update==1"}),
            rule("list", "operation == 'LIST'", "true", "ALLOW", {"rsqlPredicate": "list==1"})))],
        [req("filter-with-no-operation", filter=True, omitOperation=True),
         req("filter-with-update", filter=True, operation="UPDATE")],
        about="filter-without-an-operation records read==1 against rules on READ and on UPDATE, which fits both a "
              "default operation of READ and the first rule that applies. This set has rules on UPDATE and on LIST "
              "and none on READ, uploaded in that order: DENY means the operation defaults to READ, list==1 that it "
              "defaults to LIST, and update==1 that the first rule in upload order is taken. filter-with-update, "
              "the operation spelled out, is the control that the set answers a filter at all."))
    return f


for build in (failed_pip_beside_allow, set_target_refusal, filter_cases):
    build().write()
