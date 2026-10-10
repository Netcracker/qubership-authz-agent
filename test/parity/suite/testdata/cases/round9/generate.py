"""Writes the round 9 case files next to this script: python3 generate.py.

Round 9 was first written in Go; these files hold the same cases, request for request, so the goldens recorded
then still apply. Each file is one test function of the parity suite, in the format case_files_test.go reads:

  empty-header-and-claim.json             every operator over an absent header and an absent claim
  right-operand.json                      an absent header, an absent claim, or a failed PIP on the right
  single-element-list.json                ==, !=, IN and CONTAINS over a header and a claim holding one value
  plain-array-equality.json               == and != over a resource attribute that is a JSON array
  is-null-over-dead-forms.json            IS NULL over resource['x'] and the literal null
  token-default-list.json                 whether the defaultValue of a TOKEN PIP is split on commas
  non-string-pip-value.json               a GENERAL PIP answering a number or a boolean beside an allowing rule
  deny-rule-without-predicate.json        a DENY rule with no predicate in check/filter, under every algorithm
  false-condition-without-predicate.json  an ALLOW rule with no predicate and a false subject condition
  filter-algebra.json                     filter answers whose check/resource decision is recorded
  unresolved-placeholder.json             a placeholder that cannot be resolved beside one that can
  subject-scalar-substitution.json        ${subject.name} and ${subject.type} in every predicate dialect

A case id ending in -control is the probe's control: the operand under question on the right of
resource.a == 'y' OR, where it is true whatever the operand does, so a false control means the fixture is broken.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PIP_MOCK = "http://pip-mock:8090/api/v1/pip"
READER_TARGET = "subject.roles CONTAINS 'ROLE_PARITY_READER'"
ISOLATED_PREFIX = "PARITY_SUITE_R9_"
REGULAR_PREFIX = "PARITY_SUITE_REG_"


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


def or_probe_pair(f, cid, resource_type, operand, requests, pips=(), reads_routes=None):
    """The probe puts operand on the left of an OR whose right operand is true; the control swaps them."""
    probe = isolated(cid, operand + " OR resource.a == 'y'", requests, pips)
    if reads_routes:
        probe = {**{k: v for k, v in probe.items() if k != "requests"}, "readsRoutes": reads_routes,
                 "requests": requests}
    f.add(probe, resource_type)
    f.add(isolated(cid + "-control", "resource.a == 'y' OR " + operand, requests, pips), resource_type + "_CTL")


def req(name, resource=None, **extra):
    r = {"name": name}
    r.update(extra)
    if resource is not None:
        r["resource"] = resource
    return r


NO_HEADER = {"name": "subject.parityR9NoHeader", "type": "UUID", "pipType": "HEADER",
             "header": "x-parity-r9-no-such-header", "cacheable": False}
NO_CLAIM = {"name": "subject.parityR9NoClaim", "type": "UUID", "pipType": "TOKEN",
            "claim": "parity_r9_no_such_claim", "cacheable": False}

OPERATORS = [
    ("equals", "== 'v'"), ("not-equals", "!= 'v'"), ("less-than", "< 5"), ("is-null", "IS NULL"),
    ("is-not-null", "IS NOT NULL"), ("is-empty", "IS EMPTY"), ("is-not-empty", "IS NOT EMPTY"),
    ("in", "IN 'v', 'w'"), ("not-in", "NOT IN 'v', 'w'"), ("contains", "CONTAINS 'v'"),
    ("not-contains", "NOT CONTAINS 'v'"), ("match", "MATCH v*"), ("not-match", "NOT MATCH v*"),
    ("contains-any", "CONTAINS ANY 'v', 'w'"), ("not-contains-any", "NOT CONTAINS ANY 'v', 'w'"),
    ("is-subset", "IS SUBSET 'v', 'w'"), ("is-not-subset", "IS NOT SUBSET 'v', 'w'"),
]


def empty_header_and_claim():
    f = File("empty-header-and-claim",
             "What each operator answers over a HEADER PIP whose header is absent and over a TOKEN PIP whose claim is "
             "absent, both with no defaultValue. Recorded before this file: for the header, !=, IS NULL and IS EMPTY "
             "all true (h1, h2, hl3/no-header); for the claim, == false, != true and IS NULL true (p1a-p1c). The header "
             "answers IS EMPTY true, which null does not, so the absent header may be an empty list; the two readings "
             "differ under NOT CONTAINS, NOT CONTAINS ANY and IS NOT EMPTY. Each operator is asked alone, where a true "
             "answer is the leaf's value and a false answer is a false leaf or an ended rule, and through a probe and "
             "its control, which tell the two apart. The agent's condition parser accepts every condition here.",
             ISOLATED_PREFIX, pips={"noheader": NO_HEADER, "noclaim": NO_CLAIM})
    resource = {"id": "r9-empty", "a": "y"}
    for key, pip in (("absent-header", "noheader"), ("absent-claim", "noclaim")):
        name = f.pips[pip]["name"]
        for op_key, operator in OPERATORS:
            cid = "es-" + key + "-" + op_key
            rt = ISOLATED_PREFIX + "ES_" + upper(key + "_" + op_key)
            operand = name + " " + operator
            f.add(isolated(cid + "-alone", operand, [req("reader", resource)], [pip]), rt + "_ALONE")
            or_probe_pair(f, cid, rt, operand, [req("reader", resource)], [pip])
    f.add(isolated("es-empty-collection-is-null", "resource.x IS NULL", [
        req("empty-collection", {"id": "r9-empty", "x": []}),
        req("key-absent", {"id": "r9-empty"}),
    ], about="IS NULL over an empty resource collection, the value an absent header may be read as. key-absent is the "
             "control, recorded true by s6a."), ISOLATED_PREFIX + "ES_EMPTY_COLLECTION")
    f.add(isolated("es-empty-header-in-a-predicate", None, [
        req("no-header", filter=True),
        req("header-sent", filter=True, headers={"x-parity-r9-no-such-header": "h1"}),
    ], ["noheader"], operation="LIST", policy={"rsqlPredicate": "a==${subject.parityR9NoHeader}"},
        about="The absent header rendered through an rsql placeholder of a simplified policy; header-sent is the "
              "control. p5 records an absent claim there as an empty string."),
        ISOLATED_PREFIX + "ES_HEADER_PREDICATE")
    return f


def right_operand():
    failed_route = "/api/v1/pip/r9-right-failed"
    f = File("right-operand",
             "What a condition answers when the attribute on the right of an operator is an absent header, an absent "
             "claim, or a GENERAL PIP that answered 500. a1 records an absent resource key on the right as false alone, "
             "which does not tell a false leaf from an ended rule, and no earlier case puts a PIP there. The agent's "
             "condition parser accepts every condition here. Each goes through a probe and its control: the probe is true "
             "when the right operand is a value the operator is false over, and false when it ends the rule or, for "
             "the failed PIP, the whole answer. The failed PIP is read by the probe alone, and the probe fails unless "
             "pip-mock received a call to it.",
             ISOLATED_PREFIX,
             pips={
                 "noheader": NO_HEADER, "noclaim": NO_CLAIM,
                 "failed": {"name": "subject.parityR9RightFailed", "url": PIP_MOCK + "/r9-right-failed",
                            "httpMethod": "POST", "pipType": "GENERAL",
                            "requestAttributes": {"resourceType": "PARITY_SUITE_R9_RIGHT"}, "cacheable": False},
                 "home": {"name": "subject.parityR9HomeIds", "type": "UUID", "pipType": "HEADER",
                          "header": "x-parity-r9-home-ids", "cacheable": False},
                 "delegated": {"name": "subject.parityR9DelegatedIds", "type": "UUID", "pipType": "HEADER",
                               "header": "x-parity-r9-delegated-ids", "cacheable": False},
             },
             pins={failed_route: {"statusCode": 500, "body": {"error": "parity right-operand case"}}})
    resource = {"id": "r9-right", "a": "y", "x": "v"}
    for key, operand, pip, routes in (
        ("in-an-absent-header", "resource.x IN subject.parityR9NoHeader", "noheader", None),
        ("equals-an-absent-claim", "resource.x == subject.parityR9NoClaim", "noclaim", None),
        ("in-a-failed-pip", "resource.x IN subject.parityR9RightFailed", "failed", [failed_route]),
    ):
        or_probe_pair(f, "ro-" + key, ISOLATED_PREFIX + "RO_" + upper(key), operand, [req("reader", resource)], [pip],
                      routes)
    customer = {"id": "r9-right", "customerId": "c1"}
    f.add(isolated(
        "ro-in-either-header",
        "resource.customerId IN subject.parityR9HomeIds OR resource.customerId IN subject.parityR9DelegatedIds",
        [
            req("only-delegated-holds-the-id", customer, headers={"x-parity-r9-delegated-ids": "c1"}),
            req("only-home-holds-the-id", customer, headers={"x-parity-r9-home-ids": "c1"}),
            req("neither-header-holds-the-id", customer,
                headers={"x-parity-r9-home-ids": "c2", "x-parity-r9-delegated-ids": "c3"}),
        ], ["home", "delegated"],
        about="The one condition of the product policies in reach whose OR could depend on how the right operand of IN "
              "resolves. With only the second header sent, the first IN reads an absent header, and the answer is "
              "true when that IN is false and OR goes on. only-home-holds-the-id is the control, true whatever the "
              "second IN does, and neither-header-holds-the-id the negative control."))
    return f


def single_element_list():
    f = File("single-element-list",
             "What ==, !=, IN and CONTAINS answer over a HEADER PIP whose header holds one value, and over a TOKEN PIP "
             "whose claim is a list of one element. hl1-hl3 record that a header is split on commas into a list, and "
             "== 'a,b' over the header a,b is false; no earlier case asks == over a header holding a single value, the "
             "form every header of the product policies in reach is sent in. Each header case is sent the header a, the "
             "value the operator is asked about, and the header b; sl-header-contains is the control, true over a "
             "whichever way the header is read. The claim cases select the reader's role through a filter expression, "
             "so the claim is a list of one; sl-claim-contains is their control. tk2 records only a plain path into the "
             "token, so a refused upload of a claim case is a refused filter expression. The agent's condition parser "
             "accepts every condition here.",
             ISOLATED_PREFIX,
             pips={
                 "oneheader": {"name": "subject.parityR9OneHeader", "type": "UUID", "pipType": "HEADER",
                               "header": "x-parity-r9-one", "cacheable": False},
                 "onerole": {"name": "subject.parityR9OneRole", "type": "UUID", "pipType": "TOKEN",
                             "claim": "$.realm_access.roles[?(@ == 'ROLE_PARITY_READER')]", "cacheable": False},
             })
    header_requests = [req("header-" + v, {"id": "r9-one"}, headers={"x-parity-r9-one": v}) for v in ("a", "b")]
    for key, operator in (("equals", "== 'a'"), ("not-equals", "!= 'a'"), ("in", "IN 'a', 'z'"),
                          ("contains", "CONTAINS 'a'")):
        f.add(isolated("sl-header-" + key, "subject.parityR9OneHeader " + operator, header_requests, ["oneheader"]))
    for key, operator in (("equals", "== 'ROLE_PARITY_READER'"), ("not-equals", "!= 'ROLE_PARITY_READER'"),
                          ("in", "IN 'ROLE_PARITY_READER', 'ROLE_PARITY_NOBODY'"),
                          ("contains", "CONTAINS 'ROLE_PARITY_READER'")):
        f.add(isolated("sl-claim-" + key, "subject.parityR9OneRole " + operator, [req("reader", {"id": "r9-one"})],
                       ["onerole"]))
    return f


def plain_array_equality():
    f = File("plain-array-equality",
             "What == and != answer over a resource attribute that is a plain JSON array. No earlier golden records "
             "either operator over an array: j5-array-index compares one element, resource.list[0] == 'a', and is "
             "true. The agent's condition parser accepts both conditions. Each case is sent an array "
             "holding only the literal, an array holding it beside another value, an array without it, and a string, "
             "the control that the operator answers true where the attribute is a scalar.",
             ISOLATED_PREFIX)

    def requests(scalar):
        return [
            req("array-of-only-v", {"id": "r9-array", "list": ["v"]}),
            req("array-of-v-and-w", {"id": "r9-array", "list": ["v", "w"]}),
            req("array-without-v", {"id": "r9-array", "list": ["w"]}),
            req("string-" + scalar, {"id": "r9-array", "list": scalar}),
        ]

    f.add(isolated("pa-equals-over-an-array", "resource.list == 'v'", requests("v")), ISOLATED_PREFIX + "PA_EQUALS")
    f.add(isolated("pa-not-equals-over-an-array", "resource.list != 'v'", requests("w")),
          ISOLATED_PREFIX + "PA_NOT_EQUALS")
    return f


def is_null_over_dead_forms():
    f = File("is-null-over-dead-forms",
             "What IS NULL answers over the bracket path resource['x'] and the literal null, two forms the PAP accepts "
             "and that answer false under every other operator recorded (j7-bracket-path, df1, df2). IS NULL is the one "
             "operator that is true over an absent key (s6a), so a form read as an absent attribute is true here for "
             "every request. Each case is sent a resource that holds x and one that does not; "
             "dn-is-null-over-a-plain-path is the control, false and true. The agent's condition parser accepts both "
             "forms.",
             ISOLATED_PREFIX)
    requests = [req("x-present", {"id": "r9-dead", "x": "v"}), req("x-absent", {"id": "r9-dead"})]
    for cid, condition, rt in (
        ("dn-is-null-over-a-bracket-path", "resource['x'] IS NULL", "DN_BRACKET"),
        ("dn-is-null-over-the-null-literal", "null IS NULL", "DN_LITERAL"),
        ("dn-is-null-over-a-plain-path", "resource.x IS NULL", "DN_PLAIN"),
    ):
        f.add(isolated(cid, condition, requests), ISOLATED_PREFIX + rt)
    return f


def token_default_list():
    f = File("token-default-list",
             "Whether the defaultValue of a TOKEN PIP is split on commas, as a HEADER PIP's is (hl4 CONTAINS 'y' true, "
             "hl5 == 'x, y' false); p2 records a defaultValue without a comma. td-header-default-contains repeats hl4 "
             "in the same run, the control that the defaultValue form is accepted and applied. The agent's condition "
             "parser accepts both conditions.",
             ISOLATED_PREFIX,
             pips={
                 "tokendefault": {"name": "subject.parityR9TokenDefault", "type": "UUID", "pipType": "TOKEN",
                                  "claim": "parity_r9_no_such_claim", "defaultValue": "x, y", "cacheable": False},
                 "headerdefault": {"name": "subject.parityHdrList", "type": "UUID", "pipType": "HEADER",
                                   "header": "x-parity-hdr-list", "cacheable": False, "defaultValue": "x, y"},
             })
    claim_absent = [req("claim-absent", {"id": "r9-tokdef"})]
    f.add(isolated("td-token-default-contains", "subject.parityR9TokenDefault CONTAINS 'y'", claim_absent,
                   ["tokendefault"]), ISOLATED_PREFIX + "TD_CONTAINS")
    f.add(isolated("td-token-default-equals-the-string", "subject.parityR9TokenDefault == 'x, y'", claim_absent,
                   ["tokendefault"]), ISOLATED_PREFIX + "TD_EQUALS")
    f.add(isolated("td-header-default-contains", "subject.parityHdrList CONTAINS 'y'",
                   [req("no-header", {"id": "r9-tokdef"})], ["headerdefault"]), ISOLATED_PREFIX + "TD_HEADER")
    return f


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


def regular(cid, sets, requests, pips=(), reads_routes=None):
    case = {"id": cid}
    if pips:
        case["pips"] = list(pips)
    if reads_routes:
        case["readsRoutes"] = reads_routes
    case["sets"] = sets
    case["requests"] = requests
    return case


def non_string_pip_value():
    algorithms = (("permit-unless-deny", "PERMIT_UNLESS_DENY", "PermitUnlessDeny"),
                  ("deny-overrides", "DENY_OVERRIDES", "DenyOverrides"))
    pips, pins = {}, {}
    for key, _, suffix in algorithms:
        rt = REGULAR_PREFIX + upper("non-string-pip-beside-allow-" + key)
        for kind, value in (("Number", 1000), ("Boolean", True), ("String", "v")):
            pips[kind.lower() + "-" + key] = {
                "name": "subject.parityR9" + kind + suffix, "url": PIP_MOCK + "/r9-value-" + kind + "-" + key,
                "httpMethod": "POST", "pipType": "GENERAL", "type": "JSON", "jsonPath": "$.value",
                "requestAttributes": {"resourceType": rt}, "cacheable": False}
            pins["/api/v1/pip/r9-value-" + kind + "-" + key] = {"statusCode": 200, "body": {"value": value}}
    f = File("non-string-pip-value",
             "A rule whose condition reads a GENERAL PIP that answers a JSON number or a JSON boolean, beside a rule "
             "of the same policy that allows. No earlier golden records such a value in a condition: the limits of t8a "
             "and t8b are pinned as strings. The shape is failed-pip-beside-allow-*'s, which records that a PIP "
             "answering 500 beside an allowing rule refuses the whole answer, under the same two algorithms, where a "
             "permit is not terminal and every rule is "
             "evaluated whatever order the stand takes them in. READ is an ALLOW reading the number beside an ALLOW, "
             "UPDATE the same with the boolean, DELETE a DENY reading the number beside an ALLOW, and PROBE the rule "
             "that reads a PIP answering a string, alone: the control that the declarations and pip-mock work. Every "
             "case declares all six PIPs, because an upload of the domain replaces its declarations while the sets of "
             "the earlier case are still loaded. Each case fails unless pip-mock received a call on each of its "
             "three routes.",
             REGULAR_PREFIX, pips=pips, pins=pins)
    for key, algorithm, suffix in algorithms:
        def name(kind):
            return "subject.parityR9" + kind + suffix
        resource = {"id": "r9-pip-value"}
        f.add(regular(
            "non-string-pip-beside-allow-" + key,
            one_set(algorithm, policy(
                "reader", algorithm,
                rule("read-allow-reads-the-number", "operation == 'READ'", name("Number") + " != 'x'", "ALLOW"),
                rule("read-allow", "operation == 'READ'", "true", "ALLOW"),
                rule("update-allow-reads-the-boolean", "operation == 'UPDATE'", name("Boolean") + " != 'x'", "ALLOW"),
                rule("update-allow", "operation == 'UPDATE'", "true", "ALLOW"),
                rule("delete-deny-reads-the-number", "operation == 'DELETE'", name("Number") + " != 'x'", "DENY"),
                rule("delete-allow", "operation == 'DELETE'", "true", "ALLOW"),
                rule("probe-allow-reads-the-string", "operation == 'PROBE'", name("String") + " == 'v'", "ALLOW"))),
            [req("number-allow-beside-allow", resource, operation="READ"),
             req("boolean-allow-beside-allow", resource, operation="UPDATE"),
             req("number-deny-beside-allow", resource, operation="DELETE"),
             req("string-pip-alone", resource, operation="PROBE")],
            pips=list(pips),
            reads_routes=["/api/v1/pip/r9-value-" + kind + "-" + key for kind in ("Number", "Boolean", "String")]))
    return f


ALGORITHMS = (("deny-unless-permit", "DENY_UNLESS_PERMIT"), ("permit-unless-deny", "PERMIT_UNLESS_DENY"),
              ("deny-overrides", "DENY_OVERRIDES"), ("permit-overrides", "PERMIT_OVERRIDES"))
FALSE_SUBJECT = "subject.roles CONTAINS 'ROLE_PARITY_NOBODY'"
FILTER_REQUESTS = [req("filter", filter=True), req("check-list", {"id": "r9-filter"}, operation="LIST")]


def allow_with_predicate(key, rsql):
    return rule(key, "operation == 'LIST'", "true", "ALLOW", {"rsqlPredicate": rsql})


def predicate_policy():
    return policy("with-a-predicate", "DENY_UNLESS_PERMIT", allow_with_predicate("list-with-a-predicate", "allowed==1"))


def update_only_policy():
    return policy("update-only", "DENY_UNLESS_PERMIT", rule("update-allow", "operation == 'UPDATE'", "true", "ALLOW"))


def deny_rule_without_predicate():
    f = File("deny-rule-without-predicate",
             "What check/filter does with a DENY rule that has no predicate and a condition that holds, under each "
             "combining algorithm of its policy. deny-predicates-under-* records that a DENY rule's predicate is "
             "dropped under DENY_UNLESS_PERMIT and PERMIT_OVERRIDES and enters the response negated under the other "
             "two; every recorded DENY rule without a predicate reads the resource in its condition, so it never "
             "reaches a filter. The DENY rule sits beside an ALLOW rule with a predicate, and beside an ALLOW rule with "
             "neither predicate nor condition, which lifts the filter on its own "
             "(filter-rule-without-condition-or-predicate). false-beside-a-predicate under each algorithm is the "
             "control: the same DENY rule with a condition that is false for the reader, so a response that differs "
             "from it is the true condition's. Each case sends the filter on LIST and check/resource on LIST. The "
             "agent's converter accepts every set here.",
             REGULAR_PREFIX)
    for key, algorithm in ALGORITHMS:
        for form, condition, allow in (
            ("true-beside-a-predicate", "true", allow_with_predicate("list-allow-with-a-predicate", "allowed==1")),
            ("true-beside-an-unrestricted-allow", "true", rule("list-allow", "operation == 'LIST'", "true", "ALLOW")),
            ("false-beside-a-predicate", FALSE_SUBJECT,
             allow_with_predicate("list-allow-with-a-predicate", "allowed==1")),
        ):
            f.add(regular("deny-without-predicate-" + form + "-under-" + key, one_set("DENY_UNLESS_PERMIT", policy(
                "reader", algorithm, rule("list-deny", "operation == 'LIST'", condition, "DENY"), allow)),
                FILTER_REQUESTS))
    return f


def false_condition_without_predicate():
    f = File("false-condition-without-predicate",
             "What check/filter does with an ALLOW rule that has no predicate and a condition over the subject that is "
             "false for the reader, alone and beside an ALLOW rule with a predicate. The recorded rule without a "
             "predicate lifts the filter when its subject condition holds "
             "(filter-rule-with-a-subject-condition-and-no-predicate) and is left out when its condition reads the "
             "resource (filter-rule-with-a-resource-condition-and-no-predicate). "
             "allow-without-predicate-true-beside-a-predicate is the control, the same pair with the condition true; it "
             "is also the only case of an unrestricted ALLOW beside a predicate in one policy, which filter-algebra.json "
             "relies on. The agent's converter accepts every set here.",
             REGULAR_PREFIX)

    def without_predicate(condition):
        return rule("list-under-a-subject-condition", "operation == 'LIST'", condition, "ALLOW")

    with_predicate = allow_with_predicate("list-with-a-predicate", "allowed==1")
    for cid, rules in (
        ("allow-without-predicate-false-alone", [without_predicate(FALSE_SUBJECT)]),
        ("allow-without-predicate-false-beside-a-predicate", [without_predicate(FALSE_SUBJECT), with_predicate]),
        ("allow-without-predicate-true-beside-a-predicate", [without_predicate(READER_TARGET), with_predicate]),
    ):
        f.add(regular(cid, one_set("DENY_UNLESS_PERMIT", policy("reader", "DENY_UNLESS_PERMIT", *rules)),
                      FILTER_REQUESTS))
    return f


def filter_algebra():
    f = File("filter-algebra",
             "How check/filter combines nodes whose check/resource decision is recorded and whose filter answer is not. "
             "Each case pairs with a control that differs in the one element under question; an unrestricted ALLOW "
             "beside a predicate in one policy is asked by allow-without-predicate-true-beside-a-predicate in "
             "false-condition-without-predicate.json. "
             "permit-unless-deny-with-deny-rules-elsewhere is a PERMIT_UNLESS_DENY policy whose one DENY rule, with a "
             "predicate, is on UPDATE: on LIST nothing applies, the policy permits in check/resource "
             "(only-deny-rules-*), and the filter may answer ALLOW or nothing. Its filter on UPDATE is the control, "
             "where the DENY rule applies and its predicate enters negated (deny-predicates-under-*). "
             "deny-overrides-set-with-a-policy-without-a-list-rule is a DENY_OVERRIDES set of a policy with an ALLOW "
             "predicate on LIST and a policy with a rule on UPDATE alone; in check/resource the second policy denies "
             "LIST and overrides the first (TestInterpreterCombiningCases), and the control is the set with the first "
             "policy alone. deny-in-one-policy-beside-a-predicate-in-another is a DENY_UNLESS_PERMIT set of a "
             "DENY_OVERRIDES policy whose DENY rule on LIST has no predicate and a true condition, beside a policy with "
             "an ALLOW predicate: check/resource permits, since the set permits when any policy does, and the filter "
             "may deny the whole answer instead. Its control gives the DENY rule a false condition. The agent's "
             "converter accepts every set here.",
             REGULAR_PREFIX)
    f.add(regular("permit-unless-deny-with-deny-rules-elsewhere", one_set("DENY_UNLESS_PERMIT", policy(
        "reader", "PERMIT_UNLESS_DENY",
        rule("update-deny", "operation == 'UPDATE'", "true", "DENY", {"rsqlPredicate": "blocked==1"}))),
        FILTER_REQUESTS + [req("filter-update", operation="UPDATE", filter=True)]))
    f.add(regular("deny-overrides-set-with-a-policy-without-a-list-rule",
                  one_set("DENY_OVERRIDES", predicate_policy(), update_only_policy()), FILTER_REQUESTS))
    f.add(regular("deny-overrides-set-with-the-predicate-policy-alone",
                  one_set("DENY_OVERRIDES", predicate_policy()), FILTER_REQUESTS))
    for cid, condition in (("deny-in-one-policy-beside-a-predicate-in-another", "true"),
                           ("false-deny-in-one-policy-beside-a-predicate-in-another", FALSE_SUBJECT)):
        f.add(regular(cid, one_set(
            "DENY_UNLESS_PERMIT",
            policy("denies", "DENY_OVERRIDES", rule("list-deny", "operation == 'LIST'", condition, "DENY")),
            predicate_policy()), FILTER_REQUESTS))
    return f


def unresolved_placeholder():
    f = File("unresolved-placeholder",
             "What check/filter and check/resource answer when one rule's predicate names a placeholder that cannot be "
             "resolved and a neighbor rule of the same policy has a predicate that can. x20 records that an undeclared "
             "placeholder in a simplified policy's only predicate denies the whole filter answer, and "
             "permission-list-no-mapping records the same for ${subject.permissions} with no MAPPING PIP; neither has a "
             "neighbor. undeclared-placeholder-alone is the regular-set twin of x20, without the neighbor; "
             "declared-placeholder-beside-a-predicate is the positive control, the same pair with ${subject.id}, which "
             "renders (rls-happy). No case declares a PIP. The agent's converter accepts every set here.",
             REGULAR_PREFIX)
    for cid, predicate, neighbor in (
        ("undeclared-placeholder-beside-a-predicate", "a==${subject.parityR9Undeclared}", True),
        ("permissions-without-mapping-beside-a-predicate", "perms=in=(${subject.permissions})", True),
        ("undeclared-placeholder-alone", "a==${subject.parityR9Undeclared}", False),
        ("declared-placeholder-beside-a-predicate", "a==${subject.id}", True),
    ):
        rules = [allow_with_predicate("list-with-the-placeholder", predicate)]
        if neighbor:
            rules.append(allow_with_predicate("list-with-b", "b==2"))
        f.add(regular(cid, one_set("DENY_UNLESS_PERMIT", policy("reader", "DENY_UNLESS_PERMIT", *rules)),
                      FILTER_REQUESTS))
    return f


def subject_scalar_substitution():
    f = File("subject-scalar-substitution",
             "How ${subject.name} and ${subject.type} are rendered by each predicate dialect. rls-happy records "
             "${subject.id} unquoted in rsql, and substitution-subject-roles records a subject list quoted; the two "
             "other scalar subject attributes are recorded nowhere, so an unquoted id is an observation of one "
             "attribute rather than a rule for scalars. Each case is the substitution-* shape: one placeholder in all "
             "five predicate fields of one LIST rule, and one filter request. substitution-subject-id is the control, "
             "the attribute already recorded, in the same five fields. The agent's converter accepts every set here.",
             REGULAR_PREFIX)
    for attribute in ("name", "type", "id"):
        placeholder = "subject." + attribute
        predicates = {
            "rsqlPredicate": "a==${" + placeholder + "}",
            "sqlPredicate": "a=${" + placeholder + "}",
            "mongodbPredicate": '{ "a": ${' + placeholder + "} }",
            "predicate": "${resourceType}.a.eq(${" + placeholder + "})",
            "customPredicate": {"predicate": "a:${p}", "params": {"p": placeholder}},
        }
        f.add(regular("substitution-subject-" + attribute, one_set("DENY_UNLESS_PERMIT", policy(
            "reader", "DENY_UNLESS_PERMIT", rule("list", "operation == 'LIST'", "true", "ALLOW", predicates))),
            [req("filter", filter=True)]))
    return f


for build in (empty_header_and_claim, right_operand, single_element_list, plain_array_equality,
              is_null_over_dead_forms, token_default_list, non_string_pip_value, deny_rule_without_predicate,
              false_condition_without_predicate, filter_algebra, unresolved_placeholder, subject_scalar_substitution):
    build().write()
