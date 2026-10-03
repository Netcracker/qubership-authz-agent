"""Writes the round 10 case files next to this script: python3 generate.py.

Round 10 was first written in Go; these files hold the same cases, request for request, so the goldens recorded
then still apply. Each file is one test function of the parity suite, in the format case_files_test.go reads:

  dead-form-not-null.json               IS NOT NULL over resource['x'] and over the literal null
  empty-collection-not-null.json        IS NOT NULL over a resource attribute that is an empty array
  undeclared-placeholder-check.json     check/resource on the policy of x20-undeclared-placeholder
  null-operand.json                     IN, CONTAINS, CONTAINS ANY, IS SUBSET and MATCH over a null attribute
  single-value-header.json              four operators over a header holding one value, and a header sent empty
  null-body-and-right-operand.json      a GENERAL PIP whose body is null, and an absent header or claim on the right
  path-pattern-and-word-operator.json   MATCH /ab.*/ on path values, and LESS THAN OR EQUAL without TO
  non-string-pip-operator.json          operators over a GENERAL PIP answering the number 1000
  set-algorithm-filter.json             what each set algorithm does to the predicates of its policies in a filter
  filter-resource-condition.json        a filter over a rule whose condition or target reads the resource
  deny-list-filter.json                 a filter over a deny list whose DENY rules read the resource
  request-attributes.json               what a GENERAL PIP sends when a requestAttributes value is a placeholder

A case id ending in -control is the probe's control: the operand under question on the right of
resource.a == 'y' OR, where it is true whatever the operand does, so a false control means the fixture is broken.
A case id ending in -alone asks the operand as the whole condition, which records its value where it has one; the
probe, with the operand on the left of that OR, tells a false operand (true) from an ended rule (false).
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PIP_MOCK = "http://pip-mock:8090/api/v1/pip"
READER_TARGET = "subject.roles CONTAINS 'ROLE_PARITY_READER'"
ISOLATED_PREFIX = "PARITY_SUITE_R10_"
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


def req(name, resource=None, **extra):
    r = {"name": name}
    r.update(extra)
    if resource is not None:
        r["resource"] = resource
    return r


def or_probe_pair(f, cid, operand, requests, pips=()):
    """The probe puts operand on the left of an OR whose right operand is true; the control swaps them."""
    rt = ISOLATED_PREFIX + upper(cid)
    f.add(isolated(cid, operand + " OR resource.a == 'y'", requests, pips), rt)
    f.add(isolated(cid + "-control", "resource.a == 'y' OR " + operand, requests, pips), rt + "_CTL")


def alone_and_probe(f, key, operand, requests, pips=()):
    """Asks operand as the whole condition, then through or_probe_pair, all three sent requests."""
    f.add(isolated(key + "-alone", operand, requests, pips))
    or_probe_pair(f, key, operand, requests, pips)


def dead_form_not_null():
    f = File("dead-form-not-null",
             "What IS NOT NULL answers over resource['x'] and over the literal null. The PAP accepts both forms, and "
             "IS NULL over either is true whether x is there or not (dn-is-null-over-a-bracket-path, "
             "dn-is-null-over-the-null-literal), while == over resource['x'] ends the rule (df1). IS NOT NULL over "
             "them is recorded nowhere, so neither is whether it is a value or ends the rule. Each form is asked alone "
             "and through the probe and its control, with x present and absent; resource.a is y in every request, so "
             "the probe's right operand holds. The agent's condition parser accepts both conditions.",
             ISOLATED_PREFIX)
    requests = [req("x-present", {"id": "r10-dead", "x": "v", "a": "y"}), req("x-absent", {"id": "r10-dead", "a": "y"})]
    alone_and_probe(f, "dn-is-not-null-over-a-bracket-path", "resource['x'] IS NOT NULL", requests)
    alone_and_probe(f, "dn-is-not-null-over-the-null-literal", "null IS NOT NULL", requests)
    return f


def empty_collection_not_null():
    f = File("empty-collection-not-null",
             "What IS NOT NULL answers over a resource attribute that is an empty array. IS NULL over it is true "
             "(es-empty-collection-is-null), which leaves IS NOT NULL either its negation or false, as over an empty "
             "header; neither is recorded. The attribute is asked alone and through the probe and its control, empty "
             "and holding one value; the one value, list-of-one, is the control that IS NOT NULL holds over a "
             "collection. The agent's condition parser accepts the condition.",
             ISOLATED_PREFIX)
    alone_and_probe(f, "ec-is-not-null-over-an-empty-array", "resource.list IS NOT NULL", [
        req("list-empty", {"id": "r10-empty", "list": [], "a": "y"}),
        req("list-of-one", {"id": "r10-empty", "list": ["v"], "a": "y"}),
    ])
    return f


def undeclared_placeholder_check():
    f = File("undeclared-placeholder-check",
             "What check/resource answers for a simplified policy whose only predicate names an undeclared "
             "placeholder. x20-undeclared-placeholder records the filter, which denies; the decision on the same "
             "policy is recorded nowhere. A filter that denies where check/resource allows is the one shape in which "
             "the agent would need to mark such a policy. The agent's converter accepts the policy.",
             ISOLATED_PREFIX)
    f.add(isolated("x20-undeclared-placeholder-check", None, [
        req("check-list", {"id": "r10-x20"}, operation="LIST"),
        req("filter", operation="LIST", filter=True),
    ], operation="LIST", policy={"rsqlPredicate": "owner==${subject.parityUndeclared}"},
        about="The policy of x20-undeclared-placeholder on a resource type of its own. The filter is asked again "
              "beside check/resource, the control that the policy is the one x20 records."),
        ISOLATED_PREFIX + "X20_CHECK")
    return f


def null_operand():
    f = File("null-operand",
             "What IN, CONTAINS, CONTAINS ANY, IS SUBSET and MATCH answer over a resource attribute that is null. Over "
             "null, NOT IN is true (n1), and NOT CONTAINS and NOT MATCH are false (n2, m1) alone, where a false "
             "operand and an ended rule look the same; the plain operators are recorded over null nowhere. Each "
             "operator is asked alone, which records its value if it has one, and through the probe and its control, "
             "which tell a value from an ended rule; resource.a is y. The agent's condition parser accepts every "
             "condition here.",
             ISOLATED_PREFIX)
    requests = [req("x-null", {"id": "r10-null", "x": None, "a": "y"})]
    for key, operand in (
        ("nc-in", "resource.x IN 'a', 'z'"),
        ("nc-contains", "resource.x CONTAINS 'a'"),
        ("nc-contains-any", "resource.x CONTAINS ANY 'a', 'z'"),
        ("nc-is-subset", "resource.x IS SUBSET 'a', 'z'"),
        ("nc-match", "resource.x MATCH a*"),
    ):
        alone_and_probe(f, key, operand, requests)
    return f


ONE_HEADER = {"name": "subject.parityR9OneHeader", "type": "UUID", "pipType": "HEADER", "header": "x-parity-r9-one",
              "cacheable": False}


def single_value_header():
    f = File("single-value-header",
             "What NOT IN, MATCH, CONTAINS ANY and IS SUBSET answer over a HEADER PIP whose header holds one value, "
             "and what a header sent empty resolves to. ==, !=, IN and CONTAINS over one value are recorded "
             "(sl-header-*); the other operators are recorded over a header split into a list (hl1-hl3) or absent "
             "(es-*), and an empty header is recorded nowhere: it may be an empty list, a list of one empty string, "
             "or an absent header. The single-value cases are sent the header a and the header b, alone, and the "
             "header a through the probe and its control, whose ids end in -or-true. The empty-header cases ask IS "
             "EMPTY, IS NULL, equality with the empty string, and resource.id IN the header, each with the header "
             "sent empty and not sent at all; the absent header is the control, recorded as an empty list "
             "(es-absent-header-*). The agent's condition parser accepts every condition here.",
             ISOLATED_PREFIX, pips={"oneheader": ONE_HEADER})
    header_a = {"x-parity-r9-one": "a"}
    for key, operator in (("not-in", "NOT IN 'a', 'z'"), ("match", "MATCH a"), ("contains-any", "CONTAINS ANY 'a', 'z'"),
                          ("is-subset", "IS SUBSET 'a', 'z'")):
        cid = "sv-header-" + key
        operand = "subject.parityR9OneHeader " + operator
        f.add(isolated(cid, operand, [
            req("header-a", {"id": "r10-sv"}, headers=header_a),
            req("header-b", {"id": "r10-sv"}, headers={"x-parity-r9-one": "b"}),
        ], ["oneheader"]))
        or_probe_pair(f, cid + "-or-true", operand, [req("header-a", {"id": "r10-sv", "a": "y"}, headers=header_a)],
                      ["oneheader"])
    for key, condition in (("is-empty", "subject.parityR9OneHeader IS EMPTY"),
                           ("is-null", "subject.parityR9OneHeader IS NULL"),
                           ("equals-empty-string", "subject.parityR9OneHeader == ''"),
                           ("resource-in", "resource.id IN subject.parityR9OneHeader")):
        f.add(isolated("eh-header-" + key, condition, [
            req("header-empty", {"id": ""}, headers={"x-parity-r9-one": ""}),
            req("header-absent", {"id": ""}),
        ], ["oneheader"]))
    return f


def general_pip(name, route, json_path):
    pip = {"name": name, "url": PIP_MOCK + "/" + route, "httpMethod": "POST", "pipType": "GENERAL",
           "requestAttributes": {"case": "r10-null-body"}, "cacheable": False}
    if json_path:
        pip["type"] = "JSON"
        pip["jsonPath"] = "$.value"
    return pip


def null_body_and_right_operand():
    f = File("null-body-and-right-operand",
             "What a GENERAL PIP whose body is the JSON literal null resolves to under IS EMPTY and IS NULL, and what "
             "an absent header and an absent claim answer on the right of an operator when nothing follows them. p7 "
             "records != over the null body, which is true for a null and for an empty list alike; the right-operand "
             "forms are recorded only on the left of an OR (ro-in-an-absent-header, ro-equals-an-absent-claim). Each "
             "condition is asked alone. The null body under IS EMPTY and IS NULL tells a null (false, true) from an "
             "empty list (true, true); nb-null-body-equals-a-value is the control, a PIP at another route answering "
             "{\"value\": \"v\"} under == 'v'. The agent's condition parser accepts every condition here.",
             ISOLATED_PREFIX,
             pips={
                 "nullbody": general_pip("subject.parityR10NullBody", "r10-null-body", False),
                 "control": general_pip("subject.parityR10NullBodyControl", "r10-null-body-control", True),
                 "noheader": {"name": "subject.parityR9NoHeader", "type": "UUID", "pipType": "HEADER",
                              "header": "x-parity-r9-no-such-header", "cacheable": False},
                 "noclaim": {"name": "subject.parityR9NoClaim", "type": "UUID", "pipType": "TOKEN",
                             "claim": "parity_r9_no_such_claim", "cacheable": False},
             },
             pins={
                 "/api/v1/pip/r10-null-body": {"statusCode": 200, "bodyRaw": "null"},
                 "/api/v1/pip/r10-null-body-control": {"statusCode": 200, "body": {"value": "v"}},
             })
    requests = [req("reader", {"id": "r10-null-body", "x": "v"})]
    for cid, condition, pip in (
        ("nb-null-body-is-empty", "subject.parityR10NullBody IS EMPTY", "nullbody"),
        ("nb-null-body-is-null", "subject.parityR10NullBody IS NULL", "nullbody"),
        ("nb-null-body-equals-a-value", "subject.parityR10NullBodyControl == 'v'", "control"),
        ("nb-in-an-absent-header", "resource.x IN subject.parityR9NoHeader", "noheader"),
        ("nb-equals-an-absent-claim", "resource.x == subject.parityR9NoClaim", "noclaim"),
    ):
        f.add(isolated(cid, condition, requests, [pip]))
    return f


def path_pattern_and_word_operator():
    f = File("path-pattern-and-word-operator",
             "What MATCH /ab.*/ selects on values of the path form, and whether the word form LESS THAN OR EQUAL is "
             "accepted without TO. df4 records MATCH /ab.*/ against abc, which no path pattern selects, so what the "
             "form selects is recorded nowhere; LESS THAN OR EQUAL is recorded with TO only. The MATCH case is sent "
             "four values, alone and through the probe, whose control is true for a live policy. LESS THAN OR EQUAL is "
             "sent 5 and 6, and its upload status is an answer too; pp-less-than-or-equal-to, the form with TO, is the "
             "control. The agent's condition parser accepts every condition here.",
             ISOLATED_PREFIX)

    def value(name, x):
        return req(name, {"id": "r10-pattern", "x": x, "a": "y"})

    alone_and_probe(f, "pp-match-slash-pattern", "resource.x MATCH /ab.*/", [
        value("x-slash-ab-dot-c-slash", "/ab.c/"), value("x-slash-ab-dot-slash", "/ab./"),
        value("x-slash-abc-slash", "/abc/"), value("x-abc", "abc"),
    ])
    for cid, condition in (("pp-less-than-or-equal-without-to", "resource.x LESS THAN OR EQUAL 5"),
                           ("pp-less-than-or-equal-to", "resource.x LESS THAN OR EQUAL TO 5")):
        f.add(isolated(cid, condition, [value("x-5", 5), value("x-6", 6)]))
    return f


def non_string_pip_operator():
    def pip(kind, name):
        return {"name": "subject.parityR10Value" + name, "url": PIP_MOCK + "/r10-value-" + kind, "httpMethod": "POST",
                "pipType": "GENERAL", "type": "JSON", "jsonPath": "$.value",
                "requestAttributes": {"case": "r10-value"}, "cacheable": False}

    f = File("non-string-pip-operator",
             "What a condition answers when a GENERAL PIP it reads answers the JSON number 1000. "
             "non-string-pip-beside-allow-* records one form, != 'x', beside an allowing rule, which refuses the whole "
             "answer; a relational operator, an equality with the string 1000, IS NOT NULL, the PIP on the right of "
             "the operator, and a policy that does not read the PIP at all are recorded nowhere. Each condition is "
             "asked alone and through the probe and its control, with resource.amount 5 and resource.a y. "
             "resource.amount <= <PIP> is also asked at 5000, the other side of the limit. Every nv-number-* case is "
             "repeated as nv-string-* with the PIP answering the string \"1000\", the control the number cases are "
             "read against. nv-number-unrelated-policy declares the number PIP and reads only the resource, and has "
             "to allow. The agent's condition parser accepts every condition here.",
             ISOLATED_PREFIX,
             pips={"number": pip("number", "Number"), "string": pip("string", "String")},
             pins={
                 "/api/v1/pip/r10-value-number": {"statusCode": 200, "body": {"value": 1000}},
                 "/api/v1/pip/r10-value-string": {"statusCode": 200, "body": {"value": "1000"}},
             })
    requests = [req("amount-5", {"id": "r10-value", "amount": 5, "a": "y"})]
    for kind, name in (("number", "Number"), ("string", "String")):
        operand = "subject.parityR10Value" + name
        for key, form in (("amount-at-most-the-pip", "resource.amount <= " + operand),
                          ("pip-at-least-the-amount", operand + " >= resource.amount"),
                          ("pip-equals-the-string", operand + " == '1000'"),
                          ("pip-is-not-null", operand + " IS NOT NULL")):
            alone_and_probe(f, "nv-" + kind + "-" + key, form, requests, [kind])
        f.add(isolated("nv-" + kind + "-amount-at-most-the-pip-over-the-limit", "resource.amount <= " + operand,
                       [req("amount-5000", {"id": "r10-value", "amount": 5000})], [kind]))
    f.add(isolated("nv-number-unrelated-policy", "resource.a == 'y'", requests, ["number"]))
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


def regular(cid, sets, requests, about=None):
    case = {"id": cid}
    if about:
        case["about"] = about
    case["sets"] = sets
    case["requests"] = requests
    return case


FILTER_REQUESTS = [req("filter", filter=True), req("check-list", {"id": "r9-filter"}, operation="LIST")]
ALGORITHMS = (("deny-unless-permit", "DENY_UNLESS_PERMIT"), ("permit-unless-deny", "PERMIT_UNLESS_DENY"),
              ("deny-overrides", "DENY_OVERRIDES"), ("permit-overrides", "PERMIT_OVERRIDES"))


def allow_with_predicate(key, rsql):
    return rule(key, "operation == 'LIST'", "true", "ALLOW", {"rsqlPredicate": rsql})


def allow_predicate_policy():
    return policy("allows", "DENY_UNLESS_PERMIT", allow_with_predicate("list-allow-with-a-predicate", "allowed==1"))


def deny_predicate_policy():
    return policy("denies", "DENY_OVERRIDES",
                  rule("list-deny-with-a-predicate", "operation == 'LIST'", "true", "DENY",
                       {"rsqlPredicate": "blocked==1"}))


def set_algorithm_filter():
    f = File("set-algorithm-filter",
             "What the algorithm of a set does to the predicates of its policies in check/filter. Every recorded case "
             "of a predicate reaching a filter under a set puts the set under DENY_UNLESS_PERMIT "
             "(deny-predicates-under-*, deny-in-one-policy-beside-a-predicate-in-another), except "
             "deny-overrides-set-*, where the set denies through a policy with no rule on the operation and no "
             "predicate is left to shape. A PERMIT_UNLESS_DENY policy drops the ALLOW predicates of its rules "
             "(deny-predicates-under-permit-unless-deny), and a PERMIT_UNLESS_DENY iterate node keeps them "
             "(scope-filter/*/filter-custom-permit-unless-deny); what a PERMIT_UNLESS_DENY set does with the ALLOW "
             "predicate of a policy is recorded nowhere. Under each of the four set algorithms, "
             "-over-an-allow-predicate holds one DENY_UNLESS_PERMIT policy with an ALLOW on LIST carrying allowed==1, "
             "-over-a-deny-predicate holds one DENY_OVERRIDES policy with a DENY on LIST carrying blocked==1, and "
             "-over-allow-and-deny-predicates holds both. The sets under DENY_UNLESS_PERMIT are the controls, the set "
             "algorithm every recorded predicate was seen under. check/resource on LIST records the decision the "
             "filter has to follow. The agent's converter accepts every set here.",
             REGULAR_PREFIX)
    for key, algorithm in ALGORITHMS:
        prefix = "set-algorithm-" + key
        f.add(regular(prefix + "-over-an-allow-predicate", one_set(algorithm, allow_predicate_policy()),
                      FILTER_REQUESTS,
                      about="Under DENY_OVERRIDES this repeats deny-overrides-set-with-the-predicate-policy-alone, "
                            "whose filter is allowed==1, and has to record the same answer."
                      if algorithm == "DENY_OVERRIDES" else None))
        f.add(regular(prefix + "-over-a-deny-predicate", one_set(algorithm, deny_predicate_policy()), FILTER_REQUESTS))
        f.add(regular(prefix + "-over-allow-and-deny-predicates",
                      one_set(algorithm, allow_predicate_policy(), deny_predicate_policy()), FILTER_REQUESTS))
    return f


def filter_resource_condition():
    f = File("filter-resource-condition",
             "What check/filter does with a rule whose condition or target reads the resource and evaluates without "
             "it. A filter request carries no resource, and the recorded rule without a predicate whose condition is "
             "resource.x == 'a' is left out of the filter (filter-rule-with-a-resource-condition-and-no-predicate). "
             "Over an absent key IS NULL is true in check/resource (s6a), and an OR whose other operand is true is "
             "true there too when the resource is read second; a filter that evaluated these conditions the same way "
             "would lift the filter. Each rule is an ALLOW on LIST with no predicate: resource.x IS NULL as the "
             "condition, resource.x == 'a' OR the reader's role, the same operands swapped, and resource.x IS NULL in "
             "the rule target with a true condition. Each is asked alone, where the filter answer is the rule's own, "
             "and beside an ALLOW with the predicate allowed==1, where an unrestricted ALLOW beside a predicate "
             "answers ALLOW (allow-without-predicate-true-beside-a-predicate). "
             "resource-equals-without-predicate-beside-a-predicate is the control, the recorded condition in the same "
             "pair, and is asked beside the predicate only. check/resource on LIST, for a resource without x, records "
             "what the rule decides when the resource is there. The agent's converter accepts every set here.",
             REGULAR_PREFIX)
    for key, target, condition, alone in (
        ("resource-is-null", "operation == 'LIST'", "resource.x IS NULL", True),
        ("resource-or-subject", "operation == 'LIST'", "resource.x == 'a' OR " + READER_TARGET, True),
        ("subject-or-resource", "operation == 'LIST'", READER_TARGET + " OR resource.x == 'a'", True),
        ("target-resource-is-null", "operation == 'LIST' AND resource.x IS NULL", "true", True),
        ("resource-equals", "operation == 'LIST'", "resource.x == 'a'", False),
    ):
        without_predicate = rule("list-reads-the-resource", target, condition, "ALLOW")
        if alone:
            f.add(regular(key + "-without-predicate-alone",
                          one_set("DENY_UNLESS_PERMIT", policy("reader", "DENY_UNLESS_PERMIT", without_predicate)),
                          FILTER_REQUESTS))
        f.add(regular(key + "-without-predicate-beside-a-predicate", one_set("DENY_UNLESS_PERMIT", policy(
            "reader", "DENY_UNLESS_PERMIT", without_predicate,
            allow_with_predicate("list-with-a-predicate", "allowed==1"))), FILTER_REQUESTS))
    return f


def deny_list_filter():
    f = File("deny-list-filter",
             "What check/filter does with a deny list whose rules carry no predicate and read the resource: a "
             "PERMIT_UNLESS_DENY policy of DENY rules on resource.uri MATCH, the form every deny list of the product "
             "policies in reach takes. The recorded deny list carries predicates (filter-under-a-deny-list), and the "
             "recorded DENY rules without a predicate read the subject (deny-without-predicate-*). "
             "deny-list-without-predicate is the deny list alone, under a DENY_UNLESS_PERMIT set; the filter may "
             "answer ALLOW, as the PERMIT_UNLESS_DENY policy permits wherever its DENY does not apply, or DENY. "
             "-beside-a-predicate adds a policy with an ALLOW carrying allowed==1, where the answer may be that "
             "predicate or ALLOW. check/resource on LIST with a uri the rule matches and with one it does not is the "
             "control that the deny list applies to a resource. The agent's converter accepts every set here.",
             REGULAR_PREFIX)
    deny_list = policy("deny-list", "PERMIT_UNLESS_DENY",
                       rule("list-deny-a-secret-uri", "operation == 'LIST'", "resource.uri MATCH /v1/secret/**",
                            "DENY"))
    requests = [
        req("filter", filter=True),
        req("check-list-uri-in-the-list", {"id": "r10-deny-list", "uri": "/v1/secret/a"}, operation="LIST"),
        req("check-list-uri-outside-the-list", {"id": "r10-deny-list", "uri": "/v1/open/a"}, operation="LIST"),
    ]
    f.add(regular("deny-list-without-predicate", one_set("DENY_UNLESS_PERMIT", deny_list), requests))
    f.add(regular("deny-list-without-predicate-beside-a-predicate",
                  one_set("DENY_UNLESS_PERMIT", deny_list, allow_predicate_policy()), requests))
    return f



def request_attributes():
    f = File("request-attributes",
             "What a GENERAL PIP sends in the requestAttributes of its call when a value there is a placeholder. The "
             "documentation writes ${subject.<TOKEN or HEADER PIP>} there; every recorded GENERAL PIP sends literal "
             "values only, so what a placeholder over subject.roles, a resource attribute holding an object, and a "
             "resource attribute the request does not carry become is recorded nowhere, and neither is whether an "
             "unresolved one sends the call at all. The agent's PIP loader validates placeholders in "
             "requestAttributes and expands them when it calls the PIP. Each form is its own case: one GENERAL PIP "
             "whose requestAttributes hold {\"value\": <placeholder>}, answering {\"value\": \"v\"} at a route of its "
             "own, and a READ policy whose condition reads the PIP. Every request carries the resource "
             "{\"id\": \"r10-ra\", \"obj\": {\"k\": \"v\"}}. The decision and what pip-mock received over the case, its "
             "call count and the requestAttributes of the first call, are recorded. The cases live in their own test "
             "function so that a recording run can be filtered to them and leave every golden already committed alone.",
             ISOLATED_PREFIX)
    f.pips["department"] = {"name": "subject.parityR10RaDepartment", "type": "UUID", "pipType": "TOKEN",
                            "claim": "department", "cacheable": False}
    for key, placeholder, about in (
        ("literal", "lit", "The control whose answer is known: true after one call carrying {\"value\": \"lit\"}."),
        ("token", "${subject.parityR10RaDepartment}", "The form the documentation gives."),
        ("subject-roles", "${subject.roles}", None),
        ("resource-id", "${resource.id}", "A resource attribute holding a string, the one the resource forms differ "
                                          "from."),
        ("resource-object", "${resource.obj}", None),
        ("resource-missing", "${resource.missing}", None),
    ):
        cid = "ra-" + key
        route = "/api/v1/pip/r10-" + cid
        f.pins[route] = {"statusCode": 200, "body": {"value": "v"}}
        f.pips[cid] = {"name": "subject.parityR10RaGeneral", "url": "http://pip-mock:8090" + route,
                       "httpMethod": "POST", "pipType": "GENERAL", "type": "JSON", "jsonPath": "$.value",
                       "cacheable": False, "requestAttributes": {"value": placeholder}}
        case = isolated(cid, "subject.parityR10RaGeneral == 'v'",
                        [req("read", {"id": "r10-ra", "obj": {"k": "v"}})], ["department", cid], about=about)
        case["policy"] = {"id": "00000000-0000-0000-0000-0000000f1044"}
        case["pipCalls"] = route
        f.add(case)
    return f

for build in (dead_form_not_null, empty_collection_not_null, undeclared_placeholder_check, null_operand,
              single_value_header, null_body_and_right_operand, path_pattern_and_word_operator,
              non_string_pip_operator, set_algorithm_filter, filter_resource_condition, deny_list_filter,
              request_attributes):
    build().write()
