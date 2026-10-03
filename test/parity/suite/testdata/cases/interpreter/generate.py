"""Writes the interpreter case files next to this script: python3 generate.py.

These cases were first written in Go; these files hold the same cases, request for request, so the goldens recorded
then still apply. Each file is one TestInterpreter* function of the parity suite, in the format case_files_test.go
reads:

  null-and-absence.json   null under the relational operators, an absent key and an empty JSON Path selection
                          on the left of OR, and the boundary 5 against 5.0
  permission-case.json    whether subject.permissions CONTAINS ignores case
  dead-form.json          whether the forms the PAP accepts and always answers false are false leaves or end the rule
  combining.json          what a policy or a nested set with no applicable rule contributes to its parent
  operation-all.json      a simplified policy on operation ALL with a condition and with a predicate
  regular-load.json       four forms the simplified upload refused, in a rule of a regular set
  set-target.json         set targets that read the resource
  substitution.json       each source of a placeholder in each predicate dialect
  permission-list.json    what ${subject.permissions} renders with MAPPING PIPs of each shape
  access-operator.json    subject allowed and subject denied beside a policy for the operation they name
  bare-path.json          a path with no resource. prefix
  deny-predicate.json     the predicates of DENY rules in check/filter under each policy algorithm
  pip-declaration.json    HEADER, TOKEN and MAPPING PIPs under declaration shapes no other case declares

TestInterpreterFilterCases stays in Go because one of its cases uploads two simplified policies beside two sets under
two external ids; TestInterpreterTerminalEffectCases because it uploads its case again before each request;
TestInterpreterIterateBindingCases because it declares the scope PIP and waits before its first case, outside any case.
TestInterpreterConfigExportCases, TestInterpreterIterateAlgorithmCases, TestInterpreterIterateNodeAlgorithmCases and
TestInterpreterTenantClaimCases read the configuration export, re-pin the scope service between groups of requests
with golden paths of their own, or work with tenants.

A case id ending in -control is the probe's control: the operand under question on the right of
resource.a == 'y' OR, where it is true whatever the operand does, so a false control means the fixture is broken
and the probe's answer means nothing. The probe puts the operand on the left: a true probe means the operand
evaluated to a value and OR went on, a false probe means the operand ended the rule (s11-false-or-absent against
s9-true-or-absent, and s10-absent-or-true, which is false although its right operand is true).
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PIP_MOCK = "http://pip-mock:8090/api/v1/pip"
READER_TARGET = "subject.roles CONTAINS 'ROLE_PARITY_READER'"
NOBODY_TARGET = "subject.roles CONTAINS 'ROLE_PARITY_NOBODY'"
REGULAR_PREFIX = "PARITY_SUITE_REG_"
READER_ID = "00000000-0000-0000-0000-000000000101"  # parity-reader's subject id
SET_TARGET = "resourceType == '{{resourceType}}'"
ACCEPTED_ALGORITHMS = (("deny-unless-permit", "DENY_UNLESS_PERMIT"), ("permit-unless-deny", "PERMIT_UNLESS_DENY"),
                       ("deny-overrides", "DENY_OVERRIDES"), ("permit-overrides", "PERMIT_OVERRIDES"))


def upper(text):
    return text.upper().replace("-", "_")


class File:
    """The cases of one file and the PIPs and pins they name."""

    def __init__(self, name, about, prefix=REGULAR_PREFIX, pips=None, pins=None):
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


def or_probe_pair(f, cid, resource_type, operand, requests):
    """The probe puts operand on the left of an OR whose right operand is true; the control swaps them."""
    f.add(isolated(cid, operand + " OR resource.a == 'y'", requests), resource_type)
    f.add(isolated(cid + "-control", "resource.a == 'y' OR " + operand, requests), resource_type + "_CTL")


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


def set_(key, algorithm, *policies, target=SET_TARGET, sets=None):
    s = {"key": key, "target": target, "algorithm": algorithm, "policies": list(policies)}
    if sets:
        s["sets"] = sets
    return s


def regular(cid, sets, requests, pips=(), about=None, reads_routes=None):
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


def null_and_absence():
    f = File("null-and-absence",
             "What a condition answers over a null value and over an absent key, in the operators no other golden "
             "records, over a JSON Path that selects nothing, and at a fractional boundary. Over a null value the "
             "recorded answers are per operator: > does not end the rule (n3-greater-than-null-or-true is true) and "
             "its value alone is not recorded, NOT IN is true (n1), and IS EMPTY and NOT CONTAINS are false (n4, n2) "
             "alone, where a false leaf and an ended rule look the same. The nl cases record <, >=, >, <=, IS NOT NULL "
             "and IS NOT EMPTY alone over null, so the operator-by-state table has a value in every relational cell "
             "rather than in two (IS NOT NULL over an absent key is recorded only inside a guarded chain, s12a); "
             "the second request of each is the control that the operator answers true for a value. Over an absent "
             "key IS NULL is true (s6a) and == ends the rule (s10); !=, >, NOT IN and NOT CONTAINS (s2b, s5, s3, s4), "
             "IS EMPTY and IS NOT EMPTY (s7, l9) are recorded false only alone, and NOT MATCH, NOT CONTAINS ANY and IS "
             "NOT SUBSET only over null (m1, m2, m3). The nn cases put each through a probe and its control. The np "
             "cases do the same for a JSON Path that selects nothing from a resource that has the parent, where a plain "
             "path to an absent key ends the rule (s2b-neq-attribute-absent with s10): a filter "
             "expression with no match and a recursive descent that finds nothing are recorded only under CONTAINS "
             "(j9, j10), where an empty selection and an ended rule both answer false, and an index past the end and "
             "a wildcard to a key no element has are not recorded at all. A selection is a collection, and == over one "
             "is recorded nowhere, so each path goes through a probe with NOT CONTAINS and alone with IS EMPTY: an "
             "empty selection is IS EMPTY true and probe true, an ended rule probe false. The relational operators "
             "compare numerically once the attribute is a number (c3-greater-than-string-number), while == compares "
             "the string forms and is false for 5.0 against 5 (c1-number-literal/float); nb1 and nb2 send 5.0 as a "
             "number and as a string against >= 5 and <= 5, with the integer 5 as the control, which "
             "x4-greater-or-equal-words records as true. A true probe means the operand evaluated to a value and OR went on, "
             "a false probe that it ended the rule, and a false control that the fixture is broken. Every case carries "
             "a request a working operator answers true, because a condition access-control accepts and never "
             "evaluates answers false to every request. The agent's condition parser accepts every condition here.",
             "PARITY_SUITE_NUL_")

    def probe(name, extra=None):
        return req(name, {"id": "nul-" + name, "a": "y", **(extra or {})})

    for cid, rt, condition, control, key, value in (
        ("nl1-less-than-over-null", "NL1", "resource.n < 5", "number-below", "n", 4),
        ("nl2-greater-or-equal-over-null", "NL2", "resource.n >= 5", "number-at-the-boundary", "n", 5),
        ("nl5-greater-than-over-null", "NL5", "resource.n > 5", "number-above", "n", 6),
        ("nl6-less-or-equal-over-null", "NL6", "resource.n <= 5", "number-at-the-boundary", "n", 5),
        ("nl3-is-not-null-over-null", "NL3", "resource.x IS NOT NULL", "string", "x", "v"),
        ("nl4-is-not-empty-over-null", "NL4", "resource.x IS NOT EMPTY", "collection-with-an-element", "x", ["v"]),
    ):
        rid = "nul-" + cid.split("-")[0]
        about = None
        if cid.startswith("nl4"):
            about = ("IS EMPTY over null is recorded false (n4). If IS NOT EMPTY is false as well, null is neither "
                     "empty nor non-empty; if it is true, the two operators are complements.")
        f.add(isolated(cid, condition, [req("null", {"id": rid, key: None}), req(control, {"id": rid, key: value})],
                       about=about),
              "PARITY_SUITE_NUL_" + rt)
    for cid, rt, operand in (
        ("nn1-is-empty-over-absence", "NN1", "resource.x IS EMPTY"),
        ("nn2-is-not-empty-over-absence", "NN2", "resource.x IS NOT EMPTY"),
        ("nn3-not-match-over-absence", "NN3", "resource.x NOT MATCH ab*"),
        ("nn4-not-contains-any-over-absence", "NN4", "resource.tags NOT CONTAINS ANY 'p', 'q'"),
        ("nn5-is-not-subset-over-absence", "NN5", "resource.list IS NOT SUBSET 'p', 'q'"),
    ):
        or_probe_pair(f, cid, "PARITY_SUITE_NUL_" + rt, operand, [probe("key-absent")])
    populated = {"items": [{"type": "a", "id": "x"}], "list": ["a"]}
    for cid, rt, path in (
        ("np1-filter-expression-without-a-match", "NP1", "resource.items[?(@.type=='zzz')].id"),
        ("np2-recursive-descent-without-a-match", "NP2", "resource..nocode"),
        ("np3-index-past-the-end", "NP3", "resource.list[5]"),
        ("np4-wildcard-to-a-missing-key", "NP4", "resource.items[*].nokey"),
    ):
        rt = "PARITY_SUITE_NUL_" + rt
        or_probe_pair(f, cid, rt, path + " NOT CONTAINS 'v'", [probe("nothing-selected", populated)])
        f.add(isolated(cid + "-is-empty", path + " IS EMPTY", [probe("nothing-selected", populated)]), rt + "_EMPTY")
    for cid, rt, condition in (
        ("nb1-greater-or-equal-at-a-fractional-boundary", "NB1", "resource.n >= 5"),
        ("nb2-less-or-equal-at-a-fractional-boundary", "NB2", "resource.n <= 5"),
    ):
        rid = "nul-" + cid.split("-")[0]
        f.add(isolated(cid, condition, [
            req("integer", {"id": rid, "n": 5}),
            req("one-decimal-place", {"id": rid, "n": 5.0}),
            req("one-decimal-place-as-a-string", {"id": rid, "n": "5.0"}),
        ]), "PARITY_SUITE_NUL_" + rt)
    return f


def permission_case():
    f = File("permission-case",
             "Whether subject.permissions CONTAINS compares case-insensitively. Case is ignored under == "
             "(c5-string-equals-other-case), under CONTAINS over a resource collection (vt3 asks) and under "
             "subject.roles CONTAINS (u2-subject-roles-other-case), and subject.permissions CONTAINS is the leaf "
             "product policies are built from. The MAPPING PIP grants Parity.Read, spelled in mixed case, to "
             "ROLE_PARITY_READER under its own suffix, so that it never merges with another mapping. "
             "pm1-mapping-pip-merged-list records a permission granted through a MAPPING PIP and read back in the same "
             "case, so pc3, which repeats that shape, is the control for the two cases that spell the permission in "
             "another case. pm3-mapping-pip-after-declaration-removed records that a mapping goes away with its "
             "declaration, so each case declares the PIP again.",
             "PARITY_SUITE_PERM_",
             pips={"mixedcase": {"name": "subject.permissions.PARITY_CASE", "type": "UUID", "pipType": "MAPPING",
                                 "cacheable": False,
                                 "customMapping": {"subject.roles": {"ROLE_PARITY_READER": ["Parity.Read"]}}}})
    for cid, rt, permission in (("pc1-permission-in-lower-case", "PC1", "parity.read"),
                                ("pc2-permission-in-upper-case", "PC2", "PARITY.READ"),
                                ("pc3-permission-in-the-granted-case", "PC3", "Parity.Read")):
        f.add(isolated(cid, "subject.permissions CONTAINS '" + permission + "'",
                       [req("reader", {"id": "perm-" + cid.split("-")[0]})], ["mixedcase"]),
              "PARITY_SUITE_PERM_" + rt)
    return f


def dead_form():
    f = File("dead-form",
             "What a form that is always false alone does to the rest of its condition and to the rules beside it. "
             "Four forms are recorded as accepted by the PAP and false for a value they describe: resource['x'] == 'v' "
             "(j7-bracket-path), resource.x != null (x26-null-literal/attribute-present), MATCH against a pattern "
             "taken from an attribute (a2-match-attribute-pattern) and MATCH against a /.../ regex literal "
             "(x34-regex-literal). Alone, a leaf that is false and a rule that was ended look the same, and the two "
             "readings differ for every policy that has an OR, a DENY rule, or a second ALLOW rule beside the form. "
             "subject allowed 'READ' on resource (u7-has-access) is recorded false too, on a policy whose condition "
             "refers to the policy's own decision; access-operator.json sends it beside a policy for the operation it "
             "names. The df cases put each form through a probe and its control: a true probe means the form is a "
             "false leaf and OR went on to resource.a == 'y'; a false probe means the form ended the rule the way an "
             "absent key does (s10-absent-or-true); a false control means the fixture is broken. The two cases with sets ask the same of the levels above the "
             "condition, run on the legacy profile only, and each sends a request where nothing depends on the form "
             "as its control.",
             REGULAR_PREFIX)
    probe = [req("form-is-false-and-the-right-operand-true", {"id": "dead-form", "a": "y", "x": "abc", "p": "ab*"})]
    for cid, rt, operand in (
        ("df1-bracket-path", "DF1", "resource['x'] == 'v'"),
        ("df2-null-literal", "DF2", "resource.x != null"),
        ("df3-match-against-an-attribute", "DF3", "resource.x MATCH resource.p"),
        ("df4-match-against-a-regex-literal", "DF4", "resource.x MATCH /ab.*/"),
    ):
        or_probe_pair(f, cid, "PARITY_SUITE_DEAD_" + rt, operand, probe)
    f.add(regular("dead-form-in-a-deny-rule", [set_("set", "PERMIT_UNLESS_DENY", policy(
        "reader", "PERMIT_UNLESS_DENY",
        rule("read-deny", "operation == 'READ'", "resource.x != null OR resource.a == 'y'", "DENY")))],
        [req("form-beside-a-true-operand", {"id": "reg-dead-deny", "x": "abc", "a": "y"}),
         req("nothing-denies", {"id": "reg-dead-deny", "x": "abc", "a": "n"})],
        about="A DENY rule whose condition is a dead form OR a true operand, under the algorithm that permits what no "
              "rule denied: it denies when the form is a false leaf and does not apply when the form ends the rule. "
              "form-beside-a-true-operand is the question; nothing-denies is the control that the set permits by "
              "default."))
    f.add(regular("dead-form-beside-an-allowing-rule", [set_("set", "DENY_UNLESS_PERMIT", policy(
        "reader", "DENY_UNLESS_PERMIT",
        rule("read-allow-dead-form", "operation == 'READ'", "resource.x != null", "ALLOW"),
        rule("read-allow", "operation == 'READ'", "resource.a == 'y'", "ALLOW")))],
        [req("the-neighbor-allows", {"id": "reg-dead-allow", "x": "abc", "a": "y"}),
         req("the-neighbor-does-not", {"id": "reg-dead-allow", "x": "abc", "a": "n"})],
        about="An ALLOW rule whose condition is a dead form, beside an ALLOW rule that applies. The rule holding the "
              "form is expected to leave the neighbor alone, the way approve-failed-allow-beside-allow records for an "
              "absent key. the-neighbor-allows is the question; the-neighbor-does-not is the control that the set "
              "denies when no rule allows."))
    return f


def combining():
    f = File("combining",
             "What a policy contributes to its set when it has no rule that applies, and what a nested set contributes "
             "to its parent in the same state. The recorded algorithm-* cases give the set and its one policy the same "
             "algorithm and see only the set's answer, so they do not separate a policy that answers deny from a "
             "policy that is not applicable: under DENY_UNLESS_PERMIT both read as false, and under PERMIT_UNLESS_DENY "
             "both read as true. The two outcomes differ once the set combines the policy with a neighbor, and an "
             "evaluator of regular sets has to pick one. Each case gives the set an algorithm that reacts to the "
             "difference and sends the operation the policy has no rule for, and also sends an operation a live rule "
             "decides, so a set that was never consulted is told from a set that answered. The algorithms are the "
             "four the PAP loads (load-policy-sets-v1/regular/algorithm-*); it refuses the other six names. Legacy profile "
             "only.",
             REGULAR_PREFIX)
    two_policies = (rule("create-allow", "operation == 'CREATE'", "true", "ALLOW"),
                    rule("probe-allow-first", "operation == 'PROBE'", "true", "ALLOW"))
    reads = policy("reads", "DENY_UNLESS_PERMIT", rule("read-allow", "operation == 'READ'", "true", "ALLOW"),
                   rule("probe-allow-second", "operation == 'PROBE'", "true", "ALLOW"))
    for cid, rid, first_algorithm, about in (
        ("policy-without-a-rule-under-deny-overrides", "reg-mixed-do", "DENY_UNLESS_PERMIT",
         "Two DENY_UNLESS_PERMIT policies under DENY_OVERRIDES, each allowing one operation. READ reaches an ALLOW in "
         "the second policy and no rule in the first: false means the first policy answered deny and the set let it "
         "override; true means the first policy was not applicable. PROBE has an ALLOW in both policies and is the "
         "control."),
        ("policy-without-a-rule-under-its-own-deny-overrides", "reg-mixed-do-own", "DENY_OVERRIDES",
         "The same two policies and requests, with the first policy under DENY_OVERRIDES of its own. The algorithm-* "
         "cases record a policy with no rule under its own DENY_OVERRIDES only as the lone policy of a DENY_OVERRIDES "
         "set, where a denial and inapplicability both read false; beside a policy that allows READ the two read "
         "apart."),
    ):
        f.add(regular(cid, [set_("set", "DENY_OVERRIDES", policy("creates", first_algorithm, *two_policies), reads)],
                      [req("read-allowed-by-one-policy-without-a-rule-in-the-other", {"id": rid}, operation="READ"),
                       req("probe-allowed-by-both-policies", {"id": rid}, operation="PROBE")], about=about))
    f.add(regular("policy-without-a-rule-under-permit-unless-deny", [set_("set", "PERMIT_UNLESS_DENY", policy(
        "creates", "DENY_UNLESS_PERMIT", rule("create-allow", "operation == 'CREATE'", "true", "ALLOW"),
        rule("delete-deny", "operation == 'DELETE'", "true", "DENY")))],
        [req("read-without-a-rule", {"id": "reg-mixed-pud"}, operation="READ"),
         req("create-allowed", {"id": "reg-mixed-pud"}, operation="CREATE"),
         req("delete-denied", {"id": "reg-mixed-pud"}, operation="DELETE")],
        about="One DENY_UNLESS_PERMIT policy under PERMIT_UNLESS_DENY. READ reaches no rule: false means the policy's "
              "default deny counts as a denial; true means the policy was not applicable and the set permitted by "
              "default. CREATE reaches the ALLOW and DELETE the DENY; both are controls."))
    nested_about = ("The same question one level up: a nested set whose only policy has no rule for READ, under each "
                    "accepted inner algorithm and under the two outer algorithms that react to the difference. Under "
                    "PERMIT_UNLESS_DENY the outer set holds nothing else, so READ is true when the inner set is not "
                    "applicable and false when it contributes its default denial. Under DENY_OVERRIDES the outer set "
                    "holds a policy that allows READ, so READ is true when the inner set contributes no denial. An "
                    "inner PERMIT_UNLESS_DENY permits READ by default and is the column where both readings answer "
                    "true; it is the control for the other three. nested-outer-deny-inner-allow-* records the outer "
                    "PERMIT_OVERRIDES and DENY_UNLESS_PERMIT, where a not-applicable child and a denying child read "
                    "the same.")
    for outer_key, outer in (("permit-unless-deny", "PERMIT_UNLESS_DENY"), ("deny-overrides", "DENY_OVERRIDES")):
        for inner_key, inner in ACCEPTED_ALGORITHMS:
            outer_policies = []
            if outer == "DENY_OVERRIDES":
                outer_policies = [policy("outer-reader", "DENY_UNLESS_PERMIT",
                                         rule("outer-read-allow", "operation == 'READ'", "true", "ALLOW"))]
            inner_set = set_("inner", inner, policy("inner-reader", inner, rule(
                "inner-create-allow", "operation == 'CREATE'", "true", "ALLOW")))
            f.add(regular("nested-no-rule-" + inner_key + "-in-" + outer_key,
                          [set_("outer", outer, *outer_policies, sets=[inner_set])],
                          [req("read-without-a-rule-in-the-inner-set", {"id": "reg-mixed-nested"}, operation="READ"),
                           req("create-allowed-by-the-inner-set", {"id": "reg-mixed-nested"}, operation="CREATE")],
                          about=nested_about))
    f.add(regular("policy-with-a-false-target-under-permit-unless-deny", [set_(
        "set", "PERMIT_UNLESS_DENY",
        policy("nobody", "DENY_UNLESS_PERMIT", rule("read-deny", "operation == 'READ'", "true", "DENY"),
               target=NOBODY_TARGET),
        policy("reader", "PERMIT_UNLESS_DENY", rule("delete-deny", "operation == 'DELETE'", "true", "DENY")))],
        [req("read-denied-only-under-the-false-target", {"id": "reg-mixed-target"}, operation="READ"),
         req("delete-denied-under-the-true-target", {"id": "reg-mixed-target"}, operation="DELETE")],
        about="A policy whose target is false, holding a DENY that would apply, under PERMIT_UNLESS_DENY. True means "
              "the target keeps the policy out of the combination; false means the policy was combined and its denial "
              "counted. The control policy is PERMIT_UNLESS_DENY itself, so that it never contributes a default "
              "denial of its own to READ, and its DELETE denial shows the set is evaluated. "
              "deny-policy-target-does-not-match asks the same under DENY_OVERRIDES, where a not-applicable policy "
              "and a permitting one read the same."))
    for set_key, set_algorithm in ACCEPTED_ALGORITHMS:
        for policy_key, policy_algorithm in ACCEPTED_ALGORITHMS:
            if set_algorithm == policy_algorithm:
                continue
            resource = {"id": "reg-mixed-alg"}
            f.add(regular("set-" + set_key + "-policy-" + policy_key, [set_("set", set_algorithm, policy(
                "reader", policy_algorithm,
                rule("read-allow", "operation == 'READ'", "true", "ALLOW"),
                rule("read-deny", "operation == 'READ'", "true", "DENY"),
                rule("update-deny", "operation == 'UPDATE'", "true", "DENY"),
                rule("update-allow", "operation == 'UPDATE'", "true", "ALLOW"),
                rule("delete-deny", "operation == 'DELETE'", "true", "DENY"),
                rule("approve-allow-missing-attribute", "operation == 'APPROVE'", "resource.x == 'v'", "ALLOW"),
                rule("approve-allow", "operation == 'APPROVE'", "true", "ALLOW"),
                rule("reject-deny-missing-attribute", "operation == 'REJECT'", "resource.x == 'v'", "DENY"),
                rule("reject-allow", "operation == 'REJECT'", "true", "ALLOW")))],
                [req("read-allow-then-deny", resource, operation="READ"),
                 req("update-deny-then-allow", resource, operation="UPDATE"),
                 req("delete-deny-alone", resource, operation="DELETE"),
                 req("create-no-rule", resource, operation="CREATE"),
                 req("approve-failed-allow-beside-allow", resource, operation="APPROVE"),
                 req("reject-failed-deny-beside-allow", resource, operation="REJECT")],
                about="One of the twelve pairs of distinct accepted algorithms, one on the set and one on its "
                      "policy, over the rules and the six requests of the algorithm-* cases, which record the "
                      "diagonal of the table."))
    f.add(regular("permit-overrides-over-a-default-permit-and-a-deny", [set_(
        "set", "PERMIT_OVERRIDES",
        policy("deny-list", "PERMIT_UNLESS_DENY", rule("delete-deny", "operation == 'DELETE'", "true", "DENY")),
        policy("denies-read", "DENY_UNLESS_PERMIT", rule("read-deny", "operation == 'READ'", "true", "DENY")))],
        [req("read-permitted-by-default-and-denied-by-a-rule", {"id": "reg-mixed-po"}, operation="READ"),
         req("delete-denied-by-both-policies", {"id": "reg-mixed-po"}, operation="DELETE")],
        about="PERMIT_OVERRIDES over a policy that permits by default beside a policy that denies. On the recorded "
              "requests PERMIT_OVERRIDES and DENY_UNLESS_PERMIT answer alike; here the permit comes from a deny list "
              "that did not fire rather than from an ALLOW rule, and DELETE, denied by the same deny list, is the "
              "control."))
    return f


def operation_all():
    f = File("operation-all",
             "What a simplified policy with operation ALL does with a condition and with a predicate. "
             "x30-policy-operation-all records that ALL matches READ and DELETE for a policy with neither. oa1 pairs a "
             "condition with ALL: true for a = y and false for a = n on both operations means the condition is "
             "evaluated, true for all four means ALL drops it, and a refused upload means the form is outside the "
             "language. oa2 pairs a predicate with ALL and asks two filter operations for it.",
             "PARITY_SUITE_ALL_")
    f.add(isolated("oa1-operation-all-with-a-condition", "resource.a == 'y'", [
        req(op.lower() + "-condition-" + state, {"id": "all-oa1", "a": a}, operation=op)
        for op in ("READ", "DELETE") for state, a in (("true", "y"), ("false", "n"))], operation="ALL"),
        "PARITY_SUITE_ALL_OA1")
    f.add(isolated("oa2-operation-all-with-a-predicate", None, [
        req("filter-list", operation="LIST", filter=True), req("filter-read", operation="READ", filter=True)],
        operation="ALL", policy={"rsqlPredicate": "all==1"}), "PARITY_SUITE_ALL_OA2")
    return f


def regular_load():
    f = File("regular-load",
             "Which of the forms the simplified-policy upload refused are refused in a rule of a regular set as well. "
             "On access-control 5.13 the simplified upload refused all four: subject.isM2M (g8a-subject-is-m2m, which "
             "6.1.6 accepts as a whole condition), an undeclared subject "
             "attribute (x19-undeclared-subject-attribute), operation as an operand (o1-operation-operand), although "
             "operation stands in every rule target, and subject.permissions.PARITY "
             "(pm2-mapping-pip-suffixed-reference). Nothing records the same four forms through the policy-set "
             "upload, which has a validator of its own. Each case records the upload status and, for an accepted set, "
             "one READ. The reader is an end user, carries no declared attribute of the name parityUnknown, and holds "
             "no permission from a PIP this domain declares, so the READ of an accepted set records what the form "
             "evaluates to for a subject it does not describe. Legacy profile only.",
             REGULAR_PREFIX)
    for key, condition in (("subject-is-m2m", "subject.isM2M == true"),
                           ("undeclared-subject-attribute", "subject.parityUnknown == 'x'"),
                           ("operation-in-a-condition", "operation == 'READ'"),
                           ("suffixed-permissions", "subject.permissions.PARITY CONTAINS 'parity_permission'")):
        f.add(regular("rule-condition-" + key, [set_("set", "DENY_UNLESS_PERMIT", policy(
            "reader", "DENY_UNLESS_PERMIT", rule("read-allow", "operation == 'READ'", condition, "ALLOW")))],
            [req("read", {"id": "reg-load-" + key})]))
    return f


def set_target():
    service = "parity-st-svc"
    f = File("set-target",
             "Whether the PAP accepts a set whose target reads an attribute of the resource, and what such a target "
             "does on a request that carries the attribute, one that carries another value, one that carries no such "
             "attribute, and on a filter request, which carries no resource at all. missing-attribute-in-set-target "
             "records that a set target of the form resourceType == 'T' AND resource.x == 'v' is refused at upload, "
             "while the regular policy sets of products put resourceType == 'T' AND resource.service == '...' on the "
             "set. So either the PAP accepts some resource attributes on a set target and refuses others, or the "
             "refusal recorded had another cause; the two policies of that fixture share one policyId, and "
             "TestRound7SetTargetRefusalCases records that shape on its own. Each set-target-reads-* case uploads one "
             "set with one attribute in its target and records the upload status: resource.service, the attribute "
             "product sets read; resource.uri under MATCH and resource.id, the attributes product rules read; "
             "resource.x, the control that repeats the recorded refusal; and resource.service with no resourceType "
             "beside it, the boundary of what a set target has to name. Every target compares with this file's own "
             "service, parity-st-svc, so a set whose target names no resource type applies to no request of another "
             "case. Under an accepted set, one policy allows READ and LIST without a condition, so a request the set "
             "target admits is true and a request it does not is false, and the filter carries the LIST rule's "
             "predicate when the set target lets a request with no resource through. A second set on the same "
             "resource type allows READ when resource.s is 'y', the sibling missing-attribute-in-set-target pairs "
             "with the reading set: attribute-absent-beside-the-sibling carries s and not the attribute the first set "
             "reads, so true means the first set was not applicable and false means it ended the decision the way a "
             "missing attribute ends a rule (s10-absent-or-true). attribute-absent, with no sibling to fall back on, "
             "and the filter request, where the resource is always absent, record the same target on its own. "
             "Legacy profile only; the set with no resourceType is emptied when the test ends.",
             REGULAR_PREFIX)
    for key, target, with_type, equal, other, absent in (
        ("reads-service", "resource.service == '" + service + "'", True,
         {"id": "reg-st", "service": service}, {"id": "reg-st", "service": "parity-other-svc"}, {"id": "reg-st"}),
        ("reads-uri-with-match", "resource.uri MATCH /parity-st/**", True,
         {"id": "reg-st", "uri": "/parity-st/items/1"}, {"id": "reg-st", "uri": "/parity-other/items/1"},
         {"id": "reg-st"}),
        ("reads-id", "resource.id == 'reg-st-id'", True, {"id": "reg-st-id"}, {"id": "reg-st-other"}, {"a": "y"}),
        ("reads-unknown-attribute", "resource.x == 'v'", True,
         {"id": "reg-st", "x": "v"}, {"id": "reg-st", "x": "w"}, {"id": "reg-st"}),
        ("reads-service-without-resource-type", "resource.service == '" + service + "'", False,
         {"id": "reg-st", "service": service}, {"id": "reg-st", "service": "parity-other-svc"}, {"id": "reg-st"}),
    ):
        set_target_text = SET_TARGET + " AND " + target if with_type else target
        f.add(regular("set-target-" + key, [
            set_("set", "DENY_UNLESS_PERMIT", policy(
                "reader", "DENY_UNLESS_PERMIT", rule("read", "operation == 'READ'", "true", "ALLOW"),
                rule("list", "operation == 'LIST'", "true", "ALLOW", {"rsqlPredicate": "st==1"})),
                target=set_target_text),
            set_("sibling", "DENY_UNLESS_PERMIT", policy(
                "sibling-reader", "DENY_UNLESS_PERMIT",
                rule("read-when-s", "operation == 'READ'", "resource.s == 'y'", "ALLOW"))),
        ], [req("attribute-equal", equal), req("attribute-other", other), req("attribute-absent", absent),
            req("attribute-absent-beside-the-sibling", {"s": "y", **absent}), req("filter", filter=True)]))
    cid = "set-target-resource-type-in-lower-case"
    rt = REGULAR_PREFIX + upper(cid)
    f.add(regular(cid, [set_("set", "DENY_UNLESS_PERMIT", policy(
        "reader", "DENY_UNLESS_PERMIT", rule("read", "operation == 'READ'", "true", "ALLOW")),
        target="resourceType == '{{resourceTypeLowerCase}}'")],
        [req("the-request-in-upper-case", {"id": "reg-st-case"}, type=rt),
         req("the-request-in-the-same-case", {"id": "reg-st-case"}, type=rt.lower())],
        about="A set target that spells the resource type in lower case, against a request in upper case. "
              "x28-policy-resource-type-lowercase records that a simplified policy's resource type matches a request "
              "whatever the case; the set target is a condition, and the recorded conditions compare case "
              "insensitively (c5-string-equals-other-case) but the resourceType operand of a set target is not among "
              "them. the-request-in-the-same-case is the control."))
    return f


def substitution_rule(placeholder):
    return rule("list", "operation == 'LIST'", "true", "ALLOW", {
        "rsqlPredicate": "a==${" + placeholder + "}",
        "sqlPredicate": "a=${" + placeholder + "}",
        "mongodbPredicate": '{ "a": ${' + placeholder + "} }",
        "predicate": "${resourceType}.a.eq(${" + placeholder + "})",
        "customPredicate": {"predicate": "a:${p}", "params": {"p": placeholder}},
    })


def substitution():
    # A header the thin client does not strip (prohibitedHeaders).
    header = "x-parity-sub-header"
    pips, pins, sources = {}, {}, []

    def general(key, name, json_path, response):
        pip = {"name": "subject.paritySub" + name, "url": PIP_MOCK + "/sub-" + name, "httpMethod": "POST",
               "pipType": "GENERAL", "requestAttributes": {"resourceType": "PARITY_SUITE_SUB"}, "cacheable": False}
        if json_path:
            pip["type"] = "JSON"
            pip["jsonPath"] = json_path
        pips[key] = pip
        route = "/api/v1/pip/sub-" + name
        pins[route] = response
        sources.append((key, "subject.paritySub" + name, key, route, None))

    def ok(body):
        return {"statusCode": 200, "body": body}

    sources.append(("subject-roles", "subject.roles", None, None, None))
    pips["token-scalar"] = {"name": "subject.paritySubToken", "type": "UUID", "pipType": "TOKEN",
                            "claim": "department", "defaultValue": "none", "cacheable": False}
    sources.append(("token-scalar", "subject.paritySubToken", "token-scalar", None, None))
    pips["header-scalar"] = {"name": "subject.paritySubHeader", "type": "UUID", "pipType": "HEADER",
                             "header": header, "defaultValue": "none", "cacheable": False}
    sources.append(("header-scalar", "subject.paritySubHeader", "header-scalar", None,
                    {header: "parity-header-value"}))
    general("general-string", "String", "$.value", ok({"value": "v"}))
    general("general-number", "Number", "$.value", ok({"value": 1000}))
    general("general-boolean", "Boolean", "$.value", ok({"value": True}))
    general("general-list", "List", "", ok(["a", "b"]))
    general("general-single-element-list", "SingleElementList", "", ok(["a"]))
    general("general-empty-list", "EmptyList", "", ok([]))
    general("general-null", "Null", "", {"statusCode": 200, "bodyRaw": "null"})
    general("general-object", "Object", "", ok({"k": "v"}))
    general("general-special-chars", "SpecialChars", "$.value", ok({"value": "red,blue;green('q')\"x\""}))
    general("general-failed", "Failed", "", {"statusCode": 500, "body": {"error": "parity substitution case"}})
    f = File("substitution",
             "How each source of a placeholder is rendered by each predicate dialect of check/filter. The recorded "
             "filter cases cover a few of the cells: subject.id in four dialects (full-use-filter), a PIP string, "
             "number, boolean and object in rsql (general-scalar-substitution, general-scalar-number-substitution, "
             "general-scalar-boolean-substitution, general-pip-dict), a PIP scalar in sql (token-scalar-into-sql), a "
             "PIP collection in sql (general-array-into-sql) and in rsql (general-pip-list), a HEADER scalar in "
             "mongodb (header-scalar-into-mongodb), and a scalar with characters rsql gives meaning to, in rsql alone "
             "(general-scalar-special-chars). Before these cases no cell recorded the custom dialect at all, the querydsl dialect with a "
             "PIP, a collection in mongodb, or what a number, a boolean, an empty collection, a null body, or an "
             "object becomes outside rsql. Each case uploads one regular set whose LIST rule carries the same "
             "placeholder in all five predicate fields, so one filter request records the five renderings at once: "
             "rsql, sql, mongodb, querydsl (the predicate field) and custom (customPredicate, whose parameter names "
             "the same source). A GENERAL source answers at a pip-mock route of its own, a body that is the JSON "
             "literal null is spelled out as the recorded null-body case does, and each GENERAL case fails unless "
             "pip-mock received a call on its route: a rendering that shows the placeholder unreplaced is explained "
             "by a PIP access-control never called as much as by one it does not substitute. The HEADER source's "
             "header goes with the filter request; subject.roles needs no declaration. general-string is the control: "
             "a scalar every recorded dialect renders. Legacy profile only.",
             REGULAR_PREFIX, pips=pips, pins=pins)
    for key, placeholder, pip, route, headers in sources:
        extra = {"headers": headers} if headers else {}
        f.add(regular("substitution-" + key, [set_("set", "DENY_UNLESS_PERMIT", policy(
            "reader", "DENY_UNLESS_PERMIT", substitution_rule(placeholder)))],
            [req("filter", filter=True, **extra)], pips=[pip] if pip else (),
            reads_routes=[route] if route else None))
    return f


def permission_list():
    def mapping(suffix, role, permissions):
        return {"name": "subject.permissions." + suffix, "type": "UUID", "pipType": "MAPPING", "cacheable": False,
                "customMapping": {"subject.roles": {role: permissions}}}

    pips = {
        "other-role": mapping("PARITY_OTHER", "ROLE_PARITY_OTHER", ["parity_other_permission"]),
        "the-role": mapping("PARITY_LIST", "ROLE_PARITY_READER", ["parity_permission"]),
        "one": mapping("PARITY_LIST_ONE", "ROLE_PARITY_READER", ["parity_permission"]),
        "two-other": mapping("PARITY_LIST_TWO", "ROLE_PARITY_READER", ["parity_other_permission"]),
        "two-same": mapping("PARITY_LIST_TWO", "ROLE_PARITY_READER", ["parity_permission"]),
        "empty": mapping("PARITY_LIST_EMPTY", "ROLE_PARITY_READER", []),
    }
    f = File("permission-list",
             "What subject.permissions holds, read through a placeholder of check/filter. "
             "u10-subject-permissions-is-empty and u11-subject-permissions-contains record false for IS EMPTY and for "
             "CONTAINS with no MAPPING PIP declared, and false under IS EMPTY is what a non-empty list, a null, and an "
             "absent attribute all produce. A predicate that names the list as a placeholder renders it in the "
             "response, the way general-pip-list renders a PIP collection, and the rendering tells the three apart. "
             "Each case is one regular set whose LIST rule carries ${subject.permissions} in its rsql and sql "
             "predicates, and one filter request. The cases partition the MAPPING PIPs declared beside the set: none; "
             "one for a role the reader does not hold; one for the reader's role, the control that the placeholder "
             "renders a granted permission (pm1-mapping-pip-merged-list records the grant itself); two that grant "
             "different permissions, which says whether two declarations are merged into one list; two that grant the "
             "same permission, which says whether the merged list holds it once; and one that grants an empty list. "
             "permission-list-scopes-and-roles renders ${subject.scopes} and ${subject.roles}, the two other "
             "list-valued subject keys, with no MAPPING PIP declared. A case replaces the domain's PIPs only when it "
             "declares some, so the two cases with no declaration run first, on the domain the previous test's "
             "cleanup emptied, and every case after them declares its own. Legacy profile only.",
             REGULAR_PREFIX, pips=pips)
    for key, pip_keys, rsql, sql in (
        ("no-mapping", (), None, None),
        ("scopes-and-roles", (), "scopes=in=(${subject.scopes})", "roles IN (${subject.roles})"),
        ("mapping-for-another-role", ("other-role",), None, None),
        ("mapping-for-the-role", ("the-role",), None, None),
        ("two-mappings-with-different-permissions", ("one", "two-other"), None, None),
        ("two-mappings-with-the-same-permission", ("one", "two-same"), None, None),
        ("mapping-with-an-empty-list", ("empty",), None, None),
    ):
        predicates = {"rsqlPredicate": rsql or "perms=in=(${subject.permissions})",
                      "sqlPredicate": sql or "perms IN (${subject.permissions})"}
        f.add(regular("permission-list-" + key, [set_("set", "DENY_UNLESS_PERMIT", policy(
            "reader", "DENY_UNLESS_PERMIT", rule("list", "operation == 'LIST'", "true", "ALLOW", predicates)))],
            [req("filter", filter=True)], pips=pip_keys))
    return f


def access_operator():
    f = File("access-operator",
             "What subject allowed 'OP' on resource and subject denied 'OP' on resource evaluate when a policy for OP "
             "exists. u7-has-access and u12-subject-denied record false for both, on a lone READ policy whose "
             "condition names READ: the nested decision is the policy's own, so the false there is a decision that "
             "refers to itself, cut off or refused, and says nothing about the operator over a policy for another "
             "operation. The two forms are either a decision for another operation on the same resource, read from "
             "inside a condition, or accepted and always false; the recorded cases cannot tell. Legacy profile only.",
             REGULAR_PREFIX)

    def resource(a):
        return {"id": "reg-ao", "a": a}

    f.add(regular("access-operator-reads-another-operation", [set_("set", "DENY_UNLESS_PERMIT", policy(
        "reader", "DENY_UNLESS_PERMIT",
        rule("read-when-a", "operation == 'READ'", "resource.a == 'y'", "ALLOW"),
        rule("update-if-read-allowed", "operation == 'UPDATE'", "subject allowed 'READ' on resource", "ALLOW"),
        rule("delete-if-read-denied", "operation == 'DELETE'", "subject denied 'READ' on resource", "ALLOW")))],
        [req("update-when-read-is-allowed", resource("y"), operation="UPDATE"),
         req("update-when-read-is-denied", resource("n"), operation="UPDATE"),
         req("delete-when-read-is-allowed", resource("y"), operation="DELETE"),
         req("delete-when-read-is-denied", resource("n"), operation="DELETE"),
         req("read-allowed", resource("y"), operation="READ"),
         req("read-denied", resource("n"), operation="READ")],
        about="A READ rule with a condition on resource.a, an UPDATE rule whose condition is subject allowed 'READ' on "
              "resource, and a DELETE rule whose condition is subject denied 'READ' on resource. UPDATE with a = y "
              "and a = n decides as READ would if the operator evaluates the READ decision, and false under both if "
              "the form is always false; DELETE is the negated twin; READ under both values is the control that the "
              "READ rule itself decides on a."))
    depth = 6
    rules = [rule("read", "operation == 'READ'", "true", "ALLOW")]
    for i in range(depth, 0, -1):
        following = "READ" if i == depth else "PARITY_OP%d" % (i + 1)
        rules.append(rule("op%d" % i, "operation == 'PARITY_OP%d'" % i,
                          "subject allowed '%s' on resource" % following, "ALLOW"))
    names = ("six-nested-decisions", "five-nested-decisions", "four-nested-decisions", "three-nested-decisions",
             "two-nested-decisions", "one-nested-decision")
    f.add(regular("access-operator-chain",
                  [set_("set", "DENY_UNLESS_PERMIT", policy("reader", "DENY_UNLESS_PERMIT", *rules))],
                  [req(name, {"id": "reg-ao-chain"}, operation="PARITY_OP%d" % (i + 1)) for i, name in enumerate(names)],
                  about="Six operations where each one's rule is subject allowed on the next, ending in a READ rule "
                        "that allows without a condition. PARITY_OP1 needs six nested decisions and PARITY_OP6 one; "
                        "the answers record where the nesting is cut off, if anywhere."))
    return f


def bare_path():
    f = File("bare-path",
             "Whether a path with no resource. prefix names an attribute of the resource. Every recorded condition "
             "reads the resource as resource.<path>, and the agent's own condition parser accepts nothing else; a bare "
             "a == 'y' is either the same attribute or a form the PAP refuses. Each case records the upload status "
             "and, for an accepted policy, one request the condition holds for and one it does not, so an accepted "
             "form that is never evaluated (false under both) is told from one that reads the resource. The case "
             "with sets runs on the legacy profile only.",
             REGULAR_PREFIX)
    f.add(isolated("bp1-bare-path-against-a-literal", "a == 'y'", [
        req("attribute-equal", {"id": "bare-bp1", "a": "y"}), req("attribute-other", {"id": "bare-bp1", "a": "n"})],
        about="A bare one-segment path compared with a literal."), "PARITY_SUITE_BARE_BP1")
    f.add(isolated("bp2-bare-nested-path-against-subject-id", "owner.id == subject.id", [
        req("owner-is-the-reader", {"id": "bare-bp2", "owner": {"id": READER_ID}}),
        req("owner-is-someone-else", {"id": "bare-bp2", "owner": {"id": "00000000-0000-0000-0000-0000000000ee"}})],
        about="A bare two-segment path compared with subject.id, the shape a rule that reads the owner takes."),
        "PARITY_SUITE_BARE_BP2")
    f.add(regular("bare-path-in-a-regular-set", [set_("set", "DENY_UNLESS_PERMIT", policy(
        "reader", "DENY_UNLESS_PERMIT", rule("read-when-a", "operation == 'READ'", "a == 'y'", "ALLOW")))],
        [req("attribute-equal", {"id": "reg-bare", "a": "y"}), req("attribute-other", {"id": "reg-bare", "a": "n"})],
        about="bp1 in the rule of a regular set, since the two uploads have validators of their own."))
    return f


def deny_predicate():
    f = File("deny-predicate",
             "What check/filter carries for the predicates of DENY rules under each combining algorithm of the policy. "
             "filter-allow-and-deny-rules records, under DENY_UNLESS_PERMIT, a response that holds the ALLOW rule's "
             "predicate and not the DENY rule's. Whether the DENY predicates are left out under every algorithm, or "
             "enter the response in some negated form under the algorithms where a DENY decides, was recorded nowhere, "
             "and the answer is per dialect: an rsql, sql, mongodb, querydsl and custom predicate each have a negation "
             "of their own, or none. Each case is one regular set with one policy under one of the four accepted "
             "algorithms, holding two ALLOW rules and two DENY rules on LIST, every rule with all five predicate "
             "fields testing its own field against its own value, and one filter request. The set's own algorithm is "
             "DENY_UNLESS_PERMIT in every case, so a difference between the four responses is the policy algorithm's. "
             "deny-predicates-under-deny-overrides-without-custom-predicate repeats the DENY_OVERRIDES case with the "
             "four string predicates alone, since no upload recorded before it carried a customPredicate and a refusal of that "
             "shape would otherwise look like a refusal of the DENY rules. Legacy profile only.",
             REGULAR_PREFIX)

    def predicate_rule(key, field, value, effect, with_custom):
        predicates = {
            "rsqlPredicate": field + "==" + value,
            "sqlPredicate": field + "=" + value,
            "mongodbPredicate": '{ "' + field + '": ' + value + " }",
            "predicate": "${resourceType}." + field + ".eq(" + value + ")",
        }
        if with_custom:
            predicates["customPredicate"] = {"predicate": field + ":" + value + ":${owner}",
                                             "params": {"owner": "subject.id"}}
        return rule(key, "operation == 'LIST'", "true", effect, predicates)

    forms = [(key, name, True) for key, name in ACCEPTED_ALGORITHMS]
    forms.append(("deny-overrides-without-custom-predicate", "DENY_OVERRIDES", False))
    for key, algorithm, with_custom in forms:
        f.add(regular("deny-predicates-under-" + key, [set_("set", "DENY_UNLESS_PERMIT", policy(
            "reader", algorithm,
            predicate_rule("allow-a", "a", "1", "ALLOW", with_custom),
            predicate_rule("allow-b", "b", "2", "ALLOW", with_custom),
            predicate_rule("deny-c", "c", "3", "DENY", with_custom),
            predicate_rule("deny-d", "d", "4", "DENY", with_custom)))], [req("filter", filter=True)]))
    return f


def pip_declaration():
    header = "x-parity-hdr-list"

    def header_list(default_value=None):
        pip = {"name": "subject.parityHdrList", "type": "UUID", "pipType": "HEADER", "header": header,
               "cacheable": False}
        if default_value:
            pip["defaultValue"] = default_value
        return pip

    def mapping(suffix, key, value, permission):
        return {"name": "subject.permissions." + suffix, "type": "UUID", "pipType": "MAPPING", "cacheable": False,
                "customMapping": {key: {value: [permission]}}}

    f = File("pip-declaration",
             "What a HEADER PIP, a TOKEN PIP and a MAPPING PIP resolve under declaration shapes no other case declares. "
             "Every recorded HEADER PIP is read with a header holding one value and no comma (header-pip, h1, h2), so "
             "whether the value is one string or a list split on commas is not recorded, and neither is a defaultValue "
             "with a comma. Every recorded TOKEN PIP names a claim by its bare name (department, tier), not by a path "
             "into the token. Every recorded MAPPING PIP keys its mapping on subject.roles (pm1, pc1-pc3); whether the "
             "key may be another subject attribute or a TOKEN PIP is not recorded. The hl cases send the header a,b "
             "and ask CONTAINS 'b' (true for a list), == 'a,b' (true for one string) and IS EMPTY; hl4 and hl5 declare "
             "a defaultValue of x, y with a space after the comma, send no header, and ask CONTAINS 'y' and == 'x, y'. "
             "The tk cases read a claim by a path: tk1 the department claim as $.department, the control that a path "
             "resolves at all; tk2 the realm roles as $.realm_access.roles, a list inside an object. The mk cases key "
             "a MAPPING on subject.id, with the reader's id, and on a TOKEN PIP over the department claim, with the "
             "reader's department; mk3 keys it on subject.roles with a role the reader does not hold, the control "
             "that a mapping keyed on the wrong value grants nothing.",
             "PARITY_SUITE_",
             pips={
                 "list": header_list(),
                 "list-default": header_list("x, y"),
                 "department-path": {"name": "subject.parityTkDepartment", "type": "UUID", "pipType": "TOKEN",
                                     "claim": "$.department", "cacheable": False},
                 "roles-path": {"name": "subject.parityTkRoles", "type": "UUID", "pipType": "TOKEN",
                                "claim": "$.realm_access.roles", "cacheable": False},
                 "by-id": mapping("PARITY_MK1", "subject.id", READER_ID, "parity_by_id"),
                 "department": {"name": "subject.parityMkDepartment", "type": "UUID", "pipType": "TOKEN",
                                "claim": "department", "cacheable": False},
                 "by-department": mapping("PARITY_MK2", "subject.parityMkDepartment", "finance",
                                          "parity_by_department"),
                 "by-other-role": mapping("PARITY_MK3", "subject.roles", "ROLE_PARITY_OTHER", "parity_by_other_role"),
             })
    with_list = {header: "a,b"}
    f.add(isolated("hl1-header-list-contains", "subject.parityHdrList CONTAINS 'b'",
                   [req("header-a-comma-b", {"id": "hdr-hl1"}, headers=with_list)], ["list"]),
          "PARITY_SUITE_HDR_HL1")
    f.add(isolated("hl2-header-list-equals-joined", "subject.parityHdrList == 'a,b'",
                   [req("header-a-comma-b", {"id": "hdr-hl2"}, headers=with_list)], ["list"]),
          "PARITY_SUITE_HDR_HL2")
    f.add(isolated("hl3-header-list-is-empty", "subject.parityHdrList IS EMPTY",
                   [req("header-a-comma-b", {"id": "hdr-hl3"}, headers=with_list),
                    req("no-header", {"id": "hdr-hl3"})], ["list"]), "PARITY_SUITE_HDR_HL3")
    f.add(isolated("hl4-default-with-a-space-contains", "subject.parityHdrList CONTAINS 'y'",
                   [req("no-header", {"id": "hdr-hl4"})], ["list-default"]), "PARITY_SUITE_HDR_HL4")
    f.add(isolated("hl5-default-with-a-space-equals-joined", "subject.parityHdrList == 'x, y'",
                   [req("no-header", {"id": "hdr-hl5"})], ["list-default"]), "PARITY_SUITE_HDR_HL5")
    f.add(isolated("tk1-token-claim-by-path", "subject.parityTkDepartment == 'finance'",
                   [req("reader", {"id": "tok-tk1"})], ["department-path"]), "PARITY_SUITE_TOK_TK1")
    f.add(isolated("tk2-token-claim-list-by-path", "subject.parityTkRoles CONTAINS 'ROLE_PARITY_READER'",
                   [req("reader", {"id": "tok-tk2"})], ["roles-path"]), "PARITY_SUITE_TOK_TK2")
    f.add(isolated("mk1-mapping-keyed-on-subject-id", "subject.permissions CONTAINS 'parity_by_id'",
                   [req("reader", {"id": "map-mk1"})], ["by-id"]), "PARITY_SUITE_MAP_MK1")
    f.add(isolated("mk2-mapping-keyed-on-a-token-pip", "subject.permissions CONTAINS 'parity_by_department'",
                   [req("reader", {"id": "map-mk2"})], ["department", "by-department"]), "PARITY_SUITE_MAP_MK2")
    f.add(isolated("mk3-mapping-keyed-on-a-role-not-held", "subject.permissions CONTAINS 'parity_by_other_role'",
                   [req("reader", {"id": "map-mk3"})], ["by-other-role"]), "PARITY_SUITE_MAP_MK3")
    return f


for build in (null_and_absence, permission_case, dead_form, combining, operation_all, regular_load, set_target,
              substitution, permission_list, access_operator, bare_path, deny_predicate, pip_declaration):
    build().write()
