# Copyright 2024-2026 Netcracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

package rls

import rego.v1

default evaluate(resource_type, operation, resource, subject, ols_roles, subject_roles) := {
  "allow": false,
  "predicate": "",
  "typed_predicates": {}
}

evaluate(resource_type, operation, resource, subject, ols_roles, subject_roles) := {
  "allow": allow,
  "predicate": predicate,
  "typed_predicates": typed
} if {
  rules := granted_rules(resource_type, operation, resource, subject, ols_roles, subject_roles)
  allow := count(rules) > 0
  rsql_values := predicate_values_for_type(rules, "rsql")
  # D-AF-S (OQ-AF-7 owner resolution on 2026-04-15): if ANY granted
  # rule is unrestricted (pure OLS — no `condition`/`conditionAst`
  # beyond the default true shortcut AND no non-trivial predicate),
  # the whole aggregation collapses to ALLOW with an empty predicate.
  # This mirrors legacy `EvaluationResultBuilder.java:72-93`: a
  # matching pure-OLS rule absorbs any restrictive RLS rule on the
  # same locator. Without this collapse, authz-agent returns
  # `USE_FILTER_CONDITION` with the restrictive predicate while
  # legacy returns `ALLOW` with no predicate — the divergence row 6
  # `TestRow06CheckFilterV1AggOlsPlusRls` was pinned against.
  predicate := aggregated_predicate(rules, rsql_values)
  typed := typed_predicates_or_empty(rules, rsql_values)
}

# D-AF-S collapse: unrestricted-rule wins.
aggregated_predicate(rules, _) := "" if {
  rules_include_unrestricted(rules)
}

aggregated_predicate(rules, rsql_values) := aggregate_by_type("rsql", rsql_values) if {
  not rules_include_unrestricted(rules)
}

typed_predicates_or_empty(rules, _) := {} if {
  rules_include_unrestricted(rules)
}

typed_predicates_or_empty(rules, rsql_values) := typed_predicates_from_rules(rules, rsql_values) if {
  not rules_include_unrestricted(rules)
}

# A rule is "unrestricted" (pure OLS) when:
#   (a) its condition is effectively `true` — either the literal
#       `true` shortcut, or condition/conditionAst are both absent;
#   (b) every predicate it carries is trivial (`predicate: "true"`
#       per the docs/ai/policy-format.md normalization rule) OR it
#       carries no predicates at all.
# Such a rule represents "the role is fully authorised — no row-
# level filter needed".
rules_include_unrestricted(rules) if {
  some idx
  rule := rules[idx]
  rule_is_unrestricted(rule)
}

rule_is_unrestricted(rule) if {
  rule_condition_trivial(rule)
  rule_predicates_trivial(rule)
}

rule_condition_trivial(rule) if {
  rule.condition == true
}

rule_condition_trivial(rule) if {
  object.get(rule, "condition", "__missing__") == "__missing__"
  object.get(rule, "conditionAst", "__missing__") == "__missing__"
}

rule_predicates_trivial(rule) if {
  object.get(rule, "predicates", "__missing__") == "__missing__"
}

rule_predicates_trivial(rule) if {
  predicates := object.get(rule, "predicates", [])
  count(predicates) == 0
}

rule_predicates_trivial(rule) if {
  predicates := object.get(rule, "predicates", [])
  count(predicates) > 0
  count([1 |
    some pidx
    pred_obj := predicates[pidx]
    pred_str := object.get(pred_obj, "predicate", "")
    lower(pred_str) != "true"
    pred_str != ""
  ]) == 0
}

granted_rules(resource_type, operation, resource, subject, ols_roles, subject_roles) := rules if {
  roles := candidate_roles(ols_roles, subject_roles)
  rule_lists := direct_rule_lists(resource_type, operation, roles)

  rules := [candidate_rule |
    some list_idx
    some rule_idx
    candidate_rule := rule_lists[list_idx][rule_idx]
    condition_allows(candidate_rule, resource, subject)
  ]
}

default granted_rules(_, _, _, _, _, _) := []

candidate_roles(ols_roles, _) := ols_roles if {
  roles_include_all(ols_roles)
}

candidate_roles(ols_roles, _) := array.concat(ols_roles, ["ALL"]) if {
  not roles_include_all(ols_roles)
}

roles_include_all(roles) if {
  some idx
  roles[idx] == "ALL"
}

direct_rule_lists(resource_type, operation, roles) := lists if {
  rls_data := data.policies.rls
  rt_obj := object.get(rls_data, resource_type, {})
  all_obj := object.get(rls_data, "ALL", {})
  rt_op := object.get(rt_obj, operation, {})
  rt_all_op := object.get(rt_obj, "ALL", {})
  all_rt_op := object.get(all_obj, operation, {})
  all_all := object.get(all_obj, "ALL", {})
  lists := [rule_list |
    some role_idx
    role_key := roles[role_idx]
    some src_idx
    src := [rt_op, rt_all_op, all_rt_op, all_all][src_idx]
    rule_list := object.get(src, role_key, [])
    count(rule_list) > 0
  ]
}

default direct_rule_lists(_, _, _) := []

condition_allows(rule, resource, subject) if {
  rule.condition == true
} else if {
  object.get(rule, "condition", "__missing__") == "__missing__"
  object.get(rule, "conditionAst", "__missing__") == "__missing__"
} else if {
  ast := rule.conditionAst
  simple_ast_supported(ast)
  simple_ast_condition_allows(ast, resource, subject)
} else if {
  ast := rule.conditionAst
  ast_condition_allows(ast, resource, subject)
}

ast_condition_allows(ast, resource, subject) if {
  ast_leaf_allows(ast, resource, subject)
}

ast_condition_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "and"
  args := ast.args
  count(args) > 0
  failed := [1 |
    some idx
    arg := args[idx]
    not ast_arg_allows(arg, resource, subject)
  ]
  count(failed) == 0
}

ast_condition_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "or"
  args := ast.args
  matched := [1 |
    some idx
    ast_arg_allows(args[idx], resource, subject)
  ]
  count(matched) > 0
}

ast_condition_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "not"
  args := ast.args
  count(args) >= 1
  # ADR-0068 negation fail-closed (NEW-2 / §D): a failed/absent PIP alias must not
  # open access under negation. `not <false-or-undefined>` grants in Rego, so a
  # broken-PIP operand would otherwise flip the NOT to allow. Guard first: if the
  # inner operand references a failed PIP (known alias, absent), the NOT does not
  # match. Genuine missing attributes (non-PIP) are unaffected — legacy semantics.
  not _arg_has_failed_pip_ref(args[0], subject)
  not ast_arg_allows(args[0], resource, subject)
}

ast_arg_allows(ast, resource, subject) if {
  ast_leaf_allows(ast, resource, subject)
}

ast_arg_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "and"
  args := ast.args
  count(args) > 0
  failed := [1 |
    some idx
    arg := args[idx]
    not ast_leaf_allows(arg, resource, subject)
  ]
  count(failed) == 0
}

ast_arg_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "or"
  args := ast.args
  matched := [1 |
    some idx
    ast_leaf_allows(args[idx], resource, subject)
  ]
  count(matched) > 0
}

ast_arg_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "not"
  args := ast.args
  count(args) >= 1
  # See the ast_condition_allows "not" clause: fail-closed on a failed-PIP operand.
  not _arg_has_failed_pip_ref(args[0], subject)
  not ast_leaf_allows(args[0], resource, subject)
}

ast_leaf_allows(ast, resource, subject) if {
  has_key(ast, "const")
  const_value := object.get(ast, "const", false)
  is_boolean(const_value)
  const_value
}

simple_ast_supported(ast) if {
  op := ast_op(ast)
  op == "eq"
  args := ast.args
  count(args) >= 2
  simple_arg_supported(args[0])
  simple_arg_supported(args[1])
}

simple_ast_supported(ast) if {
  op := ast_op(ast)
  op == "neq"
  args := ast.args
  count(args) >= 2
  simple_arg_supported(args[0])
  simple_arg_supported(args[1])
}

simple_ast_condition_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "eq"
  args := ast.args
  left := simple_arg_value(args[0], resource, subject)
  right := simple_arg_value(args[1], resource, subject)
  values_equal(left, right)
}

simple_ast_condition_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "neq"
  args := ast.args
  left := simple_arg_value(args[0], resource, subject)
  right := simple_arg_value(args[1], resource, subject)
  not values_equal(left, right)
}

simple_arg_supported(arg) if {
  object.get(arg, "const", "__missing__") != "__missing__"
}

simple_arg_supported(arg) if {
  ref_obj := arg.ref
  ref_obj.scope == "resource"
  count(ref_obj.path) == 1
}

simple_arg_supported(arg) if {
  ref_obj := arg.ref
  ref_obj.scope == "subject"
  count(ref_obj.path) == 1
}

simple_arg_value(arg, resource, subject) := value if {
  object.get(arg, "const", "__missing__") != "__missing__"
  value := arg.const
}

simple_arg_value(arg, resource, subject) := value if {
  ref_obj := arg.ref
  ref_obj.scope == "resource"
  value := object.get(resource, ref_obj.path[0], null)
}

simple_arg_value(arg, resource, subject) := value if {
  ref_obj := arg.ref
  ref_obj.scope == "subject"
  # ADR-0068 (§D): a failed PIP alias resolves to UNDEFINED, not null, so the
  # fast-path neq (not values_equal(null, const) => grant) fails closed. Falls
  # through to the general path, which is guarded identically.
  not _is_failed_pip_ref(ref_obj, subject)
  value := object.get(subject, ref_obj.path[0], null)
}

ast_leaf_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "eq"
  args := ast.args
  count(args) >= 2
  left := arg_value(args[0], resource, subject)
  right := arg_value(args[1], resource, subject)
  values_equal(left, right)
}

ast_leaf_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "neq"
  args := ast.args
  count(args) >= 2
  left := arg_value(args[0], resource, subject)
  right := arg_value(args[1], resource, subject)
  not values_equal(left, right)
}

ast_leaf_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "contains"
  args := ast.args
  count(args) >= 2
  left := arg_value(args[0], resource, subject)
  right := arg_value(args[1], resource, subject)
  contains_value(left, right)
}

ast_leaf_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "contains_any"
  args := ast.args
  count(args) >= 2
  left := arg_value(args[0], resource, subject)
  right := arg_value(args[1], resource, subject)
  contains_any_value(left, right)
}

ast_leaf_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "in"
  args := ast.args
  count(args) >= 2
  left := arg_value(args[0], resource, subject)
  right := arg_value(args[1], resource, subject)
  in_value(left, right)
}

ast_leaf_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "match"
  args := ast.args
  count(args) >= 2
  left := arg_value(args[0], resource, subject)
  right := arg_value(args[1], resource, subject)
  pattern_match(left, right)
}

ast_leaf_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "is_empty"
  args := ast.args
  count(args) >= 1
  value := arg_value(args[0], resource, subject)
  is_empty_value(value)
}

ast_leaf_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "is_null"
  args := ast.args
  count(args) >= 1
  value := arg_value(args[0], resource, subject)
  value == null
}

ast_leaf_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "is_subset"
  args := ast.args
  count(args) >= 2
  left := arg_value(args[0], resource, subject)
  right := arg_value(args[1], resource, subject)
  is_subset_value(left, right)
}

ast_leaf_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "gt"
  args := ast.args
  count(args) >= 2
  left := as_number(arg_value(args[0], resource, subject))
  right := as_number(arg_value(args[1], resource, subject))
  left > right
}

ast_leaf_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "gte"
  args := ast.args
  count(args) >= 2
  left := as_number(arg_value(args[0], resource, subject))
  right := as_number(arg_value(args[1], resource, subject))
  left >= right
}

ast_leaf_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "lt"
  args := ast.args
  count(args) >= 2
  left := as_number(arg_value(args[0], resource, subject))
  right := as_number(arg_value(args[1], resource, subject))
  left < right
}

ast_leaf_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "lte"
  args := ast.args
  count(args) >= 2
  left := as_number(arg_value(args[0], resource, subject))
  right := as_number(arg_value(args[1], resource, subject))
  left <= right
}

ast_leaf_allows(ast, resource, subject) if {
  op := ast_op(ast)
  op == "has_access"
  args := ast.args
  count(args) >= 1
  mode := lower(sprintf("%v", [arg_value(args[0], resource, subject)]))
  depth := has_access_depth(args, resource, subject)
  mode == "allowed"
  depth <= 5
}

ast_op(ast) := lower(object.get(ast, "op", ""))

both_strings(left, right) if {
  is_string(left)
  is_string(right)
}

values_equal(left, right) if {
  both_strings(left, right)
  lower(left) == lower(right)
}

values_equal(left, right) if {
  not both_strings(left, right)
  left == right
}

as_array(value) := value if {
  is_array(value)
}

as_array(value) := [] if {
  value == null
}

as_array(value) := [value] if {
  not is_array(value)
  value != null
}

contains_value(left, right) if {
  left_arr := as_array(left)
  some idx
  values_equal(left_arr[idx], right)
}

contains_any_value(left, right) if {
  left_arr := as_array(left)
  right_arr := as_array(right)
  some left_idx
  some right_idx
  values_equal(left_arr[left_idx], right_arr[right_idx])
}

in_value(left, right) if {
  contains_value(right, left)
}

is_empty_value(value) if {
  is_array(value)
  count(value) == 0
}

is_empty_value(value) if {
  is_object(value)
  count(object.keys(value)) == 0
}

is_empty_value(value) if {
  is_string(value)
  value == ""
}

is_subset_value(left, right) if {
  left_arr := as_array(left)
  right_arr := as_array(right)
  missing := [1 |
    some idx
    value := left_arr[idx]
    not contains_value(right_arr, value)
  ]
  count(missing) == 0
}

pattern_match(left, right) if {
  is_string(left)
  is_string(right)
  glob.match(right, ["/"], left)
}

pattern_match(left, right) if {
  is_string(left)
  is_string(right)
  startswith(right, "^")
  regex.match(right, left)
}

pattern_match(left, right) if {
  is_string(left)
  is_string(right)
  glob.match(left, ["/"], right)
}

pattern_match(left, right) if {
  is_string(left)
  is_string(right)
  startswith(left, "^")
  regex.match(left, right)
}

as_number(value) := to_number(value)

has_access_depth(args, resource, subject) := 1 if {
  count(args) < 4
}

has_access_depth(args, resource, subject) := depth if {
  count(args) >= 4
  raw_depth := arg_value(args[3], resource, subject)
  depth := as_number(raw_depth)
}

arg_value(arg, resource, subject) := value if {
  object.get(arg, "ref", "__missing__") != "__missing__"
  # ADR-0068 (§D): a failed PIP alias resolves to UNDEFINED (not the path_lookup
  # null default), so negative leaf operators (neq / is_null / is_subset) fail
  # closed instead of granting on null. The `not`-wrapper case is handled by the
  # _arg_has_failed_pip_ref guard on the not clauses.
  not _is_failed_pip_ref(arg.ref, subject)
  value := ref_value(arg.ref, resource, subject)
}

arg_value(arg, resource, subject) := value if {
  object.get(arg, "const", "__missing__") != "__missing__"
  value := arg.const
}

arg_value(arg, resource, subject) := null if {
  object.get(arg, "const", "__missing__") == "__missing__"
  object.get(arg, "ref", "__missing__") == "__missing__"
}

# ── PIP-failure-aware ref resolution (ADR-0068 §D / negation fail-closed) ──
# A GENERAL/TOKEN/HEADER PIP that fails to produce a value leaves its alias
# ABSENT from the enriched subject (never present-with-null: resolve_general_values
# / resolve_token_values / resolve_header_values only bind non-null values, and
# soft-defaults are non-null). So "known PIP alias + absent" uniquely identifies a
# failed PIP. Such a ref resolves to UNDEFINED (not the path_lookup null default),
# which makes both positive and negative leaf operators fail closed, and — via the
# _arg_has_failed_pip_ref guard on the two `not` clauses — makes negation over a
# failed PIP fail closed too. Genuine missing attributes (not PIP aliases) keep the
# legacy missing==null semantics, so `NOT(x==const)` / `x!=const` / `is_null` over a
# non-PIP attribute are unchanged.
_is_failed_pip_ref(ref_obj, subject) if {
  ref_obj.scope == "subject"
  count(ref_obj.path) >= 1
  alias := ref_obj.path[0]
  data.pip.known_pip_aliases[alias]
  object.get(subject, alias, _pip_ref_absent) == _pip_ref_absent
}

# Set sentinel that can never equal a JSON subject value.
_pip_ref_absent := {"__pip_ref_absent__"}

# True if any subject ref anywhere inside the operand node is a failed-PIP ref.
# Skips paths that enter a `const` branch: a const value is a JSON literal, never
# an AST ref node, so a const shaped like {ref:{scope:"subject",path:[alias]}}
# must not be mistaken for a real ref (that would over-deny a legitimate NOT).
_arg_has_failed_pip_ref(node, subject) if {
  walk(node, [path, sub])
  not _path_enters_const(path)
  is_object(sub)
  ref_obj := object.get(sub, "ref", null)
  ref_obj != null
  _is_failed_pip_ref(ref_obj, subject)
}

_path_enters_const(path) if {
  some i
  path[i] == "const"
}

# ── Entitlement-scoped ref (ADR-0054 / D-AG-11 / D-AG-12) ──────────────
# The simplified-policy parser emits entitlement operands as a ref node
# with `scope == "entitlements"` carrying `resourceType` + `names[]`.
# Evaluation happens against `subject.entitledResources` which the
# authorize.rego pipeline materialises from the container-pinned PIP
# resolver before RLS runs. Chained / multi-name `.as(...)` evaluates
# as UNION per D-AG-12; the returned value is a sorted array of
# resource ids ready for the existing CONTAINS / CONTAINS ANY / IN /
# IS EMPTY / NOT CONTAINS operator handlers.

ref_value(ref_obj, resource, subject) := value if {
  ref_obj.scope == "entitlements"
  value := entitlement_ref_value(ref_obj, subject)
}

ref_value(ref_obj, resource, subject) := value if {
  ref_obj.scope != "entitlements"
  base := ref_scope_base(ref_obj.scope, resource, subject)
  value := path_lookup(base, ref_obj.path)
}

entitlement_ref_value(ref_obj, subject) := sorted_ids if {
  ent_tree := object.get(subject, "entitledResources", {})
  rt_bucket := object.get(ent_tree, ref_obj.resourceType, {})
  names := ref_obj.names
  id_set := {id |
    some idx
    name := names[idx]
    id_list := object.get(rt_bucket, name, [])
    some ididx
    id := id_list[ididx]
  }
  sorted_ids := sort([id | some id in id_set])
}

default entitlement_ref_value(_, _) := []

ref_scope_base("resource", resource, subject) := resource
ref_scope_base("subject", resource, subject) := subject
ref_scope_base(scope, resource, subject) := {} if {
  scope != "resource"
  scope != "subject"
  scope != "entitlements"
}

path_lookup(base, path) := base if {
  count(path) == 0
}

path_lookup(base, path) := object.get(base, path[0], null) if {
  count(path) == 1
}

path_lookup(base, path) := object.get(object.get(base, path[0], {}), path[1], null) if {
  count(path) == 2
}

path_lookup(base, path) := object.get(object.get(object.get(base, path[0], {}), path[1], {}), path[2], null) if {
  count(path) == 3
}

path_lookup(base, path) := object.get(object.get(object.get(object.get(base, path[0], {}), path[1], {}), path[2], {}), path[3], null) if {
  count(path) == 4
}

path_lookup(base, path) := object.get(object.get(object.get(object.get(object.get(base, path[0], {}), path[1], {}), path[2], {}), path[3], {}), path[4], null) if {
  count(path) == 5
}

path_lookup(base, path) := object.get(object.get(object.get(object.get(object.get(object.get(base, path[0], {}), path[1], {}), path[2], {}), path[3], {}), path[4], {}), path[5], null) if {
  count(path) == 6
}

# Depth > 6 truncates to null. Multi-segment RLS refs in practice are shallow
# (map-extract subject.<alias>.<name> = depth 2; ${resource.attrs.X} = depth 2),
# so depth 6 is well beyond any real reference; a null here is a non-match for
# eq/contains/in but note it can read as a false-positive for neq/is_null on a
# genuinely-deeper path — the same missing-ref semantics that exist at all depths.
path_lookup(base, path) := null if {
  count(path) > 6
}

# ── Type-specific OR aggregation (ADR-0025) ──────────────────────────────

# Normalise empty type string to "rsql" (legacy default).
effective_predicate_type("") := "rsql"

effective_predicate_type(t) := t if {
  t != ""
}

# Collect non-trivial predicate strings for the given effective type.
predicate_values_for_type(rules, ptype) := sorted_values if {
  values := {pred |
    some idx
    rule := rules[idx]
    some pidx
    pred_obj := object.get(rule, "predicates", [])[pidx]
    effective_predicate_type(lower(object.get(pred_obj, "type", ""))) == ptype
    pred := object.get(pred_obj, "predicate", "")
    pred != ""
    lower(pred) != "true"
  }
  sorted_values := sort(values)
}

# Empty array → empty string (any type).
aggregate_by_type(_, values) := "" if {
  count(values) == 0
}

# rsql: single as-is; multiple as (p1),(p2),...
aggregate_by_type("rsql", values) := values[0] if {
  count(values) == 1
}

aggregate_by_type("rsql", values) := concat(",", values) if {
  count(values) > 1
}
# D-AF-S (OQ-AF-7 owner resolution on 2026-04-15, supersedes ADR-0025's
# parenthesized-OR wrapping): RSQL aggregation emits flat comma-joined
# predicates that match legacy `access-control`'s aggregator output
# byte-for-byte. The previous form wrapped each item in `(%v)` which
# diverged from legacy and broke parity on
# `TestRow06CheckFilterV1AggTwoPredicates`. Per-item predicates that
# already carry their own top-level grouping (e.g. policies written in
# `a=in=(...)` form) retain their internal parentheses naturally; we
# only removed the outer wrapper that the aggregator added.

# sql: p1 OR p2 OR ...
aggregate_by_type("sql", values) := concat(" OR ", values) if {
  count(values) > 0
}

# querydsl: single as-is; multiple as .or(p1,p2,...)
aggregate_by_type("querydsl", values) := values[0] if {
  count(values) == 1
}

aggregate_by_type("querydsl", values) := sprintf(".or(%v)", [concat(",", values)]) if {
  count(values) > 1
}

# mongodb: single as-is; multiple as {"$or": [p1,p2,...]}
aggregate_by_type("mongodb", values) := values[0] if {
  count(values) == 1
}

aggregate_by_type("mongodb", values) := sprintf("{\"$or\": [%v]}", [concat(",", values)]) if {
  count(values) > 1
}

# custom: single as-is; multiple as {"op": "OR", "predicates": [p1,p2,...]}
aggregate_by_type("custom", values) := values[0] if {
  count(values) == 1
}

aggregate_by_type("custom", values) := sprintf("{\"op\": \"OR\", \"predicates\": [%v]}", [concat(",", values)]) if {
  count(values) > 1
}

typed_predicates_from_rules(rules, rsql_values) := result if {
  all_by_type := _collect_all_predicates_by_type(rules)
  rsql_agg := aggregate_by_type("rsql", rsql_values)
  querydsl_agg := aggregate_by_type("querydsl", object.get(all_by_type, "querydsl", []))
  mongodb_agg := aggregate_by_type("mongodb", object.get(all_by_type, "mongodb", []))
  sql_agg := aggregate_by_type("sql", object.get(all_by_type, "sql", []))
  custom_agg := aggregate_by_type("custom", object.get(all_by_type, "custom", []))
  result := {ptype: value |
    some entry in [
      {"type": "rsql", "value": rsql_agg},
      {"type": "querydsl", "value": querydsl_agg},
      {"type": "mongodb", "value": mongodb_agg},
      {"type": "sql", "value": sql_agg},
      {"type": "custom", "value": custom_agg},
    ]
    ptype := entry.type
    value := entry.value
    value != ""
  }
}

default typed_predicates_from_rules(_, _) := {}

# Single-pass collection of all non-rsql predicate values by effective type.
_collect_all_predicates_by_type(rules) := result if {
  pairs := [{"type": ptype, "pred": pred} |
    some idx
    rule := rules[idx]
    some pidx
    pred_obj := object.get(rule, "predicates", [])[pidx]
    raw_type := lower(object.get(pred_obj, "type", ""))
    ptype := effective_predicate_type(raw_type)
    ptype != "rsql"
    pred := object.get(pred_obj, "predicate", "")
    pred != ""
    lower(pred) != "true"
  ]
  result := {ptype: sort(values) |
    some pair in pairs
    ptype := pair.type
    values := {p | some p2 in pairs; p2.type == ptype; p := p2.pred}
  }
}

default _collect_all_predicates_by_type(_) := {}

has_key(obj, key) if {
  object.get(obj, key, "__missing__") != "__missing__"
}

direct_and_all_keys(value) := array.concat(lookup_keys(value), ["ALL"]) if {
  upper(value) != "ALL"
}

direct_and_all_keys(value) := ["ALL"] if {
  upper(value) == "ALL"
}

lookup_keys(value) := [value] if {
  value != ""
  upper(value) == value
}

lookup_keys(value) := [value, upper(value)] if {
  value != ""
  upper(value) != value
}
