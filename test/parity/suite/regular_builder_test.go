// Copyright 2024-2026 Netcracker Technology Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package paritysuite

// regularBuilder builds the policy set, policy, and rule objects of one case. Every
// id is derived from the case id and the element's path, so a rerun uploads the
// same ids and replaces its own sets, and two cases share no id unless a case
// file takes one case's rule ids from another with ruleIdsOf.
type regularBuilder struct{ caseID string }

func (b regularBuilder) id(path string) string { return derivedID(b.caseID, path) }

// set builds a policy set; an empty algorithm leaves combiningAlgorithm out.
func (b regularBuilder) set(key, target, algorithm string, policies []any, nested []any) map[string]any {
	set := map[string]any{
		"policySetId": b.id("set/" + key),
		"name":        b.caseID + " " + key,
		"status":      "ACTIVE",
		"target":      target,
		"policies":    policies,
		"policySets":  emptyIfNil(nested),
	}
	if algorithm != "" {
		set["combiningAlgorithm"] = algorithm
	}
	return set
}

// policy builds a policy; an empty algorithm leaves combiningAlgorithm out. A
// policy with no rules uploads an empty list rather than null, so that a case about
// an empty rule list is about that and not about the JSON form.
func (b regularBuilder) policy(key, target, algorithm string, rules ...any) map[string]any {
	policy := map[string]any{
		"policyId": b.id("policy/" + key),
		"name":     b.caseID + " " + key,
		"target":   target,
		"rules":    emptyIfNil(rules),
	}
	if algorithm != "" {
		policy["combiningAlgorithm"] = algorithm
	}
	return policy
}

// rule builds a rule with the given predicates, keyed by their field names.
func (b regularBuilder) rule(key, target, condition, effect string, predicates map[string]string) map[string]any {
	rule := map[string]any{
		"ruleId":    b.id("rule/" + key),
		"name":      b.caseID + " " + key,
		"target":    target,
		"condition": condition,
		"effect":    effect,
	}
	for field, predicate := range predicates {
		rule[field] = predicate
	}
	return rule
}

// buildSet turns set into the wire form regularBuilder writes, with the
// resource type placeholders in every target and condition replaced. Rule ids
// come from ruleIDs, and every other id from b. The fields of a set, a
// policy, and a rule are merged last, with mergeFields, and then the members
// named by each one's omitFields are removed.
func buildSet(b, ruleIDs regularBuilder, set setSpec, rt string) map[string]any {
	sub := resourceTypeReplacer(rt).Replace
	policies := make([]any, 0, len(set.Policies))
	for _, p := range set.Policies {
		rules := make([]any, 0, len(p.Rules))
		for _, r := range p.Rules {
			rule := b.rule(r.Key, sub(r.Target), sub(r.Condition), r.Effect, nil)
			rule["ruleId"] = ruleIDs.id("rule/" + r.Key)
			for field, predicate := range r.Predicates {
				rule[field] = predicate
			}
			mergeFields(rule, r.Fields, rt)
			omitMembers(rule, r.OmitFields)
			rules = append(rules, rule)
		}
		policy := b.policy(p.Key, sub(p.Target), p.Algorithm, rules...)
		mergeFields(policy, p.Fields, rt)
		omitMembers(policy, p.OmitFields)
		policies = append(policies, policy)
	}
	var nested []any
	for _, n := range set.Sets {
		nested = append(nested, buildSet(b, ruleIDs, n, rt))
	}
	out := b.set(set.Key, sub(set.Target), set.Algorithm, policies, nested)
	if set.Status != "" {
		out["status"] = set.Status
	}
	if set.OmitStatus {
		delete(out, "status")
	}
	if set.Iterate != nil {
		out["iterate"] = map[string]any{"foreach": set.Iterate.Foreach, "combiningAlgorithm": set.Iterate.Algorithm}
	}
	mergeFields(out, set.Fields, rt)
	omitMembers(out, set.OmitFields)
	return out
}

// omitMembers deletes from object each member whose name is in names.
func omitMembers(object map[string]any, names []string) {
	for _, name := range names {
		delete(object, name)
	}
}
