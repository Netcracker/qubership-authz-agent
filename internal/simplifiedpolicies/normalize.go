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

package simplifiedpolicies

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Policy struct {
	Component         string `json:"component"`
	ResourceType      string `json:"resourceType"`
	Operation         string `json:"operation"`
	Condition         any    `json:"condition"`
	RSQLPredicate     string `json:"rsqlPredicate"`
	SQLPredicate      string `json:"sqlPredicate"`
	MongoDBPredicate  string `json:"mongodbPredicate"`
	QueryDSLPredicate string `json:"querydslPredicate"`
	Roles             []any  `json:"roles"`
}

func Normalize(input []byte) (map[string]any, error) {
	policies, err := decodePolicies(input)
	if err != nil {
		return nil, err
	}
	return NormalizePolicies(policies)
}

func NormalizePolicies(policies []Policy) (map[string]any, error) {
	ols := map[string]any{}
	rls := map[string]any{}
	globalAccessByRole := map[string]any{}

	for idx, policy := range policies {
		rt := normalizeKey(policy.ResourceType)
		if rt == "" {
			return nil, fmt.Errorf("simplified policy %d: resourceType is required", idx)
		}

		op := normalizeKey(policy.Operation)
		if op == "" {
			return nil, fmt.Errorf("simplified policy %d: operation is required", idx)
		}

		if strings.TrimSpace(policy.Component) == "" {
			return nil, fmt.Errorf("simplified policy %d: component is required", idx)
		}

		roles, err := normalizeRoles(policy.Roles)
		if err != nil {
			return nil, fmt.Errorf("simplified policy %d: %w", idx, err)
		}

		isWildcardRT := rt == "ALL"
		isWildcardOP := op == "ALL"

		if (isWildcardRT || isWildcardOP) && len(roles) > 0 {
			for _, role := range roles {
				mergeGlobalAccessRole(globalAccessByRole, role, rt, op, isWildcardRT, isWildcardOP)
			}
			continue
		}

		if len(roles) > 0 {
			if err := mergeOLSRule(ols, rt, op, roles); err != nil {
				return nil, fmt.Errorf("simplified policy %d: %w", idx, err)
			}
		}

		rule, err := normalizeRule(policy)
		if err != nil {
			return nil, fmt.Errorf("simplified policy %d: %w", idx, err)
		}

		roleKeys := roles
		if len(roleKeys) == 0 {
			roleKeys = []string{"ALL"}
		}

		for _, role := range roleKeys {
			appendRLSRule(rls, rt, op, role, rule)
		}
	}

	refIndex := buildRefIndex(rls)

	result := map[string]any{
		"ols": ols,
		"rls": rls,
	}

	if len(refIndex) > 0 {
		result["refIndex"] = map[string]any{
			"subjectRefsByResourceTypeOperation": refIndex,
		}
	}

	if len(globalAccessByRole) > 0 {
		result["globalAccessRoles"] = map[string]any{
			"byRole": globalAccessByRole,
		}
	}

	return result, nil
}

func mergeGlobalAccessRole(byRole map[string]any, role, rt, op string, isWildcardRT, isWildcardOP bool) {
	entry := ensureObject(byRole, role)
	switch {
	case isWildcardRT && isWildcardOP:
		entry["all"] = true
	case isWildcardRT:
		ops := ensureObject(entry, "operations")
		ops[op] = true
	default:
		rts := ensureObject(entry, "resourceTypes")
		rts[rt] = true
	}
}

func decodePolicies(input []byte) ([]Policy, error) {
	raw := strings.TrimSpace(string(input))
	if raw == "" {
		return nil, fmt.Errorf("invalid json")
	}

	if strings.HasPrefix(raw, "[") {
		var policies []Policy
		if err := json.Unmarshal(input, &policies); err != nil {
			return nil, fmt.Errorf("invalid simplified policies json")
		}
		return policies, nil
	}

	var wrapper struct {
		Policies           []Policy `json:"policies"`
		SimplifiedPolicies []Policy `json:"simplifiedPolicies"`
	}
	if err := json.Unmarshal(input, &wrapper); err != nil {
		return nil, fmt.Errorf("invalid simplified policies json")
	}

	if len(wrapper.SimplifiedPolicies) > 0 {
		return wrapper.SimplifiedPolicies, nil
	}
	if len(wrapper.Policies) > 0 {
		return wrapper.Policies, nil
	}

	return nil, fmt.Errorf("simplified policies payload must be a non-empty array or object with policies[]")
}

func normalizeRoles(rawRoles []any) ([]string, error) {
	if rawRoles == nil {
		return nil, fmt.Errorf("roles is required")
	}

	roleSet := map[string]struct{}{}
	for _, rawRole := range rawRoles {
		role := normalizeKey(fmt.Sprintf("%v", rawRole))
		if role == "" {
			continue
		}
		roleSet[role] = struct{}{}
	}

	roles := make([]string, 0, len(roleSet))
	for role := range roleSet {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles, nil
}

func mergeOLSRule(ols map[string]any, resourceType, operation string, roles []string) error {
	rtObj := ensureObject(ols, resourceType)
	existing := normalizeStringSlice(rtObj[operation])

	if len(existing) == 0 {
		rtObj[operation] = roles
		return nil
	}

	roleSet := map[string]struct{}{}
	for _, role := range existing {
		roleSet[role] = struct{}{}
	}
	for _, role := range roles {
		roleSet[role] = struct{}{}
	}

	merged := make([]string, 0, len(roleSet))
	for role := range roleSet {
		merged = append(merged, role)
	}
	sort.Strings(merged)
	rtObj[operation] = merged
	return nil
}

func appendRLSRule(rls map[string]any, resourceType, operation, role string, rule map[string]any) {
	rtObj := ensureObject(rls, resourceType)
	opObj := ensureObject(rtObj, operation)
	items := normalizeRuleSlice(opObj[role])
	opObj[role] = append(items, cloneRule(rule))
}

func normalizeRule(policy Policy) (map[string]any, error) {
	hasCondition, normalizedCondition, err := normalizeCondition(policy.Condition)
	if err != nil {
		return nil, err
	}

	hasRSQL := strings.TrimSpace(policy.RSQLPredicate) != ""
	hasSQL := strings.TrimSpace(policy.SQLPredicate) != ""
	hasMongoDB := strings.TrimSpace(policy.MongoDBPredicate) != ""
	hasQueryDSL := strings.TrimSpace(policy.QueryDSLPredicate) != ""
	hasAnyPredicate := hasRSQL || hasSQL || hasMongoDB || hasQueryDSL

	rule := map[string]any{}

	switch {
	case !hasCondition && !hasAnyPredicate:
		rule["condition"] = true
		rule["predicates"] = []map[string]any{{"predicate": "true", "type": "rsql"}}
	case !hasCondition && hasAnyPredicate:
		rule["condition"] = true
	case hasCondition:
		switch value := normalizedCondition.(type) {
		case bool:
			rule["condition"] = value
		case map[string]any:
			rule["conditionAst"] = value
		default:
			return nil, fmt.Errorf("unsupported normalized condition type %T", normalizedCondition)
		}
	}

	if hasAnyPredicate {
		var predicates []map[string]any
		if hasRSQL {
			predObj := map[string]any{
				"predicate": policy.RSQLPredicate,
				"type":      "rsql",
			}
			keys := extractPlaceholderKeys(policy.RSQLPredicate)
			if len(keys) > 0 {
				predObj["placeholderKeys"] = keys
			}
			predicates = append(predicates, predObj)
		}
		if hasQueryDSL {
			predObj := map[string]any{
				"predicate": policy.QueryDSLPredicate,
				"type":      "querydsl",
			}
			keys := extractPlaceholderKeys(policy.QueryDSLPredicate)
			if len(keys) > 0 {
				predObj["placeholderKeys"] = keys
			}
			predicates = append(predicates, predObj)
		}
		if hasMongoDB {
			predObj := map[string]any{
				"predicate": policy.MongoDBPredicate,
				"type":      "mongodb",
			}
			keys := extractPlaceholderKeys(policy.MongoDBPredicate)
			if len(keys) > 0 {
				predObj["placeholderKeys"] = keys
			}
			predicates = append(predicates, predObj)
		}
		if hasSQL {
			predObj := map[string]any{
				"predicate": policy.SQLPredicate,
				"type":      "sql",
			}
			keys := extractPlaceholderKeys(policy.SQLPredicate)
			if len(keys) > 0 {
				predObj["placeholderKeys"] = keys
			}
			predicates = append(predicates, predObj)
		}
		rule["predicates"] = predicates
	}

	return rule, nil
}

func extractPlaceholderKeys(predicate string) []string {
	matches := subjectRefRegex.FindAllStringSubmatch(predicate, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	for _, match := range matches {
		if len(match) >= 2 && match[1] != "" {
			seen[match[1]] = struct{}{}
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func normalizeCondition(raw any) (bool, any, error) {
	switch value := raw.(type) {
	case nil:
		return false, nil, nil
	case bool:
		return true, value, nil
	case string:
		text := strings.TrimSpace(value)
		if text == "" {
			return false, nil, nil
		}
		switch strings.ToLower(text) {
		case "true":
			return true, true, nil
		case "false":
			return true, false, nil
		}
		ast, err := ParseCondition(text)
		if err != nil {
			return false, nil, err
		}
		return true, ast, nil
	default:
		return false, nil, fmt.Errorf("condition must be a string or boolean")
	}
}

func normalizeKey(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func ensureObject(parent map[string]any, key string) map[string]any {
	if existing, ok := parent[key].(map[string]any); ok {
		return existing
	}
	created := map[string]any{}
	parent[key] = created
	return created
}

func normalizeStringSlice(value any) []string {
	rawItems, ok := value.([]string)
	if ok {
		return append([]string{}, rawItems...)
	}

	items, ok := value.([]any)
	if !ok {
		return nil
	}

	out := make([]string, 0, len(items))
	for _, item := range items {
		text := normalizeKey(fmt.Sprintf("%v", item))
		if text == "" {
			continue
		}
		out = append(out, text)
	}
	sort.Strings(out)
	return out
}

func normalizeRuleSlice(value any) []map[string]any {
	items, ok := value.([]map[string]any)
	if ok {
		cloned := make([]map[string]any, 0, len(items))
		for _, item := range items {
			cloned = append(cloned, cloneRule(item))
		}
		return cloned
	}

	rawItems, ok := value.([]any)
	if !ok {
		return nil
	}

	out := make([]map[string]any, 0, len(rawItems))
	for _, rawItem := range rawItems {
		item, ok := rawItem.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, cloneRule(item))
	}
	return out
}

func cloneRule(rule map[string]any) map[string]any {
	content, _ := json.Marshal(rule)
	cloned := map[string]any{}
	_ = json.Unmarshal(content, &cloned)
	return cloned
}

var subjectRefRegex = regexp.MustCompile(`\$\{subject\.([^}]+)\}`)

// buildRefIndex scans normalized RLS data for subject.* references in predicates
// and conditionAst nodes, producing a resourceType -> operation -> [attr] index
// so the Rego deny-reason path can skip runtime regex/walk discovery.
func buildRefIndex(rls map[string]any) map[string]any {
	index := map[string]any{}
	for rt, rtValue := range rls {
		rtObj, ok := rtValue.(map[string]any)
		if !ok {
			continue
		}
		for op, opValue := range rtObj {
			opObj, ok := opValue.(map[string]any)
			if !ok {
				continue
			}
			refs := collectSubjectRefs(opObj)
			if len(refs) > 0 {
				rtIdx := ensureObject(index, rt)
				sort.Strings(refs)
				rtIdx[op] = refs
			}
		}
	}
	return index
}

func collectSubjectRefs(opObj map[string]any) []string {
	seen := map[string]struct{}{}
	for _, roleValue := range opObj {
		rules, ok := roleValue.([]map[string]any)
		if !ok {
			rawRules, ok := roleValue.([]any)
			if !ok {
				continue
			}
			for _, rawRule := range rawRules {
				rule, ok := rawRule.(map[string]any)
				if !ok {
					continue
				}
				scanRuleForSubjectRefs(rule, seen)
			}
			continue
		}
		for _, rule := range rules {
			scanRuleForSubjectRefs(rule, seen)
		}
	}
	refs := make([]string, 0, len(seen))
	for ref := range seen {
		refs = append(refs, ref)
	}
	return refs
}

func scanRuleForSubjectRefs(rule map[string]any, seen map[string]struct{}) {
	if ast, ok := rule["conditionAst"]; ok {
		scanASTNodeForSubjectRefs(ast, seen)
	}
	if predicates, ok := rule["predicates"]; ok {
		rawPreds, ok := predicates.([]any)
		if ok {
			for _, pVal := range rawPreds {
				pred, ok := pVal.(map[string]any)
				if !ok {
					continue
				}
				predStr := fmt.Sprintf("%v", pred["predicate"])
				scanPredicateStringForSubjectRefs(predStr, seen)
			}
		}
		typedPreds, ok := predicates.([]map[string]any)
		if ok {
			for _, pred := range typedPreds {
				predStr := fmt.Sprintf("%v", pred["predicate"])
				scanPredicateStringForSubjectRefs(predStr, seen)
			}
		}
	}
}

func scanASTNodeForSubjectRefs(node any, seen map[string]struct{}) {
	obj, ok := node.(map[string]any)
	if !ok {
		return
	}
	if ref, ok := obj["ref"].(map[string]any); ok {
		scope := fmt.Sprintf("%v", ref["scope"])
		if strings.EqualFold(scope, "subject") {
			if path, ok := ref["path"].([]any); ok && len(path) > 0 {
				attr := fmt.Sprintf("%v", path[0])
				if attr != "" {
					seen[attr] = struct{}{}
				}
			}
		}
	}
	if args, ok := obj["args"].([]any); ok {
		for _, arg := range args {
			scanASTNodeForSubjectRefs(arg, seen)
		}
	}
}

func scanPredicateStringForSubjectRefs(predicate string, seen map[string]struct{}) {
	matches := subjectRefRegex.FindAllStringSubmatch(predicate, -1)
	for _, match := range matches {
		if len(match) >= 2 && match[1] != "" {
			seen[match[1]] = struct{}{}
		}
	}
}

func toNumber(text string) (any, bool) {
	if strings.Contains(text, ".") {
		value, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return nil, false
		}
		return value, true
	}

	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return nil, false
	}
	return value, true
}
