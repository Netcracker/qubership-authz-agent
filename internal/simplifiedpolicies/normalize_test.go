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
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNormalizePolicyLanguageConditions(t *testing.T) {
	t.Parallel()

	cases := loadPolicyLanguageCases(t)
	for name, fixture := range cases {
		simplified := fixture.SimplifiedPolicy
		if simplified.Condition == nil {
			continue
		}
		if conditionText, ok := simplified.Condition.(string); ok && fixture.Expression != "" && conditionText != fixture.Expression {
			continue
		}

		normalized, err := normalizeRule(simplified)
		if err != nil {
			t.Fatalf("%s: normalizeRule failed: %v", name, err)
		}

		if fixture.Condition != nil {
			actual, ok := normalized["condition"].(bool)
			if !ok {
				t.Fatalf("%s: expected boolean condition, got %#v", name, normalized)
			}
			if actual != *fixture.Condition {
				t.Fatalf("%s: expected condition %v, got %v", name, *fixture.Condition, actual)
			}
			continue
		}

		actual, ok := normalized["conditionAst"].(map[string]any)
		if !ok {
			t.Fatalf("%s: expected conditionAst, got %#v", name, normalized)
		}

		if !jsonEqual(actual, fixture.ConditionAST) {
			t.Fatalf("%s: ast mismatch\nexpected: %#v\nactual: %#v", name, fixture.ConditionAST, actual)
		}
	}
}

func TestNormalizeSimplifiedPoliciesBuildsRoleScopedData(t *testing.T) {
	t.Parallel()

	policies := []Policy{
		{
			Component:     "TEST",
			ResourceType:  "Order",
			Operation:     "READ",
			Roles:         []any{"role_admin", "ROLE_ADMIN"},
			RSQLPredicate: "true",
		},
		{
			Component:     "TEST",
			ResourceType:  "Order",
			Operation:     "READ",
			Roles:         []any{"ROLE_USER"},
			Condition:     "resource.ownerId == subject.id",
			RSQLPredicate: "ownerId==${subject.id}",
		},
	}

	normalized, err := NormalizePolicies(policies)
	if err != nil {
		t.Fatalf("NormalizePolicies failed: %v", err)
	}

	ols := normalized["ols"].(map[string]any)
	roles := ols["ORDER"].(map[string]any)["READ"].([]string)
	if len(roles) != 2 || roles[0] != "ROLE_ADMIN" || roles[1] != "ROLE_USER" {
		t.Fatalf("unexpected ols roles: %#v", roles)
	}

	rls := normalized["rls"].(map[string]any)
	orderRead := rls["ORDER"].(map[string]any)["READ"].(map[string]any)
	if _, ok := orderRead["ROLE_ADMIN"]; !ok {
		t.Fatalf("expected ROLE_ADMIN rule")
	}
	if _, ok := orderRead["ROLE_USER"]; !ok {
		t.Fatalf("expected ROLE_USER rule")
	}
}

func TestNormalizeSimplifiedPoliciesSkipsOLSForEmptyRoles(t *testing.T) {
	t.Parallel()

	normalized, err := NormalizePolicies([]Policy{{
		Component:     "TEST",
		ResourceType:  "Public_Doc",
		Operation:     "READ",
		Roles:         []any{},
		RSQLPredicate: "subjectId==${subject.id}",
	}})
	if err != nil {
		t.Fatalf("NormalizePolicies failed: %v", err)
	}

	ols := normalized["ols"].(map[string]any)
	if _, ok := ols["PUBLIC_DOC"]; ok {
		t.Fatalf("expected PUBLIC_DOC to be absent from OLS when roles are empty, got %#v", ols)
	}

	rls := normalized["rls"].(map[string]any)
	publicDocRules := rls["PUBLIC_DOC"].(map[string]any)["READ"].(map[string]any)
	if _, ok := publicDocRules["ALL"]; !ok {
		t.Fatalf("expected RLS ALL rule for empty-roles policy, got %#v", publicDocRules)
	}
}

type policyLanguageSuite struct {
	Cases map[string]policyLanguageCase `json:"cases"`
}

type policyLanguageCase struct {
	Expression       string         `json:"expression"`
	ConditionAST     map[string]any `json:"conditionAst"`
	Condition        *bool          `json:"condition"`
	SimplifiedPolicy Policy         `json:"simplifiedPolicy"`
}

func loadPolicyLanguageCases(t *testing.T) map[string]policyLanguageCase {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("failed to resolve caller")
	}

	fixturePath := filepath.Join(filepath.Dir(currentFile), "..", "..", "policies", "fixtures", "policy_language", "cases.json")
	content, err := os.ReadFile(filepath.Clean(fixturePath))
	if err != nil {
		t.Fatalf("failed to read fixture file: %v", err)
	}

	var suite policyLanguageSuite
	if err := json.Unmarshal(content, &suite); err != nil {
		t.Fatalf("failed to unmarshal fixture suite: %v", err)
	}
	return suite.Cases
}

func jsonEqual(left, right any) bool {
	leftBytes, _ := json.Marshal(left)
	rightBytes, _ := json.Marshal(right)
	return string(leftBytes) == string(rightBytes)
}

func TestNormalizeWildcardAllAllWritesToGlobalAccessRoles(t *testing.T) {
	t.Parallel()

	normalized, err := NormalizePolicies([]Policy{{
		Component:    "ALL",
		ResourceType: "ALL",
		Operation:    "ALL",
		Roles:        []any{"ROLE_ADMINISTRATOR"},
	}})
	if err != nil {
		t.Fatalf("NormalizePolicies failed: %v", err)
	}

	gar, ok := normalized["globalAccessRoles"].(map[string]any)
	if !ok {
		t.Fatalf("expected globalAccessRoles, got %#v", normalized)
	}
	byRole := gar["byRole"].(map[string]any)
	entry := byRole["ROLE_ADMINISTRATOR"].(map[string]any)
	if entry["all"] != true {
		t.Fatalf("expected all=true for ROLE_ADMINISTRATOR, got %#v", entry)
	}

	ols := normalized["ols"].(map[string]any)
	if _, ok := ols["ALL"]; ok {
		t.Fatalf("expected ALL absent from OLS, got %#v", ols)
	}

	rls := normalized["rls"].(map[string]any)
	if _, ok := rls["ALL"]; ok {
		t.Fatalf("expected ALL absent from RLS, got %#v", rls)
	}
}

func TestNormalizeWildcardAllOperationWritesToGlobalAccessRoles(t *testing.T) {
	t.Parallel()

	normalized, err := NormalizePolicies([]Policy{{
		Component:    "TEST",
		ResourceType: "ALL",
		Operation:    "READ",
		Roles:        []any{"ROLE_READ_ANY"},
	}})
	if err != nil {
		t.Fatalf("NormalizePolicies failed: %v", err)
	}

	gar := normalized["globalAccessRoles"].(map[string]any)
	byRole := gar["byRole"].(map[string]any)
	entry := byRole["ROLE_READ_ANY"].(map[string]any)
	ops := entry["operations"].(map[string]any)
	if ops["READ"] != true {
		t.Fatalf("expected operations.READ=true, got %#v", entry)
	}
	if _, ok := entry["all"]; ok {
		t.Fatalf("expected no all key, got %#v", entry)
	}

	ols := normalized["ols"].(map[string]any)
	if _, ok := ols["ALL"]; ok {
		t.Fatalf("expected ALL absent from OLS, got %#v", ols)
	}
}

func TestNormalizeWildcardResourceTypeAllWritesToGlobalAccessRoles(t *testing.T) {
	t.Parallel()

	normalized, err := NormalizePolicies([]Policy{{
		Component:    "TEST",
		ResourceType: "Order",
		Operation:    "ALL",
		Roles:        []any{"ROLE_ORDER_ANY"},
	}})
	if err != nil {
		t.Fatalf("NormalizePolicies failed: %v", err)
	}

	gar := normalized["globalAccessRoles"].(map[string]any)
	byRole := gar["byRole"].(map[string]any)
	entry := byRole["ROLE_ORDER_ANY"].(map[string]any)
	rts := entry["resourceTypes"].(map[string]any)
	if rts["ORDER"] != true {
		t.Fatalf("expected resourceTypes.ORDER=true, got %#v", entry)
	}
	if _, ok := entry["all"]; ok {
		t.Fatalf("expected no all key, got %#v", entry)
	}

	ols := normalized["ols"].(map[string]any)
	if _, ok := ols["ORDER"]; ok {
		t.Fatalf("expected ORDER absent from OLS for wildcard op, got %#v", ols)
	}
}

func TestNormalizeWildcardEmptyMapOmission(t *testing.T) {
	t.Parallel()

	normalized, err := NormalizePolicies([]Policy{
		{
			Component:    "TEST",
			ResourceType: "Order",
			Operation:    "READ",
			Roles:        []any{"ROLE_USER"},
		},
	})
	if err != nil {
		t.Fatalf("NormalizePolicies failed: %v", err)
	}

	if _, ok := normalized["globalAccessRoles"]; ok {
		t.Fatalf("expected globalAccessRoles to be absent when no wildcard policies, got %#v", normalized["globalAccessRoles"])
	}
}

func TestNormalizeWildcardMixedPolicies(t *testing.T) {
	t.Parallel()

	normalized, err := NormalizePolicies([]Policy{
		{
			Component:    "ALL",
			ResourceType: "ALL",
			Operation:    "ALL",
			Roles:        []any{"ROLE_ADMIN"},
		},
		{
			Component:     "TEST",
			ResourceType:  "Order",
			Operation:     "READ",
			Roles:         []any{"ROLE_USER"},
			RSQLPredicate: "ownerId==${subject.id}",
		},
	})
	if err != nil {
		t.Fatalf("NormalizePolicies failed: %v", err)
	}

	gar := normalized["globalAccessRoles"].(map[string]any)
	byRole := gar["byRole"].(map[string]any)
	if byRole["ROLE_ADMIN"].(map[string]any)["all"] != true {
		t.Fatalf("expected ROLE_ADMIN.all=true")
	}
	if _, ok := byRole["ROLE_USER"]; ok {
		t.Fatalf("expected ROLE_USER absent from globalAccessRoles")
	}

	ols := normalized["ols"].(map[string]any)
	if _, ok := ols["ALL"]; ok {
		t.Fatalf("expected ALL absent from OLS")
	}
	orderOps := ols["ORDER"].(map[string]any)
	roles := orderOps["READ"].([]string)
	if len(roles) != 1 || roles[0] != "ROLE_USER" {
		t.Fatalf("expected exact OLS for ORDER/READ with ROLE_USER, got %#v", roles)
	}

	rls := normalized["rls"].(map[string]any)
	if _, ok := rls["ALL"]; ok {
		t.Fatalf("expected ALL absent from RLS")
	}
	if _, ok := rls["ORDER"]; !ok {
		t.Fatalf("expected exact RLS for ORDER")
	}
}

func TestNormalizeWildcardMultipleRolesDedup(t *testing.T) {
	t.Parallel()

	normalized, err := NormalizePolicies([]Policy{
		{
			Component:    "ALL",
			ResourceType: "ALL",
			Operation:    "ALL",
			Roles:        []any{"role_admin", " ROLE_ADMIN "},
		},
	})
	if err != nil {
		t.Fatalf("NormalizePolicies failed: %v", err)
	}

	gar := normalized["globalAccessRoles"].(map[string]any)
	byRole := gar["byRole"].(map[string]any)
	if len(byRole) != 1 {
		t.Fatalf("expected 1 role after dedup, got %d: %#v", len(byRole), byRole)
	}
	if byRole["ROLE_ADMIN"].(map[string]any)["all"] != true {
		t.Fatalf("expected ROLE_ADMIN.all=true")
	}
}

func TestNormalizeWildcardEmptyRolesNotInGlobalAccess(t *testing.T) {
	t.Parallel()

	normalized, err := NormalizePolicies([]Policy{{
		Component:    "ALL",
		ResourceType: "ALL",
		Operation:    "ALL",
		Roles:        []any{},
	}})
	if err != nil {
		t.Fatalf("NormalizePolicies failed: %v", err)
	}

	if _, ok := normalized["globalAccessRoles"]; ok {
		t.Fatalf("expected globalAccessRoles absent for empty-roles policy")
	}

	rls := normalized["rls"].(map[string]any)
	if _, ok := rls["ALL"]; !ok {
		t.Fatalf("expected RLS ALL entry for empty-roles wildcard policy")
	}
}

func TestBuildRefIndexWildcardAllAll(t *testing.T) {
	t.Parallel()

	// Empty roles → goes to rls with role="ALL", rt="ALL", op="ALL"
	normalized, err := NormalizePolicies([]Policy{{
		Component:     "ALL",
		ResourceType:  "ALL",
		Operation:     "ALL",
		Roles:         []any{},
		RSQLPredicate: "attr==${subject.someAttr}",
	}})
	if err != nil {
		t.Fatalf("NormalizePolicies failed: %v", err)
	}

	refIndexRaw, ok := normalized["refIndex"]
	if !ok {
		t.Fatalf("expected refIndex to be present, got %#v", normalized)
	}
	refIndex := refIndexRaw.(map[string]any)
	byRtOp := refIndex["subjectRefsByResourceTypeOperation"].(map[string]any)
	allRt := byRtOp["ALL"].(map[string]any)
	allOp := allRt["ALL"].([]string)
	if len(allOp) != 1 || allOp[0] != "someAttr" {
		t.Fatalf("expected refIndex ALL/ALL = [someAttr], got %#v", allOp)
	}

	// Verify placeholderKeys in the predicate object
	rls := normalized["rls"].(map[string]any)
	allRules := rls["ALL"].(map[string]any)["ALL"].(map[string]any)["ALL"].([]map[string]any)
	preds := allRules[0]["predicates"].([]any)
	pred0 := preds[0].(map[string]any)
	keys := pred0["placeholderKeys"].([]any)
	if len(keys) != 1 || fmt.Sprintf("%v", keys[0]) != "someAttr" {
		t.Fatalf("expected placeholderKeys=[someAttr], got %#v", keys)
	}
}

func TestBuildRefIndexWildcardAllOperation(t *testing.T) {
	t.Parallel()

	normalized, err := NormalizePolicies([]Policy{{
		Component:     "TEST",
		ResourceType:  "ALL",
		Operation:     "READ",
		Roles:         []any{},
		RSQLPredicate: "ownerId==${subject.email}",
	}})
	if err != nil {
		t.Fatalf("NormalizePolicies failed: %v", err)
	}

	refIndex := normalized["refIndex"].(map[string]any)
	byRtOp := refIndex["subjectRefsByResourceTypeOperation"].(map[string]any)
	allRt := byRtOp["ALL"].(map[string]any)
	readOp := allRt["READ"].([]string)
	if len(readOp) != 1 || readOp[0] != "email" {
		t.Fatalf("expected refIndex ALL/READ = [email], got %#v", readOp)
	}
}

func TestBuildRefIndexWildcardResourceTypeAll(t *testing.T) {
	t.Parallel()

	normalized, err := NormalizePolicies([]Policy{{
		Component:     "TEST",
		ResourceType:  "Order",
		Operation:     "ALL",
		Roles:         []any{},
		RSQLPredicate: "regionId==${subject.region}",
	}})
	if err != nil {
		t.Fatalf("NormalizePolicies failed: %v", err)
	}

	refIndex := normalized["refIndex"].(map[string]any)
	byRtOp := refIndex["subjectRefsByResourceTypeOperation"].(map[string]any)
	orderRt := byRtOp["ORDER"].(map[string]any)
	allOp := orderRt["ALL"].([]string)
	if len(allOp) != 1 || allOp[0] != "region" {
		t.Fatalf("expected refIndex ORDER/ALL = [region], got %#v", allOp)
	}
}
