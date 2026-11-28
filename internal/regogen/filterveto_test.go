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

package regogen

import (
	"fmt"
	"testing"

	"authz-agent/internal/policyir"
)

// filterOfRead answers check/filter for a read of doc over the policy sets
// sets of tenant t1 by a subject in role R, whose GENERAL PIPs subject.g and subject.h resolve to
// values.
func filterOfRead(t *testing.T, sets string, values map[string]Resolved) FilterAnswer {
	t.Helper()
	exp, err := policyir.FromRegular([]byte(`{"policySets": [`+sets+`]}`), []byte(`{"pips": [
		{"tenantId": "t1", "name": "subject.g", "pipType": "GENERAL", "url": "http://g"},
		{"tenantId": "t1", "name": "subject.h", "pipType": "GENERAL", "url": "http://h"}]}`))
	if err != nil {
		t.Fatalf("FromRegular: %v", err)
	}
	tree, ok := exp.Trees["t1"]
	if !ok {
		t.Fatalf("FromRegular: no tree of t1; failed %v, dropped %v", exp.Failed, exp.Dropped)
	}
	m, err := GenerateFilter(tree, table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("GenerateFilter: %v", err)
	}
	req := Request{Body: Body{Operation: "read", ResourceType: "doc"}, Values: values, Roles: []string{"R"}}
	return evalFilter(t, m, prepareFilter(t, m), req)
}

// A leaf the filter cannot read row by row, such as subject allowed over a
// decision that read a failed source, is unknown on every row where the
// check reads it as unknown, so it neither drops the veto of a failed
// comparison beside it nor lets its rule keep the predicate.
func TestALeafUnknownOnEveryRowKeepsTheFilterWithinTheCheck(t *testing.T) {
	const (
		allowAll = `{"policySetId": "s1", "status": "ACTIVE", "target": "resourceType == 'doc'",
			"combiningAlgorithm": "PERMIT_UNLESS_DENY", "tenantId": "t1", "policies": [{"policyId": "p1",
			"target": "true", "combiningAlgorithm": "PERMIT_OVERRIDES", "tenantId": "t1",
			"rules": [{"ruleId": "r1", "target": "true", "effect": "ALLOW", "tenantId": "t1"}]}]}`
		// the write decision denies the resource whole where subject.g failed
		writeOverG = `{"policySetId": "s3", "status": "ACTIVE", "target": "resourceType == 'doc'",
			"combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "t1", "policies": [{"policyId": "p3",
			"target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "t1",
			"rules": [{"ruleId": "r5", "target": "operation == 'write'", "condition": "subject.g == 'x'",
			"effect": "DENY", "tenantId": "t1"}]}]}`
		readRule = `{"policySetId": "s2", "status": "ACTIVE", "target": "resourceType == 'doc'",
			"combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "t1", "policies": [{"policyId": "p2",
			"target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "t1",
			"rules": [{"ruleId": "r4", "target": "%s", "condition": "%s", "effect": "%s", "tenantId": "t1"}]}]}`
		writeAllowedUnlessG = `{"policySetId": "w", "status": "ACTIVE", "target": "resourceType == 'doc'",
			"combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1", "policies": [{"policyId": "p",
			"target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1",
			"rules": [{"ruleId": "w1", "target": "operation == 'write'", "effect": "ALLOW", "tenantId": "t1"},
			{"ruleId": "w2", "target": "operation == 'write'", "condition": "subject.g == 'x'", "effect": "ALLOW",
			"tenantId": "t1"}]}]}`
		readIfWritable = `{"policySetId": "r", "status": "ACTIVE", "target": "resourceType == 'doc'",
			"combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1", "policies": [{"policyId": "p",
			"target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1",
			"rules": [{"ruleId": "r1", "target": "operation == 'read'",
			"condition": "%s", "effect": "ALLOW", "tenantId": "t1", "rsqlPredicate": "b==\"z\""}]}]}`
		// a DENY rule with a predicate beside an ALLOW rule over every row
		readBeside = `{"policySetId": "r", "status": "ACTIVE", "target": "resourceType == 'doc'",
			"combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "t1", "policies": [{"policyId": "p",
			"target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "t1",
			"rules": [{"ruleId": "r0", "target": "operation == 'read'", "effect": "ALLOW", "tenantId": "t1"},
			{"ruleId": "r1", "target": "%s", "condition": "%s", "effect": "DENY", "tenantId": "t1",
			"rsqlPredicate": "b==\"z\""}]}]}`
		simplifiedIfWritable = `{"policySetId": "r", "status": "ACTIVE", "type": "SIMPLIFIED",
			"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1",
			"policies": [{"policyId": "q", "target": "operation == 'read'", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"tenantId": "t1", "rules": [{"ruleId": "r", "target": "subject.roles CONTAINS ANY 'R'",
			"condition": "%s", "effect": "ALLOW", "tenantId": "t1",
			"rsqlPredicate": "a==\"y\""}]}]}`
	)
	readRuleOf := func(target, condition, effect string) string {
		return fmt.Sprintf(readRule, target, condition, effect)
	}
	failed := map[string]Resolved{`["subj","g"]`: resolved(t, "ERROR", ""), `["subj","h"]`: resolved(t, "ERROR", "")}
	answered := map[string]Resolved{`["subj","g"]`: resolved(t, "VALUE", `"x"`),
		`["subj","h"]`: resolved(t, "VALUE", `"x"`)}
	tests := []struct {
		name   string
		sets   string
		values map[string]Resolved
		want   string
		// bound says why the filter answers DENY where the check allows
		// some rows
		bound string
	}{
		{"an ALLOW rule over subject allowed beside a failed comparison, sources failed",
			allowAll + "," + writeOverG + "," + readRuleOf("operation == 'read'",
				"subject allowed 'write' on resource AND resource.a == subject.h", "ALLOW"), failed, FilterDeny, ""},
		{"a failed rule of another operation, sources failed", allowAll + "," + writeOverG, failed, FilterAllow, ""},
		{"an ALLOW rule over subject allowed beside a failed comparison, sources answered",
			allowAll + "," + writeOverG + "," + readRuleOf("operation == 'read'",
				"subject allowed 'write' on resource AND resource.a == subject.h", "ALLOW"), answered, FilterAllow, ""},
		{"the failed comparison before subject allowed, sources failed",
			allowAll + "," + writeOverG + "," + readRuleOf("operation == 'read'",
				"resource.a == subject.h AND subject allowed 'write' on resource", "ALLOW"), failed, FilterDeny, ""},
		{"a DENY rule over subject allowed beside a failed comparison, sources failed",
			allowAll + "," + writeOverG + "," + readRuleOf("operation == 'read'",
				"subject allowed 'write' on resource AND resource.a == subject.h", "DENY"), failed, FilterDeny, ""},
		{"subject allowed over a decision that reads the same rule, sources failed",
			allowAll + "," + readRuleOf("true", "subject allowed 'write' on resource AND resource.a == subject.h",
				"ALLOW"), failed, FilterDeny, ""},
		{"subject allowed over a decision that reads the same rule, sources answered",
			allowAll + "," + readRuleOf("true", "subject allowed 'write' on resource AND resource.a == subject.h",
				"ALLOW"), answered, FilterAllow, ""},
		{"a predicate under subject allowed over a failed decision, sources failed",
			writeAllowedUnlessG + "," + fmt.Sprintf(readIfWritable, "subject allowed 'write' on resource"), failed, FilterDeny, ""},
		{"a predicate under subject allowed over a failed decision, sources answered",
			writeAllowedUnlessG + "," + fmt.Sprintf(readIfWritable, "subject allowed 'write' on resource"), answered, FilterCondition, ""},
		{"a simplified predicate under subject allowed over a failed decision, sources failed",
			writeAllowedUnlessG + "," + fmt.Sprintf(simplifiedIfWritable, "subject allowed 'write' on resource"), failed, FilterDeny, ""},
		{"a simplified predicate under subject allowed over a failed decision, sources answered",
			writeAllowedUnlessG + "," + fmt.Sprintf(simplifiedIfWritable, "subject allowed 'write' on resource"), answered, FilterCondition, ""},
		{"a simplified predicate under subject allowed OR a leaf over the resource, sources failed",
			writeAllowedUnlessG + "," + fmt.Sprintf(simplifiedIfWritable, "subject allowed 'write' on resource OR resource.b == 'z'"),
			failed, FilterDeny, "; the check allows the rows with a = 'y' and b = 'z', which the filter does not write apart from the condition"},
		{"a simplified predicate under subject allowed OR a leaf over the resource, sources answered",
			writeAllowedUnlessG + "," + fmt.Sprintf(simplifiedIfWritable, "subject allowed 'write' on resource OR resource.b == 'z'"),
			answered, FilterCondition, ""},
		{"a predicate under subject allowed OR a leaf over the resource, sources failed",
			writeAllowedUnlessG + "," + fmt.Sprintf(readIfWritable,
				"subject allowed 'write' on resource OR resource.a == 'y'"), failed, FilterDeny,
			"; the check allows the rows with a = 'y', which the filter does not write apart from the predicate"},
		{"a predicate under subject allowed OR a leaf over the resource, sources answered",
			writeAllowedUnlessG + "," + fmt.Sprintf(readIfWritable,
				"subject allowed 'write' on resource OR resource.a == 'y'"), answered, FilterCondition, ""},
		{"a DENY predicate under subject allowed AND a leaf over the resource, sources failed",
			writeAllowedUnlessG + "," + fmt.Sprintf(readBeside, "operation == 'read'", "subject allowed 'write' on resource AND resource.a == 'y'"),
			failed, FilterDeny, "; the check allows the rows with a other than 'y', which the filter does not write apart from the predicate"},
		{"a DENY predicate under subject allowed and a target over the resource, sources failed",
			writeAllowedUnlessG + "," + fmt.Sprintf(readBeside, "resource.c == 'q'", "subject allowed 'write' on resource"),
			failed, FilterDeny, "; the check allows the rows with c other than 'q', which the filter does not write apart from the predicate"},
		{"a DENY predicate under subject allowed AND a leaf over the resource, sources answered",
			writeAllowedUnlessG + "," + fmt.Sprintf(readBeside, "operation == 'read'", "subject allowed 'write' on resource AND resource.a == 'y'"),
			answered, FilterCondition, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := filterOfRead(t, tt.sets, tt.values); got.Result != tt.want {
				t.Errorf("check/filter(read) = %s %v, want %s%s", got.Result, got.Text, tt.want, tt.bound)
			}
		})
	}
}
