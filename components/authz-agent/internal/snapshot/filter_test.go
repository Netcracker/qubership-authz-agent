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

package snapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// denySet is a DENY_OVERRIDES set of tenant t on the resource type doc: one
// rule allows every operation without a predicate, and one denies the
// operation read where the predicate holds. predicate is the predicate
// fields of the DENY rule, such as "mongodbPredicate": "…".
func denySet(id, predicate string) string {
	return fmt.Sprintf(`{"policySetId": %q, "name": "s", "status": "ACTIVE", "tenantId": "t",
		"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_OVERRIDES",
		"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "t",
			"rules": [{"ruleId": "allow", "target": "true", "effect": "ALLOW", "tenantId": "t"},
				{"ruleId": "deny", "target": "operation == 'read'", "effect": "DENY", "tenantId": "t", %s}]}]}`,
		id, predicate)
}

// filter loads sets into a registry of tenant t, with the first
// approximation of the algebra where first is set, and returns the answer to
// a filter of doc for the operation op, as the service writes it.
func filter(t *testing.T, first bool, op string, sets ...string) string {
	t.Helper()
	r := New(Config{FilterFirstApproximation: first}, tab(t), quiet{})
	load(t, r, "", sets...)
	return filterOf(t, r, "t", op)
}

// filterOf is the answer of r to a filter of doc in tenant for the
// operation op, as the service writes it.
func filterOf(t *testing.T, r *Registry, tenant, op string) string {
	t.Helper()
	a, err := r.Filter(context.Background(), FilterRequest{Tenant: tenant, ResourceType: "doc", Operation: &op})
	if err != nil {
		t.Fatalf("Filter(doc, %s): %v", op, err)
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// condition is the answer USE_FILTER_CONDITION with text in the field of
// one dialect and null in the others.
func condition(field, text string) string {
	fields := map[string]string{"filterCondition": "null", "mongodbFilterCondition": "null",
		"rsqlFilterCondition": "null", "sqlFilterCondition": "null"}
	quoted, _ := json.Marshal(text)
	fields[field] = string(quoted)
	return fmt.Sprintf(`{"calculationResult":"USE_FILTER_CONDITION","filterCondition":%s,"mongodbFilterCondition":%s,`+
		`"rsqlFilterCondition":%s,"sqlFilterCondition":%s,"customFilterCondition":null}`,
		fields["filterCondition"], fields["mongodbFilterCondition"], fields["rsqlFilterCondition"],
		fields["sqlFilterCondition"])
}

const allow = `{"calculationResult":"ALLOW","filterCondition":null,"mongodbFilterCondition":null,` +
	`"rsqlFilterCondition":null,"sqlFilterCondition":null,"customFilterCondition":null}`

const deny = `{"calculationResult":"DENY","filterCondition":null,"mongodbFilterCondition":null,` +
	`"rsqlFilterCondition":null,"sqlFilterCondition":null,"customFilterCondition":null}`

// A DENY rule with a predicate leaves the rows where the predicate does not
// hold: its negation, in the dialect of the predicate. The pairs legacy
// negates correctly stay as legacy writes them; $gt and <= get their true
// opposites; a MongoDB field matched by a bare value has no opposite
// operator and is wrapped in $nor.
func TestADenyPredicateIsNegatedInItsDialect(t *testing.T) {
	for _, tc := range []struct {
		name, predicate, field, want string
	}{
		{"mongodb $lt becomes $gte", `"mongodbPredicate": "{\"a\": {\"$lt\": 5}}"`,
			"mongodbFilterCondition", `{{"a": {"$gte": 5}}}`},
		{"mongodb $in becomes $nin", `"mongodbPredicate": "{\"a\": {\"$in\": [1, 2]}}"`,
			"mongodbFilterCondition", `{{"a": {"$nin": [1, 2]}}}`},
		{"mongodb $eq becomes $ne", `"mongodbPredicate": "{\"a\": {\"$eq\": 1}}"`,
			"mongodbFilterCondition", `{{"a": {"$ne": 1}}}`},
		{"mongodb $gt becomes $lte", `"mongodbPredicate": "{\"a\": {\"$gt\": 5}}"`,
			"mongodbFilterCondition", `{{"a": {"$lte": 5}}}`},
		{"a mongodb bare value is wrapped in $nor", `"mongodbPredicate": "{\"a\": 5}"`,
			"mongodbFilterCondition", `{ "$nor": [ {{"a": 5}} ] }`},
		{"rsql =in= becomes =out=", `"rsqlPredicate": "a=in=(1,2)"`, "rsqlFilterCondition", `a=out=(1,2)`},
		{"rsql < becomes >=", `"rsqlPredicate": "a<5"`, "rsqlFilterCondition", `a>=5`},
		{"rsql <= becomes >", `"rsqlPredicate": "a<=5"`, "rsqlFilterCondition", `a>5`},
		{"rsql =gt= becomes =le=", `"rsqlPredicate": "a=gt=5"`, "rsqlFilterCondition", `a=le=5`},
		{"an rsql OR becomes an AND of the opposites", `"rsqlPredicate": "a==1,b==2"`,
			"rsqlFilterCondition", `a!=1;b!=2`},
		{"sql is wrapped in NOT", `"sqlPredicate": "a = 1"`, "sqlFilterCondition", `NOT (a = 1)`},
		{"querydsl is wrapped in not()", `"predicate": "doc.a.eq(1)"`, "filterCondition", `(doc.a.eq(1)).not()`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, want := filter(t, false, "read", denySet("s", tc.predicate)), condition(tc.field, tc.want); got != want {
				t.Errorf("Filter(doc, read) = %s, want %s", got, want)
			}
		})
	}
}

// The DENY rule names the operation read alone, so a filter of write meets
// the ALLOW rule only and allows every row: the negation of the predicate
// comes from the DENY rule and not from the set around it.
func TestAnOperationTheDenyRuleDoesNotNameIsAllowed(t *testing.T) {
	if got := filter(t, false, "write", denySet("s", `"mongodbPredicate": "{\"a\": {\"$lt\": 5}}"`)); got != allow {
		t.Errorf("Filter(doc, write) = %s, want %s", got, allow)
	}
}

// The first approximation of the algebra writes no negation: a DENY
// predicate subtracted from the rows leaves none.
func TestTheFirstApproximationDeniesWhereADenyPredicateIsSubtracted(t *testing.T) {
	if got := filter(t, true, "read", denySet("s", `"rsqlPredicate": "a<5"`)); got != deny {
		t.Errorf("Filter(doc, read) with the first approximation = %s, want %s", got, deny)
	}
}

// Two DENY predicates of one set are both subtracted, so the rows are where
// neither holds: in MongoDB the negations join by $and (LI-5).
func TestTheDenyPredicatesOfOneSetJoinByAnd(t *testing.T) {
	set := `{"policySetId": "s", "name": "s", "status": "ACTIVE", "tenantId": "t",
		"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_OVERRIDES",
		"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "t",
			"rules": [{"ruleId": "allow", "target": "true", "effect": "ALLOW", "tenantId": "t"},
				{"ruleId": "d1", "target": "true", "effect": "DENY", "tenantId": "t",
					"mongodbPredicate": "{\"a\": {\"$lt\": 5}}"},
				{"ruleId": "d2", "target": "true", "effect": "DENY", "tenantId": "t",
					"mongodbPredicate": "{\"b\": {\"$in\": [1]}}"}]}]}`
	want := condition("mongodbFilterCondition", `{ "$and": [ {{"a": {"$gte": 5}}}, {{"b": {"$nin": [1]}}} ] }`)
	if got := filter(t, false, "read", set); got != want {
		t.Errorf("Filter(doc, read) = %s, want %s", got, want)
	}
}

// Two top-level sets each allow the rows outside their own DENY predicate,
// and the filter returns the rows either allows: where the two predicates
// do not both hold, each set's rows in their own parentheses.
func TestTheRowsOfTwoSetsWithDenyPredicatesAreTheirUnion(t *testing.T) {
	got := filter(t, false, "read", denySet("s1", `"rsqlPredicate": "a==1"`), denySet("s2", `"rsqlPredicate": "b==2"`))
	if want := condition("rsqlFilterCondition", `(a!=1),(b!=2)`); got != want {
		t.Errorf("Filter(doc, read) = %s, want %s", got, want)
	}
}

// pairSet is a set of tenant t on doc whose set and policy both combine by
// alg: one rule allows read where allowPredicate holds, and one denies read
// where denyPredicate holds. Each predicate is rule fields, such as
// "rsqlPredicate": "…".
func pairSet(id, alg, allowPredicate, denyPredicate string) string {
	return fmt.Sprintf(`{"policySetId": %q, "name": "s", "status": "ACTIVE", "tenantId": "t",
		"target": "resourceType == 'doc'", "combiningAlgorithm": %q,
		"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": %q, "tenantId": "t",
			"rules": [{"ruleId": "allow", "target": "operation == 'read'", "effect": "ALLOW", "tenantId": "t", %s},
				{"ruleId": "deny", "target": "operation == 'read'", "effect": "DENY", "tenantId": "t", %s}]}]}`,
		id, alg, alg, allowPredicate, denyPredicate)
}

// Each algorithm combines the rows the ALLOW rule allows, a==1, with the
// rows the DENY rule denies, b==2. Only DENY_OVERRIDES subtracts the DENY
// rows from the ALLOW rows; PERMIT_UNLESS_DENY allows every row outside the
// DENY rows, whatever the ALLOW rule says.
func TestEachAlgorithmCombinesTheAllowAndDenyRows(t *testing.T) {
	for _, tc := range []struct{ alg, want string }{
		{"DENY_OVERRIDES", `(a==1);b!=2`},
		{"PERMIT_OVERRIDES", `a==1`},
		{"DENY_UNLESS_PERMIT", `a==1`},
		{"PERMIT_UNLESS_DENY", `b!=2`},
	} {
		t.Run(tc.alg, func(t *testing.T) {
			set := pairSet("s", tc.alg, `"rsqlPredicate": "a==1"`, `"rsqlPredicate": "b==2"`)
			if got, want := filter(t, false, "read", set), condition("rsqlFilterCondition", tc.want); got != want {
				t.Errorf("Filter(doc, read) = %s, want %s", got, want)
			}
		})
	}
}

// An ALLOW rule whose target reads the resource is left out of the filter,
// predicate and all, as the target of a rule over the resource drops the
// rule in the specification. Its predicate used to be the answer, and the
// filter returned rows whose target was false, which the check denies. The
// same rule with a target true for every row is the control that the
// predicate is the answer.
func TestAnAllowRuleWhoseTargetReadsTheResourceIsLeftOut(t *testing.T) {
	for _, tc := range []struct{ target, want string }{
		{"resource.secret == 0", deny},
		{"true", condition("rsqlFilterCondition", "a==1")},
	} {
		t.Run(tc.target, func(t *testing.T) {
			r := New(Config{}, tab(t), quiet{})
			load(t, r, ``, fmt.Sprintf(`{"policySetId": "s", "name": "s", "status": "ACTIVE", "tenantId": "a",
				"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_OVERRIDES",
				"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "a",
					"rules": [{"ruleId": "allow", "target": %q, "effect": "ALLOW", "tenantId": "a",
						"rsqlPredicate": "a==1"}]}]}`, tc.target))
			if got := filterOf(t, r, "a", "read"); got != tc.want {
				t.Errorf("Filter(doc, read) = %s, want %s", got, tc.want)
			}
		})
	}
}

// The negation of a DENY predicate that is an AND is an OR, which RSQL
// puts in parentheses inside the AND with the ALLOW rows, since ; binds
// tighter than ,. It used to be written bare, and (a==1);a!=2,c!=2 selected
// rows with a==2 and c!=2, which the check denies. The negation of an OR
// is an AND and needs none.
func TestAnRSQLNegationThatIsAnOrIsParenthesized(t *testing.T) {
	for _, tc := range []struct{ deny, want string }{
		{"a==2;c==2", `(a==1);(a!=2,c!=2)`},
		{"a==2,c==2", `(a==1);a!=2;c!=2`},
	} {
		t.Run(tc.deny, func(t *testing.T) {
			set := pairSet("s", "DENY_OVERRIDES", `"rsqlPredicate": "a==1"`, `"rsqlPredicate": "`+tc.deny+`"`)
			if got, want := filter(t, false, "read", set), condition("rsqlFilterCondition", tc.want); got != want {
				t.Errorf("Filter(doc, read) = %s, want %s", got, want)
			}
		})
	}
}

// A dialect the DENY predicate does not write cannot subtract its rows, so
// that dialect gets no condition rather than the ALLOW predicate alone, which
// would return rows the check denies.
func TestADialectWithoutTheDenyPredicateGetsNoCondition(t *testing.T) {
	set := pairSet("s", "DENY_OVERRIDES", `"rsqlPredicate": "a==1", "mongodbPredicate": "{\"a\": {\"$eq\": 1}}"`,
		`"rsqlPredicate": "b==2"`)
	if got, want := filter(t, false, "read", set), condition("rsqlFilterCondition", `(a==1);b!=2`); got != want {
		t.Errorf("Filter(doc, read) = %s, want %s", got, want)
	}
}

// =like= has no opposite in RSQL, so the DENY rows cannot be subtracted in
// any dialect, and the filter denies rather than drop the subtraction.
func TestADenyPredicateWithoutANegationDenies(t *testing.T) {
	if got := filter(t, false, "read", denySet("s", `"rsqlPredicate": "a=like=x*"`)); got != deny {
		t.Errorf("Filter(doc, read) = %s, want %s", got, deny)
	}
}

// A filter that names no operation filters read; the operation ALL is never
// filtered.
func TestTheOperationOfAFilter(t *testing.T) {
	set := pairSet("s", "DENY_OVERRIDES", `"rsqlPredicate": "a==1"`, `"rsqlPredicate": "b==2"`)
	for _, tc := range []struct{ op, want string }{
		{"", condition("rsqlFilterCondition", `(a==1);b!=2`)},
		{"ALL", deny},
	} {
		t.Run(fmt.Sprintf("%q", tc.op), func(t *testing.T) {
			if got := filter(t, false, tc.op, set); got != tc.want {
				t.Errorf("Filter(doc, %q) = %s, want %s", tc.op, got, tc.want)
			}
		})
	}
}

// Two top-level sets each allow the rows of their own ALLOW predicate, and
// each dialect writes the union in its own form.
func TestEachDialectJoinsTheRowsOfTwoSets(t *testing.T) {
	allow := func(id, predicate string) string {
		return fmt.Sprintf(`{"policySetId": %q, "name": "s", "status": "ACTIVE", "tenantId": "t",
			"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_OVERRIDES",
			"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "t",
				"rules": [{"ruleId": "allow", "target": "true", "effect": "ALLOW", "tenantId": "t", %s}]}]}`, id, predicate)
	}
	for _, tc := range []struct{ name, p1, p2, field, want string }{
		{"mongodb", `"mongodbPredicate": "{\"a\": 1}"`, `"mongodbPredicate": "{\"b\": 2}"`,
			"mongodbFilterCondition", `{ "$or": [ {{"a": 1}},{{"b": 2}} ] }`},
		{"sql", `"sqlPredicate": "a = 1"`, `"sqlPredicate": "b = 2"`, "sqlFilterCondition", `(a = 1) or (b = 2)`},
		{"querydsl", `"predicate": "doc.a.eq(1)"`, `"predicate": "doc.b.eq(2)"`, "filterCondition",
			`(doc.a.eq(1)).or(doc.b.eq(2))`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := filter(t, false, "read", allow("s1", tc.p1), allow("s2", tc.p2))
			if want := condition(tc.field, tc.want); got != want {
				t.Errorf("Filter(doc, read) = %s, want %s", got, want)
			}
		})
	}
}

// A DENY customPredicate is subtracted as a NOT over its path, with its
// predicate and parameters under data.
func TestACustomDenyPredicateIsNegated(t *testing.T) {
	got := filter(t, false, "read", denySet("s", `"customPredicate": {"predicate": "owner", "params": {"x": 1}}`))
	if want := `"customFilterCondition":{"logic":{"op":"NOT"`; !strings.Contains(got, want) ||
		!strings.Contains(got, `"predicate":"owner"`) {
		t.Errorf("Filter(doc, read) = %s, want a customFilterCondition with %s and the predicate owner", got, want)
	}
}

// policySetBeside is a DENY_OVERRIDES set of tenant a on doc with two
// policies: one allows every row, and one under policyTarget holds a rule of
// effect under ruleTarget with condition.
func policySetBeside(policyTarget, ruleTarget, condition, effect string) string {
	return fmt.Sprintf(`{"policySetId": "s", "name": "s", "status": "ACTIVE", "tenantId": "a",
		"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_OVERRIDES",
		"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "a",
			"rules": [{"ruleId": "allow", "target": "true", "effect": "ALLOW", "tenantId": "a"}]},
			{"policyId": "q", "target": %q, "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "a",
			"rules": [{"ruleId": "r", "target": %q, "condition": %q, "effect": %q, "tenantId": "a"}]}]}`,
		policyTarget, ruleTarget, condition, effect)
}

// A DENY rule under a target the filter cannot evaluate denies, as the check
// does: under a policy target that reads the resource it denies rows the
// filter cannot name, and under a policy or a rule target that reads a PIP
// whose call failed it denies every row. An ALLOW rule under such a target
// does not apply, as in the check, and the policy beside it allows; so does a
// DENY rule whose condition is false. Each such node used to be left out,
// and later to deny whatever it held. A DENY policy whose target is false
// for the operation is the control that the ALLOW policy allows.
func TestATargetTheFilterCannotEvaluateDeniesWhereItsNodeDenies(t *testing.T) {
	srv, _ := pipServer(t, http.StatusInternalServerError, `oops`)
	for _, tc := range []struct {
		name, policyTarget, ruleTarget, condition, effect, want string
	}{
		{"a policy target over the resource and a DENY rule", "resource.secret == 1", "true", "true", "DENY", deny},
		{"a policy target over a failed PIP and a DENY rule", "subject.g == 'blocked'", "true", "true", "DENY", deny},
		{"a rule target over a failed PIP and a DENY rule", "true", "subject.g == 'blocked'", "true", "DENY", deny},
		{"a policy target over a failed PIP and an ALLOW rule", "subject.g == 'blocked'", "true", "true", "ALLOW", allow},
		{"a rule target over a failed PIP and an ALLOW rule", "true", "subject.g == 'blocked'", "true", "ALLOW", allow},
		{"a policy target over the resource and a DENY rule whose condition is false", "resource.secret == 1", "true",
			"operation == 'write'", "DENY", allow},
		{"a rule target over a failed PIP and a DENY rule whose condition is false", "true", "subject.g == 'blocked'",
			"operation == 'write'", "DENY", allow},
		{"a policy target false for the operation", "operation == 'write'", "true", "true", "DENY", allow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := pipRegistry(t)
			load(t, r, generalPIP(srv.URL, ""), policySetBeside(tc.policyTarget, tc.ruleTarget, tc.condition, tc.effect))
			if got := filterOf(t, r, "a", "read"); got != tc.want {
				t.Errorf("Filter(doc, read) = %s, want %s", got, tc.want)
			}
		})
	}
}

// A policy whose target reads the resource denies rows the filter cannot
// name only where it denies some row once its target holds. One that denies
// none does not apply, and the policy beside it allows. A policy of ALLOW
// rules alone used to deny too, and the filter answered DENY where the check
// allows every row. DENY_UNLESS_PERMIT denies where its ALLOW rule does not
// apply, and a DENY rule whose target is false denies nothing. A target over
// a selection that can stop as too large, which the check may leave
// undefined on a row, follows the same rule.
func TestAPolicyOverTheResourceThatDeniesNoRowDoesNotApply(t *testing.T) {
	for _, tc := range []struct{ setAlg, target, alg, effect, ruleTarget, want string }{
		{"DENY_OVERRIDES", "resource.secret == 1", "PERMIT_OVERRIDES", "ALLOW", "true", allow},
		{"DENY_OVERRIDES", "resource.secret == 1", "DENY_OVERRIDES", "DENY", "true", deny},
		{"DENY_OVERRIDES", "resource.secret == 1", "DENY_UNLESS_PERMIT", "ALLOW", "true", allow},
		{"DENY_OVERRIDES", "resource.secret == 1", "DENY_UNLESS_PERMIT", "ALLOW", "operation == 'read'", allow},
		{"DENY_OVERRIDES", "resource.secret == 1", "DENY_UNLESS_PERMIT", "ALLOW", "operation == 'write'", deny},
		{"PERMIT_UNLESS_DENY", "resource.secret == 1", "PERMIT_OVERRIDES", "ALLOW", "true", allow},
		{"PERMIT_UNLESS_DENY", "resource.secret == 1", "DENY_OVERRIDES", "DENY", "true", deny},
		{"DENY_OVERRIDES", "resource.secret == 1", "DENY_OVERRIDES", "DENY", "operation == 'write'", allow},
		{"DENY_OVERRIDES", "resource.items[*].id == 1", "PERMIT_OVERRIDES", "ALLOW", "true", allow},
		{"DENY_OVERRIDES", "resource.items[*].id == 1", "DENY_OVERRIDES", "DENY", "true", deny},
	} {
		t.Run(tc.setAlg+" "+tc.target+" "+tc.alg+" "+tc.effect+" "+tc.ruleTarget, func(t *testing.T) {
			r := New(Config{}, tab(t), quiet{})
			load(t, r, ``, fmt.Sprintf(`{"policySetId": "s", "name": "s", "status": "ACTIVE", "tenantId": "a",
				"target": "resourceType == 'doc'", "combiningAlgorithm": %q,
				"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "a",
					"rules": [{"ruleId": "allow", "target": "true", "effect": "ALLOW", "tenantId": "a"}]},
					{"policyId": "q", "target": %q, "combiningAlgorithm": %q, "tenantId": "a",
					"rules": [{"ruleId": "r", "target": %q, "effect": %q, "tenantId": "a"}]}]}`,
				tc.setAlg, tc.target, tc.alg, tc.ruleTarget, tc.effect))
			if got := filterOf(t, r, "a", "read"); got != tc.want {
				t.Errorf("Filter(doc, read) = %s, want %s", got, tc.want)
			}
		})
	}
}

// A rule whose target the check may leave undefined on a row, such as a
// path with a trailing dot, denies in the filter only when it is a DENY
// rule, as in the check, and an ALLOW rule over such a target does not
// apply: the policy beside it allows. A target over a path of keys is the
// control.
func TestARuleTargetTheCheckMayLeaveUndefinedDeniesOnlyForADenyRule(t *testing.T) {
	for _, tc := range []struct{ policyTarget, ruleTarget, effect, want string }{
		{"true", "resource.a. == 1", "ALLOW", allow},
		{"resource.secret == 1", "resource.a. == 1", "ALLOW", allow},
		{"true", "resource.a. == 1", "DENY", deny},
		{"true", "resource.a == 1", "ALLOW", allow},
		{"resource.secret == 1", "resource.a == 1", "ALLOW", allow},
	} {
		t.Run(tc.policyTarget+" "+tc.ruleTarget+" "+tc.effect, func(t *testing.T) {
			r := New(Config{}, tab(t), quiet{})
			load(t, r, ``, fmt.Sprintf(`{"policySetId": "s", "name": "s", "status": "ACTIVE", "tenantId": "a",
				"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_OVERRIDES",
				"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "a",
					"rules": [{"ruleId": "allow", "target": "true", "effect": "ALLOW", "tenantId": "a"}]},
					{"policyId": "q", "target": %q, "combiningAlgorithm": "PERMIT_OVERRIDES", "tenantId": "a",
					"rules": [{"ruleId": "r", "target": %q, "effect": %q, "tenantId": "a"}]}]}`,
				tc.policyTarget, tc.ruleTarget, tc.effect))
			if got := filterOf(t, r, "a", "read"); got != tc.want {
				t.Errorf("Filter(doc, read) = %s, want %s", got, tc.want)
			}
		})
	}
}

// A policy whose target reads the resource and whose DENY rule reads a PIP
// whose call failed denies the rows the filter cannot name, not the whole
// request: under PERMIT_OVERRIDES the policy beside it still allows, as in
// the check. Under DENY_OVERRIDES the unknown denied rows empty the rows the
// other policy allows.
func TestAFailedSourceBelowATargetOverTheResourceDeniesOnlyItsRows(t *testing.T) {
	srv, _ := pipServer(t, http.StatusInternalServerError, `oops`)
	for _, tc := range []struct{ setAlg, want string }{
		{"PERMIT_OVERRIDES", allow},
		{"DENY_OVERRIDES", deny},
	} {
		t.Run(tc.setAlg, func(t *testing.T) {
			r := pipRegistry(t)
			load(t, r, generalPIP(srv.URL, ""), fmt.Sprintf(`{"policySetId": "s", "name": "s", "status": "ACTIVE",
				"tenantId": "a", "target": "resourceType == 'doc'", "combiningAlgorithm": %q,
				"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "a",
					"rules": [{"ruleId": "allow", "target": "true", "effect": "ALLOW", "tenantId": "a"}]},
					{"policyId": "q", "target": "resource.secret == 1", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "a",
					"rules": [{"ruleId": "deny", "target": "true", "condition": "subject.g == 'blocked'", "effect": "DENY",
					"tenantId": "a"}]}]}`, tc.setAlg))
			if got := filterOf(t, r, "a", "read"); got != tc.want {
				t.Errorf("Filter(doc, read) = %s, want %s", got, tc.want)
			}
		})
	}
}

// A policy of ALLOW rules under a target the filter cannot evaluate does not
// apply, so the set's algorithm decides as over no child: PERMIT_UNLESS_DENY
// allows every row, as legacy does, and DENY_UNLESS_PERMIT denies.
func TestAnAllowPolicyUnderAnUnknownTargetLeavesTheSetToItsAlgorithm(t *testing.T) {
	srv, _ := pipServer(t, http.StatusInternalServerError, `oops`)
	for _, tc := range []struct{ setAlg, policyTarget, ruleTarget, want string }{
		{"PERMIT_UNLESS_DENY", "subject.g == 'x'", "true", allow},
		{"PERMIT_UNLESS_DENY", "true", "subject.g == 'x'", allow},
		{"PERMIT_UNLESS_DENY", "resource.secret == 1", "true", allow},
		{"DENY_UNLESS_PERMIT", "subject.g == 'x'", "true", deny},
		{"DENY_UNLESS_PERMIT", "true", "subject.g == 'x'", deny},
		{"DENY_UNLESS_PERMIT", "resource.secret == 1", "true", deny},
	} {
		t.Run(tc.setAlg+" "+tc.policyTarget+" "+tc.ruleTarget, func(t *testing.T) {
			r := pipRegistry(t)
			load(t, r, generalPIP(srv.URL, ""), loneAllowPolicySet(tc.setAlg, tc.policyTarget, tc.ruleTarget))
			if got := filterOf(t, r, "a", "read"); got != tc.want {
				t.Errorf("Filter(doc, read) = %s, want %s", got, tc.want)
			}
		})
	}
}

// A policy of ALLOW rules whose target reads the entitlements service, which
// fails, does not apply, and PERMIT_UNLESS_DENY allows every row, as legacy
// does; DENY_UNLESS_PERMIT denies.
func TestAnAllowPolicyUnderAFailedEntitlementsReadLeavesTheSetToItsAlgorithm(t *testing.T) {
	for _, tc := range []struct{ setAlg, policyTarget, ruleTarget, want string }{
		{"PERMIT_UNLESS_DENY", entitled, "true", allow},
		{"PERMIT_UNLESS_DENY", "true", entitled, allow},
		{"DENY_UNLESS_PERMIT", entitled, "true", deny},
	} {
		t.Run(tc.setAlg+" "+tc.policyTarget+" "+tc.ruleTarget, func(t *testing.T) {
			r := failedEntitlementsRegistry(t)
			load(t, r, ``, loneAllowPolicySet(tc.setAlg, tc.policyTarget, tc.ruleTarget))
			if got := filterOf(t, r, "a", "read"); got != tc.want {
				t.Errorf("Filter(doc, read) = %s, want %s", got, tc.want)
			}
		})
	}
}

// A DENY rule with a predicate under a target the filter cannot evaluate
// keeps its predicate, so the filter subtracts the rows it names from those
// the ALLOW rule beside it allows, rather than denying every row.
func TestADenyRuleWithAPredicateUnderAnUnknownTargetKeepsItsPredicate(t *testing.T) {
	got := filter(t, false, "read", `{"policySetId": "s", "name": "s", "status": "ACTIVE", "tenantId": "t",
		"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_OVERRIDES",
		"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "t",
			"rules": [{"ruleId": "allow", "target": "true", "effect": "ALLOW", "tenantId": "t"},
				{"ruleId": "deny", "target": "resource.a. == 1", "effect": "DENY", "tenantId": "t",
					"sqlPredicate": "b = 2"}]}]}`)
	if want := condition("sqlFilterCondition", `NOT (b = 2)`); got != want {
		t.Errorf("Filter(doc, read) = %s, want %s", got, want)
	}
}

// A rule target over a PIP that the answer of the PIP leaves undefined, such
// as a list with a null element, makes a DENY rule deny every row, in the
// check and in the filter, and leaves an ALLOW rule out, so the policy beside
// it allows. An ALLOW rule whose target compares the resource and a PIP
// answering ["x"] does not apply either.
func TestARuleTargetOverAPIPTheCheckMayLeaveUndefinedDeniesOnlyForADenyRule(t *testing.T) {
	for _, tc := range []struct{ answer, ruleTarget, effect, want string }{
		{`[null]`, "subject.g == 'x'", "ALLOW", allow},
		{`[null]`, "subject.g == 'x'", "DENY", deny},
		{`["x"]`, "resource.a == '1' AND subject.g == 'x'", "ALLOW", allow},
	} {
		t.Run(tc.answer+" "+tc.ruleTarget+" "+tc.effect, func(t *testing.T) {
			srv, _ := pipServer(t, http.StatusOK, tc.answer)
			r := pipRegistry(t)
			load(t, r, generalPIP(srv.URL, ""), fmt.Sprintf(`{"policySetId": "s", "name": "s", "status": "ACTIVE",
				"tenantId": "a", "target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_OVERRIDES",
				"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "a",
					"rules": [{"ruleId": "allow", "target": "true", "effect": "ALLOW", "tenantId": "a"}]},
					{"policyId": "q", "target": "true", "combiningAlgorithm": "PERMIT_OVERRIDES", "tenantId": "a",
					"rules": [{"ruleId": "r", "target": %q, "effect": %q, "tenantId": "a"}]}]}`, tc.ruleTarget, tc.effect))
			if got := filterOf(t, r, "a", "read"); got != tc.want {
				t.Errorf("Filter(doc, read) = %s, want %s", got, tc.want)
			}
		})
	}
}

// A set inside a set follows the same rule as a policy: under a target over
// the resource it does not apply where it denies no row once its target
// holds, and denies rows the filter cannot name where it does.
func TestANestedSetOverTheResourceThatDeniesNoRowDoesNotApply(t *testing.T) {
	for _, tc := range []struct{ effect, want string }{
		{"ALLOW", allow},
		{"DENY", deny},
	} {
		t.Run(tc.effect, func(t *testing.T) {
			r := New(Config{}, tab(t), quiet{})
			load(t, r, ``, fmt.Sprintf(`{"policySetId": "s", "name": "s", "status": "ACTIVE", "tenantId": "a",
				"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_OVERRIDES",
				"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "a",
					"rules": [{"ruleId": "allow", "target": "true", "effect": "ALLOW", "tenantId": "a"}]}],
				"policySets": [{"policySetId": "t", "name": "t", "status": "ACTIVE", "tenantId": "a",
					"target": "resource.secret == 1", "combiningAlgorithm": "PERMIT_OVERRIDES",
					"policies": [{"policyId": "q", "target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "a",
						"rules": [{"ruleId": "r", "target": "true", "effect": %q, "tenantId": "a"}]}]}]}`, tc.effect))
			if got := filterOf(t, r, "a", "read"); got != tc.want {
				t.Errorf("Filter(doc, read) = %s, want %s", got, tc.want)
			}
		})
	}
}
