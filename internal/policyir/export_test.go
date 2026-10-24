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

package policyir

import (
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
)

// fromRegular reads an export of the given policy sets and PIPs, each a JSON
// array, and fails the test when the documents are refused.
func fromRegular(t *testing.T, sets, pips string) *Export {
	t.Helper()
	e, err := FromRegular([]byte(`{"policySets": `+sets+`}`), []byte(`{"pips": `+pips+`}`))
	if err != nil {
		t.Fatalf("FromRegular: %v", err)
	}
	return e
}

// tree returns the tree of tenant, and fails the test when there is none.
func tree(t *testing.T, e *Export, tenant string) *Tree {
	t.Helper()
	tr, ok := e.Trees[tenant]
	if !ok {
		t.Fatalf("no tree of tenant %q; trees %v, failed %v, orphans %v",
			tenant, slices.Sorted(maps.Keys(e.Trees)), e.Failed, e.Orphans)
	}
	return tr
}

// The export documents in testdata are the ones the legacy service serves for
// two tenants. The expected dumps were checked against those documents: a
// SIMPLIFIED set of two policies, regular sets with a DENY rule, iterate, a
// nested set, every predicate dialect and a customPredicate, and every PIP
// type.
func TestFromRegularReadsTheExportOfTwoTenants(t *testing.T) {
	t.Parallel()

	sets, err := os.ReadFile("testdata/export-policy-sets.json")
	if err != nil {
		t.Fatal(err)
	}
	pips, err := os.ReadFile("testdata/export-pips.json")
	if err != nil {
		t.Fatal(err)
	}
	e, err := FromRegular(sets, pips)
	if err != nil {
		t.Fatalf("FromRegular: %v", err)
	}
	if len(e.Failed) != 0 || len(e.Orphans) != 0 {
		t.Errorf("FromRegular: failed %v, orphans %v, want none", e.Failed, e.Orphans)
	}
	for _, tenant := range []string{"default", "parity-mt-b"} {
		want, err := os.ReadFile("testdata/export-" + tenant + ".dump")
		if err != nil {
			t.Fatal(err)
		}
		if got := tree(t, e, tenant).Dump(); got != string(want) {
			t.Errorf("Dump() of tenant %q =\n%s\nwant\n%s", tenant, got, want)
		}
	}
	if got := slices.Sorted(maps.Keys(e.Trees)); !slices.Equal(got, []string{"default", "parity-mt-b"}) {
		t.Errorf("tenants = %v, want [default parity-mt-b]", got)
	}
}

// A set the API for regular policy sets stores comes as type DEFAULT, with no
// type, or with a type the agent does not know; each is read with its DENY
// rules.
func TestFromRegularReadsRegularSetsWithDenyRules(t *testing.T) {
	t.Parallel()

	e := fromRegular(t, `[
		{"type": "DEFAULT", "tenantId": "t", "policySetId": "s1", "status": "ACTIVE",
		 "combiningAlgorithm": "DENY_OVERRIDES", "target": "resourceType == 'R'",
		 "policies": [{"policyId": "p1", "target": "subject.roles CONTAINS 'A'",
		  "rules": [{"ruleId": "r1", "effect": "DENY", "condition": "true", "target": "operation == 'DELETE'"}]}]},
		{"tenantId": "t", "policySetId": "s2", "combiningAlgorithm": "PERMIT_UNLESS_DENY",
		 "policies": [{"policyId": "p2", "rules": [{"ruleId": "r2", "effect": "DENY"}]}]},
		{"type": "OTHER", "tenantId": "t", "policySetId": "s3"}]`, `[]`)

	want := `set "s1" name="" domain="" algorithm=DENY_OVERRIDES
  target[set_target]: resourceType EQ "R"
  policy "p1" name="" algorithm=absent
    target[policy_target]: subject.roles CONTAINS "A"
    rule "r1" name="" effect=DENY
      target[rule_target]: operation EQ "DELETE"
      condition[rule_condition]: TRUE
set "s2" name="" domain="" algorithm=PERMIT_UNLESS_DENY
  policy "p2" name="" algorithm=absent
    rule "r2" name="" effect=DENY
set "s3" name="" domain="" algorithm=absent
`
	if got := tree(t, e, "t").Dump(); got != want {
		t.Errorf("Dump() =\n%s\nwant\n%s", got, want)
	}
}

// simplifiedSet is a set in the shape the PAP writes for the simplified
// policies of one resource type, with policies the JSON of its policies.
func simplifiedSet(tenant, resourceType, policies string) string {
	return simplifiedSetWithTarget(tenant, "resourceType == '"+resourceType+"'", policies)
}

// simplifiedSetWithTarget is [simplifiedSet] with the set target target.
func simplifiedSetWithTarget(tenant, target, policies string) string {
	return `{"type": "SIMPLIFIED", "tenantId": "` + tenant + `", "domain": "D", "component": "C",
		"status": "ACTIVE", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "policySetId": "s",
		"target": "` + target + `", "policySets": [], "policies": ` + policies + `}`
}

// A simplified policy of operation ALL keeps its condition and its predicates,
// and so does one of resource type ALL.
func TestFromRegularKeepsTheConditionOfOperationAll(t *testing.T) {
	t.Parallel()

	e := fromRegular(t, `[`+simplifiedSet("t", "ALL", `[{"combiningAlgorithm": "DENY_UNLESS_PERMIT", "target": "true",
		"rules": [{"ruleId": "r1", "effect": "ALLOW", "condition": "resource.a == 'y'", "rsqlPredicate": "all==1",
		 "querydslPredicate": "q", "ruleType": "APPLICABLE_FOR_FRONTEND",
		 "target": "subject.roles CONTAINS ANY 'ROLE_A','ROLE_B'"}]}]`)+`]`, `[]`)

	want := `simplified domain="D" component="C" resourceType="ALL"
  policy "r1" operation="ALL" roles=["ROLE_A", "ROLE_B"] frontend
    condition[simplified]: resource.a EQ "y"
    predicate rsql "all==1"
    predicate querydsl "q"
`
	if got := tree(t, e, "t").Dump(); got != want {
		t.Errorf("Dump() =\n%s\nwant\n%s", got, want)
	}
}

// Only a SIMPLIFIED set in the exact shape the PAP writes is read back as
// simplified policies; a set uploaded through the API for regular sets and
// marked SIMPLIFIED is evaluated as the set it is.
func TestFromRegularReadsASimplifiedSetOfAnotherShapeAsARegularSet(t *testing.T) {
	t.Parallel()

	const readPolicy = `[{"combiningAlgorithm": "DENY_UNLESS_PERMIT", "target": "operation == 'READ'",
		"rules": [{"effect": "ALLOW", "target": "subject.roles CONTAINS ANY 'A'"}]}]`
	cases := []struct {
		name      string
		setTarget string
		policies  string
	}{
		{"a set target spelled with EQUALS", "resourceType EQUALS 'R'", readPolicy},
		{"a policy target of operation ALL", "", `[{"combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"target": "operation == 'ALL'", "rules": [{"effect": "ALLOW", "target": "subject.roles CONTAINS ANY 'A'"}]}]`},
		{"a policy target spelled with EQUALS", "", `[{"combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"target": "operation EQUALS 'READ'", "rules": [{"effect": "ALLOW", "target": "subject.roles CONTAINS ANY 'A'"}]}]`},
		{"roles joined with a comma and a space", "", `[{"combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"target": "operation == 'READ'", "rules": [{"effect": "ALLOW", "target": "subject.roles CONTAINS ANY 'A', 'B'"}]}]`},
		{"roles in the policy target", "", `[{"combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"target": "subject.roles CONTAINS ANY 'A'", "rules": [{"effect": "ALLOW", "target": "true"}]}]`},
		{"a DENY rule", "", `[{"combiningAlgorithm": "DENY_UNLESS_PERMIT", "target": "true",
			"rules": [{"effect": "DENY", "target": "subject.roles CONTAINS ANY 'A'"}]}]`},
		{"another policy algorithm", "", `[{"combiningAlgorithm": "DENY_OVERRIDES", "target": "true",
			"rules": [{"effect": "ALLOW", "target": "subject.roles CONTAINS ANY 'A'"}]}]`},
		{"a policy target of two operations", "", `[{"combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"target": "operation == 'READ' OR operation == 'LIST'",
			"rules": [{"effect": "ALLOW", "target": "subject.roles CONTAINS ANY 'A'"}]}]`},
		{"a rule with the querydsl field of a regular rule", "", `[{"combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"target": "true", "rules": [{"effect": "ALLOW", "predicate": "q", "target": "subject.roles CONTAINS ANY 'A'"}]}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			setTarget := tc.setTarget
			if setTarget == "" {
				setTarget = "resourceType == 'R'"
			}
			tr := tree(t, fromRegular(t, `[`+simplifiedSetWithTarget("t", setTarget, tc.policies)+`]`, `[]`), "t")
			if len(tr.Simplified) != 0 || len(tr.Sets) != 1 {
				t.Errorf("simplified groups %d, sets %d, want 0 and 1; dump:\n%s", len(tr.Simplified), len(tr.Sets), tr.Dump())
			}
		})
	}
}

// Each tenant gets its own tree, keyed by the tenant ID exactly as written:
// two spellings of one name are two tenants, and a PIP name declared in both
// keeps the declaration of each.
func TestFromRegularKeepsTenantsApart(t *testing.T) {
	t.Parallel()

	tenants := []string{"parity-p50i-072", "PARITY-P50I-072", " parity-p50i-072"}
	var sets, pips []string
	for _, id := range tenants {
		sets = append(sets, simplifiedSet(id, "R_"+strings.TrimSpace(id), `[]`))
		pips = append(pips, `{"name": "subject.region", "pipType": "TOKEN", "claim": "claim of `+id+`", "tenantId": "`+id+`"}`)
	}
	e := fromRegular(t, "["+strings.Join(sets, ",")+"]", "["+strings.Join(pips, ",")+"]")

	if got := slices.Sorted(maps.Keys(e.Trees)); !slices.Equal(got, slices.Sorted(slices.Values(tenants))) {
		t.Fatalf("tenants = %q, want %q", got, tenants)
	}
	for _, id := range tenants {
		tr := e.Trees[id]
		if len(tr.Simplified) != 1 || tr.Simplified[0].ResourceType != "R_"+strings.TrimSpace(id) {
			t.Errorf("tenant %q: simplified groups %v, want only the one of resource type R_%s", id, tr.Simplified, strings.TrimSpace(id))
		}
		if p, ok := tr.PIP("subject.region"); !ok || p.Claim != "claim of "+id {
			t.Errorf("tenant %q: PIP subject.region = %+v, want the claim of that tenant", id, p)
		}
	}
}

func TestFromRegularReadsTheMappingPIP(t *testing.T) {
	t.Parallel()

	e := fromRegular(t, `[]`, `[{"name": "subject.permissions", "pipType": "MAPPING", "tenantId": "t",
		"customMapping": {"subject.roles": {"ROLE_A": ["custom"]}},
		"productMapping": {"subject.roles": {"ROLE_A": ["product"]}}}]`)

	p, ok := tree(t, e, "t").PIP("subject.permissions")
	if !ok {
		t.Fatal(`PIP("subject.permissions"): none`)
	}
	if p.Type != PIPMapping || p.CustomMapping != `{"subject.roles":{"ROLE_A":["custom"]}}` ||
		p.ProductMapping != `{"subject.roles":{"ROLE_A":["product"]}}` {
		t.Errorf("PIP = %+v, want MAPPING with both mappings", p)
	}
}

// An empty customMapping is kept as written: it does not fall back to
// productMapping.
func TestFromRegularKeepsAnEmptyCustomMapping(t *testing.T) {
	t.Parallel()

	e := fromRegular(t, `[]`, `[{"name": "subject.permissions", "pipType": "MAPPING", "tenantId": "t",
		"customMapping": {}, "productMapping": {"subject.roles": {"ROLE_A": ["product"]}}}]`)

	if p, _ := tree(t, e, "t").PIP("subject.permissions"); p == nil || p.CustomMapping != "{}" {
		t.Errorf("PIP = %+v, want customMapping {}", p)
	}
}

func TestFromRegularReadsPIPFields(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		pip  string
		want string
	}{
		{"no pipType is GENERAL", `{"name": "subject.x", "url": "http://u"}`, `pip "subject.x" type=GENERAL url="http://u"`},
		{"headers as a string", `{"name": "subject.x", "pipType": "GENERAL", "headers": "X-A, X-B"}`,
			`pip "subject.x" type=GENERAL headers="X-A, X-B"`},
		{"headers as a list", `{"name": "subject.x", "pipType": "GENERAL", "headers": ["X-A", "X-B"]}`,
			`pip "subject.x" type=GENERAL headers="X-A,X-B"`},
		{"a null field is absent", `{"name": "subject.x", "pipType": "TOKEN", "claim": "c", "defaultValue": null}`,
			`pip "subject.x" type=TOKEN claim="c"`},
		{"a number default", `{"name": "subject.x", "pipType": "TOKEN", "claim": "c", "defaultValue": 5}`,
			`pip "subject.x" type=TOKEN claim="c" defaultValue=5`},
		{"fields of the agent's extension", `{"name": "subject.x", "pipType": "GENERAL", "timeoutSeconds": 3,
			"headers": {"X-A": "v"}, "query": {"q": "1"}}`,
			`pip "subject.x" type=GENERAL unsupported="headers object, query, timeoutSeconds"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pip := strings.Replace(tc.pip, "{", `{"tenantId": "t", `, 1)
			if got := strings.TrimSuffix(tree(t, fromRegular(t, `[]`, "["+pip+"]"), "t").Dump(), "\n"); got != tc.want {
				t.Errorf("Dump() = %s, want %s", got, tc.want)
			}
		})
	}
}

// A tenant that declares one PIP name twice uses the first declaration.
func TestFromRegularKeepsTheFirstOfTwoDeclarations(t *testing.T) {
	t.Parallel()

	e := fromRegular(t, `[]`, `[
		{"name": "subject.x", "pipType": "TOKEN", "claim": "first", "domain": "D1", "tenantId": "t"},
		{"name": "subject.x", "pipType": "HEADER", "header": "second", "domain": "D2", "tenantId": "t"}]`)

	if p, _ := tree(t, e, "t").PIP("subject.x"); p == nil || p.Claim != "first" {
		t.Errorf(`PIP("subject.x") = %+v, want the TOKEN declaration of D1`, p)
	}
}

func TestFromRegularAppliesTopLevelStatuses(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		status string
		want   bool
	}{
		{"ACTIVE", `"status": "ACTIVE",`, true},
		{"absent", ``, true},
		{"empty", `"status": "",`, true},
		{"unknown", `"status": "PUBLISHED",`, true},
		{"INACTIVE", `"status": "INACTIVE",`, false},
		{"DRAFT", `"status": "DRAFT",`, false},
		{"ARCHIVED", `"status": "ARCHIVED",`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := fromRegular(t, `[{"tenantId": "t", "policySetId": "s", `+tc.status+`
				"policySets": [{"policySetId": "n", "status": "INACTIVE"}]}]`, `[]`)
			tr := tree(t, e, "t")
			if got := len(tr.Sets) == 1; got != tc.want {
				t.Fatalf("top-level set of status %q applies = %t, want %t", tc.status, got, tc.want)
			}
			if tc.want && len(tr.Sets[0].Sets) != 1 {
				t.Errorf("nested INACTIVE set dropped from a set of status %q", tc.status)
			}
		})
	}
}

// The target of an iterating set is read outside its pass, and its policies
// and nested sets inside it.
func TestFromRegularBindsThePassInsideTheIteratingSet(t *testing.T) {
	t.Parallel()

	e := fromRegular(t, `[{"tenantId": "t", "policySetId": "s", "target": "subject.permissionScope.k IS NULL",
		"iterate": {"foreach": "subject.permissionScope", "combiningAlgorithm": "PERMIT_OVERRIDES"},
		"policies": [{"policyId": "p", "target": "subject.permissionScope.k IS NULL"}],
		"policySets": [{"policySetId": "n", "target": "subject.permissionScope.k IS NULL"}]}]`, `[]`)

	want := `set "s" name="" domain="" algorithm=absent
  target[set_target]: subject.permissionScope["k"] IS_NULL
  iterate var="iterate1" algorithm=PERMIT_OVERRIDES
  policy "p" name="" algorithm=absent
    target[policy_target]: pass("iterate1")["k"] IS_NULL
  set "n" name="" domain="" algorithm=absent
    target[set_target]: pass("iterate1")["k"] IS_NULL
`
	if got := tree(t, e, "t").Dump(); got != want {
		t.Errorf("Dump() =\n%s\nwant\n%s", got, want)
	}
}

// An iterate the legacy service never evaluates makes its set a permanent
// failure under the set's target.
func TestFromRegularMarksAnIterateLegacyNeverEvaluates(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		iterate string
		want    string
	}{
		{"another foreach", `{"foreach": "subject.roles", "combiningAlgorithm": "DENY_OVERRIDES"}`,
			`iterate foreach "subject.roles"`},
		{"no algorithm", `{"foreach": "subject.permissionScope"}`, "iterate without a combiningAlgorithm"},
		{"an unknown algorithm", `{"foreach": "subject.permissionScope", "combiningAlgorithm": "FIRST"}`,
			`iterate combiningAlgorithm "FIRST" unknown`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := fromRegular(t, `[{"tenantId": "t", "policySetId": "s", "target": "resourceType == 'R'",
				"iterate": `+tc.iterate+`, "policies": [{"policyId": "p"}]}]`, `[]`)
			s := tree(t, e, "t").Sets[0]
			if s.AlwaysFails != tc.want || s.Target == nil || len(s.Policies) != 0 {
				t.Errorf("set = AlwaysFails %q, target %v, %d policies; want AlwaysFails %q, the target, no policies",
					s.AlwaysFails, s.Target, len(s.Policies), tc.want)
			}
		})
	}
}

// Condition text the parser refuses stays in the tree as an Unsupported atom
// of form syntax, which Tree.Unsupported reports.
func TestFromRegularMarksAConditionTheParserRefuses(t *testing.T) {
	t.Parallel()

	e := fromRegular(t, `[{"tenantId": "t", "policySetId": "s",
		"policies": [{"policyId": "p", "rules": [{"ruleId": "r", "effect": "ALLOW", "condition": "resource.a=='y'"}]}]}]`, `[]`)

	want := []Finding{{Where: `set "s" > policy "p" > rule "r" > condition`, Form: FormSyntax, Text: "resource.a=='y'"}}
	if got := tree(t, e, "t").Unsupported(); !slices.Equal(got, want) {
		t.Errorf("Unsupported() = %v, want %v", got, want)
	}
}

// An element that cannot be read fails its own tenant; the other tenants keep
// their trees.
func TestFromRegularFailsOnlyTheTenantOfABadElement(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		sets    string
		pips    string
		wantErr string
	}{
		{"an unknown set algorithm", `[{"tenantId": "bad", "combiningAlgorithm": "FIRST_APPLICABLE"}]`, `[]`,
			`combiningAlgorithm "FIRST_APPLICABLE" unknown`},
		{"an unknown effect", `[{"tenantId": "bad", "policies": [{"rules": [{"effect": "PERMIT"}]}]}]`, `[]`,
			`effect "PERMIT" unknown`},
		{"a target that is not a string", `[{"tenantId": "bad", "target": 5}]`, `[]`, "target"},
		{"an unknown pipType", `[]`, `[{"tenantId": "bad", "name": "subject.x", "pipType": "ENTITLEMENT"}]`,
			`pipType "ENTITLEMENT" unknown`},
		{"a PIP name shorter than subject.", `[]`, `[{"tenantId": "bad", "name": "x", "pipType": "TOKEN"}]`,
			"lacks the subject. prefix"},
		{"a PIP with no name", `[]`, `[{"tenantId": "bad", "pipType": "TOKEN"}]`, "no name"},
		{"headers that are a number", `[]`, `[{"tenantId": "bad", "name": "subject.x", "headers": 5}]`,
			"neither a string, a list, nor an object"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			good := simplifiedSet("good", "R", `[]`)
			sets := "[" + good + "," + strings.TrimPrefix(tc.sets, "[")
			if tc.sets == `[]` {
				sets = "[" + good + "]"
			}
			e := fromRegular(t, sets, tc.pips)
			if err := e.Failed["bad"]; err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Failed[bad] = %v, want an error containing %q", err, tc.wantErr)
			}
			if _, ok := e.Trees["bad"]; ok {
				t.Errorf("tenant bad has a tree")
			}
			tree(t, e, "good")
		})
	}
}

func TestFromRegularReportsAnElementWithNoTenant(t *testing.T) {
	t.Parallel()

	e := fromRegular(t, `[{"policySetId": "s"}]`, `[{"name": "subject.x", "tenantId": 5}]`)

	if len(e.Orphans) != 2 || len(e.Trees) != 0 {
		t.Errorf("orphans %v, trees %v; want two orphans and no tree", e.Orphans, e.Trees)
	}
}

func TestFromRegularRefusesADocumentWithoutItsArray(t *testing.T) {
	t.Parallel()

	cases := []struct{ name, sets, pips string }{
		{"policy sets not JSON", `{`, `{"pips": []}`},
		{"no policySets array", `{"sets": []}`, `{"pips": []}`},
		{"no pips array", `{"policySets": []}`, `[]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if e, err := FromRegular([]byte(tc.sets), []byte(tc.pips)); err == nil {
				t.Errorf("FromRegular(%s, %s) = %v, nil; want an error", tc.sets, tc.pips, e)
			}
		})
	}
}
