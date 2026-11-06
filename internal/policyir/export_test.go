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
	"encoding/json"
	"errors"
	"fmt"
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
	if len(e.Failed) != 0 || len(e.Orphans) != 0 || len(e.Dropped) != 0 {
		t.Errorf("FromRegular: failed %v, orphans %v, dropped %v, want none", e.Failed, e.Orphans, e.Dropped)
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

// A simplified policy of operation ALL keeps its condition and its predicates.
// The set target resourceType == 'ALL' gives a group of the resource type
// named ALL, as written.
func TestFromRegularKeepsTheConditionOfOperationAll(t *testing.T) {
	t.Parallel()

	e := fromRegular(t, `[`+simplifiedSet("t", "ALL", `[{"combiningAlgorithm": "DENY_UNLESS_PERMIT", "target": "true",
		"rules": [{"ruleId": "r1", "effect": "ALLOW", "condition": "resource.a == 'y'", "rsqlPredicate": "all==1",
		 "ruleType": "APPLICABLE_FOR_FRONTEND",
		 "target": "subject.roles CONTAINS ANY 'ROLE_A','ROLE_B'"}]}]`)+`]`, `[]`)

	want := `simplified "s" name="" domain="D" component="C" resourceType="ALL"
  policy "r1" operation="ALL" roles=["ROLE_A", "ROLE_B"] frontend
    condition[simplified]: resource.a EQ "y"
    predicate rsql "all==1"
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
		{"the set target true of a global policy", "true", `[{"combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"target": "true", "rules": [{"effect": "ALLOW", "target": "subject.roles CONTAINS ANY 'A'"}]}]`},
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
		{"a default with characters JSON may escape", `{"name": "subject.x", "pipType": "TOKEN", "claim": "c",
			"defaultValue": "<a&b> \u00e9"}`, `pip "subject.x" type=TOKEN claim="c" defaultValue="<a&b> \u00e9"`},
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

// The export can list a declaration that another tenant's customization added
// under this tenant's tenantId, and nothing in it tells that declaration from
// the tenant's own. A name the tenant declares more than once is therefore one
// isolated declaration, and the tenant keeps its tree and its other
// declarations.
func TestFromRegularIsolatesAPIPNameDeclaredMoreThanOnce(t *testing.T) {
	t.Parallel()

	e := fromRegular(t, `[]`, `[
		{"name": "subject.x", "pipType": "TOKEN", "claim": "first", "domain": "D1", "tenantId": "t"},
		{"name": "subject.y", "pipType": "TOKEN", "claim": "c", "tenantId": "t"},
		{"name": "subject.x", "pipType": "HEADER", "header": "second", "domain": "D2", "tenantId": "t"},
		{"name": "subject.x", "pipType": "HEADER", "header": "second", "domain": "D2", "tenantId": "t"}]`)

	want := `pip "subject.x" isolated="declared 3 times"` + "\n" + `pip "subject.y" type=TOKEN claim="c"` + "\n"
	if got := tree(t, e, "t").Dump(); got != want {
		t.Errorf("Dump() =\n%s\nwant\n%s", got, want)
	}
	wantDropped := []string{`pip "subject.x": isolated: declared 3 times`}
	if got := e.Dropped["t"]; !slices.Equal(got, wantDropped) {
		t.Errorf("Dropped[t] = %q, want %q", got, wantDropped)
	}
}

// The export can show a tenant's set holding a policy of another tenant, which
// the legacy service moved there while it served an earlier export. Such a set
// is isolated with its target, and the tenant keeps its other sets. A policy
// of the set's own tenant and a rule with an empty tenantId leave a set as it
// is.
func TestFromRegularIsolatesASetWithAnElementOfAnotherTenant(t *testing.T) {
	t.Parallel()

	const control = `{"tenantId": "t", "policySetId": "ok",
		"policies": [{"policyId": "p", "tenantId": "t", "rules": [{"ruleId": "r", "tenantId": "", "effect": "ALLOW"}]}]}`
	const controlDump = "set \"ok\" name=\"\" domain=\"\" algorithm=absent\n" +
		"  policy \"p\" name=\"\" algorithm=absent\n" +
		"    rule \"r\" name=\"\" effect=ALLOW\n"
	cases := []struct {
		name       string
		set        string
		wantDomain string
		wantReason string
	}{
		{"a policy of another tenant", `{"tenantId": "t", "policySetId": "s", "target": "resourceType == 'R'",
			"policies": [{"policyId": "p", "tenantId": "u"}]}`, "", `policy "p" has tenantId "u"`},
		{"a rule of another tenant", `{"tenantId": "t", "policySetId": "s", "target": "resourceType == 'R'",
			"policies": [{"policyId": "p", "rules": [{"ruleId": "r", "tenantId": "u", "effect": "ALLOW"}]}]}`, "",
			`rule "r" has tenantId "u"`},
		{"a nested set of another tenant", `{"tenantId": "t", "policySetId": "s", "target": "resourceType == 'R'",
			"policySets": [{"policySetId": "n", "tenantId": "u"}]}`, "", `policy set "n" has tenantId "u"`},
		{"a policy of another tenant in a nested set", `{"tenantId": "t", "policySetId": "s",
			"target": "resourceType == 'R'", "policySets": [{"policySetId": "n", "tenantId": "t",
			"policies": [{"policyId": "p", "tenantId": "u"}]}]}`, "", `policy "p" has tenantId "u"`},
		{"a rule of another tenant in the simplified shape", simplifiedSet("t", "R", `[{"combiningAlgorithm":
			"DENY_UNLESS_PERMIT", "target": "true", "rules": [{"tenantId": "u", "ruleId": "r", "effect": "ALLOW",
			"target": "subject.roles CONTAINS ANY 'A'"}]}]`), "D", `rule "r" has tenantId "u"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := fromRegular(t, "["+tc.set+","+control+"]", `[]`)
			want := fmt.Sprintf("set \"s\" name=\"\" domain=%q algorithm=absent\n  isolated: %q\n"+
				"  target[set_target]: resourceType EQ \"R\"\n", tc.wantDomain, tc.wantReason) + controlDump
			if got := tree(t, e, "t").Dump(); got != want {
				t.Errorf("Dump() =\n%s\nwant\n%s", got, want)
			}
			wantDropped := []string{`policy set 0 "s": isolated: ` + tc.wantReason}
			if got := e.Dropped["t"]; !slices.Equal(got, wantDropped) {
				t.Errorf("Dropped[t] = %q, want %q", got, wantDropped)
			}
		})
	}
}

// The export can show a tenant a set of another tenant under the tenant's own
// tenantId and with the policySetId of the tenant's own set, and nothing in it
// tells the two apart. A top-level set that applies is isolated when the tenant
// has another top-level set of its policySetId, whatever the status of the
// other, while a set of the same policySetId in another tenant is read as
// usual.
func TestFromRegularIsolatesTheSetsOfAPolicySetIdATenantHasTwice(t *testing.T) {
	t.Parallel()

	const reason = "the tenant has 2 top-level sets with this policySetId"
	const other = `{"tenantId": "u", "policySetId": "s", "target": "resourceType == 'R'"}`
	cases := []struct {
		name        string
		secondSet   string
		wantDump    string
		wantDropped []string
	}{
		{"two sets that apply", `{"tenantId": "t", "policySetId": "s", "target": "resourceType == 'R2'"}`,
			"set \"s\" name=\"\" domain=\"\" algorithm=absent\n  isolated: \"" + reason + "\"\n" +
				"  target[set_target]: resourceType EQ \"R1\"\n" +
				"set \"s\" name=\"\" domain=\"\" algorithm=absent\n  isolated: \"" + reason + "\"\n" +
				"  target[set_target]: resourceType EQ \"R2\"\n",
			[]string{`policy set 0 "s": isolated: ` + reason, `policy set 1 "s": isolated: ` + reason}},
		{"a set that applies and an inactive one", `{"tenantId": "t", "policySetId": "s", "status": "INACTIVE",
			"target": "resourceType == 'R2'"}`,
			"set \"s\" name=\"\" domain=\"\" algorithm=absent\n  isolated: \"" + reason + "\"\n" +
				"  target[set_target]: resourceType EQ \"R1\"\n",
			[]string{`policy set 0 "s": isolated: ` + reason, `policy set 1 "s": status INACTIVE`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := fromRegular(t, `[{"tenantId": "t", "policySetId": "s", "status": "ACTIVE",
				"target": "resourceType == 'R1'"}, `+tc.secondSet+`, `+other+`]`, `[]`)
			if got := tree(t, e, "t").Dump(); got != tc.wantDump {
				t.Errorf("Dump() of t =\n%s\nwant\n%s", got, tc.wantDump)
			}
			if got := e.Dropped["t"]; !slices.Equal(got, tc.wantDropped) {
				t.Errorf("Dropped[t] = %q, want %q", got, tc.wantDropped)
			}
			wantOther := "set \"s\" name=\"\" domain=\"\" algorithm=absent\n  target[set_target]: resourceType EQ \"R\"\n"
			if got := tree(t, e, "u").Dump(); got != wantOther {
				t.Errorf("Dump() of u =\n%s\nwant\n%s", got, wantOther)
			}
		})
	}
}

// An unknown key of a set or of a PIP declaration is listed with its path
// inside the element, however deep it stands, in the order of the document.
func TestFromRegularListsEveryUnknownKey(t *testing.T) {
	t.Parallel()

	e := fromRegular(t, `[{"tenantId": "u", "policySetId": "o"}, {"tenantId": "t", "policySetId": "s",
		"policySets": [{"policies": [{"rules": [{"effect": "ALLOW"}, {"effect": "ALLOW",
		"customPredicate": {"predicate": "own", "extra": 1}}]}]}], "STATUS": "x"}]`,
		`[{"tenantId": "u", "name": "subject.y"}, {"tenantId": "t", "name": "subject.x", "Claim": "c"}]`)

	want := []string{
		`policy set 1 "s": unknown key policySets[0].policies[0].rules[1].customPredicate.extra`,
		`policy set 1 "s": unknown key STATUS`,
		`pip 1 "subject.x": unknown key Claim`,
	}
	if got := e.Dropped["t"]; !slices.Equal(got, want) {
		t.Errorf("Dropped[t] =\n%q\nwant\n%q", got, want)
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
			if got := len(e.Dropped["t"]) == 0; got != tc.want {
				t.Errorf("Dropped[t] = %q for a top-level set of status %q", e.Dropped["t"], tc.status)
			}
		})
	}
}

// A top-level set that its status drops is not read, so an element of it that
// cannot be read leaves its tenant a tree.
func TestFromRegularDropsAnInactiveSetBeforeReadingIt(t *testing.T) {
	t.Parallel()

	e := fromRegular(t, `[{"tenantId": "t", "policySetId": "s", "status": "INACTIVE", "policies": "x"}]`, `[]`)

	if tr := tree(t, e, "t"); len(tr.Sets) != 0 {
		t.Errorf("sets = %d, want none", len(tr.Sets))
	}
	if got, want := e.Dropped["t"], []string{`policy set 0 "s": status INACTIVE`}; !slices.Equal(got, want) {
		t.Errorf("Dropped[t] = %q, want %q", got, want)
	}
}

// A key fills a field only when spelled exactly as the export spells it, as
// the legacy service reads it; a key in another letter case is ignored.
func TestFromRegularMatchesKeysInTheirExactCase(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		set  string
		want string
	}{
		{"a status key in capitals", `{"tenantId": "t", "policySetId": "s", "STATUS": "INACTIVE"}`,
			"set \"s\" name=\"\" domain=\"\" algorithm=absent\n"},
		{"a second status key in another case", `{"tenantId": "t", "policySetId": "s", "status": "ACTIVE",
			"Status": "INACTIVE"}`, "set \"s\" name=\"\" domain=\"\" algorithm=absent\n"},
		{"a policies key in another case", `{"tenantId": "t", "policySetId": "s", "Policies": [{"policyId": "p"}]}`,
			"set \"s\" name=\"\" domain=\"\" algorithm=absent\n"},
		{"an effect key in another case", `{"tenantId": "t", "policySetId": "s",
			"policies": [{"policyId": "p", "rules": [{"ruleId": "r", "Effect": "DENY"}]}]}`,
			"set \"s\" name=\"\" domain=\"\" algorithm=absent\n  policy \"p\" name=\"\" algorithm=absent\n" +
				"    rule \"r\" name=\"\" effect=absent\n"},
		{"a policyId key written with an escape", `{"tenantId": "t", "policySetId": "s", "policies": [{"policyI\u0064": "p"}]}`,
			"set \"s\" name=\"\" domain=\"\" algorithm=absent\n  policy \"p\" name=\"\" algorithm=absent\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tree(t, fromRegular(t, "["+tc.set+"]", `[]`), "t").Dump(); got != tc.want {
				t.Errorf("Dump() =\n%s\nwant\n%s", got, tc.want)
			}
		})
	}
}

// Of a key written twice in one object the last value counts, whole: an object
// value is not merged into the earlier one.
func TestFromRegularReadsTheLastValueOfARepeatedKey(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		set  string
		want string
	}{
		{"an iterate object", `{"tenantId": "t", "policySetId": "s",
			"iterate": {"foreach": "subject.permissionScope", "combiningAlgorithm": "DENY_OVERRIDES"},
			"iterate": {"foreach": "subject.permissionScope"}}`,
			"set \"s\" name=\"\" domain=\"\" algorithm=absent\n  always fails: \"iterate without a combiningAlgorithm\"\n"},
		{"a policies array", `{"tenantId": "t", "policySetId": "s", "policies": [{"policyId": "a"}],
			"policies": [{"policyId": "b"}]}`,
			"set \"s\" name=\"\" domain=\"\" algorithm=absent\n  policy \"b\" name=\"\" algorithm=absent\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tree(t, fromRegular(t, "["+tc.set+"]", `[]`), "t").Dump(); got != tc.want {
				t.Errorf("Dump() =\n%s\nwant\n%s", got, tc.want)
			}
		})
	}
}

// The value of an unknown key is skipped whole, whatever brackets and quotes
// it and the strings around it hold.
func TestFromRegularSkipsTheValueOfAnUnknownKey(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		policy string
		want   string
	}{
		{"nested containers", `{"extra": {"a": [1, {"b": []}], "c": {}}, "policyId": "p"}`,
			"  policy \"p\" name=\"\" algorithm=absent\n"},
		{"a string that ends in an escaped backslash", `{"extra": "a\\", "policyId": "p"}`,
			"  policy \"p\" name=\"\" algorithm=absent\n"},
		{"brackets and an escaped quote inside strings", `{"extra": "]}\"{[", "policyId": "p", "name": "x]}\"{["}`,
			"  policy \"p\" name=\"x]}\\\"{[\" algorithm=absent\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			set := `{"tenantId": "t", "policySetId": "s", "policies": [` + tc.policy + `]}`
			want := "set \"s\" name=\"\" domain=\"\" algorithm=absent\n" + tc.want
			if got := tree(t, fromRegular(t, "["+set+"]", `[]`), "t").Dump(); got != want {
				t.Errorf("Dump() =\n%s\nwant\n%s", got, want)
			}
		})
	}
}

// Of two members of one object that cannot be decoded, the error names the one
// whose key sorts first.
func TestFromRegularReportsTheFirstBadKeyInSortedOrder(t *testing.T) {
	t.Parallel()

	e := fromRegular(t, `[{"tenantId": "t", "policySetId": "s", "policies": [{"policyId": 1, "name": 2}]}]`, `[]`)

	if err := e.Failed["t"]; err == nil || !strings.Contains(err.Error(), "exportSet.policies.0.name of type string") {
		t.Errorf("Failed[t] = %v, want the type error of the name key", err)
	}
}

// The error of a tenant names every node around the element it could not
// read, outermost first.
func TestFromRegularNamesTheNodesAroundABadElement(t *testing.T) {
	t.Parallel()

	e := fromRegular(t, `[{"tenantId": "t", "policySetId": "top", "policySets": [{"policySetId": "mid",
		"policies": [{"policyId": "p", "rules": [{"ruleId": "r", "effect": "PERMIT"}]}]}]}]`, `[]`)

	want := `policy set "top": policy set "mid": policy "p": rule "r": effect "PERMIT" unknown`
	if err := e.Failed["t"]; err == nil || err.Error() != want {
		t.Errorf("Failed[t] = %v, want %s", err, want)
	}
}

// A legacy field that no decision reads is known on the element that carries
// it, and the reader skips it without listing it; on another element the same
// key is unknown.
func TestFromRegularSkipsTheLegacyKeysNoDecisionReads(t *testing.T) {
	t.Parallel()

	sets := map[string]func(key string) string{
		"set": func(key string) string { return `{"tenantId": "t", "policySetId": "s", "` + key + `": "v"}` },
		"policy": func(key string) string {
			return `{"tenantId": "t", "policySetId": "s", "policies": [{"` + key + `": "v"}]}`
		},
		"rule": func(key string) string {
			return `{"tenantId": "t", "policySetId": "s", "policies": [{"rules": [{"effect": "ALLOW", "` + key + `": "v"}]}]}`
		},
	}
	cases := []struct {
		element string
		key     string
		want    string
	}{
		{"set", "description", ""},
		{"set", "deprecated", ""},
		{"set", "uiTarget", ""},
		{"set", "previousStatus", ""},
		{"policy", "description", ""},
		{"policy", "deprecated", ""},
		{"policy", "uiTarget", ""},
		{"policy", "uiCondition", `policy set 0 "s": unknown key policies[0].uiCondition`},
		{"rule", "description", ""},
		{"rule", "deprecated", ""},
		{"rule", "uiTarget", ""},
		{"rule", "uiCondition", ""},
		{"rule", "previousStatus", `policy set 0 "s": unknown key policies[0].rules[0].previousStatus`},
		{"policy", "status", `policy set 0 "s": unknown key policies[0].status`},
		{"rule", "status", `policy set 0 "s": unknown key policies[0].rules[0].status`},
		{"pip", "description", ""},
		{"pip", "deprecated", ""},
		{"pip", "uiTarget", `pip 0 "subject.x": unknown key uiTarget`},
	}
	for _, tc := range cases {
		t.Run(tc.element+" "+tc.key, func(t *testing.T) {
			t.Parallel()
			set, pip := `[]`, `[]`
			if tc.element == "pip" {
				pip = `[{"tenantId": "t", "name": "subject.x", "` + tc.key + `": "v"}]`
			} else {
				set = `[` + sets[tc.element](tc.key) + `]`
			}
			var want []string
			if tc.want != "" {
				want = []string{tc.want}
			}
			if got := fromRegular(t, set, pip).Dropped["t"]; !slices.Equal(got, want) {
				t.Errorf("Dropped[t] = %q, want %q", got, want)
			}
		})
	}
}

// The export has no field querydslPredicate: a rule keeps its querydsl
// template in predicate. The key is unknown wherever it stands, so it is
// listed in Export.Dropped, and neither a rule nor a simplified policy gets a
// querydsl predicate or a finding from it.
func TestFromRegularListsQuerydslPredicateAsAnUnknownKey(t *testing.T) {
	t.Parallel()

	const rule = `{"ruleId": "r1", "effect": "ALLOW", "querydslPredicate": "q", "target": "subject.roles CONTAINS ANY 'A'"}`
	cases := []struct {
		name     string
		target   string
		wantDump string
	}{
		{"a simplified policy of operation ALL", "true",
			"simplified \"s\" name=\"\" domain=\"D\" component=\"C\" resourceType=\"R\"\n" +
				"  policy \"r1\" operation=\"ALL\" roles=[\"A\"]\n"},
		{"a rule of a regular set", "operation == 'ALL'",
			"set \"s\" name=\"\" domain=\"D\" algorithm=DENY_UNLESS_PERMIT\n" +
				"  target[set_target]: resourceType EQ \"R\"\n" +
				"  policy \"\" name=\"\" algorithm=DENY_UNLESS_PERMIT\n" +
				"    target[policy_target]: operation EQ \"ALL\"\n" +
				"    rule \"r1\" name=\"\" effect=ALLOW\n" +
				"      target[rule_target]: subject.roles CONTAINS_ANY [\"A\"]\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			policies := `[{"combiningAlgorithm": "DENY_UNLESS_PERMIT", "target": "` + tc.target + `", "rules": [` + rule + `]}]`
			e := fromRegular(t, `[`+simplifiedSet("t", "R", policies)+`]`, `[]`)
			tr := tree(t, e, "t")
			if got := tr.Dump(); got != tc.wantDump {
				t.Errorf("Dump() =\n%s\nwant\n%s", got, tc.wantDump)
			}
			if got := tr.Unsupported(); len(got) != 0 {
				t.Errorf("Unsupported() = %v, want none", got)
			}
			want := []string{`policy set 0 "s": unknown key policies[0].rules[0].querydslPredicate`}
			if got := e.Dropped["t"]; !slices.Equal(got, want) {
				t.Errorf("Dropped[t] = %q, want %q", got, want)
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

// A tenant that fails has no tree, so nothing is listed as dropped from it.
func TestFromRegularListsNothingDroppedFromAFailedTenant(t *testing.T) {
	t.Parallel()

	e := fromRegular(t, `[{"tenantId": "t", "policySetId": "i", "status": "INACTIVE"},
		{"tenantId": "t", "policySetId": "s", "combiningAlgorithm": "FIRST_APPLICABLE"}]`, `[]`)

	if e.Failed["t"] == nil {
		t.Fatalf("Failed[t] = nil, want the error of set s")
	}
	if got, ok := e.Dropped["t"]; ok {
		t.Errorf("Dropped[t] = %q, want no entry", got)
	}
}

func TestFromRegularReportsAnElementWithNoTenant(t *testing.T) {
	t.Parallel()

	e := fromRegular(t, `[{"policySetId": "s"}, {"policySetId": "e", "tenantId": ""}, {"policySetId": "c", "TENANTID": "u"}]`,
		`[{"name": "subject.x", "tenantId": 5}]`)

	if len(e.Orphans) != 4 || len(e.Trees) != 0 {
		t.Errorf("orphans %v, trees %v; want four orphans and no tree", e.Orphans, e.Trees)
	}
}

func TestFromRegularRefusesADocumentWithoutItsArray(t *testing.T) {
	t.Parallel()

	cases := []struct{ name, sets, pips, want string }{
		{"policy sets not JSON", `{`, `{"pips": []}`, "policy sets export: unexpected end of JSON input"},
		{"no policySets array", `{"sets": []}`, `{"pips": []}`, "policy sets export: no policySets array"},
		{"a null policySets", `{"policySets": null}`, `{"pips": []}`, "policy sets export: no policySets array"},
		{"no pips array", `{"policySets": []}`, `{}`, "PIP export: no pips array"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, err := FromRegular([]byte(tc.sets), []byte(tc.pips))
			if err == nil {
				t.Fatalf("FromRegular(%s, %s) = %v, nil; want an error", tc.sets, tc.pips, e)
			}
			if got := err.Error(); got != tc.want {
				t.Errorf("FromRegular(%s, %s) error = %q, want %q", tc.sets, tc.pips, got, tc.want)
			}
		})
	}
}

// A document that does not decode is refused with the decode error in the
// chain, for the policy sets and for the PIPs.
func TestFromRegularWrapsTheDecodeError(t *testing.T) {
	t.Parallel()

	_, err := FromRegular([]byte(`{`), []byte(`{"pips": []}`))
	var se *json.SyntaxError
	if !errors.As(err, &se) {
		t.Errorf("FromRegular({, ...) error = %v, want a *json.SyntaxError in the chain", err)
	}
	_, err = FromRegular([]byte(`{"policySets": []}`), []byte(`[]`))
	var ute *json.UnmarshalTypeError
	if !errors.As(err, &ute) {
		t.Errorf("FromRegular(..., []) error = %v, want a *json.UnmarshalTypeError in the chain", err)
	}
}

// A simplified group keeps the ID, the name, and the externalId of its set.
func TestFromRegularKeepsTheIdentityOfASimplifiedSet(t *testing.T) {
	t.Parallel()

	tr := tree(t, fromRegular(t, `[{"tenantId": "t", "policySetId": "s", "name": "n", "externalId": "e",
		"type": "SIMPLIFIED", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "target": "resourceType == 'R'",
		"policies": [{"combiningAlgorithm": "DENY_UNLESS_PERMIT", "target": "operation == 'READ'",
			"rules": [{"ruleId": "r", "effect": "ALLOW", "target": "subject.roles CONTAINS ANY 'A'"}]}]}]`, `[]`), "t")

	want := `simplified "s" name="n" domain="" component="" resourceType="R" externalId="e"`
	if got, _, _ := strings.Cut(tr.Dump(), "\n"); got != want {
		t.Errorf("first line of Dump() = %s, want %s", got, want)
	}
}

// A SIMPLIFIED set that differs from the shape the PAP writes in one key of
// the set, a policy, or a rule is read as a regular set. The unchanged set is
// the control: it is read as a simplified group.
func TestFromRegularReadsASimplifiedSetThatDiffersInOneKeyAsARegularSet(t *testing.T) {
	t.Parallel()

	shaped := func() map[string]any {
		return map[string]any{
			"tenantId": "t", "policySetId": "s", "type": "SIMPLIFIED", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"target": "resourceType == 'R'",
			"policies": []any{map[string]any{
				"combiningAlgorithm": "DENY_UNLESS_PERMIT", "target": "operation == 'READ'",
				"rules": []any{map[string]any{"ruleId": "r", "effect": "ALLOW", "target": "subject.roles CONTAINS ANY 'A'"}},
			}},
		}
	}
	policy := func(s map[string]any) map[string]any { return s["policies"].([]any)[0].(map[string]any) }
	rule := func(s map[string]any) map[string]any { return policy(s)["rules"].([]any)[0].(map[string]any) }
	cases := []struct {
		name           string
		change         func(s map[string]any)
		wantSimplified int
		wantSets       int
	}{
		{"unchanged", func(map[string]any) {}, 1, 0},
		{"the set algorithm DENY_OVERRIDES", func(s map[string]any) { s["combiningAlgorithm"] = "DENY_OVERRIDES" }, 0, 1},
		{"an iterate", func(s map[string]any) {
			s["iterate"] = map[string]any{"foreach": "subject.permissionScope", "combiningAlgorithm": "DENY_OVERRIDES"}
		}, 0, 1},
		{"a nested set", func(s map[string]any) { s["policySets"] = []any{map[string]any{"policySetId": "n"}} }, 0, 1},
		{"type DEFAULT", func(s map[string]any) { s["type"] = "DEFAULT" }, 0, 1},
		{"no set target", func(s map[string]any) { delete(s, "target") }, 0, 1},
		{"no policy target", func(s map[string]any) { delete(policy(s), "target") }, 0, 1},
		{"no rule target", func(s map[string]any) { delete(rule(s), "target") }, 0, 1},
		{"a customPredicate", func(s map[string]any) { rule(s)["customPredicate"] = map[string]any{"predicate": "own"} }, 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			set := shaped()
			tc.change(set)
			doc, err := json.Marshal([]any{set})
			if err != nil {
				t.Fatal(err)
			}
			tr := tree(t, fromRegular(t, string(doc), `[]`), "t")
			if len(tr.Simplified) != tc.wantSimplified || len(tr.Sets) != tc.wantSets {
				t.Errorf("simplified groups %d, sets %d, want %d and %d; dump:\n%s",
					len(tr.Simplified), len(tr.Sets), tc.wantSimplified, tc.wantSets, tr.Dump())
			}
		})
	}
}

// A rule of ruleType APPLICABLE_FOR_FRONTEND in a regular set is a frontend
// rule; the rule of ruleType DEFAULT beside it is the control.
func TestFromRegularMarksAFrontendRuleOfARegularSet(t *testing.T) {
	t.Parallel()

	tr := tree(t, fromRegular(t, `[{"tenantId": "t", "policySetId": "s", "policies": [{"policyId": "p", "rules": [
		{"ruleId": "f", "effect": "ALLOW", "ruleType": "APPLICABLE_FOR_FRONTEND"},
		{"ruleId": "d", "effect": "ALLOW", "ruleType": "DEFAULT"}]}]}]`, `[]`), "t")

	want := "set \"s\" name=\"\" domain=\"\" algorithm=absent\n  policy \"p\" name=\"\" algorithm=absent\n" +
		"    rule \"f\" name=\"\" effect=ALLOW frontend\n    rule \"d\" name=\"\" effect=ALLOW\n"
	if got := tr.Dump(); got != want {
		t.Errorf("Dump() =\n%s\nwant\n%s", got, want)
	}
}

// A tenant whose tree NewTree refuses has no tree, so nothing is listed as
// dropped from it either.
func TestFromRegularListsNothingDroppedFromATenantNewTreeRefuses(t *testing.T) {
	t.Parallel()

	e := fromRegular(t, `[{"tenantId": "t", "policySetId": "i", "status": "INACTIVE"}]`,
		`[{"tenantId": "t", "name": "x", "pipType": "TOKEN"}]`)

	if e.Failed["t"] == nil {
		t.Fatalf("Failed[t] = nil, want the error of the PIP named x")
	}
	if got, ok := e.Dropped["t"]; ok {
		t.Errorf("Dropped[t] = %q, want no entry", got)
	}
}
