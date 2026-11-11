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

package main

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"authz-agent/internal/policyir"
)

// The stub only earns its keep if what it serves is what the service reads
// back. The import of internal/policyir lives in a _test.go file on purpose:
// the shipped binary must not link the service's reader, otherwise the
// integration suites would compare the reader against itself, but the test
// may, and it is supposed to fail when the v3 wire shape changes.
func TestV3RoundTripThroughTheServiceReader(t *testing.T) {
	input := []simplifiedPolicy{
		{Tenant: "tenant-a", Component: "billing", ResourceType: "Invoice", Operation: "READ", Roles: []any{"ROLE_ADMIN"}},
		{Tenant: "tenant-a", Component: "billing", ResourceType: "Invoice", Operation: "UPDATE", Roles: []any{"ROLE_ADMIN"}, Condition: "subject.tenantId == resource.tenantId"},
		{Tenant: "tenant-a", Component: "billing", ResourceType: "Invoice", Operation: "READ", Roles: []any{"ROLE_USER"}, RSQLPredicate: "ownerId==${subject.id}"},
	}
	raw, err := json.Marshal(v3PolicySetsResponse{Hash: "deadbeef", PolicySets: toV3PolicySets(input, defaultTenant)})
	if err != nil {
		t.Fatalf("marshal v3 envelope: %v", err)
	}

	tree := readTree(t, raw, []byte(`{"pips": []}`), "tenant-a")
	var got []string
	for _, set := range tree.Sets {
		for _, p := range set.Policies {
			for _, r := range p.Rules {
				got = append(got, format(p.Target)+" | "+format(r.Target)+" | "+format(r.Condition)+
					" | rsql="+r.Predicates.Text[policyir.DialectRSQL]+" | querydsl="+r.Predicates.Text[policyir.DialectQueryDSL])
			}
		}
	}
	slices.Sort(got)
	want := []string{
		`subject.roles CONTAINS "ROLE_ADMIN" | operation EQ "READ" |  | rsql= | querydsl=`,
		`subject.roles CONTAINS "ROLE_ADMIN" | operation EQ "UPDATE" | pip("subject.tenantId") EQ resource.tenantId | rsql= | querydsl=`,
		`subject.roles CONTAINS "ROLE_USER" | operation EQ "READ" |  | rsql=ownerId==${subject.id} | querydsl=`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("rules read back =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// format is the condition c as the reader parsed it, "" for none.
func format(c *policyir.Condition) string {
	if c == nil {
		return ""
	}
	return policyir.FormatCondition(c)
}

func TestPIPRoundTripThroughTheServiceReader(t *testing.T) {
	input := []simplifiedPIP{
		{Tenant: "tenant-a", Name: "subject.tenant", PipType: "TOKEN", Claim: "tenant_id", Domain: "billing"},
		{Tenant: "tenant-a", Name: "subject.org", PipType: "HEADER", Header: "X-Org-Id", Domain: "billing"},
	}
	raw, err := json.Marshal(v3PIPsResponse{Hash: "deadbeef", PIPs: toV3PIPs(input, defaultTenant)})
	if err != nil {
		t.Fatalf("marshal v3 envelope: %v", err)
	}

	tree := readTree(t, []byte(`{"policySets": []}`), raw, "tenant-a")
	var got []string
	for _, p := range tree.PIPs {
		got = append(got, p.Name+" "+string(p.Type)+" "+p.Claim+p.Header)
	}
	want := []string{"subject.tenant TOKEN tenant_id", "subject.org HEADER X-Org-Id"}
	if !slices.Equal(got, want) {
		t.Errorf("PIPs read back = %q, want %q", got, want)
	}
}

// TestTheRuleTakesThePredicatesAccessControlReads: a rule's filter
// predicates are the rsqlPredicate of the policy and the mongodbPredicate of
// its predicates object, or its predicates text; every other predicate key,
// top-level or nested, gives the rule nothing.
func TestTheRuleTakesThePredicatesAccessControlReads(t *testing.T) {
	tests := []struct{ name, fields, rsql, mongodb string }{
		{"a predicates object", `"predicates": {"mongodbPredicate": "nested", "sqlPredicate": "s"}`, "", "nested"},
		{"a predicates text", `"predicates": "as text"`, "", "as text"},
		{"nested beside top-level", `"predicates": {"mongodbPredicate": "nested"}, "mongodbPredicate": "top"`, "", "nested"},
		{"a top-level mongodbPredicate", `"mongodbPredicate": "top"`, "", ""},
		{"every top-level key", `"rsqlPredicate": "a==1", "sqlPredicate": "a = 1", "mongodbPredicate": "{}",
			"predicate": "doc.a.eq(1)", "querydslPredicate": "doc.a.eq(1)"`, "a==1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p simplifiedPolicy
			if err := json.Unmarshal([]byte(`{"component": "PARITY", "resourceType": "PARITY_DOC",
				"operation": "READ", "roles": ["ROLE_A"], `+tt.fields+`}`), &p); err != nil {
				t.Fatalf("unmarshal the policy: %v", err)
			}
			r := toV3PolicySets([]simplifiedPolicy{p}, defaultTenant)[0].Policies[0].Rules[0]
			got := fmt.Sprintf("rsql=%q mongodb=%q sql=%q querydsl=%q", r.RSQLPredicate, r.MongoDBPredicate,
				r.SQLPredicate, r.Predicate)
			want := fmt.Sprintf("rsql=%q mongodb=%q sql=%q querydsl=%q", tt.rsql, tt.mongodb, "", "")
			if got != want {
				t.Errorf("rule predicates = %s, want %s", got, want)
			}
		})
	}
}

// TestPIPExportKeepsTheMappingAndCacheFields: the tables of a MAPPING PIP,
// the cache settings, and the resource type of a FILTERED PIP reach the
// service reader as uploaded.
func TestPIPExportKeepsTheMappingAndCacheFields(t *testing.T) {
	var input []simplifiedPIP
	if err := json.Unmarshal([]byte(`[
		{"name": "subject.permissions", "pipType": "MAPPING", "domain": "billing",
		 "productMapping": {}, "customMapping": {"ROLE_A": ["P1"]}},
		{"name": "subject.g", "pipType": "GENERAL", "url": "http://g", "domain": "billing",
		 "cacheable": true, "cachePeriod": 5},
		{"name": "subject.f", "pipType": "FILTERED", "url": "http://f", "domain": "billing",
		 "resourceType": "ORDER"}]`), &input); err != nil {
		t.Fatalf("unmarshal the upload: %v", err)
	}
	for i := range input {
		input[i].Tenant = "tenant-a"
	}
	raw, err := json.Marshal(v3PIPsResponse{Hash: "deadbeef", PIPs: toV3PIPs(input, defaultTenant)})
	if err != nil {
		t.Fatalf("marshal v3 envelope: %v", err)
	}

	tree := readTree(t, []byte(`{"policySets": []}`), raw, "tenant-a")
	var got []string
	for _, p := range tree.PIPs {
		got = append(got, fmt.Sprintf("%s product=%s custom=%s cacheable=%s period=%s rt=%s",
			p.Name, p.ProductMapping, p.CustomMapping, p.Cacheable, p.CachePeriod, p.ResourceType))
	}
	want := []string{
		`subject.permissions product={} custom={"ROLE_A":["P1"]} cacheable= period= rt=`,
		`subject.g product= custom= cacheable=true period=5 rt=`,
		`subject.f product= custom= cacheable= period= rt=ORDER`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("PIPs read back =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// readTree reads the two documents as the service does and returns the tree
// of tenant, failing the test when the reader drops or fails anything.
func readTree(t *testing.T, policySets, pips []byte, tenant string) *policyir.Tree {
	t.Helper()
	export, err := policyir.FromRegular(policySets, pips)
	if err != nil {
		t.Fatalf("FromRegular: %v", err)
	}
	if len(export.Failed) != 0 || len(export.Orphans) != 0 || len(export.Dropped) != 0 {
		t.Fatalf("FromRegular failed %v, orphaned %v, dropped %v; want everything read", export.Failed, export.Orphans, export.Dropped)
	}
	tree := export.Trees[tenant]
	if tree == nil {
		t.Fatalf("FromRegular read tenants %v, want %s", export.Trees, tenant)
	}
	return tree
}

// TestRolesTarget_MultiRoleKeepsEveryRole pins the fidelity fix: the stub used
// to emit only the first role of a multi-role policy, so a multi-role defect
// was invisible to every test that runs against it. The round trip through the
// production converter is the assertion that matters.
func TestRolesTarget_MultiRoleKeepsEveryRole(t *testing.T) {
	got := rolesTarget("ROLE_A,ROLE_B,ROLE_C")
	want := "subject.roles CONTAINS ANY 'ROLE_A','ROLE_B','ROLE_C'"
	if got != want {
		t.Fatalf("rolesTarget: want %q got %q", want, got)
	}
}
