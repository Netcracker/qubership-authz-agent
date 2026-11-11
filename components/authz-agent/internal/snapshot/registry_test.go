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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen"
	"authz-agent/internal/regogen/spectables"
)

type quiet struct{}

func (quiet) Infof(string, ...any) {}
func (quiet) Warnf(string, ...any) {}

var table *spectables.Table

func tab(t *testing.T) *spectables.Table {
	t.Helper()
	if table == nil {
		var err error
		if table, err = regogen.DefaultTable(); err != nil {
			t.Fatalf("DefaultTable: %v", err)
		}
	}
	return table
}

// set is a policy set of tenant whose one rule allows the operation read on
// the resource type doc where condition holds.
func set(tenant, condition string) string {
	return setWithConditionJSON(tenant, strconv.Quote(condition))
}

// setWithConditionJSON is [set] with the condition written as the JSON value
// condition.
func setWithConditionJSON(tenant, condition string) string {
	return fmt.Sprintf(`{"policySetId": "s-%[1]s", "name": "s", "status": "ACTIVE", "tenantId": %[1]q,
		"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
		"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"tenantId": %[1]q, "rules": [{"ruleId": "r", "target": "operation == 'read'",
				"condition": %[2]s, "effect": "ALLOW", "tenantId": %[1]q}]}]}`, tenant, condition)
}

// documents are the v3 policy-sets and PIPs documents of sets and pips.
func documents(pips string, sets ...string) (policySets, pipsDoc []byte) {
	return []byte(`{"policySets": [` + strings.Join(sets, ",") + `]}`), []byte(`{"pips": [` + pips + `]}`)
}

// loadSnapshots is [Registry.LoadSnapshots] of sets, with no PIP.
func loadSnapshots(r *Registry, sets ...string) error {
	policySets, pips := documents(``, sets...)
	return r.LoadSnapshots(context.Background(), policySets, pips)
}

func load(t *testing.T, r *Registry, pips string, sets ...string) LoadSummary {
	t.Helper()
	policySets, pipsDoc := documents(pips, sets...)
	sum, err := r.Load(context.Background(), policySets, pipsDoc)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return sum
}

// readDoc is a request of the user u1 to read a doc whose member a is a.
func readDoc(t *testing.T, tenant, a string, items int) Request {
	t.Helper()
	return readDocAs(t, "u1", tenant, a, items)
}

// readDocAs is readDoc of the user sub.
func readDocAs(t *testing.T, sub, tenant, a string, items int) Request {
	t.Helper()
	claims, err := jsonvalue.Decode([]byte(`{"sub": "` + sub + `", "preferred_username": "alice",
		"realm_access": {"roles": ["R"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	req := Request{Tenant: tenant, Claims: claims.(*jsonvalue.Object), Headers: map[string]string{}}
	for range items {
		req.Items = append(req.Items, regogen.Body{Operation: "read", ResourceType: "doc",
			Resource: mustObject(t, `{"a": "`+a+`"}`), HasResource: true})
	}
	return req
}

func mustObject(t *testing.T, s string) jsonvalue.Value {
	t.Helper()
	v, err := jsonvalue.Decode([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func decide(t *testing.T, r *Registry, req Request) []Result {
	t.Helper()
	got, err := r.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide(%s): %v", req.Tenant, err)
	}
	return got
}

func tenantHealth(r *Registry, tenant string) (TenantHealth, bool) {
	for _, th := range r.Health().Tenants {
		if th.Tenant == tenant {
			return th, true
		}
	}
	return TenantHealth{}, false
}

// A tenant is decided by the sets that carry its tenantId alone: a set of
// tenant a that allows every doc allows nothing in tenant b, and a tenant
// the export does not name denies with the reason that names it.
func TestEachTenantIsDecidedByItsOwnPolicies(t *testing.T) {
	r := New(Config{}, tab(t), quiet{})
	load(t, r, ``, set("a", "true"), set("b", "resource.a == 'x'"))

	for _, tc := range []struct {
		tenant, a string
		want      Result
	}{
		{"a", "y", Result{Allowed: true}},
		{"b", "y", Result{Reason: ReasonDenied}},
		{"b", "x", Result{Allowed: true}},
		{"c", "x", Result{Reason: "no policies are published for tenant c"}},
	} {
		if got := decide(t, r, readDoc(t, tc.tenant, tc.a, 1)); got[0] != tc.want {
			t.Errorf("Decide(tenant %s, a=%s) = %+v, want %+v", tc.tenant, tc.a, got[0], tc.want)
		}
	}
}

// A rule condition written as the JSON boolean true allows, and false denies,
// as the policy service decides them.
func TestABooleanConditionDecidesAsItsText(t *testing.T) {
	r := New(Config{}, tab(t), quiet{})
	load(t, r, ``, setWithConditionJSON("a", "true"), setWithConditionJSON("b", "false"))

	for _, tc := range []struct {
		tenant string
		want   Result
	}{
		{"a", Result{Allowed: true}},
		{"b", Result{Reason: ReasonDenied}},
	} {
		if got := decide(t, r, readDoc(t, tc.tenant, "x", 1)); got[0] != tc.want {
			t.Errorf("Decide(tenant %s) = %+v, want %+v", tc.tenant, got[0], tc.want)
		}
	}
}

// Two top-level sets of one policySetId in one tenant are evaluated as one set
// when they are identical, and answer as a failed source when they differ.
func TestTwoSetsOfOnePolicySetIdAreEvaluatedOnlyWhenIdentical(t *testing.T) {
	for _, tc := range []struct {
		name   string
		second string
		want   Result
	}{
		{"identical", set("a", "true"), Result{Allowed: true}},
		{"different", set("a", "false"), Result{Reason: "PIP resolution failed: set s-a"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := New(Config{}, tab(t), quiet{})
			load(t, r, ``, set("a", "true"), tc.second)
			if got := decide(t, r, readDoc(t, "a", "x", 1)); got[0] != tc.want {
				t.Errorf("Decide(read doc) = %+v, want %+v", got[0], tc.want)
			}
		})
	}
}

// subject.isM2M as an operand of a comparison is ABSENT, whatever the
// subject's token holds: IS NULL holds, and an equality with a literal
// aborts the condition. The decision request used to fail with "no resolved
// value of ["subj","isM2M"]", which the service answered with 500.
func TestAComparisonWithSubjectIsM2MIsDecided(t *testing.T) {
	for _, tc := range []struct {
		condition string
		want      Result
	}{
		{"subject.isM2M IS NULL", Result{Allowed: true}},
		{"subject.isM2M == true", Result{Reason: ReasonDenied}},
		{"subject.isM2M != true", Result{Reason: ReasonDenied}},
	} {
		t.Run(tc.condition, func(t *testing.T) {
			r := New(Config{}, tab(t), quiet{})
			load(t, r, ``, set("a", tc.condition))
			if got := decide(t, r, readDoc(t, "a", "x", 1)); got[0] != tc.want {
				t.Errorf("Decide(%s) = %+v, want %+v", tc.condition, got[0], tc.want)
			}
		})
	}
}

// The filter reads subject.isM2M in a comparison as the check does.
func TestAComparisonWithSubjectIsM2MIsFiltered(t *testing.T) {
	for _, tc := range []struct{ condition, want string }{
		{"subject.isM2M IS NULL", allow},
		{"subject.isM2M == true", deny},
	} {
		t.Run(tc.condition, func(t *testing.T) {
			r := New(Config{}, tab(t), quiet{})
			load(t, r, ``, set("a", tc.condition))
			if got := filterOf(t, r, "a", "read"); got != tc.want {
				t.Errorf("Filter(doc, read) with %s = %s, want %s", tc.condition, got, tc.want)
			}
		})
	}
}

// denyWhere is a DENY_OVERRIDES set of tenant a on the resource type doc:
// one rule allows every operation, and one denies where condition holds.
func denyWhere(condition string) string {
	return fmt.Sprintf(`{"policySetId": "s", "name": "s", "status": "ACTIVE", "tenantId": "a",
		"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_OVERRIDES",
		"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "a",
			"rules": [{"ruleId": "allow", "target": "true", "effect": "ALLOW", "tenantId": "a"},
				{"ruleId": "deny", "target": "true", "condition": %q, "effect": "DENY", "tenantId": "a"}]}]}`,
		condition)
}

// A deep scan the jsonpath package stops as too large leaves a DENY rule
// over it unknown, so the item is denied as on a failed source. Such a
// selection used to fall on neither rail of a two-valued leaf, and the DENY
// rule did not apply. A resource without the member is the control that
// the ALLOW rule allows.
func TestADenyOverASelectionTooLargeDenies(t *testing.T) {
	r := New(Config{}, tab(t), quiet{})
	load(t, r, ``, denyWhere("resource..secret IS NOT NULL"))
	nested := strings.Repeat(`{"secret":`, 40) + `1` + strings.Repeat(`}`, 40)
	for _, tc := range []struct {
		name, resource string
		want           Result
	}{
		{"secret nested 40 deep", nested, Result{Reason: ReasonUnknown}},
		{"no secret", `{"a": 1}`, Result{Allowed: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := readDoc(t, "a", "x", 1)
			req.Items[0].Resource = mustObject(t, tc.resource)
			if got := decide(t, r, req); got[0] != tc.want {
				t.Errorf("Decide(resource %.40s) = %+v, want %+v", tc.resource, got[0], tc.want)
			}
		})
	}
}

// broken is a condition the agent's parser refuses, which rejects the
// candidate of its tenant as a whole.
const broken = "resource.a =="

// A tenant whose new candidate is refused keeps answering from its previous
// snapshot and names the refusal in its health, while another tenant of the
// same load is published.
func TestARefusedCandidateKeepsThePreviousSnapshot(t *testing.T) {
	r := New(Config{}, tab(t), quiet{})
	load(t, r, ``, set("a", "true"), set("b", "resource.a == 'x'"))
	sum := load(t, r, ``, set("a", broken), set("b", "true"))

	if sum.Rejected != 1 || sum.Generated != 1 {
		t.Errorf("Load summary = %+v, want 1 refused and 1 generated", sum)
	}
	if got := decide(t, r, readDoc(t, "a", "y", 1)); !got[0].Allowed {
		t.Errorf("Decide(tenant a) = %+v, want allowed by the previous snapshot", got[0])
	}
	if got := decide(t, r, readDoc(t, "b", "y", 1)); !got[0].Allowed {
		t.Errorf("Decide(tenant b) = %+v, want allowed by the new snapshot", got[0])
	}
	th, _ := tenantHealth(r, "a")
	if !th.Ready || th.Rejected == nil || th.Rejected.Stage != "unsupported" || len(th.Rejected.Forms) == 0 {
		t.Errorf("health of a = %+v, want ready with a refusal at stage unsupported naming the form", th)
	}
}

// warnings records the warnings a registry writes, formatted.
type warnings struct {
	quiet
	lines []string
}

func (w *warnings) Warnf(format string, args ...any) { w.lines = append(w.lines, fmt.Sprintf(format, args...)) }

// A load warns of each element the export leaves out, each element that
// names no tenant, and each part of a published snapshot that answers as a
// failed source; a later load warns only of what the previous one did not
// have.
func TestALoadWarnsOfWhatItLeavesOutOnce(t *testing.T) {
	w := &warnings{}
	r := New(Config{}, tab(t), w)
	inactive := strings.Replace(set("a", "true"), `"ACTIVE"`, `"INACTIVE"`, 1)
	inactive = strings.Replace(inactive, `"s-a"`, `"s-a2"`, 1)
	orphan := strings.Replace(set("", "true"), `"tenantId": ""`, `"x": 1`, 1)
	load(t, r, ``, set("a", "subject.g == 'x'"), inactive, orphan)

	want := []string{
		`policies: tenant a: left out of the policies: policy set 1 "s-a2": status INACTIVE`,
		`policies: tenant a: answers as a failed source: policy set s-a: PIP subject.g: not declared`,
		`policies: left out of the policies: policy set 2: tenantId absent, empty, or not a string`,
	}
	slices.Sort(want)
	got := slices.Sorted(slices.Values(w.lines))
	if !slices.Equal(got, want) {
		t.Errorf("warnings of the first load:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	w.lines = nil
	inactive3 := strings.Replace(inactive, `"s-a2"`, `"s-a3"`, 1)
	load(t, r, ``, set("a", "subject.g == 'x'"), inactive, orphan, set("b", "true"), inactive3)
	if want := []string{`policies: tenant a: left out of the policies: policy set 4 "s-a3": status INACTIVE`}; !slices.Equal(w.lines, want) {
		t.Errorf("warnings of a load that adds a tenant b and an inactive set s-a3 = %q, want %q", w.lines, want)
	}
}

// On its first load a refused tenant has no snapshot: it is not ready and
// denies every request, and the other tenants are served.
func TestATenantRefusedOnItsFirstLoadIsNotServed(t *testing.T) {
	r := New(Config{}, tab(t), quiet{})
	load(t, r, ``, set("a", broken), set("b", "true"))

	if got := decide(t, r, readDoc(t, "a", "y", 1)); got[0].Allowed || got[0].Reason != "no policies are published for tenant a" {
		t.Errorf("Decide(tenant a) = %+v, want denied as unpublished", got[0])
	}
	if got := decide(t, r, readDoc(t, "b", "y", 1)); !got[0].Allowed {
		t.Errorf("Decide(tenant b) = %+v, want allowed", got[0])
	}
	if th, _ := tenantHealth(r, "a"); th.Ready || th.Rejected == nil {
		t.Errorf("health of a = %+v, want not ready with the refusal", th)
	}
}

// A condition that reads a PIP whose jsonPath the agent does not compile
// rejects its tenant whole, naming the PIP; the tenant beside it is served.
// The same PIP declared and read by no condition rejects nothing.
func TestAPIPWithAJSONPathOutsideTheSubsetRejectsTheTenantThatReadsIt(t *testing.T) {
	pip := func(tenant string) string {
		return `{"tenantId": "` + tenant + `", "name": "subject.g", "pipType": "GENERAL", "type": "JSON",
			"url": "http://pip.invalid", "jsonPath": "$.a.concat('x')"}`
	}
	r := New(Config{}, tab(t), quiet{})
	load(t, r, pip("a")+`, `+pip("b"), set("a", "subject.g == 'x'"), set("b", "true"))

	th, _ := tenantHealth(r, "a")
	if th.Ready || th.Rejected == nil || th.Rejected.Stage != "unsupported" || len(th.Rejected.Forms) != 1 ||
		th.Rejected.Forms[0].Form != "jsonpath" || !strings.Contains(th.Rejected.Forms[0].Text, "subject.g") {
		t.Errorf("health of a = %+v, want not ready, refused as unsupported with one jsonpath form naming subject.g", th)
	}
	if got := decide(t, r, readDoc(t, "b", "y", 1)); !got[0].Allowed {
		t.Errorf("Decide(tenant b) = %+v, want allowed", got[0])
	}
}

// A filter predicate that reads a GENERAL or FILTERED PIP whose jsonPath the
// agent does not compile, by a placeholder or by the first word of a
// customPredicate parameter, rejects its tenant whole, naming the PIP and the
// predicate; the tenant beside it is served. An escaped placeholder, a
// parameter whose first word is empty, and a PIP of another type or declared
// twice read no such path, and reject nothing.
func TestAPredicateOverAPIPWithAJSONPathOutsideTheSubsetRejectsTheTenant(t *testing.T) {
	rule := func(predicate string) string {
		return `{"ruleId": "r", "target": "true", "effect": "ALLOW", "tenantId": "a", ` + predicate + `}`
	}
	regular := func(predicate string) string {
		return `{"policySetId": "s-a", "name": "s", "status": "ACTIVE", "tenantId": "a",
			"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "a",
				"rules": [` + rule(predicate) + `]}]}`
	}
	nested := `{"policySetId": "s-a", "name": "s", "status": "ACTIVE", "tenantId": "a",
		"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
		"policySets": [{"policySetId": "n", "name": "n", "status": "ACTIVE", "tenantId": "a", "target": "true",
			"combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "a",
				"rules": [` + rule(`"rsqlPredicate": "a==${subject.g}"`) + `]}]}]}`
	simplified := `{"policySetId": "s-a", "type": "SIMPLIFIED", "tenantId": "a", "domain": "D", "component": "C",
		"combiningAlgorithm": "DENY_UNLESS_PERMIT", "target": "resourceType == 'doc'",
		"policies": [{"policyId": "p", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "target": "operation == 'read'",
			"tenantId": "a", "rules": [{"ruleId": "r", "effect": "ALLOW", "tenantId": "a",
				"target": "subject.roles CONTAINS ANY 'R'", "rsqlPredicate": "a==${subject.g}"}]}]}`
	rejected := []struct{ name, pipType, set, where string }{
		{"a placeholder", "GENERAL", regular(`"rsqlPredicate": "a==${subject.g}"`), `set "s-a" > policy "p" > rule "r" > predicate`},
		{"a customPredicate parameter", "GENERAL", regular(`"customPredicate": {"predicate": "owner", "params": {"x": "subject.g"}}`),
			`set "s-a" > policy "p" > rule "r" > predicate`},
		{"a FILTERED PIP", "FILTERED", regular(`"rsqlPredicate": "a==${subject.g}"`), `set "s-a" > policy "p" > rule "r" > predicate`},
		{"a nested set", "GENERAL", nested, `set "s-a" > set "n" > policy "p" > rule "r" > predicate`},
		{"a simplified policy", "GENERAL", simplified, `simplified "D"/"C"/"doc" > policy "r" > predicate`},
	}
	served := []struct{ name, pips, set string }{
		{"an escaped placeholder", "", regular(`"rsqlPredicate": "a==$${subject.g}"`)},
		{"a parameter whose first word is empty", "", regular(`"customPredicate": {"predicate": "owner", "params": {"x": " subject.g"}}`)},
		{"a HEADER PIP", `{"tenantId": "a", "name": "subject.g", "pipType": "HEADER", "header": "h", "jsonPath": "$.a.concat('x')"}`,
			regular(`"rsqlPredicate": "a==${subject.g}"`)},
		{"a PIP declared twice", "twice", regular(`"rsqlPredicate": "a==${subject.g}"`)},
	}
	pip := func(tenant, pipType string) string {
		return `{"tenantId": "` + tenant + `", "name": "subject.g", "pipType": "` + pipType + `", "type": "JSON",
			"url": "http://pip.invalid", "jsonPath": "$.a.concat('x')"}`
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			r := New(Config{}, tab(t), quiet{})
			load(t, r, pip("a", tc.pipType)+`, `+pip("b", tc.pipType), tc.set, set("b", "true"))

			th, _ := tenantHealth(r, "a")
			want := []Form{{Where: tc.where, Form: "jsonpath",
				Text: `jsonPath "$.a.concat('x')" of PIP subject.g: jsonpath: unsupported path: ".a.concat('x')"`}}
			if th.Ready || th.Rejected == nil || th.Rejected.Stage != "unsupported" || !slices.Equal(th.Rejected.Forms, want) {
				t.Errorf("health of a = %+v, refused %+v, want not ready, refused as unsupported with forms %+v", th, th.Rejected, want)
			}
			if got := decide(t, r, readDoc(t, "b", "y", 1)); !got[0].Allowed {
				t.Errorf("Decide(tenant b) = %+v, want allowed", got[0])
			}
		})
	}
	for _, tc := range served {
		t.Run(tc.name, func(t *testing.T) {
			pips := tc.pips
			switch pips {
			case "":
				pips = pip("a", "GENERAL")
			case "twice":
				pips = pip("a", "GENERAL") + `, ` + pip("a", "GENERAL")
			}
			r := New(Config{}, tab(t), quiet{})
			load(t, r, pips, tc.set)

			if th, _ := tenantHealth(r, "a"); !th.Ready || th.Rejected != nil {
				t.Errorf("health of a = %+v, want ready and not refused", th)
			}
		})
	}
}

// LoadSnapshots fails with a *RefusedError for as long as a tenant's latest
// candidate is refused: on the load that refuses it, on a load of the same
// documents, and on a load that changes only another tenant. The load that
// publishes the tenant's new tree succeeds.
func TestLoadSnapshotsFailsWhileACandidateIsRefused(t *testing.T) {
	r := New(Config{}, tab(t), quiet{})
	if err := loadSnapshots(r, set("a", "true"), set("b", "true")); err != nil {
		t.Fatalf("LoadSnapshots of two valid tenants = %v, want nil", err)
	}
	steps := []struct {
		name string
		sets []string
	}{
		{"the refusing load", []string{set("a", broken), set("b", "true")}},
		{"the same documents again", []string{set("a", broken), set("b", "true")}},
		{"a change to another tenant", []string{set("a", broken), set("b", "resource.a == 'x'")}},
	}
	for _, step := range steps {
		err := loadSnapshots(r, step.sets...)
		var refused *RefusedError
		if !errors.As(err, &refused) {
			t.Errorf("LoadSnapshots after %s = %v, want a *RefusedError", step.name, err)
			continue
		}
		if len(refused.Tenants) != 1 || refused.Tenants[0].Tenant != "a" || !refused.Tenants[0].Served ||
			refused.Tenants[0].Stage != "unsupported" {
			t.Errorf("LoadSnapshots after %s refused %+v, want tenant a served by its previous snapshot at stage unsupported",
				step.name, refused.Tenants)
		}
		if !strings.Contains(err.Error(), "tenant a: candidate snapshot refused, the previous snapshot stays: unsupported: ") {
			t.Errorf("LoadSnapshots after %s = %q, want the tenant, what it keeps, and the stage", step.name, err)
		}
		if got := refused.Unserved(); got != nil {
			t.Errorf("Unserved() after %s = %q, want none: tenant a keeps its previous snapshot", step.name, got)
		}
	}
	if err := loadSnapshots(r, set("a", "true"), set("b", "true")); err != nil {
		t.Errorf("LoadSnapshots after tenant a is repaired = %v, want nil", err)
	}
}

// A tenant refused on its first load is named as not served.
func TestLoadSnapshotsNamesARefusedTenantWithNoSnapshotAsNotServed(t *testing.T) {
	r := New(Config{}, tab(t), quiet{})

	err := loadSnapshots(r, set("a", broken), set("b", "true"))

	var refused *RefusedError
	if !errors.As(err, &refused) || len(refused.Tenants) != 1 || refused.Tenants[0].Served {
		t.Fatalf("LoadSnapshots = %v, want a *RefusedError naming tenant a as not served", err)
	}
	if !strings.Contains(err.Error(), "tenant a: candidate snapshot refused, the tenant is not served: ") {
		t.Errorf("LoadSnapshots = %q, want the tenant and that it is not served", err)
	}
	if got := refused.Unserved(); !reflect.DeepEqual(got, []string{"a"}) {
		t.Errorf("Unserved() = %q, want [a]", got)
	}
	if _, ok := r.Snapshot("b"); !ok {
		t.Error("tenant b has no snapshot, want it published beside the refusal")
	}
}

// Refused tenants are named in the order of their IDs, and a load of the
// same documents, which the registry skips, names them with the same text.
// The pull reports a refusal only when its text changes, so a text that
// differed between the two loads would be reported on every pull.
func TestLoadSnapshotsNamesRefusedTenantsInOrderAcrossLoads(t *testing.T) {
	r := New(Config{}, tab(t), quiet{})
	first := loadSnapshots(r, set("b", broken), set("c", "true"), set("a", broken))
	second := loadSnapshots(r, set("b", broken), set("c", "true"), set("a", broken))

	var refused *RefusedError
	if !errors.As(first, &refused) {
		t.Fatalf("LoadSnapshots = %v, want a *RefusedError", first)
	}
	var tenants []string
	for _, tr := range refused.Tenants {
		tenants = append(tenants, tr.Tenant)
	}
	if !reflect.DeepEqual(tenants, []string{"a", "b"}) {
		t.Errorf("refused tenants = %q, want [a b]", tenants)
	}
	if second == nil || second.Error() != first.Error() {
		t.Errorf("LoadSnapshots of the same documents =\n%v\nwant\n%v", second, first)
	}
}

// A load in which a tenant's tree is unchanged keeps the tenant's snapshot
// as it was, and an unchanged refused tree is neither generated nor counted
// as refused again.
func TestAnUnchangedTreeIsNotGeneratedAgain(t *testing.T) {
	r := New(Config{}, tab(t), quiet{})
	load(t, r, ``, set("a", "true"), set("b", broken))
	before, _ := r.Snapshot("a")
	sum := load(t, r, ``, set("a", "true"), set("b", broken), set("c", "true"))

	if after, _ := r.Snapshot("a"); after != before {
		t.Errorf("snapshot of a after an unchanged load = %p, want the same %p", after, before)
	}
	if sum.Kept != 1 || sum.Generated != 1 || sum.Rejected != 0 {
		t.Errorf("Load summary = %+v, want a kept, c generated, and b not refused again", sum)
	}
}

// pipServer answers every call with body and counts the calls.
func pipServer(t *testing.T, status int, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func pipRegistry(t *testing.T) *Registry {
	t.Helper()
	return New(Config{HTTP: &regobuiltins.HTTP{Client: &http.Client{},
		Token: func() (string, error) { return "own", nil }}}, tab(t), quiet{})
}

func generalPIP(url, cacheable string) string {
	return `{"tenantId": "a", "name": "subject.g", "pipType": "GENERAL", "url": "` + url +
		`", "httpMethod": "GET"` + cacheable + `}`
}

// The items of one bulk request share one call of the PIP, and the next
// decision request calls it again, though the PIP declares itself
// cacheable: no answer outlives its decision request.
func TestTheItemsOfABulkRequestShareOneCall(t *testing.T) {
	srv, calls := pipServer(t, http.StatusOK, `["x"]`)
	r := pipRegistry(t)
	load(t, r, generalPIP(srv.URL, `, "cacheable": true`), set("a", "subject.g == 'x'"))

	decide(t, r, readDoc(t, "a", "y", 5))
	if n := calls.Load(); n != 1 {
		t.Errorf("calls of the PIP for a bulk of 5 = %d, want 1", n)
	}
	decide(t, r, readDoc(t, "a", "y", 1))
	if n := calls.Load(); n != 2 {
		t.Errorf("calls of the PIP after the next request = %d, want 2", n)
	}
}

// A panic while an item of a bulk request is evaluated on a worker reaches
// the caller of Decide, whose goroutine the server recovers, instead of
// ending the process on the worker.
func TestAPanicInABulkItemReachesTheCaller(t *testing.T) {
	srv, _ := pipServer(t, http.StatusOK, `["x"]`)
	r := New(Config{BulkWorkers: 4, HTTP: &regobuiltins.HTTP{Client: &http.Client{},
		Token: func() (string, error) { panic("token exploded") }}}, tab(t), quiet{})
	load(t, r, generalPIP(srv.URL, ``), set("a", "subject.g == 'x'"))

	defer func() {
		if p := recover(); p == nil || !strings.Contains(fmt.Sprint(p), "token exploded") {
			t.Errorf("Decide of a bulk of 5 panicked with %v, want the worker's panic, token exploded", p)
		}
	}()
	_, _ = r.Decide(context.Background(), readDoc(t, "a", "y", 5))
}

// A denial that rests on a source the agent cannot read names it.
func TestADenialOnAnUnreadSourceNamesIt(t *testing.T) {
	for _, tc := range []struct {
		name, pips, set, want string
	}{
		{"an undeclared PIP", ``, set("a", "subject.entitledResources == 'x'"),
			ReasonUnknown + ": subject.entitledResources"},
		{"entitlements without the service's URL", ``,
			set("a", "subject.entitledResources.of('doc').as('owner') CONTAINS resource.a"),
			ReasonUnknown + `: ["ent","doc",["owner"]]`},
		{"a permission scope without a PERMISSION_SCOPE PIP", ``, scopeSet("a"), ReasonUnknown + ": subject.permissionScope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := New(Config{}, tab(t), quiet{})
			load(t, r, tc.pips, tc.set)

			got := decide(t, r, readDoc(t, "a", "y", 1))

			if want := (Result{Reason: tc.want}); got[0] != want {
				t.Errorf("Decide = %+v, want %+v", got[0], want)
			}
		})
	}
}

// A denial that rests on a PIP whose call failed names the PIP.
func TestADenialOnAFailedPIPNamesIt(t *testing.T) {
	srv, _ := pipServer(t, http.StatusInternalServerError, `oops`)
	r := pipRegistry(t)
	load(t, r, generalPIP(srv.URL, ""), set("a", "subject.g == 'x'"))

	got := decide(t, r, readDoc(t, "a", "y", 1))

	if want := (Result{Reason: "PIP resolution failed: subject.g"}); got[0] != want {
		t.Errorf("Decide = %+v, want %+v", got[0], want)
	}
}

// A DENY rule over a PIP whose call failed denies, as the PIP's value is
// unknown: MATCH, where the table gives the failure the outcome false, as
// well as an equality, where it gives an unknown one. MATCH over a failed
// PIP used to be false, and the ALLOW rule allowed. The PIP answering a
// value the pattern does not match is the control that the ALLOW rule
// allows.
func TestADenyOverAFailedPIPDenies(t *testing.T) {
	for _, tc := range []struct {
		name, condition string
		status          int
		want            Result
	}{
		{"MATCH over a failed PIP", "subject.g MATCH block*", http.StatusInternalServerError,
			Result{Reason: "PIP resolution failed: subject.g"}},
		{"an equality over a failed PIP", "subject.g == 'blocked'", http.StatusInternalServerError,
			Result{Reason: "PIP resolution failed: subject.g"}},
		{"NOT MATCH over a failed PIP", "subject.g NOT MATCH other", http.StatusInternalServerError,
			Result{Reason: "PIP resolution failed: subject.g"}},
		{"MATCH over a value outside the pattern", "subject.g MATCH block*", http.StatusOK, Result{Allowed: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := pipServer(t, tc.status, `["other"]`)
			r := pipRegistry(t)
			load(t, r, generalPIP(srv.URL, ""), denyWhere(tc.condition))
			if got := decide(t, r, readDoc(t, "a", "x", 1)); got[0] != tc.want {
				t.Errorf("Decide(%s, PIP status %d) = %+v, want %+v", tc.condition, tc.status, got[0], tc.want)
			}
		})
	}
}

// A target that is undefined, as one over a PIP whose call failed is, makes
// its node deny where the node denies once the target holds, and not apply
// otherwise, so the policy beside it allows. Each such node used to deny,
// whatever it held: a policy of ALLOW rules alone denied every resource.
// What the node gives is computed on the request: a DENY rule whose condition
// is false, or a DENY_UNLESS_PERMIT policy whose ALLOW rule applies, does not
// deny, while a DENY_UNLESS_PERMIT policy whose ALLOW rule does not apply
// denies.
func TestAnUndefinedTargetDeniesOnlyWhereItsNodeDenies(t *testing.T) {
	const failed = "subject.g == 'x'"
	for _, tc := range []struct {
		name, policyTarget, alg, ruleTarget, effect, condition string
		allowed                                                bool
	}{
		{"a policy target over a failed PIP and an ALLOW rule", failed, "DENY_OVERRIDES", "true", "ALLOW", "true", true},
		{"a policy target over a failed PIP and a DENY rule", failed, "DENY_OVERRIDES", "true", "DENY", "true", false},
		{"a policy target over a failed PIP and a DENY rule whose condition reads it", failed, "DENY_OVERRIDES",
			"true", "DENY", "subject.g == 'blocked'", false},
		{"a policy target over a failed PIP and a DENY rule whose condition is false", failed, "DENY_OVERRIDES",
			"true", "DENY", "operation == 'write'", true},
		{"a policy target over a failed PIP and DENY_UNLESS_PERMIT that permits", failed, "DENY_UNLESS_PERMIT",
			"true", "ALLOW", "true", true},
		{"a policy target over a failed PIP and DENY_UNLESS_PERMIT that denies", failed, "DENY_UNLESS_PERMIT",
			"true", "ALLOW", "operation == 'write'", false},
		{"a rule target over a failed PIP and an ALLOW rule", "true", "DENY_OVERRIDES", failed, "ALLOW", "true", true},
		{"a rule target over a failed PIP and a DENY rule", "true", "DENY_OVERRIDES", failed, "DENY", "true", false},
		{"a rule target over a failed PIP and a DENY rule whose condition is false", "true", "DENY_OVERRIDES", failed,
			"DENY", "operation == 'write'", true},
		{"a policy target over a path with a trailing dot and an ALLOW rule", "resource.a. == 'x'", "DENY_OVERRIDES",
			"true", "ALLOW", "true", true},
		{"a policy target over a path with a trailing dot and a DENY rule", "resource.a. == 'x'", "DENY_OVERRIDES",
			"true", "DENY", "true", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := pipServer(t, http.StatusInternalServerError, `oops`)
			r := pipRegistry(t)
			load(t, r, generalPIP(srv.URL, ""), fmt.Sprintf(`{"policySetId": "s", "name": "s", "status": "ACTIVE",
				"tenantId": "a", "target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_OVERRIDES",
				"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "a",
					"rules": [{"ruleId": "allow", "target": "true", "effect": "ALLOW", "tenantId": "a"}]},
					{"policyId": "q", "target": %q, "combiningAlgorithm": %q, "tenantId": "a",
					"rules": [{"ruleId": "r", "target": %q, "condition": %q, "effect": %q, "tenantId": "a"}]}]}`,
				tc.policyTarget, tc.alg, tc.ruleTarget, tc.condition, tc.effect))
			if got := decide(t, r, readDoc(t, "a", "x", 1)); got[0].Allowed != tc.allowed {
				t.Errorf("Decide = %+v, want allowed %v", got[0], tc.allowed)
			}
		})
	}
}

// loneAllowPolicySet is a set of tenant a on doc under setAlg whose one
// policy, under policyTarget, holds an ALLOW rule under ruleTarget.
func loneAllowPolicySet(setAlg, policyTarget, ruleTarget string) string {
	return fmt.Sprintf(`{"policySetId": "s", "name": "s", "status": "ACTIVE", "tenantId": "a",
		"target": "resourceType == 'doc'", "combiningAlgorithm": %q,
		"policies": [{"policyId": "q", "target": %q, "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "a",
			"rules": [{"ruleId": "r", "target": %q, "effect": "ALLOW", "tenantId": "a"}]}]}`,
		setAlg, policyTarget, ruleTarget)
}

// A policy of ALLOW rules under a target over a PIP whose call failed does
// not apply, so the set's algorithm decides as over no child:
// PERMIT_UNLESS_DENY allows, as legacy does, and DENY_UNLESS_PERMIT denies.
// It neither permits nor denies, whether the failed read is in the policy
// target or in the rule target.
func TestAnAllowPolicyUnderAnUndefinedTargetLeavesTheSetToItsAlgorithm(t *testing.T) {
	const failed = "subject.g == 'x'"
	for _, tc := range []struct {
		setAlg, policyTarget, ruleTarget string
		allowed                          bool
	}{
		{"PERMIT_UNLESS_DENY", failed, "true", true},
		{"PERMIT_UNLESS_DENY", "true", failed, true},
		{"DENY_UNLESS_PERMIT", failed, "true", false},
		{"DENY_UNLESS_PERMIT", "true", failed, false},
	} {
		t.Run(tc.setAlg+" "+tc.policyTarget+" "+tc.ruleTarget, func(t *testing.T) {
			srv, _ := pipServer(t, http.StatusInternalServerError, `oops`)
			r := pipRegistry(t)
			load(t, r, generalPIP(srv.URL, ""), loneAllowPolicySet(tc.setAlg, tc.policyTarget, tc.ruleTarget))
			if got := decide(t, r, readDoc(t, "a", "x", 1)); got[0].Allowed != tc.allowed {
				t.Errorf("Decide = %+v, want allowed %v", got[0], tc.allowed)
			}
		})
	}
}

// besideAllow is a set of tenant a on doc under setAlg with two policies: one
// allows every operation, and one, under policyTarget, holds a rule of effect
// under ruleTarget with condition.
func besideAllow(setAlg, policyTarget, ruleTarget, effect, condition string) string {
	return fmt.Sprintf(`{"policySetId": "s", "name": "s", "status": "ACTIVE", "tenantId": "a",
		"target": "resourceType == 'doc'", "combiningAlgorithm": %q,
		"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "a",
			"rules": [{"ruleId": "allow", "target": "true", "effect": "ALLOW", "tenantId": "a"}]},
			{"policyId": "q", "target": %q, "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "a",
			"rules": [{"ruleId": "r", "target": %q, "condition": %q, "effect": %q, "tenantId": "a"}]}]}`,
		setAlg, policyTarget, ruleTarget, condition, effect)
}

// A rule that applies and whose condition is unknown because it reads a PIP
// whose call failed denies the resource, whatever its effect and whatever the
// policy beside it gives, as legacy answers. Such a rule used to leave the
// decision to the other rules: an ALLOW rule did not apply, and a DENY rule
// lost to the ALLOW beside it under PERMIT_OVERRIDES. A condition that the
// other operand of an OR makes true does not depend on the failed value, in
// either operand order. A policy or rule target over the failed PIP is
// undefined, which makes the rule one that can deny, so it denies the
// resource too.
func TestARuleWhoseConditionReadsAFailedPIPDeniesTheResource(t *testing.T) {
	const failed = "subject.g == 'y'"
	denied := Result{Reason: "PIP resolution failed: subject.g"}
	for _, tc := range []struct {
		name, setAlg, policyTarget, ruleTarget, effect, condition string
		want                                                      Result
	}{
		{"an ALLOW rule, DENY_OVERRIDES", "DENY_OVERRIDES", "true", "true", "ALLOW", failed, denied},
		{"an ALLOW rule, PERMIT_UNLESS_DENY", "PERMIT_UNLESS_DENY", "true", "true", "ALLOW", failed, denied},
		{"an ALLOW rule, PERMIT_OVERRIDES", "PERMIT_OVERRIDES", "true", "true", "ALLOW", failed, denied},
		{"a DENY rule, PERMIT_OVERRIDES", "PERMIT_OVERRIDES", "true", "true", "DENY", failed, denied},
		{"a DENY rule, DENY_OVERRIDES", "DENY_OVERRIDES", "true", "true", "DENY", failed, denied},
		{"a true operand OR the failed one", "DENY_OVERRIDES", "true", "true", "ALLOW",
			"resource.a == 'x' OR " + failed, Result{Allowed: true}},
		{"the failed operand OR a true one", "DENY_OVERRIDES", "true", "true", "ALLOW",
			failed + " OR resource.a == 'x'", Result{Allowed: true}},
		{"a false operand AND the failed one", "DENY_OVERRIDES", "true", "true", "DENY",
			"resource.a == 'z' AND " + failed, Result{Allowed: true}},
		{"the failed operand AND a false one", "DENY_OVERRIDES", "true", "true", "DENY",
			failed + " AND resource.a == 'z'", Result{Allowed: true}},
		{"an ALLOW rule over a PIP that is not declared, PERMIT_OVERRIDES", "PERMIT_OVERRIDES", "true", "true",
			"ALLOW", "subject.h == 'y'", Result{Reason: "PIP resolution failed: subject.h"}},
		{"a policy target that is false", "DENY_OVERRIDES", "operation == 'write'", "true", "ALLOW", failed,
			Result{Allowed: true}},
		{"a policy target over the failed PIP, DENY_OVERRIDES", "DENY_OVERRIDES", failed, "true", "ALLOW", failed, denied},
		{"a policy target over the failed PIP, PERMIT_OVERRIDES", "PERMIT_OVERRIDES", failed, "true", "ALLOW", failed,
			denied},
		{"a rule target over the failed PIP, a DENY rule, PERMIT_OVERRIDES", "PERMIT_OVERRIDES", "true", failed, "DENY",
			failed, denied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := pipServer(t, http.StatusInternalServerError, `oops`)
			r := pipRegistry(t)
			load(t, r, generalPIP(srv.URL, ""), besideAllow(tc.setAlg, tc.policyTarget, tc.ruleTarget, tc.effect,
				tc.condition))
			if got := decide(t, r, readDoc(t, "a", "x", 1)); got[0] != tc.want {
				t.Errorf("Decide(%s %s rule if %s) = %+v, want %+v", tc.setAlg, tc.effect, tc.condition, got[0], tc.want)
			}
		})
	}
}

// A PIP the tenant declares twice has no usable declaration, and a rule that
// reads it denies the resource as one over a PIP whose call failed does,
// beside a policy that allows; the filter denies every row.
func TestARuleOverAPIPDeclaredTwiceDeniesTheResource(t *testing.T) {
	srv, _ := pipServer(t, http.StatusOK, `["y"]`)
	r := pipRegistry(t)
	load(t, r, generalPIP(srv.URL, "")+", "+generalPIP(srv.URL, ""),
		besideAllow("PERMIT_OVERRIDES", "true", "true", "ALLOW", "subject.g == 'y'"))
	if got, want := decide(t, r, readDoc(t, "a", "x", 1))[0], (Result{Reason: "PIP resolution failed: subject.g"}); got != want {
		t.Errorf("Decide(read doc) = %+v, want %+v", got, want)
	}
	if got := filterOf(t, r, "a", "read"); got != deny {
		t.Errorf("Filter(doc, read) = %s, want %s", got, deny)
	}
}

// A condition that is unknown for a value alone keeps its bounds beside a
// policy that allows: resource.a. is undefined on the doc, and the PIP the
// condition also reads answers. With the PIP failed, the same rule denies
// the resource, unless a known operand settles the failed one: an AND with a
// false operand, or a comparison that is false for every value of the PIP.
func TestAnUnknownConditionWithoutAFailedSourceDoesNotDeny(t *testing.T) {
	for _, tc := range []struct {
		name, condition string
		status          int
		want            Result
	}{
		{"the PIP answers", "resource.a. == 'q' AND subject.g == 'x'", http.StatusOK, Result{Allowed: true}},
		{"the PIP failed", "resource.a. == 'q' AND subject.g == 'x'", http.StatusInternalServerError,
			Result{Reason: "PIP resolution failed: subject.g"}},
		{"the failed PIP under an AND with a false operand", "resource.a. == 'q' OR resource.b == 'no' AND subject.g == 'x'",
			http.StatusInternalServerError, Result{Allowed: true}},
		{"the failed PIP in a comparison false for every value", "resource.a. == 'q' OR subject.g IN resource.c",
			http.StatusInternalServerError, Result{Allowed: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := pipServer(t, tc.status, `["x"]`)
			r := pipRegistry(t)
			load(t, r, generalPIP(srv.URL, ""), besideAllow("DENY_OVERRIDES", "true", "true", "ALLOW", tc.condition))
			req := readDoc(t, "a", "x", 1)
			req.Items[0].Resource = mustObject(t, `{"a": "x", "b": "yes"}`)
			if got := decide(t, r, req); got[0] != tc.want {
				t.Errorf("Decide(%s, PIP status %d) = %+v, want %+v", tc.condition, tc.status, got[0], tc.want)
			}
		})
	}
}

// In a bulk request, a condition over a failed PIP denies only the item
// whose answer depends on the failed value: the doc whose member a is x
// makes the OR true and is allowed, and the doc whose member a is z is
// denied.
func TestAFailedPIPDeniesOnlyTheItemWhoseConditionDependsOnIt(t *testing.T) {
	srv, _ := pipServer(t, http.StatusInternalServerError, `oops`)
	r := pipRegistry(t)
	load(t, r, generalPIP(srv.URL, ""), besideAllow("DENY_OVERRIDES", "true", "true", "ALLOW",
		"resource.a == 'x' OR subject.g == 'y'"))
	req := readDoc(t, "a", "x", 1)
	req.Items = append(req.Items, regogen.Body{Operation: "read", ResourceType: "doc",
		Resource: mustObject(t, `{"a": "z"}`), HasResource: true})
	got := decide(t, r, req)
	want := []Result{{Allowed: true}, {Reason: "PIP resolution failed: subject.g"}}
	if !slices.Equal(got, want) {
		t.Errorf("Decide(a=x, a=z) = %+v, want %+v", got, want)
	}
}

// entitled is a target over the entitlements service.
const entitled = "subject.entitledResources.of('doc').as('owner') CONTAINS 'e1'"

// failedEntitlementsRegistry is a registry whose entitlements service
// answers every read with 404.
func failedEntitlementsRegistry(t *testing.T) *Registry {
	t.Helper()
	srv, _ := countingServer(t, "/nowhere", ``)
	return New(Config{Entitlements: srv.URL, HTTP: &regobuiltins.HTTP{Client: &http.Client{},
		Token: func() (string, error) { return "own", nil }}}, tab(t), quiet{})
}

// A policy of ALLOW rules whose target reads the entitlements service, which
// fails, does not apply: PERMIT_UNLESS_DENY allows, as legacy does, and
// DENY_UNLESS_PERMIT denies.
func TestAnAllowPolicyUnderAFailedEntitlementsReadDoesNotApply(t *testing.T) {
	for _, tc := range []struct {
		setAlg, policyTarget, ruleTarget string
		allowed                          bool
	}{
		{"PERMIT_UNLESS_DENY", entitled, "true", true},
		{"PERMIT_UNLESS_DENY", "true", entitled, true},
		{"DENY_UNLESS_PERMIT", entitled, "true", false},
	} {
		t.Run(tc.setAlg+" "+tc.policyTarget+" "+tc.ruleTarget, func(t *testing.T) {
			r := failedEntitlementsRegistry(t)
			load(t, r, ``, loneAllowPolicySet(tc.setAlg, tc.policyTarget, tc.ruleTarget))
			if got := decide(t, r, readDoc(t, "a", "x", 1)); got[0].Allowed != tc.allowed {
				t.Errorf("Decide = %+v, want allowed %v", got[0], tc.allowed)
			}
		})
	}
}

// scopeSet is a policy set of tenant that iterates over the permission
// scope and allows the operation read on a doc whose member a is a domain
// of the pass.
func scopeSet(tenant string) string {
	return fmt.Sprintf(`{"policySetId": "s-%[1]s", "name": "s", "status": "ACTIVE", "tenantId": %[1]q,
		"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
		"iterate": {"foreach": "subject.permissionScope", "combiningAlgorithm": "DENY_UNLESS_PERMIT"},
		"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"tenantId": %[1]q, "rules": [{"ruleId": "r", "target": "operation == 'read'",
				"condition": "subject.permissionScope.domain CONTAINS resource.a", "effect": "ALLOW", "tenantId": %[1]q}]}]}`,
		tenant)
}

// A role the tenant's MAPPING PIP maps grants its permissions, which a
// condition on subject.permissions reads.
func TestTheMappingTablesGrantPermissions(t *testing.T) {
	r := New(Config{}, tab(t), quiet{})
	load(t, r, `{"tenantId": "a", "name": "subject.permissions", "pipType": "MAPPING",
		"customMapping": {"subject.roles": {"r": ["p1"]}}}`,
		set("a", "subject.permissions CONTAINS 'p1'"), set("b", "subject.permissions CONTAINS 'p1'"))

	if got := decide(t, r, readDoc(t, "a", "y", 1)); !got[0].Allowed {
		t.Errorf("Decide with the role R mapped to p1 = %+v, want allowed", got[0])
	}
	if got := decide(t, r, readDoc(t, "b", "y", 1)); got[0] != (Result{Reason: ReasonDenied}) {
		t.Errorf("Decide in a tenant without the mapping = %+v, want %+v", got[0], Result{Reason: ReasonDenied})
	}
}

// countingServer answers every POST of path with body, any other request
// with 404, and counts the requests.
func countingServer(t *testing.T, path, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != path {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// The items of a bulk request share one call of the entitlements service.
func TestTheEntitlementsServiceIsCalledOncePerRequest(t *testing.T) {
	srv, calls := countingServer(t, "/api/v3/user-entitlements/user/u1", `{"entitlements": [{"resourceType": "doc",
		"references": [{"name": "owner", "resources": [{"resourceId": "y"}]}]}]}`)
	r := New(Config{Entitlements: srv.URL, HTTP: &regobuiltins.HTTP{Client: &http.Client{},
		Token: func() (string, error) { return "own", nil }}}, tab(t), quiet{})
	load(t, r, ``, set("a", "subject.entitledResources.of('doc').as('owner') CONTAINS resource.a"))

	got := decide(t, r, readDoc(t, "a", "y", 3))

	if !got[0].Allowed || !got[2].Allowed {
		t.Errorf("Decide of the entitled doc y = %+v, want every item allowed", got)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("calls of the entitlements service = %d, want 1", n)
	}
	if got := decide(t, r, readDoc(t, "a", "z", 1)); got[0].Allowed {
		t.Errorf("Decide of the doc z the service does not grant = %+v, want denied", got[0])
	}
}

// A permission scope service that answers 404 fails the scope rather than
// returning an empty one: an iterate under PERMIT_UNLESS_DENY, which permits
// over an empty scope, denies.
func TestAPermissionScopeOf404Fails(t *testing.T) {
	srv, calls := countingServer(t, "/nowhere", ``)
	r := New(Config{HTTP: &regobuiltins.HTTP{Client: &http.Client{},
		Token: func() (string, error) { return "own", nil }}}, tab(t), quiet{})
	load(t, r, `{"tenantId": "a", "name": "subject.permissionScope", "pipType": "PERMISSION_SCOPE", "url": "`+srv.URL+`"}`,
		`{"policySetId": "s", "name": "s", "status": "ACTIVE", "tenantId": "a",
		"target": "resourceType == 'doc'", "combiningAlgorithm": "PERMIT_UNLESS_DENY",
		"iterate": {"foreach": "subject.permissionScope", "combiningAlgorithm": "PERMIT_UNLESS_DENY"},
		"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "PERMIT_UNLESS_DENY",
			"tenantId": "a", "rules": [{"ruleId": "r", "target": "true",
				"condition": "subject.permissionScope.domain CONTAINS resource.a", "effect": "DENY", "tenantId": "a"}]}]}`)

	if got := decide(t, r, readDoc(t, "a", "y", 1)); got[0].Allowed {
		t.Errorf("Decide of the doc y with the scope service answering 404 = %+v, want denied", got[0])
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("reads of the permission scope = %d, want 1", n)
	}
}

// The items of a bulk request share one read of the permission scope, at
// the url of the tenant's PERMISSION_SCOPE PIP.
func TestThePermissionScopeIsReadOncePerRequest(t *testing.T) {
	srv, calls := countingServer(t, "/api/v1/permission-scope/user/u1/policies",
		`{"permissionScope": [{"policies": [{"scopeItems": [{"key": "domain", "values": [{"id": "y"}]}]}]}]}`)
	r := New(Config{HTTP: &regobuiltins.HTTP{Client: &http.Client{},
		Token: func() (string, error) { return "own", nil }}}, tab(t), quiet{})
	load(t, r, `{"tenantId": "a", "name": "subject.permissionScope", "pipType": "PERMISSION_SCOPE", "url": "`+srv.URL+`"}`,
		scopeSet("a"))

	got := decide(t, r, readDoc(t, "a", "y", 2))

	if !got[0].Allowed || !got[1].Allowed {
		t.Errorf("Decide of the doc y in the scope = %+v, want every item allowed", got)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("reads of the permission scope = %d, want 1", n)
	}
	if got := decide(t, r, readDoc(t, "a", "z", 1)); got[0].Allowed {
		t.Errorf("Decide of the doc z outside the scope = %+v, want denied", got[0])
	}
}
