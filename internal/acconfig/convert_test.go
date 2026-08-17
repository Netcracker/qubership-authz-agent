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

package acconfig

import (
	"bytes"
	"io"
	"log"
	"os"
	"strings"
	"testing"

	"authz-agent/internal/pips"
	"authz-agent/internal/simplifiedpolicies"
)

// discardLogger returns a logger that swallows all output but can be checked
// via the testLogger below.
func discardLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

// testLogger captures log lines for assertion.
func testLogger() (*log.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return log.New(&buf, "", 0), &buf
}

// ── Real v3 fixtures — all DEFAULT type, expect empty result ─────────────────

func TestConvertPolicySets_V3Fixture1_AllDefault(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/policy_setsV3_1.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	got, _, err := ConvertPolicySets(raw, discardLogger())
	if err != nil {
		t.Fatalf("ConvertPolicySets: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 policies from all-DEFAULT fixture, got %d", len(got))
	}
}

func TestConvertPolicySets_V3Fixture2_AllDefault(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/policy_setsV3_2.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	got, _, err := ConvertPolicySets(raw, discardLogger())
	if err != nil {
		t.Fatalf("ConvertPolicySets: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 policies from all-DEFAULT fixture, got %d", len(got))
	}
}

func TestConvertPolicySets_V3Fixture3_AllDefault(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/policy_setsV3_3.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	got, _, err := ConvertPolicySets(raw, discardLogger())
	if err != nil {
		t.Fatalf("ConvertPolicySets: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 policies from all-DEFAULT fixture, got %d", len(got))
	}
}

// ── PIP v3 fixtures — parse without error, known-filtered types excluded ─────

func TestConvertPIPs_V3Fixture1(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/pipsV3_1.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	got, err := ConvertPIPs(raw, discardLogger())
	if err != nil {
		t.Fatalf("ConvertPIPs: %v", err)
	}
	// FILTERED, PERMISSION_SCOPE, MAPPING, GENERAL+beanName are excluded.
	// Verify that the supported types made it through.
	names := pipNames(got)
	assertContains(t, names, "subject.getUUIDs")
	assertContains(t, names, "subject.getCustomerIds")
	assertContains(t, names, "subject.companyName")
	assertContains(t, names, "subject.pipWithHeader")
	assertContains(t, names, "subject.azp")
	assertContains(t, names, "subject.urlPipWithHeader")
	assertNotContains(t, names, "subject.filtered")             // FILTERED → excluded
	assertNotContains(t, names, "subject.permissions")          // MAPPING → excluded
	assertNotContains(t, names, "subject.permissionScope")      // PERMISSION_SCOPE → excluded
	assertNotContains(t, names, "subject.existedBeanForPip")    // GENERAL+beanName → excluded
	assertNotContains(t, names, "subject.nonExistedBeanForPip") // GENERAL+beanName → excluded
	assertNotContains(t, names, "subject.wrongTypeBeanForPip")  // GENERAL+beanName → excluded
}

// ── Hand-written simplified_policies.json cases ──────────────────────────────

func TestConvertPolicySets_SimplifiedFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/simplified_policies.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	logger, logBuf := testLogger()
	got, _, err := ConvertPolicySets(raw, logger)
	if err != nil {
		t.Fatalf("ConvertPolicySets: %v", err)
	}
	logOutput := logBuf.String()

	// The fixture has DEFAULT, no-type (DEFAULT), malformed-target, malformed-op
	// sets plus valid SIMPLIFIED sets. The malformed sets generate log lines.
	assertLogContains(t, logOutput, "Malformed-target policy set", "malformed target must be logged")
	assertLogContains(t, logOutput, "Malformed operation target", "malformed operation must be logged")

	// DEFAULT and no-type sets produce no output and no log.
	assertNotInLog(t, logOutput, "DEFAULT", "DEFAULT sets must not be logged")
	assertNotInLog(t, logOutput, "ps-no-type", "absent-type set must not be logged")

	// Basic read policies — two roles, one per policy.
	adminRead := findPolicy(got, "CustomerDomain", "Customer", "READ", "ROLE_ADMIN")
	if adminRead == nil {
		t.Fatalf("expected CustomerDomain/Customer/READ/ROLE_ADMIN policy; all=%v", got)
	}
	userRead := findPolicy(got, "CustomerDomain", "Customer", "READ", "ROLE_USER")
	if userRead == nil {
		t.Fatalf("expected CustomerDomain/Customer/READ/ROLE_USER policy; all=%v", got)
	}

	// condition: null — rule has null condition; no Condition field expected.
	nullCond := findPolicy(got, "OrderDomain", "Order", "DELETE", "ROLE_MANAGER")
	if nullCond == nil {
		t.Fatalf("expected OrderDomain/Order/DELETE/ROLE_MANAGER policy")
	}
	if nullCond.Condition != nil {
		t.Errorf("null condition must produce nil Condition, got %v", nullCond.Condition)
	}

	// target: true on the policy SET → resourceType: ALL.
	allRT := findPolicy(got, "GlobalDomain", "ALL", "MANAGE", "ROLE_SUPER_ADMIN")
	if allRT == nil {
		t.Fatalf("expected GlobalDomain/ALL/MANAGE/ROLE_SUPER_ADMIN policy")
	}

	// target: true on the POLICY (rule target) → operation: ALL.
	allOP := findPolicy(got, "AdminDomain", "Report", "ALL", "ROLE_REPORT_ADMIN")
	if allOP == nil {
		t.Fatalf("expected AdminDomain/Report/ALL/ROLE_REPORT_ADMIN policy")
	}

	// allowM2MAccess — ROLE_M2M in the roles list.
	m2m := findPolicy(got, "ServiceDomain", "ServiceResource", "GET", "ROLE_M2M")
	if m2m == nil {
		t.Fatalf("expected ServiceDomain/ServiceResource/GET/ROLE_M2M policy")
	}

	// applicableForFrontend — extra field must not break parsing.
	frontend := findPolicy(got, "FrontendDomain", "Widget", "VIEW", "ROLE_VIEWER")
	if frontend == nil {
		t.Fatalf("expected FrontendDomain/Widget/VIEW/ROLE_VIEWER policy")
	}

	// DEFAULT type set must be silently skipped.
	defaultSet := findPoliciesByRT(got, "Invoice")
	if len(defaultSet) != 0 {
		t.Errorf("DEFAULT type set must be skipped; got %d policies for Invoice", len(defaultSet))
	}

	// No-type (absent) → DEFAULT → silently skipped.
	noType := findPoliciesByRT(got, "Legacy")
	if len(noType) != 0 {
		t.Errorf("absent type set must be skipped; got %d policies for Legacy", len(noType))
	}

	// Malformed policy-set target → all policies from that set skipped.
	// The malformed target was "subject.someField == 'unexpected'", so no valid resourceType.
	for _, p := range got {
		if p.Component == "MalformedDomain" {
			t.Errorf("malformed-target set must be fully skipped; got %v", p)
		}
	}

	// Malformed operation target on one rule → that rule skipped, other rule kept.
	ticket := findPolicy(got, "MalformedOpDomain", "Ticket", "VIEW", "ROLE_SUPPORT")
	if ticket == nil {
		t.Fatalf("expected MalformedOpDomain/Ticket/VIEW/ROLE_SUPPORT policy (valid rule kept)")
	}
	// The second rule with unparseable target ("resource.status == 'OPEN'") must be skipped.
	for _, p := range got {
		if strings.EqualFold(p.Component, "MalformedOpDomain") && strings.EqualFold(p.Operation, "OPEN") {
			t.Errorf("malformed operation target must not produce a policy; got %v", p)
		}
	}

	// deprecated: true — included (flag is data, not a filter).
	deprecated := findPolicy(got, "DeprecatedDomain", "OldResource", "READ", "ROLE_LEGACY_USER")
	if deprecated == nil {
		t.Fatalf("expected DeprecatedDomain/OldResource/READ/ROLE_LEGACY_USER policy (deprecated included)")
	}

	// No domain field → falls back to tenantId.
	tenantFallback := findPolicy(got, "TenantFallback", "Tenant", "READ", "ROLE_TENANT_USER")
	if tenantFallback == nil {
		t.Fatalf("expected TenantFallback/Tenant/READ/ROLE_TENANT_USER policy (domain fallback)")
	}
}

// ── condition / RSQLPredicate forwarding ─────────────────────────────────────

func TestConvertPolicySets_ConditionAndRSQLForwarded(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
		"hash": "x",
		"lastModificationTimestamp": "2025-01-01T00:00:00",
		"policySets": [
			{
				"policySetId": "ps1",
				"name": "With RSQL",
				"type": "SIMPLIFIED",
				"domain": "D",
				"status": "ACTIVE",
				"target": "resourceType == 'RT'",
				"policies": [
					{
						"policyId": "p1",
						"target": "subject.roles CONTAINS 'ROLE_A'",
						"rules": [
							{
								"ruleId": "r1",
								"target": "operation == 'READ'",
								"condition": "resource.active == true",
								"rsqlPredicate": "active==true",
								"effect": "ALLOW"
							}
						]
					}
				]
			}
		]
	}`)
	got, _, err := ConvertPolicySets(raw, discardLogger())
	if err != nil {
		t.Fatalf("ConvertPolicySets: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(got))
	}
	p := got[0]
	if p.Condition != "resource.active == true" {
		t.Errorf("condition: want %q got %v", "resource.active == true", p.Condition)
	}
	if p.RSQLPredicate != "active==true" {
		t.Errorf("rsqlPredicate: want %q got %q", "active==true", p.RSQLPredicate)
	}
}

func TestConvertPolicySets_NullConditionOmitted(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
		"hash": "x",
		"lastModificationTimestamp": "2025-01-01T00:00:00",
		"policySets": [
			{
				"policySetId": "ps-nc",
				"name": "Null cond",
				"type": "SIMPLIFIED",
				"domain": "D",
				"status": "ACTIVE",
				"target": "resourceType == 'RT'",
				"policies": [
					{
						"policyId": "p1",
						"target": "subject.roles CONTAINS 'ROLE_A'",
						"rules": [
							{
								"ruleId": "r1",
								"target": "operation == 'READ'",
								"condition": null,
								"effect": "ALLOW"
							}
						]
					}
				]
			}
		]
	}`)
	got, _, err := ConvertPolicySets(raw, discardLogger())
	if err != nil {
		t.Fatalf("ConvertPolicySets: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(got))
	}
	if got[0].Condition != nil {
		t.Errorf("null condition must produce nil Condition, got %v", got[0].Condition)
	}
}

// ── Empty hash / invalid JSON ─────────────────────────────────────────────────

func TestConvertPolicySets_InvalidJSON(t *testing.T) {
	t.Parallel()
	_, _, err := ConvertPolicySets([]byte("{bad"), discardLogger())
	if err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

func TestConvertPIPs_InvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := ConvertPIPs([]byte("{bad"), discardLogger())
	if err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

// ── Headers normalisation ─────────────────────────────────────────────────────

func TestNormaliseHeaders_StringForm(t *testing.T) {
	t.Parallel()
	// Comma-separated string → JSON array.
	raw := []byte(`{"hash":"x","lastModificationTimestamp":"","pips":[` +
		`{"name":"subject.h","pipType":"GENERAL","url":"http://x","headers":"A,B,C"}` +
		`]}`)
	got, err := ConvertPIPs(raw, discardLogger())
	if err != nil {
		t.Fatalf("ConvertPIPs: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 PIP, got %d", len(got))
	}
	// Headers must be a JSON array.
	h := got[0].Headers
	if len(h) == 0 || h[0] != '[' {
		t.Errorf("expected JSON array headers, got %s", string(h))
	}
}

func TestNormaliseHeaders_JSONArrayPassthrough(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"hash":"x","lastModificationTimestamp":"","pips":[` +
		`{"name":"subject.h","pipType":"GENERAL","url":"http://x","headers":["X-Header"]}` +
		`]}`)
	got, err := ConvertPIPs(raw, discardLogger())
	if err != nil {
		t.Fatalf("ConvertPIPs: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 PIP, got %d", len(got))
	}
	if !strings.Contains(string(got[0].Headers), "X-Header") {
		t.Errorf("JSON array must pass through: %s", string(got[0].Headers))
	}
}

// ── Policy ends up normalizable by simplifiedpolicies.NormalizePolicies ──────

func TestConvertPolicySets_OutputIsNormalizable(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/simplified_policies.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	policies, _, err := ConvertPolicySets(raw, discardLogger())
	if err != nil {
		t.Fatalf("ConvertPolicySets: %v", err)
	}
	if len(policies) == 0 {
		t.Fatal("expected at least one policy from simplified fixture")
	}
	if _, err := simplifiedpolicies.NormalizePolicies(policies); err != nil {
		t.Fatalf("NormalizePolicies failed on converter output: %v", err)
	}
}

// ── PIP output is normalizable by pips.NormalizeItems ────────────────────────

func TestConvertPIPs_OutputIsNormalizable(t *testing.T) {
	t.Parallel()
	// Use a minimal PIP set to avoid URL-specific validation issues with
	// ${port} placeholders in the v3 fixtures.
	raw := []byte(`{"hash":"x","lastModificationTimestamp":"","pips":[` +
		`{"name":"subject.myPip","pipType":"GENERAL","url":"http://pip-service/api"},` +
		`{"name":"subject.myToken","pipType":"TOKEN","claim":"sub"},` +
		`{"name":"subject.myHeader","pipType":"HEADER","header":"X-My-Header"}` +
		`]}`)
	pipList, err := ConvertPIPs(raw, discardLogger())
	if err != nil {
		t.Fatalf("ConvertPIPs: %v", err)
	}
	if len(pipList) != 3 {
		t.Fatalf("expected 3 PIPs, got %d", len(pipList))
	}
	if _, _, err := pips.NormalizeItems(pipList); err != nil {
		t.Fatalf("NormalizeItems failed on converter output: %v", err)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func pipNames(list []pips.SimplifiedPIP) []string {
	names := make([]string, len(list))
	for i, p := range list {
		names[i] = p.Name
	}
	return names
}

func assertContains(t *testing.T, haystack []string, needle string) {
	t.Helper()
	for _, v := range haystack {
		if v == needle {
			return
		}
	}
	t.Errorf("expected %q in %v", needle, haystack)
}

func assertNotContains(t *testing.T, haystack []string, needle string) {
	t.Helper()
	for _, v := range haystack {
		if v == needle {
			t.Errorf("did not expect %q in %v", needle, haystack)
			return
		}
	}
}

func assertLogContains(t *testing.T, output, substring, msg string) {
	t.Helper()
	if !strings.Contains(output, substring) {
		t.Errorf("%s: expected log to contain %q; log=%q", msg, substring, output)
	}
}

func assertNotInLog(t *testing.T, output, substring, msg string) {
	t.Helper()
	if strings.Contains(output, substring) {
		t.Errorf("%s: did not expect log to contain %q; log=%q", msg, substring, output)
	}
}

func assertRoles(t *testing.T, policies []simplifiedpolicies.Policy, roles ...string) {
	t.Helper()
	found := make(map[string]bool)
	for _, p := range policies {
		for _, r := range p.Roles {
			if s, ok := r.(string); ok {
				found[s] = true
			}
		}
	}
	for _, want := range roles {
		if !found[want] {
			t.Errorf("expected role %q in policies %v", want, policies)
		}
	}
}

// findPolicy finds a policy matching (component, resourceType, operation, role).
// ResourceType and operation are compared case-insensitively (normalizeKey uppercases).
func findPolicy(policies []simplifiedpolicies.Policy, component, resourceType, operation, role string) *simplifiedpolicies.Policy {
	for i := range policies {
		p := &policies[i]
		if !strings.EqualFold(p.Component, component) {
			continue
		}
		if !strings.EqualFold(p.ResourceType, resourceType) {
			continue
		}
		if !strings.EqualFold(p.Operation, operation) {
			continue
		}
		for _, r := range p.Roles {
			if s, ok := r.(string); ok && strings.EqualFold(s, role) {
				return p
			}
		}
		// Empty roles → open access (any role).
		if role == "" && len(p.Roles) == 0 {
			return p
		}
	}
	return nil
}

func findPoliciesByRT(policies []simplifiedpolicies.Policy, resourceType string) []simplifiedpolicies.Policy {
	var out []simplifiedpolicies.Policy
	for _, p := range policies {
		if strings.EqualFold(p.ResourceType, resourceType) {
			out = append(out, p)
		}
	}
	return out
}
