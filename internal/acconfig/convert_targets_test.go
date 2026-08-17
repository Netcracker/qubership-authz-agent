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
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"testing"

	"authz-agent/internal/simplifiedpolicies"
)

// ── Role grammar ─────────────────────────────────────────────────────────────

func TestParseRoleExpression(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		expr  string
		roles []string
		ok    bool
	}{
		{"contains single", "subject.roles CONTAINS 'ROLE_A'", []string{"ROLE_A"}, true},
		{"contains any single", "subject.roles CONTAINS ANY 'ROLE_A'", []string{"ROLE_A"}, true},
		{"contains any list", "subject.roles CONTAINS ANY 'A','B','C'", []string{"A", "B", "C"}, true},
		{"contains any list spaced", "subject.roles CONTAINS ANY 'A', 'B' ,  'C'", []string{"A", "B", "C"}, true},
		{"or chain", "subject.roles CONTAINS 'A' OR subject.roles CONTAINS 'B'", []string{"A", "B"}, true},
		{
			"or chain mixing operators",
			"subject.roles CONTAINS 'ROLE_M2M' OR subject.roles CONTAINS 'ROLE_notification-svc' OR subject.roles CONTAINS ANY 'BSS_ROLE_ADMINISTRATOR'",
			[]string{"ROLE_M2M", "ROLE_notification-svc", "BSS_ROLE_ADMINISTRATOR"},
			true,
		},
		{"or chain with list operand", "subject.roles CONTAINS 'A' OR subject.roles CONTAINS ANY 'B','C'", []string{"A", "B", "C"}, true},
		{"lower case operators", "subject.roles contains any 'A' or subject.roles contains 'B'", []string{"A", "B"}, true},
		{"duplicates collapse", "subject.roles CONTAINS 'A' OR subject.roles CONTAINS ANY 'A','B'", []string{"A", "B"}, true},

		// A role literal is opaque: splitting the expression on " OR " would
		// break this one, which is why the parser walks tokens instead.
		{"role literal containing OR", "subject.roles CONTAINS 'A OR B'", []string{"A OR B"}, true},

		{"other attribute", "subject.headerChannel CONTAINS ANY 'B2B'", nil, false},
		{"operation expression", "operation == 'READ'", nil, false},
		{"resource type expression", "resourceType == 'ORDER'", nil, false},
		{"unterminated literal", "subject.roles CONTAINS 'A", nil, false},
		{"trailing comma", "subject.roles CONTAINS ANY 'A',", nil, false},
		{"missing operand", "subject.roles CONTAINS", nil, false},
		{"dangling OR", "subject.roles CONTAINS 'A' OR", nil, false},
		{"trailing garbage", "subject.roles CONTAINS 'A' AND resource.x == 1", nil, false},
		{"prefix must not match", "subject.rolesFoo CONTAINS 'A'", nil, false},
		{"operator prefix must not match", "subject.roles CONTAINSFOO 'A'", nil, false},
		{"empty literal", "subject.roles CONTAINS '  '", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			roles, ok := parseRoleExpression(tc.expr)
			if ok != tc.ok {
				t.Fatalf("ok: want %v got %v (roles=%v)", tc.ok, ok, roles)
			}
			if !tc.ok {
				return
			}
			if strings.Join(roles, "|") != strings.Join(tc.roles, "|") {
				t.Errorf("roles: want %v got %v", tc.roles, roles)
			}
		})
	}
}

// ── Target classification ────────────────────────────────────────────────────

func TestParseTarget_Kinds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		target string
		kind   targetKind
		value  string
	}{
		{"", targetAny, ""},
		{"true", targetAny, ""},
		{"TRUE", targetAny, ""},
		{"resourceType == 'ORDER'", targetResourceType, "ORDER"},
		{"resourceType EQUALS 'ORDER'", targetResourceType, "ORDER"},
		{"operation == 'READ'", targetOperation, "READ"},
		{"operation EQUALS 'READ'", targetOperation, "READ"},
		{"subject.roles CONTAINS ANY 'A'", targetRoles, ""},
		{"resource.status == 'OPEN'", targetUnknown, ""},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			t.Parallel()
			got := parseTarget(tc.target)
			if got.kind != tc.kind {
				t.Fatalf("kind: want %v got %v", tc.kind, got.kind)
			}
			if got.value != tc.value {
				t.Errorf("value: want %q got %q", tc.value, got.value)
			}
		})
	}
}

// ── Both nesting orders convert identically ──────────────────────────────────

// policySetJSON builds a one-rule SIMPLIFIED policy set with the given policy
// and rule targets.
func policySetJSON(policyTarget, ruleTarget string) []byte {
	return []byte(fmt.Sprintf(`{
		"hash": "h",
		"lastModificationTimestamp": "2026-01-01T00:00:00",
		"policySets": [{
			"policySetId": "ps-1",
			"name": "Set",
			"type": "SIMPLIFIED",
			"domain": "D",
			"status": "ACTIVE",
			"target": "resourceType == 'ORDER'",
			"policies": [{
				"policyId": "p1",
				"target": %q,
				"rules": [{"ruleId": "r1", "target": %q, "condition": "true", "effect": "ALLOW"}]
			}]
		}]
	}`, policyTarget, ruleTarget))
}

func TestConvertPolicySets_BothNestingOrders(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		policyTarget string
		ruleTarget   string
	}{
		{
			// Shape served by the real access-control on dev-4.
			"operation on policy, roles on rule",
			"operation == 'READ'",
			"subject.roles CONTAINS ANY 'ROLE_CLOUD-ADMIN'",
		},
		{
			// Shape the pre-2026-08 fixtures use.
			"roles on policy, operation on rule",
			"subject.roles CONTAINS 'ROLE_CLOUD-ADMIN'",
			"operation == 'READ'",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, stats, err := ConvertPolicySets(policySetJSON(tc.policyTarget, tc.ruleTarget), discardLogger())
			if err != nil {
				t.Fatalf("ConvertPolicySets: %v", err)
			}
			if stats.RulesSkipped != 0 {
				t.Fatalf("expected no skipped rules, got %d", stats.RulesSkipped)
			}
			if len(got) != 1 {
				t.Fatalf("expected 1 policy, got %d", len(got))
			}
			if findPolicy(got, "D", "ORDER", "READ", "ROLE_CLOUD-ADMIN") == nil {
				t.Fatalf("expected D/ORDER/READ/ROLE_CLOUD-ADMIN; got %+v", got[0])
			}
		})
	}
}

func TestConvertPolicySets_TargetPairs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name          string
		policyTarget  string
		ruleTarget    string
		wantOperation string
		wantRole      string // "" = open access (no roles)
		wantSkipped   bool
	}{
		{"operation + any", "operation == 'READ'", "true", "READ", "", false},
		{"any + operation", "true", "operation == 'READ'", "READ", "", false},
		{"any + roles", "true", "subject.roles CONTAINS 'R'", "ALL", "R", false},
		{"roles + any", "subject.roles CONTAINS 'R'", "true", "ALL", "R", false},
		{"any + any", "true", "true", "ALL", "", false},

		// Ambiguous or unreadable pairs must drop the rule, never widen it.
		{"roles + roles", "subject.roles CONTAINS 'A'", "subject.roles CONTAINS 'B'", "", "", true},
		{"operation + operation", "operation == 'READ'", "operation == 'WRITE'", "", "", true},
		{"unknown rule target", "subject.roles CONTAINS 'A'", "resource.status == 'OPEN'", "", "", true},
		{"unknown policy target", "resource.status == 'OPEN'", "operation == 'READ'", "", "", true},
		{"resourceType nested below the set", "resourceType == 'X'", "subject.roles CONTAINS 'A'", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, stats, err := ConvertPolicySets(policySetJSON(tc.policyTarget, tc.ruleTarget), discardLogger())
			if err != nil {
				t.Fatalf("ConvertPolicySets: %v", err)
			}
			if tc.wantSkipped {
				if len(got) != 0 || stats.RulesSkipped != 1 {
					t.Fatalf("expected the rule to be skipped, got %d policies and %d skips", len(got), stats.RulesSkipped)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("expected 1 policy, got %d", len(got))
			}
			if findPolicy(got, "D", "ORDER", tc.wantOperation, tc.wantRole) == nil {
				t.Fatalf("expected operation %q role %q; got %+v", tc.wantOperation, tc.wantRole, got[0])
			}
		})
	}
}

// TestConvertPolicySets_UnreadableRoleTargetIsNotOpenAccess pins the fail-closed
// decision: before 2026-08-01 an unrecognised role expression produced a policy
// with an empty role list, which OPA reads as "any subject". Dropping the rule
// is the safe read of data the converter does not understand.
func TestConvertPolicySets_UnreadableRoleTargetIsNotOpenAccess(t *testing.T) {
	t.Parallel()
	raw := policySetJSON("operation == 'READ'", "subject.roles MATCHES /ROLE_.*/")
	got, stats, err := ConvertPolicySets(raw, discardLogger())
	if err != nil {
		t.Fatalf("ConvertPolicySets: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("unreadable role target must not produce a policy; got %+v", got)
	}
	if stats.RulesSkipped != 1 {
		t.Errorf("expected rulesSkipped=1, got %d", stats.RulesSkipped)
	}
}

func TestConvertPolicySets_MultiRoleTargetProducesAllRoles(t *testing.T) {
	t.Parallel()
	raw := policySetJSON("operation == 'READ'", "subject.roles CONTAINS ANY 'A','B' OR subject.roles CONTAINS 'C'")
	got, _, err := ConvertPolicySets(raw, discardLogger())
	if err != nil {
		t.Fatalf("ConvertPolicySets: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(got))
	}
	assertRoles(t, got, "A", "B", "C")
	if len(got[0].Roles) != 3 {
		t.Errorf("expected exactly 3 roles, got %v", got[0].Roles)
	}
}

// ── Stats ────────────────────────────────────────────────────────────────────

func TestConvertPolicySets_Stats(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/simplified_policies.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	got, stats, err := ConvertPolicySets(raw, discardLogger())
	if err != nil {
		t.Fatalf("ConvertPolicySets: %v", err)
	}
	if stats.Policies != len(got) {
		t.Errorf("stats.Policies=%d but %d policies returned", stats.Policies, len(got))
	}
	// The fixture carries one set with an unparseable policy-set target and one
	// rule with an unparseable target inside an otherwise valid set.
	if stats.PolicySetsSkipped != 1 {
		t.Errorf("expected 1 skipped policy set, got %d", stats.PolicySetsSkipped)
	}
	if stats.RulesSkipped != 1 {
		t.Errorf("expected 1 skipped rule, got %d", stats.RulesSkipped)
	}
	if stats.PolicySets == 0 || stats.Rules == 0 {
		t.Errorf("expected non-zero totals, got %+v", stats)
	}
}

func TestConvertPolicySets_DenyRulesCountedSeparately(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
		"hash": "h",
		"lastModificationTimestamp": "",
		"policySets": [{
			"policySetId": "ps-1", "name": "Set", "type": "SIMPLIFIED", "domain": "D",
			"status": "ACTIVE", "target": "resourceType == 'ORDER'",
			"policies": [{
				"policyId": "p1", "target": "operation == 'READ'",
				"rules": [
					{"ruleId": "r1", "target": "subject.roles CONTAINS 'A'", "effect": "ALLOW"},
					{"ruleId": "r2", "target": "subject.roles CONTAINS 'B'", "effect": "DENY"}
				]
			}]
		}]
	}`)
	got, stats, err := ConvertPolicySets(raw, discardLogger())
	if err != nil {
		t.Fatalf("ConvertPolicySets: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(got))
	}
	if stats.RulesDenySkipped != 1 {
		t.Errorf("expected rulesDenySkipped=1, got %d", stats.RulesDenySkipped)
	}
	if stats.RulesSkipped != 0 {
		t.Errorf("a DENY rule is normal data, not a conversion failure; rulesSkipped=%d", stats.RulesSkipped)
	}
}

// ── Regression: the real access-control payload ──────────────────────────────

const realPayloadFixture = "testdata/policy_setsV3_real_dev4.json"

// TestConvertPolicySets_RealDev4Payload is the regression test the package was
// missing: every committed fixture before it was authored against the
// converter's own assumptions, so a green suite said nothing about the real
// integration. This one is the verbatim GET /access/v3/config/policySets body
// from access-control on cloud-platform-security-dev-4, captured 2026-08-01,
// on which the previous converter skipped all 2207 rules.
func TestConvertPolicySets_RealDev4Payload(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(realPayloadFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	logger, logBuf := testLogger()
	got, stats, err := ConvertPolicySets(raw, logger)
	if err != nil {
		t.Fatalf("ConvertPolicySets: %v", err)
	}

	if stats.PolicySetsSkipped != 0 || stats.RulesSkipped != 0 {
		t.Fatalf("expected zero skips on the real payload, got %+v; log=%s",
			stats, truncate(logBuf.String(), 2000))
	}
	if strings.Contains(logBuf.String(), "warn:") {
		t.Errorf("expected no warnings, got: %s", truncate(logBuf.String(), 2000))
	}
	if stats.PolicySets != 1294 {
		t.Errorf("expected 1294 SIMPLIFIED policy sets, got %d", stats.PolicySets)
	}
	if stats.Rules != 2207 {
		t.Errorf("expected 2207 rules, got %d", stats.Rules)
	}
	if len(got) != stats.Rules {
		t.Errorf("every convertible rule should yield one policy: %d rules, %d policies", stats.Rules, len(got))
	}

	// The policy set uploaded by hand during the investigation, through
	// access-control's own PUT /access/v1/simplifiedPolicies/domainPolicies API.
	if findPolicy(got, "authz-agent-smoke", "ORDER", "READ", "ROLE_CLOUD-ADMIN") == nil {
		t.Error("expected the authz-agent-smoke/ORDER/READ/ROLE_CLOUD-ADMIN policy")
	}
}

// TestConvertPolicySets_RealDev4PayloadIsNormalizable closes the loop: the
// converter output has to survive the same normalisation the pull loop runs
// before pushing to OPA. Until this test the real payload never reached
// NormalizePolicies at all, because every rule had already been dropped.
func TestConvertPolicySets_RealDev4PayloadIsNormalizable(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(realPayloadFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	got, _, err := ConvertPolicySets(raw, discardLogger())
	if err != nil {
		t.Fatalf("ConvertPolicySets: %v", err)
	}
	if _, err := simplifiedpolicies.NormalizePolicies(got); err != nil {
		t.Fatalf("NormalizePolicies failed on real converter output: %v", err)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// TestConvertPIP_CarriesContractExtension pins the ADR-0066..0069 request
// fields through the v3 conversion.
//
// These four are absent from access-control's own PIP model — its authoritative
// PolicyInformationPointJson has no query/body/timeoutSeconds/response — so a
// real source never sends them and this test says nothing about
// access-control compatibility. What it pins is the authz-policy-admin path
// (authz-agent-ADR-0073): the stub serves them, and before this was wired the
// converter silently dropped all four, which left the extension with no
// delivery path any end-to-end test could drive. The failure mode was invisible
// — the PIP still resolved its URL and the call still went out, just without
// the query, body, timeout and extraction the operator configured.
func TestConvertPIP_CarriesContractExtension(t *testing.T) {
	raw := []byte(`{"hash":"h","lastModificationTimestamp":"t","pips":[{
		"name":"subject.ext","pipType":"GENERAL","url":"http://pip/x","httpMethod":"POST",
		"query":{"rt":"${resource.type}"},
		"body":{"id":"${subject.id}"},
		"timeoutSeconds":3,
		"response":{"extract":"$.data.ids[*].id","coerce":"array","onMissing":"defaultValue"}
	}]}`)

	got, err := ConvertPIPs(raw, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("ConvertPIPs: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 PIP, got %d", len(got))
	}
	pip := got[0]

	if pip.Query["rt"] != "${resource.type}" {
		t.Errorf("query dropped or mangled: %#v", pip.Query)
	}
	if len(pip.Body) == 0 || !strings.Contains(string(pip.Body), "${subject.id}") {
		t.Errorf("body dropped or mangled: %s", pip.Body)
	}
	if pip.TimeoutSeconds == nil || *pip.TimeoutSeconds != 3 {
		t.Errorf("timeoutSeconds dropped: %v", pip.TimeoutSeconds)
	}
	if pip.Response == nil {
		t.Fatalf("response block dropped entirely")
	}
	if pip.Response.Coerce != "array" || pip.Response.OnMissing != "defaultValue" {
		t.Errorf("response coerce/onMissing mangled: %+v", pip.Response)
	}
	if !strings.Contains(string(pip.Response.Extract), "$.data.ids[*].id") {
		t.Errorf("response.extract dropped or mangled: %s", pip.Response.Extract)
	}
}

// TestConvertPIP_MalformedExtensionIsDroppedNotFatal — a bad `response` block
// must cost that block only. The converter is fail-soft by design: one
// unparseable PIP must not deprive the agent of every other policy in a 1.9 MB
// payload.
func TestConvertPIP_MalformedExtensionIsDroppedNotFatal(t *testing.T) {
	raw := []byte(`{"hash":"h","lastModificationTimestamp":"t","pips":[{
		"name":"subject.bad","pipType":"GENERAL","url":"http://pip/x","response":"not-an-object"
	}]}`)

	got, err := ConvertPIPs(raw, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("a malformed response block must not fail the whole pull: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected the PIP to survive, got %d", len(got))
	}
	if got[0].Response != nil {
		t.Errorf("malformed response block should be dropped, got %+v", got[0].Response)
	}
	if got[0].URL != "http://pip/x" {
		t.Errorf("the rest of the PIP must survive, got %+v", got[0])
	}
}
