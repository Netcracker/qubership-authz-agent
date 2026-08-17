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
	"io"
	"log"
	"testing"

	"authz-agent/internal/acconfig"
	"authz-agent/internal/simplifiedpolicies"
)

// The stub only earns its keep if what it serves is what the production
// converter can read back. This test closes the loop in milliseconds; before
// the stub moved into this module the only check was a ten-minute Compose run.
//
// The import of internal/acconfig is deliberate and lives in a _test.go file on
// purpose: the shipped binary must not link the production converter (otherwise
// the integration suites would compare the converter against itself), but the
// test may — and it is supposed to fail when the v3 wire shape changes.
func TestV3RoundTripThroughProductionConverter(t *testing.T) {
	input := []simplifiedPolicy{
		{Component: "billing", ResourceType: "Invoice", Operation: "READ", Roles: []any{"ROLE_ADMIN"}},
		{Component: "billing", ResourceType: "Invoice", Operation: "UPDATE", Roles: []any{"ROLE_ADMIN"}, Condition: "subject.tenantId == resource.tenantId"},
		{Component: "billing", ResourceType: "Invoice", Operation: "READ", Roles: []any{"ROLE_USER"}, RSQLPredicate: "ownerId==${subject.id}"},
	}

	raw, err := json.Marshal(v3PolicySetsResponse{Hash: "deadbeef", PolicySets: toV3PolicySets(input)})
	if err != nil {
		t.Fatalf("marshal v3 envelope: %v", err)
	}

	got, _, err := acconfig.ConvertPolicySets(raw, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("ConvertPolicySets: %v", err)
	}
	if len(got) != len(input) {
		t.Fatalf("converter returned %d policies, want %d: %+v", len(got), len(input), got)
	}

	for _, want := range input {
		if !containsPolicy(got, want) {
			t.Errorf("policy lost in the round trip: %+v\ngot: %+v", want, got)
		}
	}
}

func TestPIPRoundTripThroughProductionConverter(t *testing.T) {
	input := []simplifiedPIP{
		{Name: "tenant", PipType: "TOKEN", Claim: "tenant_id", Domain: "billing"},
		{Name: "org-header", PipType: "HEADER", Header: "X-Org-Id"},
	}

	raw, err := json.Marshal(v3PIPsResponse{Hash: "deadbeef", PIPs: toV3PIPs(input)})
	if err != nil {
		t.Fatalf("marshal v3 envelope: %v", err)
	}

	got, err := acconfig.ConvertPIPs(raw, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("ConvertPIPs: %v", err)
	}
	if len(got) != len(input) {
		t.Fatalf("converter returned %d PIPs, want %d: %+v", len(got), len(input), got)
	}
	for i, want := range input {
		if got[i].Name != want.Name {
			t.Errorf("PIP %d: name %q, want %q", i, got[i].Name, want.Name)
		}
	}
}

func containsPolicy(got []simplifiedpolicies.Policy, want simplifiedPolicy) bool {
	for _, g := range got {
		if g.Component == want.Component &&
			g.ResourceType == want.ResourceType &&
			g.Operation == want.Operation &&
			g.RSQLPredicate == want.RSQLPredicate &&
			conditionString(g.Condition) == conditionString(want.Condition) &&
			rolesKey(g.Roles) == rolesKey(want.Roles) {
			return true
		}
	}
	return false
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
