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
	"testing"
)

// TestNormalize_EntitlementsFixtureShape verifies that each of the six
// committed ENT fixtures under tests/parity/suite/testdata/fixtures/policies/suite/
// normalizes cleanly through the Go policy pipeline — i.e. the ADR-0054
// parser extension unblocks the authz-agent seeder path. The fixture JSON
// shapes are embedded inline to keep the unit test self-contained (the
// fixture files themselves stay frozen per D-AF-G / D-AG-7).
func TestNormalize_EntitlementsFixtureShape(t *testing.T) {
	fixtures := []struct {
		name string
		body string
	}{
		{
			name: "ent-contains (rows 76/82/83)",
			body: `[{
				"component": "PARITY",
				"resourceType": "PARITY_SUITE_ENT_CONTAINS",
				"operation": "READ",
				"condition": "subject.entitledResources.of('PARITY_CONTRACT').as('Owner') CONTAINS resource.id",
				"roles": ["ROLE_PARITY_READER"]
			}]`,
		},
		{
			name: "ent-contains-any (row 79)",
			body: `[{
				"component": "PARITY",
				"resourceType": "PARITY_SUITE_ENT_ANY",
				"operation": "READ",
				"condition": "subject.entitledResources.of('PARITY_CONTRACT').as('Owner') CONTAINS ANY resource.relatedIds",
				"roles": ["ROLE_PARITY_READER"]
			}]`,
		},
		{
			name: "ent-in-rhs (row 77)",
			body: `[{
				"component": "PARITY",
				"resourceType": "PARITY_SUITE_ENT_IN",
				"operation": "READ",
				"condition": "resource.id IN subject.entitledResources.of('PARITY_CONTRACT').as('Owner')",
				"roles": ["ROLE_PARITY_READER"]
			}]`,
		},
		{
			name: "ent-is-empty (rows 80/83)",
			body: `[{
				"component": "PARITY",
				"resourceType": "PARITY_SUITE_ENT_EMPTY",
				"operation": "READ",
				"condition": "subject.entitledResources.of('PARITY_CONTRACT').as('Owner') IS EMPTY",
				"roles": ["ROLE_PARITY_READER"]
			}]`,
		},
		{
			name: "ent-multi-as (row 78)",
			body: `[{
				"component": "PARITY",
				"resourceType": "PARITY_SUITE_ENT_MULTI",
				"operation": "READ",
				"condition": "subject.entitledResources.of('PARITY_CONTRACT').as('Owner', 'Accountant') CONTAINS resource.id",
				"roles": ["ROLE_PARITY_READER"]
			}]`,
		},
		{
			name: "ent-not-contains (row 81)",
			body: `[{
				"component": "PARITY",
				"resourceType": "PARITY_SUITE_ENT_NOT",
				"operation": "READ",
				"condition": "subject.entitledResources.of('PARITY_CONTRACT').as('Owner') NOT CONTAINS resource.id",
				"roles": ["ROLE_PARITY_READER"]
			}]`,
		},
	}
	for _, tc := range fixtures {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			normalized, err := Normalize([]byte(tc.body))
			if err != nil {
				t.Fatalf("Normalize failed: %v", err)
			}
			rls, ok := normalized["rls"].(map[string]any)
			if !ok {
				t.Fatalf("expected rls map in %v", normalized)
			}
			if len(rls) == 0 {
				t.Fatalf("expected at least one resourceType in rls, got empty map")
			}
			// Ensure the AST round-trips through JSON marshalling (OPA
			// consumes the normalized document via HTTP + JSON).
			if _, err := json.Marshal(normalized); err != nil {
				t.Fatalf("normalized document is not JSON-serialisable: %v", err)
			}
		})
	}
}
