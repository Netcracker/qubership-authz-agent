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
	"reflect"
	"strings"
	"testing"
)

// TestParseCondition_EntitlementOperand covers every operator variant from
// the six ENT simplified-policy fixtures under
// tests/parity/suite/testdata/fixtures/policies/suite/ plus a few
// surrounding cases (chained .as, multi-name .as, ENT on RHS) so the
// parser contract pinned by ADR-0054 + D-AG-11/D-AG-12 stays covered.
//
// The expected AST is represented with JSON-safe Go primitives (map[string]any
// / []any / string / bool) so reflect.DeepEqual matches what ParseCondition
// actually returns.
func TestParseCondition_EntitlementOperand(t *testing.T) {
	entRef := func(rt string, names ...string) map[string]any {
		anyNames := make([]any, 0, len(names))
		for _, n := range names {
			anyNames = append(anyNames, n)
		}
		return map[string]any{
			"ref": map[string]any{
				"scope":        "entitlements",
				"resourceType": rt,
				"names":        anyNames,
			},
		}
	}
	subjectRef := func(path string) map[string]any {
		return map[string]any{
			"ref": map[string]any{
				"scope": "subject",
				"path":  []string{path},
			},
		}
	}
	resourceRef := func(path string) map[string]any {
		return map[string]any{
			"ref": map[string]any{
				"scope": "resource",
				"path":  []string{path},
			},
		}
	}

	cases := []struct {
		name     string
		input    string
		expected map[string]any
	}{
		{
			name:  "ent-contains on LHS (row 76/82/83)",
			input: "subject.entitledResources.of('PARITY_CONTRACT').as('Owner') CONTAINS resource.id",
			expected: map[string]any{
				"op": "contains",
				"args": []any{
					entRef("PARITY_CONTRACT", "Owner"),
					resourceRef("id"),
				},
			},
		},
		{
			name:  "ent-contains-any on LHS (row 79)",
			input: "subject.entitledResources.of('PARITY_CONTRACT').as('Owner') CONTAINS ANY resource.relatedIds",
			expected: map[string]any{
				"op": "contains_any",
				"args": []any{
					entRef("PARITY_CONTRACT", "Owner"),
					resourceRef("relatedIds"),
				},
			},
		},
		{
			name:  "ent-in-rhs (row 77)",
			input: "resource.id IN subject.entitledResources.of('PARITY_CONTRACT').as('Owner')",
			expected: map[string]any{
				"op": "in",
				"args": []any{
					resourceRef("id"),
					entRef("PARITY_CONTRACT", "Owner"),
				},
			},
		},
		{
			name:  "ent-is-empty (row 80/83)",
			input: "subject.entitledResources.of('PARITY_CONTRACT').as('Owner') IS EMPTY",
			expected: map[string]any{
				"op": "is_empty",
				"args": []any{
					entRef("PARITY_CONTRACT", "Owner"),
				},
			},
		},
		{
			name:  "ent-not-contains (row 81)",
			input: "subject.entitledResources.of('PARITY_CONTRACT').as('Owner') NOT CONTAINS resource.id",
			expected: map[string]any{
				"op": "not",
				"args": []any{
					map[string]any{
						"op": "contains",
						"args": []any{
							entRef("PARITY_CONTRACT", "Owner"),
							resourceRef("id"),
						},
					},
				},
			},
		},
		{
			name:  "ent-multi-as single-call union (row 78 fixture shape)",
			input: "subject.entitledResources.of('PARITY_CONTRACT').as('Owner', 'Accountant') CONTAINS resource.id",
			expected: map[string]any{
				"op": "contains",
				"args": []any{
					entRef("PARITY_CONTRACT", "Owner", "Accountant"),
					resourceRef("id"),
				},
			},
		},
		{
			name:  "ent-multi-as chained .as().as() collapses to flat names",
			input: "subject.entitledResources.of('PARITY_CONTRACT').as('Owner').as('Viewer') CONTAINS resource.id",
			expected: map[string]any{
				"op": "contains",
				"args": []any{
					entRef("PARITY_CONTRACT", "Owner", "Viewer"),
					resourceRef("id"),
				},
			},
		},
		{
			name:  "ent-is-not-empty flips to not+is_empty",
			input: "subject.entitledResources.of('PARITY_CONTRACT').as('Owner') IS NOT EMPTY",
			expected: map[string]any{
				"op": "not",
				"args": []any{
					map[string]any{
						"op": "is_empty",
						"args": []any{
							entRef("PARITY_CONTRACT", "Owner"),
						},
					},
				},
			},
		},
		{
			name:  "ent-not-in on LHS (negated membership)",
			input: "resource.id NOT IN subject.entitledResources.of('PARITY_CONTRACT').as('Owner')",
			expected: map[string]any{
				"op": "not",
				"args": []any{
					map[string]any{
						"op": "in",
						"args": []any{
							resourceRef("id"),
							entRef("PARITY_CONTRACT", "Owner"),
						},
					},
				},
			},
		},
		{
			name:  "ent operand composes with AND alongside subject-scoped clause",
			input: "subject.entitledResources.of('PARITY_CONTRACT').as('Owner') CONTAINS resource.id AND subject.level EQUALS 'GOLD'",
			expected: map[string]any{
				"op": "and",
				"args": []any{
					map[string]any{
						"op": "contains",
						"args": []any{
							entRef("PARITY_CONTRACT", "Owner"),
							resourceRef("id"),
						},
					},
					map[string]any{
						"op": "eq",
						"args": []any{
							subjectRef("level"),
							map[string]any{"const": "GOLD"},
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseCondition(tc.input)
			if err != nil {
				t.Fatalf("ParseCondition(%q) unexpected error: %v", tc.input, err)
			}
			if !reflect.DeepEqual(got, tc.expected) {
				t.Fatalf("ParseCondition(%q):\n  got  = %#v\n  want = %#v", tc.input, got, tc.expected)
			}
		})
	}
}

// TestParseCondition_EntitlementOperandErrors exercises the "prefix matched
// but body is malformed" branch so parse errors surface as a policy upload
// 400 rather than degrading to a scalar-constant operand.
func TestParseCondition_EntitlementOperandErrors(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "missing .as clause",
			input:   "subject.entitledResources.of('PARITY_CONTRACT') CONTAINS resource.id",
			wantErr: "at least one .as",
		},
		{
			name:    "unterminated resource-type literal",
			input:   "subject.entitledResources.of('PARITY_CONTRACT).as('Owner') CONTAINS resource.id",
			wantErr: "entitlements operand",
		},
		{
			name:    "empty resource-type literal is accepted by parser (semantics deferred to rego)",
			input:   "subject.entitledResources.of('').as('Owner') CONTAINS resource.id",
			wantErr: "",
		},
		{
			name:    "as without closing paren",
			input:   "subject.entitledResources.of('PARITY_CONTRACT').as('Owner' CONTAINS resource.id",
			wantErr: "entitlements operand",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseCondition(tc.input)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error for %q, got %v", tc.input, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q for %q, got nil", tc.wantErr, tc.input)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

// TestParseCondition_NonEntitlementUnchanged pins the parser's backwards
// compatibility — every previously-supported condition shape returns the
// same AST regardless of the ADR-0054 scanner extension.
func TestParseCondition_NonEntitlementUnchanged(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected map[string]any
	}{
		{
			name:  "subject.ref CONTAINS resource.ref",
			input: "subject.allowedIds CONTAINS resource.id",
			expected: map[string]any{
				"op": "contains",
				"args": []any{
					map[string]any{"ref": map[string]any{"scope": "subject", "path": []string{"allowedIds"}}},
					map[string]any{"ref": map[string]any{"scope": "resource", "path": []string{"id"}}},
				},
			},
		},
		{
			name:  "parenthesized OR sub-expression still tokenises",
			input: "(subject.level EQUALS 'GOLD' OR subject.level EQUALS 'PLATINUM')",
			expected: map[string]any{
				"op": "or",
				"args": []any{
					map[string]any{
						"op": "eq",
						"args": []any{
							map[string]any{"ref": map[string]any{"scope": "subject", "path": []string{"level"}}},
							map[string]any{"const": "GOLD"},
						},
					},
					map[string]any{
						"op": "eq",
						"args": []any{
							map[string]any{"ref": map[string]any{"scope": "subject", "path": []string{"level"}}},
							map[string]any{"const": "PLATINUM"},
						},
					},
				},
			},
		},
		{
			name:  "IN multi-literal right operand",
			input: "subject.status IN 'ACTIVE', 'PENDING'",
			expected: map[string]any{
				"op": "in",
				"args": []any{
					map[string]any{"ref": map[string]any{"scope": "subject", "path": []string{"status"}}},
					map[string]any{"const": []any{"ACTIVE", "PENDING"}},
				},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseCondition(tc.input)
			if err != nil {
				t.Fatalf("ParseCondition(%q) unexpected error: %v", tc.input, err)
			}
			if !reflect.DeepEqual(got, tc.expected) {
				t.Fatalf("ParseCondition(%q):\n  got  = %#v\n  want = %#v", tc.input, got, tc.expected)
			}
		})
	}
}
