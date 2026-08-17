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

package pips

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestBuildActivationIndexFromPolicies(t *testing.T) {
	t.Parallel()

	policies := map[string]any{
		"policies": map[string]any{
			"ols": map[string]any{
				"Customer": map[string]any{
					"READ": []any{"ROLE_USER"},
				},
			},
			"rls": map[string]any{
				"Customer": map[string]any{
					"READ": map[string]any{
						"ROLE_USER": []any{
							map[string]any{
								"conditionAst": map[string]any{
									"op": "eq",
									"args": []any{
										map[string]any{"ref": map[string]any{"scope": "subject", "path": []any{"allowedCustomers"}}},
										map[string]any{"ref": map[string]any{"scope": "resource", "path": []any{"id"}}},
									},
								},
								"predicates": []any{
									map[string]any{
										"predicate": "id=in=(${subject.allowedCustomers})",
										"type":      "rsql",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policies.json")
	content, _ := json.Marshal(policies)
	if err := os.WriteFile(policyPath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	generalPIPs := map[string]GeneralPIPConfig{
		"subject.allowedCustomers": {
			Name:  "subject.allowedCustomers",
			Alias: "allowedCustomers",
			URL:   "http://pip:8080/allowed",
		},
		"subject.other": {
			Name:  "subject.other",
			Alias: "other",
			URL:   "http://pip:8080/other",
		},
	}

	result := BuildActivationIndex(generalPIPs, policyPath)

	customerRead, ok := result["Customer"]["READ"]
	if !ok {
		t.Fatal("expected Customer/READ in activation index")
	}

	if len(customerRead) != 1 || customerRead[0] != "subject.allowedCustomers" {
		t.Fatalf("expected [subject.allowedCustomers], got %v", customerRead)
	}

	if _, ok := result["Customer"]["WRITE"]; ok {
		t.Fatal("unexpected Customer/WRITE in activation index")
	}
}

func TestBuildActivationIndexPredicateRef(t *testing.T) {
	t.Parallel()

	policies := map[string]any{
		"rls": map[string]any{
			"Order": map[string]any{
				"CREATE": map[string]any{
					"ROLE_ADMIN": []any{
						map[string]any{
							"condition": true,
							"predicates": []any{
								map[string]any{
									"predicate": "tenantId==${subject.tenantInfo}",
									"type":      "rsql",
								},
							},
						},
					},
				},
			},
		},
	}

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policies.json")
	content, _ := json.Marshal(policies)
	_ = os.WriteFile(policyPath, content, 0o644)

	generalPIPs := map[string]GeneralPIPConfig{
		"subject.tenantInfo": {
			Name:  "subject.tenantInfo",
			Alias: "tenantInfo",
			URL:   "http://pip:8080/tenant",
		},
	}

	result := BuildActivationIndex(generalPIPs, policyPath)

	if names := result["Order"]["CREATE"]; len(names) != 1 || names[0] != "subject.tenantInfo" {
		t.Fatalf("expected [subject.tenantInfo], got %v", names)
	}
}

func TestBuildActivationIndexMultiplePIPs(t *testing.T) {
	t.Parallel()

	policies := map[string]any{
		"policies": map[string]any{
			"rls": map[string]any{
				"Invoice": map[string]any{
					"READ": map[string]any{
						"ROLE_USER": []any{
							map[string]any{
								"conditionAst": map[string]any{
									"op": "and",
									"args": []any{
										map[string]any{
											"op": "contains",
											"args": []any{
												map[string]any{"ref": map[string]any{"scope": "subject", "path": []any{"allowedRegions"}}},
												map[string]any{"ref": map[string]any{"scope": "resource", "path": []any{"region"}}},
											},
										},
										map[string]any{
											"op": "eq",
											"args": []any{
												map[string]any{"ref": map[string]any{"scope": "subject", "path": []any{"tenantScope"}}},
												map[string]any{"ref": map[string]any{"scope": "resource", "path": []any{"tenantId"}}},
											},
										},
									},
								},
								"predicates": []any{
									map[string]any{"predicate": "region=in=(${subject.allowedRegions})", "type": "rsql"},
								},
							},
						},
					},
				},
			},
		},
	}

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policies.json")
	content, _ := json.Marshal(policies)
	_ = os.WriteFile(policyPath, content, 0o644)

	generalPIPs := map[string]GeneralPIPConfig{
		"subject.allowedRegions": {Name: "subject.allowedRegions", Alias: "allowedRegions", URL: "http://pip:8080/regions"},
		"subject.tenantScope":    {Name: "subject.tenantScope", Alias: "tenantScope", URL: "http://pip:8080/tenant"},
	}

	result := BuildActivationIndex(generalPIPs, policyPath)

	names := result["Invoice"]["READ"]
	sort.Strings(names)
	if len(names) != 2 {
		t.Fatalf("expected 2 PIPs, got %v", names)
	}
	if names[0] != "subject.allowedRegions" || names[1] != "subject.tenantScope" {
		t.Fatalf("unexpected PIP names: %v", names)
	}
}

func TestBuildActivationIndexNoPoliciesFile(t *testing.T) {
	t.Parallel()

	generalPIPs := map[string]GeneralPIPConfig{
		"subject.foo": {Name: "subject.foo", Alias: "foo", URL: "http://x"},
	}

	result := BuildActivationIndex(generalPIPs, "/nonexistent/policies.json")
	if len(result) != 0 {
		t.Fatalf("expected empty index for missing file, got %v", result)
	}
}

func TestBuildActivationIndexNoGeneralPIPs(t *testing.T) {
	t.Parallel()
	result := BuildActivationIndex(map[string]GeneralPIPConfig{}, "/some/path")
	if len(result) != 0 {
		t.Fatalf("expected empty index for no GENERAL PIPs, got %v", result)
	}
}

func TestBuildActivationIndexTokenPIPNotActivated(t *testing.T) {
	t.Parallel()

	policies := map[string]any{
		"policies": map[string]any{
			"rls": map[string]any{
				"Order": map[string]any{
					"READ": map[string]any{
						"ROLE_USER": []any{
							map[string]any{
								"conditionAst": map[string]any{
									"op": "eq",
									"args": []any{
										map[string]any{"ref": map[string]any{"scope": "subject", "path": []any{"customerId"}}},
										map[string]any{"ref": map[string]any{"scope": "resource", "path": []any{"ownerId"}}},
									},
								},
								"predicates": []any{
									map[string]any{"predicate": "ownerId==${subject.customerId}", "type": "rsql"},
								},
							},
						},
					},
				},
			},
		},
	}

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policies.json")
	content, _ := json.Marshal(policies)
	_ = os.WriteFile(policyPath, content, 0o644)

	generalPIPs := map[string]GeneralPIPConfig{
		"subject.unrelated": {Name: "subject.unrelated", Alias: "unrelated", URL: "http://pip:8080/x"},
	}

	result := BuildActivationIndex(generalPIPs, policyPath)
	if len(result) != 0 {
		t.Fatalf("expected empty index (customerId is not a GENERAL PIP), got %v", result)
	}
}
