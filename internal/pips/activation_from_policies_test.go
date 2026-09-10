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
	"reflect"
	"testing"
)

// TestBuildActivationIndexFromPolicies_MatchesTheFileVariant: the index
// built from the document in memory is the one built from the same
// document persisted, and an empty PIP set or a document without RLS rules
// gives an empty index. The rules are held as NormalizePolicies holds
// them, a slice of maps rather than the slice of any the persisted file
// reads back as. The scanner used to assert the file's types on the
// in-memory document, found no rule, and activated no PIP.
func TestBuildActivationIndexFromPolicies_MatchesTheFileVariant(t *testing.T) {
	policies := map[string]any{
		"rls": map[string]any{
			"ORDER": map[string]any{
				"READ": map[string]any{
					"ROLE_USER": []map[string]any{{
						"conditionAst": map[string]any{"ref": map[string]any{"scope": "subject", "path": []string{"dept"}}},
						"predicates":   []map[string]any{{"predicate": "owner==${subject.region}"}},
					}},
				},
			},
		},
	}
	general := map[string]GeneralPIPConfig{
		"subject.dept":   {Name: "subject.dept", Alias: "dept"},
		"subject.region": {Name: "subject.region", Alias: "region"},
		"subject.unused": {Name: "subject.unused", Alias: "unused"},
	}
	file := filepath.Join(t.TempDir(), "policies.json")
	raw, _ := json.Marshal(map[string]any{"policies": policies})
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile := BuildActivationIndex(general, file)
	fromMemory := BuildActivationIndexFromPolicies(general, policies)
	sortIndex(fromFile)
	sortIndex(fromMemory)
	want := map[string]map[string][]string{"ORDER": {"READ": {"subject.dept", "subject.region"}}}
	if !reflect.DeepEqual(fromMemory, want) {
		t.Errorf("BuildActivationIndexFromPolicies() = %v, want %v", fromMemory, want)
	}
	if !reflect.DeepEqual(fromMemory, fromFile) {
		t.Errorf("in memory %v, from the file %v; want the same index", fromMemory, fromFile)
	}
	if got := BuildActivationIndexFromPolicies(nil, policies); len(got) != 0 {
		t.Errorf("BuildActivationIndexFromPolicies(no PIPs) = %v, want empty", got)
	}
	if got := BuildActivationIndexFromPolicies(general, map[string]any{}); len(got) != 0 {
		t.Errorf("BuildActivationIndexFromPolicies(no rls) = %v, want empty", got)
	}
}

func sortIndex(index map[string]map[string][]string) {
	for _, ops := range index {
		for _, names := range ops {
			for i := range names {
				for j := i + 1; j < len(names); j++ {
					if names[j] < names[i] {
						names[i], names[j] = names[j], names[i]
					}
				}
			}
		}
	}
}
