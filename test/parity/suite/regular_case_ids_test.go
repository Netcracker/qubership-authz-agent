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

//go:build integration

package paritysuite

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"testing"
)

// regularCaseLists are the functions that build regular cases. A new list is
// added here, or its ids are checked by nothing.
var regularCaseLists = map[string]func() []regularCase{
	"regularPolicySetCases":                 regularPolicySetCases,
	"translatorPolicySetCases":              translatorPolicySetCases,
	"interpreterFilterCases":                interpreterFilterCases,
	"iterateBindingCases":                   iterateBindingCases,
	"terminalEffectCases":                   terminalEffectCases,
	"failedPIPScopeCases":                   failedPIPScopeCases,
	"failedPIPFilterCases":                  failedPIPFilterCases,
	"customizationRegularCases":             customizationRegularCases,
	"customizationUnderIterateRegularCases": customizationUnderIterateRegularCases,
	"pipScopeRegularCases":                  pipScopeRegularCases,
	"repeatedValuesRegularCases":            repeatedValuesRegularCases,
	"policyWithoutAlgorithmCases":           policyWithoutAlgorithmCases,
	"round11FailedPIPOnTheRightCases":       round11FailedPIPOnTheRightCases,
	"caseFileRegularCases":                  caseFileRegularCases,
}

// caseFileRegularCases builds the cases with sets of every file under
// testdata/cases, so that their ids are checked against the Go cases as well.
// It panics on a file runCaseFile could not run, which
// TestCaseFilesAreWellFormed reports by name.
func caseFileRegularCases() []regularCase {
	var cases []regularCase
	root := filepath.Join("testdata", "cases")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".json" {
			return err
		}
		name, _ := filepath.Rel(root, path)
		f, err := readCaseFile(name)
		if err != nil {
			return err
		}
		_, regular, _, err := caseFileCases(f)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		cases = append(cases, regular...)
		return nil
	})
	if err != nil {
		panic(err)
	}
	return cases
}

// casesSharingElementIDs are the regular cases whose one upload carries one id
// twice: two-sets-whose-policies-share-one-id and
// s23-048-pap-same-rule-key-other-predicates, which ask the PAP about the shared
// id, and missing-attribute-in-set-target and
// q19-same-predicate-in-two-policies, whose fixtures are kept as they were
// recorded. The PAP refused q19-same-predicate-in-two-policies for its shared
// ruleId, so its goldens say nothing about the predicates it was written for.
var casesSharingElementIDs = map[string]struct{}{
	"missing-attribute-in-set-target":            {},
	"two-sets-whose-policies-share-one-id":       {},
	"s23-048-pap-same-rule-key-other-predicates": {},
	"q19-same-predicate-in-two-policies":         {},
}

// Every set, policy, and rule of one upload carries an id of its own, unless the
// case is listed in casesSharingElementIDs. missing-attribute-in-set-target
// built two policies from one key, so both carried one policyId, and the PAP's
// refusal was read as a refusal of the set target.
func TestRegularCaseElementIDsAreUnique(t *testing.T) {
	for list, build := range regularCaseLists {
		for _, tc := range build() {
			if _, shared := casesSharingElementIDs[tc.id]; shared {
				continue
			}
			for i, upload := range tc.uploads {
				owners := map[string][]string{}
				collectElementIDs(upload.sets, owners)
				for id, names := range owners {
					if len(names) > 1 {
						t.Errorf("%s: case %q upload %d: id %s is carried by %v", list, tc.id, i+1, id, names)
					}
				}
			}
		}
	}
}

// collectElementIDs records, for every policySetId, policyId, and ruleId under v,
// the kind and name of each element carrying it.
func collectElementIDs(v any, owners map[string][]string) {
	switch typed := v.(type) {
	case map[string]any:
		for _, field := range []string{"policySetId", "policyId", "ruleId"} {
			if id, ok := typed[field].(string); ok {
				owners[id] = append(owners[id], field+" of "+fmt.Sprint(typed["name"]))
			}
		}
		for _, value := range typed {
			collectElementIDs(value, owners)
		}
	case []any:
		for _, element := range typed {
			collectElementIDs(element, owners)
		}
	}
}

// Every regular case has an id of its own across every list, and every request of
// a case a name of its own. The golden path is regular/<id>/<request>, so two
// cases with one id would compare against each other's goldens, and their sets
// would replace each other on the stand under one resource type.
func TestRegularCaseIDsAreUnique(t *testing.T) {
	seen := map[string]string{}
	for list, build := range regularCaseLists {
		for _, tc := range build() {
			if earlier, dup := seen[tc.id]; dup {
				t.Errorf("regular case id %q is built by %s and by %s", tc.id, earlier, list)
			}
			seen[tc.id] = list
			names := map[string]struct{}{}
			for _, req := range tc.requests {
				if _, dup := names[req.name]; dup {
					t.Errorf("regular case %q names two requests %q", tc.id, req.name)
				}
				names[req.name] = struct{}{}
			}
		}
	}
}
