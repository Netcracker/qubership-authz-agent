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
	"testing"
)

// regularCaseLists are the functions that build regular cases. A new list is
// added here, or its ids are checked by nothing.
var regularCaseLists = map[string]func() []regularCase{
	"regularPolicySetCases":                     regularPolicySetCases,
	"translatorPolicySetCases":                  translatorPolicySetCases,
	"failedPIPRegularCases":                     failedPIPRegularCases,
	"deadFormRegularCases":                      deadFormRegularCases,
	"combiningCases":                            combiningCases,
	"interpreterFilterCases":                    interpreterFilterCases,
	"iterateBindingCases":                       iterateBindingCases,
	"setTargetCases":                            setTargetCases,
	"substitutionRegularCases":                  substitutionRegularCases,
	"permissionListCases":                       permissionListCases,
	"accessOperatorCases":                       accessOperatorCases,
	"barePathRegularCases":                      barePathRegularCases,
	"denyPredicateCases":                        denyPredicateCases,
	"terminalEffectCases":                       terminalEffectCases,
	"setTargetRefusalCases":                     setTargetRefusalCases,
	"round7FilterCases":                         round7FilterCases,
	"failedPIPScopeCases":                       failedPIPScopeCases,
	"round9DenyRuleWithoutPredicateCases":       round9DenyRuleWithoutPredicateCases,
	"round9FalseConditionWithoutPredicateCases": round9FalseConditionWithoutPredicateCases,
	"round9FilterAlgebraCases":                  round9FilterAlgebraCases,
	"round9UnresolvedPlaceholderCases":          round9UnresolvedPlaceholderCases,
	"round9SubjectScalarSubstitutionCases":      round9SubjectScalarSubstitutionCases,
	"nonStringPIPValueRegularCases":             nonStringPIPValueRegularCases,
	"round10SetAlgorithmFilterCases":            round10SetAlgorithmFilterCases,
	"round10FilterResourceConditionCases":       round10FilterResourceConditionCases,
	"round10DenyListFilterCases":                round10DenyListFilterCases,
	"failedPIPFilterCases":                      failedPIPFilterCases,
	"customizationRegularCases":                 customizationRegularCases,
	"pipScopeRegularCases":                      pipScopeRegularCases,
	"repeatedValuesRegularCases":                repeatedValuesRegularCases,
	"policyWithoutAlgorithmCases":               policyWithoutAlgorithmCases,
	"round11FailedPIPOnTheRightCases":           round11FailedPIPOnTheRightCases,
	"round11ScopeOutsideIterateCases":           round11ScopeOutsideIterateCases,
	"round11FilterCases":                        round11FilterCases,
	"round12ScopeOutsideIterateControlCases":    round12ScopeOutsideIterateControlCases,
	"round12NotApplicableFilterCases":           round12NotApplicableFilterCases,
	"round12IterateNodeInAFilterCases":          round12IterateNodeInAFilterCases,
	"round13IterateCases": func() []regularCase {
		var cases []regularCase
		for _, shape := range round13ScopeShapes {
			cases = append(cases, round13IterateCases(shape.name)...)
		}
		return cases
	},
	"round13ScopeOutsideIterateCases":   round13ScopeOutsideIterateCases,
	"round13FilterCases":                round13FilterCases,
	"round13FailingPIPInADenyRuleCases": round13FailingPIPInADenyRuleCases,
}

// casesSharingElementIDs are the regular cases whose one upload carries one
// policyId twice: two-sets-whose-policies-share-one-id, which asks the PAP about
// the shared id, and missing-attribute-in-set-target, whose fixture is kept as
// it was recorded.
var casesSharingElementIDs = map[string]struct{}{
	"missing-attribute-in-set-target":      {},
	"two-sets-whose-policies-share-one-id": {},
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
