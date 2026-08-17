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
	"fmt"
	"os"
	"regexp"
	"strings"
)

var subjectRefRe = regexp.MustCompile(`\$\{subject\.([^}]+)\}`)

// BuildActivationIndex reads the persisted policies file and cross-references
// subject.* references in RLS conditions/predicates with the given GENERAL PIP
// configs to build a resourceType -> operation -> [PIP names] activation map.
func BuildActivationIndex(generalPIPs map[string]GeneralPIPConfig, policiesPath string) map[string]map[string][]string {
	if len(generalPIPs) == 0 || policiesPath == "" {
		return map[string]map[string][]string{}
	}

	aliasToName := make(map[string]string, len(generalPIPs))
	for name, cfg := range generalPIPs {
		aliasToName[cfg.Alias] = name
		aliasToName[strings.TrimPrefix(name, "subject.")] = name
	}

	rlsData := loadRLSData(policiesPath)
	if len(rlsData) == 0 {
		return map[string]map[string][]string{}
	}

	return buildIndex(rlsData, aliasToName)
}

func loadRLSData(path string) map[string]any {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}

	if policies, ok := doc["policies"].(map[string]any); ok {
		if rls, ok := policies["rls"].(map[string]any); ok {
			return rls
		}
	}

	if rls, ok := doc["rls"].(map[string]any); ok {
		return rls
	}

	return nil
}

func buildIndex(rlsData map[string]any, aliasToName map[string]string) map[string]map[string][]string {
	result := make(map[string]map[string][]string)

	for resourceType, rtValue := range rlsData {
		rtObj, ok := rtValue.(map[string]any)
		if !ok {
			continue
		}

		for operation, opValue := range rtObj {
			opObj, ok := opValue.(map[string]any)
			if !ok {
				continue
			}

			pipNames := collectPIPRefsFromOperation(opObj, aliasToName)
			if len(pipNames) > 0 {
				if result[resourceType] == nil {
					result[resourceType] = make(map[string][]string)
				}
				result[resourceType][operation] = pipNames
			}
		}
	}

	return result
}

func collectPIPRefsFromOperation(opObj map[string]any, aliasToName map[string]string) []string {
	seen := make(map[string]bool)

	for _, roleValue := range opObj {
		rules, ok := roleValue.([]any)
		if !ok {
			continue
		}

		for _, ruleVal := range rules {
			rule, ok := ruleVal.(map[string]any)
			if !ok {
				continue
			}

			if ast, ok := rule["conditionAst"]; ok {
				scanASTForSubjectRefs(ast, aliasToName, seen)
			}

			if predicates, ok := rule["predicates"].([]any); ok {
				for _, pVal := range predicates {
					pred, ok := pVal.(map[string]any)
					if !ok {
						continue
					}
					predStr := fmt.Sprintf("%v", pred["predicate"])
					scanPredicateForSubjectRefs(predStr, aliasToName, seen)
				}
			}
		}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	return names
}

func scanASTForSubjectRefs(node any, aliasToName map[string]string, seen map[string]bool) {
	obj, ok := node.(map[string]any)
	if !ok {
		return
	}

	if ref, ok := obj["ref"].(map[string]any); ok {
		scope := fmt.Sprintf("%v", ref["scope"])
		if strings.EqualFold(scope, "subject") {
			if path, ok := ref["path"].([]any); ok && len(path) > 0 {
				alias := fmt.Sprintf("%v", path[0])
				if pipName, found := aliasToName[alias]; found {
					seen[pipName] = true
				}
			}
		}
	}

	if args, ok := obj["args"].([]any); ok {
		for _, arg := range args {
			scanASTForSubjectRefs(arg, aliasToName, seen)
		}
	}
}

func scanPredicateForSubjectRefs(predicate string, aliasToName map[string]string, seen map[string]bool) {
	matches := subjectRefRe.FindAllStringSubmatch(predicate, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		alias := match[1]
		if pipName, found := aliasToName[alias]; found {
			seen[pipName] = true
		}
	}
}
