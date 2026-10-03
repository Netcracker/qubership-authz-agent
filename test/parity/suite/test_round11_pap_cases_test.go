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

// round11FilteredPIP declares a FILTERED PIP named name over resource type rt,
// with a top-level resourceType when withResourceType is set.
func round11FilteredPIP(name, rt string, withResourceType bool) map[string]any {
	pip := map[string]any{
		"name": name, "url": parityPipMockBase + "/r11-filtered", "httpMethod": "POST", "pipType": "FILTERED",
		"requestAttributes": map[string]string{"resourceType": rt}, "cacheable": false,
	}
	if withResourceType {
		pip["resourceType"] = rt
	}
	return pip
}

// Which of a top-level resourceType and a name ending in .filtered the PAP needs
// in a FILTERED declaration. config-export/declare-the-filtered-pip records a
// declaration with both, accepted, and h3-filtered-pip-plain-reference one with
// neither, refused together with a policy that reads it, so its refusal may be
// the condition's.
//
// Each declaration is uploaded alone, with a policy that reads nothing, over the
// case's own resource type, and its status is recorded: fd-both is the control
// that the upload is accepted, fd-neither has neither field, like h3's
// declaration, without h3's condition, and the other two carry one of the two
// fields each.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound11FilteredDeclarationCases() {
	var cases []isolatedCase
	for _, form := range []struct {
		key, name        string
		withResourceType bool
	}{
		{"fd-both", "subject.parityR11FdBoth.filtered", true},
		{"fd-resource-type-only", "subject.parityR11FdTypeOnly", true},
		{"fd-suffix-only", "subject.parityR11FdSuffixOnly.filtered", false},
		{"fd-neither", "subject.parityR11FdNeither", false},
	} {
		cases = append(cases, isolatedCase{id: form.key, resourceType: round11ResourceType(form.key), pips: []any{round11FilteredPIP(form.name, round11ResourceType(form.key), form.withResourceType)}})
	}
	s.runIsolatedCases(cases)
}
