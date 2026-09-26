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

// isM2MHeader is the header the PIP of TestRound11DeclaredNameCases reads.
const isM2MHeader = "x-parity-r11-is-m2m"

// round11HeaderPIP declares name as a HEADER PIP over isM2MHeader.
func round11HeaderPIP(name string) map[string]any {
	return map[string]any{"name": name, "type": "UUID", "pipType": "HEADER", "header": isM2MHeader, "cacheable": false}
}

// round11MappingPIP declares name as a MAPPING PIP granting permission to
// ROLE_PARITY_READER.
func round11MappingPIP(name, permission string) map[string]any {
	return map[string]any{
		"name": name, "type": "UUID", "pipType": "MAPPING", "cacheable": false,
		"customMapping": map[string]any{"subject.roles": map[string]any{"ROLE_PARITY_READER": []string{permission}}},
	}
}

// Whether the PAP refuses subject.isM2M in a condition by its name or because
// nothing declares it, and whether it refuses a MAPPING PIP named
// subject.permissions with no suffix. rule-condition-subject-is-m2m, in a regular
// set, and g8a-subject-is-m2m, a bare subject.isM2M in a simplified policy,
// record the refusal of an undeclared subject.isM2M, which either reason
// produces; pm1
// records a MAPPING PIP with a suffix, and a declaration without one is recorded
// nowhere.
//
// dm-is-m2m-declared declares a HEADER PIP named subject.isM2M and reads it;
// dm-is-m2m-undeclared sends the same condition with nothing declared, and
// dm-same-pip-under-another-name declares the same PIP under another name; the
// two are the controls. um-unsuffixed-mapping declares a MAPPING PIP named
// subject.permissions; um-suffixed-mapping, the control, names it
// subject.permissions.PARITY_R11. Each case reads what it declares, with the
// header set to yes where it reads the header.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound11DeclaredNameCases() {
	yes := map[string]string{isM2MHeader: "yes"}
	s.runIsolatedCases([]isolatedCase{
		{id: "dm-is-m2m-declared", resourceType: round11ResourceType("dm-is-m2m-declared"), condition: "subject.isM2M == 'yes'",
			pips:     []any{round11HeaderPIP("subject.isM2M")},
			requests: []isolatedRequest{{name: "header-yes", resource: map[string]any{"id": "r11-is-m2m"}, headers: yes}}},
		{id: "dm-is-m2m-undeclared", resourceType: round11ResourceType("dm-is-m2m-undeclared"), condition: "subject.isM2M == 'yes'",
			requests: []isolatedRequest{{name: "header-yes", resource: map[string]any{"id": "r11-is-m2m"}, headers: yes}}},
		{id: "dm-same-pip-under-another-name", resourceType: round11ResourceType("dm-same-pip-under-another-name"), condition: "subject.parityR11IsM2M == 'yes'",
			pips:     []any{round11HeaderPIP("subject.parityR11IsM2M")},
			requests: []isolatedRequest{{name: "header-yes", resource: map[string]any{"id": "r11-is-m2m"}, headers: yes}}},
		{id: "um-unsuffixed-mapping", resourceType: round11ResourceType("um-unsuffixed-mapping"), condition: "subject.permissions CONTAINS 'parity_r11_unsuffixed'",
			pips:     []any{round11MappingPIP("subject.permissions", "parity_r11_unsuffixed")},
			requests: []isolatedRequest{{name: "reader", resource: map[string]any{"id": "r11-mapping"}}}},
		{id: "um-suffixed-mapping", resourceType: round11ResourceType("um-suffixed-mapping"), condition: "subject.permissions CONTAINS 'parity_r11_suffixed'",
			pips:     []any{round11MappingPIP("subject.permissions.PARITY_R11", "parity_r11_suffixed")},
			requests: []isolatedRequest{{name: "reader", resource: map[string]any{"id": "r11-mapping"}}}},
	})
}

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
