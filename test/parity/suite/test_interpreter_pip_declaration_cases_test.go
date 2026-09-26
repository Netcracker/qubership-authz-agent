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

// headerListHeader is the header the HEADER PIP of the hl cases reads.
const headerListHeader = "x-parity-hdr-list"

// headerListPIP declares a HEADER PIP over headerListHeader with the given
// defaultValue, or none when it is empty.
func headerListPIP(defaultValue string) map[string]any {
	pip := map[string]any{
		"name":      "subject.parityHdrList",
		"type":      "UUID",
		"pipType":   "HEADER",
		"header":    headerListHeader,
		"cacheable": false,
	}
	if defaultValue != "" {
		pip["defaultValue"] = defaultValue
	}
	return pip
}

// What a HEADER PIP, a TOKEN PIP and a MAPPING PIP resolve under declaration
// shapes no recorded case declares. Every recorded HEADER PIP is read with a
// header holding one value and no comma (header-pip, h1, h2), so whether the
// value is one string or a list split on commas is not recorded, and neither is
// a defaultValue with a comma. Every recorded TOKEN PIP names a claim by its bare
// name (department, tier), not by a path into the token. Every recorded MAPPING
// PIP keys its mapping on subject.roles (pm1, pc1-pc3); whether the key may be
// another subject attribute or a TOKEN PIP is not recorded.
//
// The hl cases send the header a,b and ask CONTAINS 'b' (true for a list),
// == 'a,b' (true for one string) and IS EMPTY; hl4 and hl5 declare a
// defaultValue of x, y with a space after the comma, send no header, and ask
// CONTAINS 'y' and == 'x, y'. The tk cases read a claim by a path: tk1 the
// department claim as $.department, the control that a path resolves at all;
// tk2 the realm roles as $.realm_access.roles, a list inside an object. The mk
// cases key a MAPPING on subject.id, with the reader's id, and on a TOKEN PIP
// over the department claim, with the reader's department; mk3 keys it on
// subject.roles with a role the reader does not hold, the control that a
// mapping keyed on the wrong value grants nothing.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestInterpreterPIPDeclarationCases() {
	withList := map[string]string{headerListHeader: "a,b"}
	departmentPIP := map[string]any{
		"name": "subject.parityMkDepartment", "type": "UUID", "pipType": "TOKEN", "claim": "department", "cacheable": false,
	}
	s.runIsolatedCases([]isolatedCase{
		{id: "hl1-header-list-contains", resourceType: "PARITY_SUITE_HDR_HL1", condition: "subject.parityHdrList CONTAINS 'b'", pips: []any{headerListPIP("")}, requests: []isolatedRequest{
			{name: "header-a-comma-b", resource: map[string]any{"id": "hdr-hl1"}, headers: withList},
		}},
		{id: "hl2-header-list-equals-joined", resourceType: "PARITY_SUITE_HDR_HL2", condition: "subject.parityHdrList == 'a,b'", pips: []any{headerListPIP("")}, requests: []isolatedRequest{
			{name: "header-a-comma-b", resource: map[string]any{"id": "hdr-hl2"}, headers: withList},
		}},
		{id: "hl3-header-list-is-empty", resourceType: "PARITY_SUITE_HDR_HL3", condition: "subject.parityHdrList IS EMPTY", pips: []any{headerListPIP("")}, requests: []isolatedRequest{
			{name: "header-a-comma-b", resource: map[string]any{"id": "hdr-hl3"}, headers: withList},
			{name: "no-header", resource: map[string]any{"id": "hdr-hl3"}},
		}},
		{id: "hl4-default-with-a-space-contains", resourceType: "PARITY_SUITE_HDR_HL4", condition: "subject.parityHdrList CONTAINS 'y'", pips: []any{headerListPIP("x, y")}, requests: []isolatedRequest{
			{name: "no-header", resource: map[string]any{"id": "hdr-hl4"}},
		}},
		{id: "hl5-default-with-a-space-equals-joined", resourceType: "PARITY_SUITE_HDR_HL5", condition: "subject.parityHdrList == 'x, y'", pips: []any{headerListPIP("x, y")}, requests: []isolatedRequest{
			{name: "no-header", resource: map[string]any{"id": "hdr-hl5"}},
		}},

		{id: "tk1-token-claim-by-path", resourceType: "PARITY_SUITE_TOK_TK1", condition: "subject.parityTkDepartment == 'finance'", pips: []any{map[string]any{
			"name": "subject.parityTkDepartment", "type": "UUID", "pipType": "TOKEN", "claim": "$.department", "cacheable": false,
		}}, requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "tok-tk1"}},
		}},
		{id: "tk2-token-claim-list-by-path", resourceType: "PARITY_SUITE_TOK_TK2", condition: "subject.parityTkRoles CONTAINS 'ROLE_PARITY_READER'", pips: []any{map[string]any{
			"name": "subject.parityTkRoles", "type": "UUID", "pipType": "TOKEN", "claim": "$.realm_access.roles", "cacheable": false,
		}}, requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "tok-tk2"}},
		}},

		{id: "mk1-mapping-keyed-on-subject-id", resourceType: "PARITY_SUITE_MAP_MK1", condition: "subject.permissions CONTAINS 'parity_by_id'", pips: []any{map[string]any{
			"name": "subject.permissions.PARITY_MK1", "type": "UUID", "pipType": "MAPPING", "cacheable": false,
			"customMapping": map[string]any{"subject.id": map[string]any{parityReaderSubjectID: []string{"parity_by_id"}}},
		}}, requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "map-mk1"}},
		}},
		{id: "mk2-mapping-keyed-on-a-token-pip", resourceType: "PARITY_SUITE_MAP_MK2", condition: "subject.permissions CONTAINS 'parity_by_department'", pips: []any{departmentPIP, map[string]any{
			"name": "subject.permissions.PARITY_MK2", "type": "UUID", "pipType": "MAPPING", "cacheable": false,
			"customMapping": map[string]any{"subject.parityMkDepartment": map[string]any{"finance": []string{"parity_by_department"}}},
		}}, requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "map-mk2"}},
		}},
		{id: "mk3-mapping-keyed-on-a-role-not-held", resourceType: "PARITY_SUITE_MAP_MK3", condition: "subject.permissions CONTAINS 'parity_by_other_role'", pips: []any{map[string]any{
			"name": "subject.permissions.PARITY_MK3", "type": "UUID", "pipType": "MAPPING", "cacheable": false,
			"customMapping": map[string]any{"subject.roles": map[string]any{"ROLE_PARITY_OTHER": []string{"parity_by_other_role"}}},
		}}, requests: []isolatedRequest{
			{name: "reader", resource: map[string]any{"id": "map-mk3"}},
		}},
	})
}
