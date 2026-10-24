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

// Round 29 asks what access-control does where no golden decides: the members
// of a PIP declaration at runtime, the fields of a set, a policy, and a rule
// that the earlier cases never sent, the constraints of an upload,
// customization of sets and PIPs, bulk checks, and checks on behalf of another
// user. It also asks the pairs of configuration dimensions no golden combined,
// the defaults the earlier rounds left unchecked, and the readings round 28
// left open. Its cases are data under testdata/cases/round29, and each case's
// about field says what it asks. Each function runs one file, so that a
// recording run can be filtered to it and record it on a stand of its own.

// TestRound29DocCustomMappingEmptyCases runs round29/doc-custom-mapping-empty.json.
func (s *ParitySuite) TestRound29DocCustomMappingEmptyCases() {
	s.runCaseFile("round29/doc-custom-mapping-empty.json")
}

// TestRound29DocFilterRsqlUnitsCases runs round29/doc-filter-rsql-units.json.
func (s *ParitySuite) TestRound29DocFilterRsqlUnitsCases() {
	s.runCaseFile("round29/doc-filter-rsql-units.json")
}

// TestRound29DocJsonpathNoDollarCases runs round29/doc-jsonpath-no-dollar.json.
func (s *ParitySuite) TestRound29DocJsonpathNoDollarCases() {
	s.runCaseFile("round29/doc-jsonpath-no-dollar.json")
}

// TestRound29DocJsonpathRootBracketCases runs round29/doc-jsonpath-root-bracket.json.
func (s *ParitySuite) TestRound29DocJsonpathRootBracketCases() {
	s.runCaseFile("round29/doc-jsonpath-root-bracket.json")
}

// TestRound29DocPipSetCases runs round29/doc-pip-set.json.
func (s *ParitySuite) TestRound29DocPipSetCases() { s.runCaseFile("round29/doc-pip-set.json") }

// TestRound29DocScopeTrimCases runs round29/doc-scope-trim.json.
func (s *ParitySuite) TestRound29DocScopeTrimCases() {
	s.runCaseFile("round29/doc-scope-trim.json")
}

// TestRound29FieldsCustomEffectCases runs round29/fields-custom-effect.json.
func (s *ParitySuite) TestRound29FieldsCustomEffectCases() {
	s.runCaseFile("round29/fields-custom-effect.json")
}

// TestRound29FieldsDomainCases runs round29/fields-domain.json.
func (s *ParitySuite) TestRound29FieldsDomainCases() { s.runCaseFile("round29/fields-domain.json") }

// TestRound29FieldsExternalIdCases runs round29/fields-external-id.json.
func (s *ParitySuite) TestRound29FieldsExternalIdCases() {
	s.runCaseFile("round29/fields-external-id.json")
}

// TestRound29FieldsFrontendCases runs round29/fields-frontend.json.
func (s *ParitySuite) TestRound29FieldsFrontendCases() {
	s.runCaseFile("round29/fields-frontend.json")
}

// TestRound29FieldsPipMethodCases runs round29/fields-pip-method.json.
func (s *ParitySuite) TestRound29FieldsPipMethodCases() {
	s.runCaseFile("round29/fields-pip-method.json")
}

// TestRound29FieldsPredicatesCases runs round29/fields-predicates.json.
func (s *ParitySuite) TestRound29FieldsPredicatesCases() {
	s.runCaseFile("round29/fields-predicates.json")
}

// TestRound29FieldsTenantCases runs round29/fields-tenant.json.
func (s *ParitySuite) TestRound29FieldsTenantCases() { s.runCaseFile("round29/fields-tenant.json") }

// TestRound29GapsEntitlementsCases runs round29/gaps-entitlements.json.
func (s *ParitySuite) TestRound29GapsEntitlementsCases() {
	s.runCaseFile("round29/gaps-entitlements.json")
}

// TestRound29GapsScopeCases runs round29/gaps-scope.json.
func (s *ParitySuite) TestRound29GapsScopeCases() { s.runCaseFile("round29/gaps-scope.json") }

// TestRound29GapsSetsCases runs round29/gaps-sets.json.
func (s *ParitySuite) TestRound29GapsSetsCases() { s.runCaseFile("round29/gaps-sets.json") }

// TestRound29GapsValuesCases runs round29/gaps-values.json.
func (s *ParitySuite) TestRound29GapsValuesCases() { s.runCaseFile("round29/gaps-values.json") }

// TestRound29GapsW2CustomShapeCases runs round29/gaps-w2-custom-shape.json.
func (s *ParitySuite) TestRound29GapsW2CustomShapeCases() {
	s.runCaseFile("round29/gaps-w2-custom-shape.json")
}

// TestRound29GapsW2RuleStatusCases runs round29/gaps-w2-rule-status.json.
func (s *ParitySuite) TestRound29GapsW2RuleStatusCases() {
	s.runCaseFile("round29/gaps-w2-rule-status.json")
}

// TestRound29PairsNoGrantCases runs round29/pairs-no-grant.json.
func (s *ParitySuite) TestRound29PairsNoGrantCases() {
	s.runCaseFile("round29/pairs-no-grant.json")
}

// TestRound29PairsOneGrantCases runs round29/pairs-one-grant.json.
func (s *ParitySuite) TestRound29PairsOneGrantCases() {
	s.runCaseFile("round29/pairs-one-grant.json")
}

// TestRound29PairsPlainCases runs round29/pairs-plain.json.
func (s *ParitySuite) TestRound29PairsPlainCases() { s.runCaseFile("round29/pairs-plain.json") }

// TestRound29PairsTwoGrantsCases runs round29/pairs-two-grants.json.
func (s *ParitySuite) TestRound29PairsTwoGrantsCases() {
	s.runCaseFile("round29/pairs-two-grants.json")
}

// TestRound29PapCustomizationCases runs round29/pap-customization.json.
func (s *ParitySuite) TestRound29PapCustomizationCases() {
	s.runCaseFile("round29/pap-customization.json")
}

// TestRound29PapPipsCases runs round29/pap-pips.json.
func (s *ParitySuite) TestRound29PapPipsCases() { s.runCaseFile("round29/pap-pips.json") }

// TestRound29PapPoliciesCases runs round29/pap-policies.json.
func (s *ParitySuite) TestRound29PapPoliciesCases() { s.runCaseFile("round29/pap-policies.json") }

// TestRound29PapSetsCases runs round29/pap-sets.json.
func (s *ParitySuite) TestRound29PapSetsCases() { s.runCaseFile("round29/pap-sets.json") }

// TestRound29PipfieldCacheLongCases runs round29/pipfield-cache-long.json.
//
// Each of its two cases waits 70 s, so the function takes about 140 s.
func (s *ParitySuite) TestRound29PipfieldCacheLongCases() {
	s.runCaseFile("round29/pipfield-cache-long.json")
}

// TestRound29PipfieldCacheCases runs round29/pipfield-cache.json.
func (s *ParitySuite) TestRound29PipfieldCacheCases() {
	s.runCaseFile("round29/pipfield-cache.json")
}

// TestRound29PipfieldCustomParamCases runs round29/pipfield-custom-param.json.
func (s *ParitySuite) TestRound29PipfieldCustomParamCases() {
	s.runCaseFile("round29/pipfield-custom-param.json")
}

// TestRound29PipfieldHeadersCases runs round29/pipfield-headers.json.
func (s *ParitySuite) TestRound29PipfieldHeadersCases() {
	s.runCaseFile("round29/pipfield-headers.json")
}

// TestRound29PipfieldLevelCases runs round29/pipfield-level.json.
//
// Its cases need the three users of testdata/realm/round29-pipfield-users.json in
// the parity realm and the mapper of the end-user client that puts the user
// attribute level into the claim level; subjectClaims fails a request whose
// token lacks the claim.
func (s *ParitySuite) TestRound29PipfieldLevelCases() {
	s.runCaseFile("round29/pipfield-level.json")
}

// TestRound29PipfieldNamesCases runs round29/pipfield-names.json.
func (s *ParitySuite) TestRound29PipfieldNamesCases() {
	s.runCaseFile("round29/pipfield-names.json")
}

// TestRound29PipfieldRemoteCases runs round29/pipfield-remote.json.
func (s *ParitySuite) TestRound29PipfieldRemoteCases() {
	s.runCaseFile("round29/pipfield-remote.json")
}

// TestRound29PipfieldRequestAttributesCases runs round29/pipfield-request-attributes.json.
func (s *ParitySuite) TestRound29PipfieldRequestAttributesCases() {
	s.runCaseFile("round29/pipfield-request-attributes.json")
}

// TestRound29PipfieldScopeCacheCases runs round29/pipfield-scope-cache.json.
func (s *ParitySuite) TestRound29PipfieldScopeCacheCases() {
	s.runCaseFile("round29/pipfield-scope-cache.json")
}

// TestRound29PipfieldTypeCases runs round29/pipfield-type.json.
func (s *ParitySuite) TestRound29PipfieldTypeCases() { s.runCaseFile("round29/pipfield-type.json") }

// TestRound29R28AroundRefusalCases runs round29/r28-around-refusal.json.
func (s *ParitySuite) TestRound29R28AroundRefusalCases() {
	s.runCaseFile("round29/r28-around-refusal.json")
}

// TestRound29R28EmptyOutCases runs round29/r28-empty-out.json.
func (s *ParitySuite) TestRound29R28EmptyOutCases() { s.runCaseFile("round29/r28-empty-out.json") }

// TestRound29R28MappingKeyCases runs round29/r28-mapping-key.json.
func (s *ParitySuite) TestRound29R28MappingKeyCases() {
	s.runCaseFile("round29/r28-mapping-key.json")
}

// TestRound29R28MappingTypeCases runs round29/r28-mapping-type.json.
func (s *ParitySuite) TestRound29R28MappingTypeCases() {
	s.runCaseFile("round29/r28-mapping-type.json")
}

// TestRound29R28MongoEqCases runs round29/r28-mongo-eq.json.
func (s *ParitySuite) TestRound29R28MongoEqCases() { s.runCaseFile("round29/r28-mongo-eq.json") }

// TestRound29R28PermissionsOrderCases runs round29/r28-permissions-order.json.
func (s *ParitySuite) TestRound29R28PermissionsOrderCases() {
	s.runCaseFile("round29/r28-permissions-order.json")
}

// TestRound29R28TokenCases runs round29/r28-token.json.
func (s *ParitySuite) TestRound29R28TokenCases() { s.runCaseFile("round29/r28-token.json") }

// TestRound29R28UrlCases runs round29/r28-url.json.
func (s *ParitySuite) TestRound29R28UrlCases() { s.runCaseFile("round29/r28-url.json") }

// TestRound29R28ValuesCases runs round29/r28-values.json.
func (s *ParitySuite) TestRound29R28ValuesCases() { s.runCaseFile("round29/r28-values.json") }

// TestRound29StructureBulkCases runs round29/structure-bulk.json.
func (s *ParitySuite) TestRound29StructureBulkCases() {
	s.runCaseFile("round29/structure-bulk.json")
}

// TestRound29StructureCustomFieldsCases runs round29/structure-custom-fields.json.
func (s *ParitySuite) TestRound29StructureCustomFieldsCases() {
	s.runCaseFile("round29/structure-custom-fields.json")
}

// TestRound29StructureCustomPipsCases runs round29/structure-custom-pips.json.
func (s *ParitySuite) TestRound29StructureCustomPipsCases() {
	s.runCaseFile("round29/structure-custom-pips.json")
}

// TestRound29StructureCustomizationCases runs round29/structure-customization.json.
func (s *ParitySuite) TestRound29StructureCustomizationCases() {
	s.runCaseFile("round29/structure-customization.json")
}

// TestRound29StructureEffectCases runs round29/structure-effect.json.
func (s *ParitySuite) TestRound29StructureEffectCases() {
	s.runCaseFile("round29/structure-effect.json")
}

// TestRound29StructureOnBehalfCases runs round29/structure-on-behalf.json.
func (s *ParitySuite) TestRound29StructureOnBehalfCases() {
	s.runCaseFile("round29/structure-on-behalf.json")
}

// TestRound29StructureStatusCases runs round29/structure-status.json.
func (s *ParitySuite) TestRound29StructureStatusCases() {
	s.runCaseFile("round29/structure-status.json")
}

// TestRound29StructureTypeCases runs round29/structure-type.json.
func (s *ParitySuite) TestRound29StructureTypeCases() {
	s.runCaseFile("round29/structure-type.json")
}
