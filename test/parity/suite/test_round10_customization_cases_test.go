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
	"context"
	"net/http"
	"testing"

	"authz-agent/test/parity/suite/model"
)

const (
	customizationCaseID = "customization"
	// customizationLevel is the level the case customizes at. Decisions and the
	// active export are documented to use the effective policies of this level.
	customizationLevel = "CUSTOMER"
)

// customizationCase builds the set of TestRound10CustomizationCases and the
// customization of it. The set is a DENY_UNLESS_PERMIT policy of three ALLOW
// rules: READ, unconditional, which the customization disables; UPDATE, under a
// condition false for the reader, which the customization replaces with one
// that holds; PROBE, unconditional, which the customization leaves alone.
func customizationCase() (tc regularCase, customization []any, setID string) {
	b := regularBuilder{caseID: customizationCaseID}
	rt := regularResourceType(customizationCaseID)
	tc = regularCase{
		id:           customizationCaseID,
		resourceType: rt,
		uploads: []regularUpload{{externalID: "parity-" + customizationCaseID, sets: []any{
			b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
				b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
					b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil),
					b.rule("update-allow", "operation == 'UPDATE'", round9FalseSubjectCondition, "ALLOW", nil),
					b.rule("probe-allow", "operation == 'PROBE'", "true", "ALLOW", nil)),
			}, nil),
		}}},
		requests: []isolatedRequest{
			{name: "read-of-the-disabled-rule", operation: "READ", resource: map[string]any{"id": "r10-customization"}},
			{name: "update-of-the-replaced-rule", operation: "UPDATE", resource: map[string]any{"id": "r10-customization"}},
			{name: "probe-of-the-untouched-rule", operation: "PROBE", resource: map[string]any{"id": "r10-customization"}},
		},
	}
	setID = b.id("set/set")
	customization = []any{map[string]any{
		"policySetId": setID,
		"policies": []any{map[string]any{
			"policyId": b.id("policy/reader"),
			"rules": []any{
				map[string]any{"ruleId": b.id("rule/read-allow"), "status": "INACTIVE"},
				map[string]any{
					"ruleId":    b.id("rule/update-allow"),
					"name":      customizationCaseID + " update-allow replaced",
					"target":    "operation == 'UPDATE'",
					"condition": "true",
					"effect":    "ALLOW",
				},
			},
		}},
	}}
	return tc, customization, setID
}

// customizationRegularCases is the regular case of customizationCase, for
// TestRegularCaseIDsAreUnique.
func customizationRegularCases() []regularCase {
	tc, _, _ := customizationCase()
	return []regularCase{tc}
}

// Whether the decisions and the v3 export follow a customization of an
// uploaded rule. The PAP keeps customizations apart from the uploaded sets and
// documents the policies a decision uses as the uploaded ones with the
// customizations of every level applied; whether GET /access/v3/config/policySets,
// which the agent loads its configuration from, carries the uploaded rules or
// the customized ones is recorded nowhere. If it carries the uploaded ones, a
// rule a customization disabled still allows at the agent.
//
// The set's READ rule is disabled by status INACTIVE, its UPDATE rule is
// replaced by one whose condition holds, and its PROBE rule is left alone. The
// three requests and the export are sent before the customization, the control
// that the set is on the stand and decides as uploaded, and after it; PROBE is
// true both times, the control that the set is still loaded. The import status
// is recorded.
//
// When the test ends, the customization is deleted and the set is emptied by
// its externalId. The import drops the set's externalId, so emptying misses the
// set; the cleanup then reads the v3 export and deactivates the set, which
// stays in the export as INACTIVE. The test fails only if the set is still
// active after that. Each recording runs on a fresh stack, so the inactive set
// reaches no other case.
//
// The case lives in its own test function so that a recording run can be
// filtered to it. Legacy profile only: customizations are the PAP's.
func (s *ParitySuite) TestRound10CustomizationCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("customizations are applied by the access-control PAP; authz-policy-admin has none")
	}
	ctx := context.Background()
	m2m := s.mustM2MToken()
	tc, customization, setID := customizationCase()
	// The cleanups run after the suite has handed s.T() back to its parent, so
	// they report through the test they were registered in.
	t := s.T()
	deleteCustomization := func() {
		status, body, err := HelperDeleteSetCustomization(ctx, s.cfg, m2m, customizationLevel, setID)
		t.Logf("delete the %s customization of set %s: status %d, %v, %s", customizationLevel, setID, status, err, body)
	}
	// A customization a failed run left behind would make the answers recorded
	// before the import depend on that run.
	deleteCustomization()
	// Cleanups run last registered first: the customization is deleted, the set
	// is emptied by its externalId, and then the export is checked.
	t.Cleanup(func() { s.requireSetInactive(t, m2m, tc.resourceType, setID) })
	s.emptyPolicySetsOnCleanup(s.cfg, tc.uploads[0].externalID)
	t.Cleanup(deleteCustomization)

	upload := tc.uploads[0]
	uploadStatus, _, err := HelperPutPolicySets(ctx, s.cfg, m2m, upload.externalID, upload.sets)
	s.Require().NoError(err)
	s.Run("upload-1", func() {
		s.requirePendingGolden(PSUITE_LOAD_POLICY_SETS, customizationCaseID+"/upload-1", &model.PolicyLoadOutcome{Status: uploadStatus})
	})
	if uploadStatus < http.StatusOK || uploadStatus >= http.StatusMultipleChoices {
		return
	}
	s.runCustomizationRequests(tc, "before")

	importStatus, body, err := HelperImportCustomization(ctx, s.cfg, m2m, customizationLevel, customization)
	s.Require().NoError(err)
	s.T().Logf("import the %s customization: status %d, %s", customizationLevel, importStatus, body)
	s.Run("import", func() {
		s.requirePendingGolden(PSUITE_IMPORT_CUSTOMIZATION, customizationCaseID+"/import", &model.PolicyLoadOutcome{Status: importStatus})
	})
	if importStatus < http.StatusOK || importStatus >= http.StatusMultipleChoices {
		return
	}
	s.runCustomizationRequests(tc, "after")
}

// requireSetInactive deactivates the set setID if the v3 export lists it as
// active, and fails t if it is still active after that. The import drops the
// set's externalId, so emptying the externalId leaves the set in place, and the
// suite knows no PAP call that removes it; deactivation keeps it in the export
// as INACTIVE, where it decides nothing (inactive-set). The set is found by resourceType, the marker
// its target carries, and then by its policySetId.
func (s *ParitySuite) requireSetInactive(t *testing.T, m2m, resourceType, setID string) {
	ctx := context.Background()
	status, found := s.exportedSetStatus(t, m2m, resourceType, setID)
	if !found || status == "INACTIVE" {
		return
	}
	deactivated, answer, err := HelperDeactivatePolicySet(ctx, s.cfg, m2m, setID)
	t.Logf("deactivate policy set %s, whose status in the v3 export is %q: status %d, %v, %s", setID, status, deactivated, err, answer)
	status, found = s.exportedSetStatus(t, m2m, resourceType, setID)
	if found && status != "INACTIVE" {
		t.Errorf("policy set %s has status %q in the v3 export after its customization was deleted, its externalId emptied, "+
			"and deactivate answered %d", setID, status, deactivated)
	}
}

// exportedSetStatus returns the status of the set setID in the v3 export, and
// whether the export lists the set at all. A failed read is reported through t
// as a set not found.
func (s *ParitySuite) exportedSetStatus(t *testing.T, m2m, resourceType, setID string) (string, bool) {
	status, body, err := HelperGetConfigExport(context.Background(), s.cfg, PSUITE_CONFIG_POLICY_SETS_V3, m2m, PerCallOptions{})
	if err != nil || status != http.StatusOK {
		t.Errorf("read the v3 export after the cleanup: status %d, %v, %s", status, err, body)
		return "", false
	}
	export := narrowConfigExport(status, body, []string{resourceType})
	sets, _ := export.Export["policySets"].([]any)
	for _, set := range sets {
		fields, _ := set.(map[string]any)
		if fields["policySetId"] == setID {
			setStatus, _ := fields["status"].(string)
			return setStatus, true
		}
	}
	return "", false
}

// runCustomizationRequests sends the requests of tc and reads the v3 export of
// its set, recording both under stage.
func (s *ParitySuite) runCustomizationRequests(tc regularCase, stage string) {
	ctx := context.Background()
	s.Run(stage, func() {
		for _, req := range tc.requests {
			s.Run(req.name, func() {
				s.runPendingCheckResourceV1OutcomeCase(
					customizationCaseID+"/"+stage+"/"+req.name,
					model.CheckAccessRequest{Operation: req.operation, Type: tc.resourceType, Resource: req.resource},
					s.mustTokenBundle(UserProfileReader),
					PerCallOptions{},
				)
			})
		}
		s.Run("export-policy-sets", func() {
			status, body, err := HelperGetConfigExport(ctx, s.cfg, PSUITE_CONFIG_POLICY_SETS_V3, s.mustM2MToken(), PerCallOptions{})
			s.Require().NoError(err)
			s.requirePendingGolden(PSUITE_CONFIG_POLICY_SETS_V3, customizationCaseID+"/"+stage, narrowConfigExport(status, body, []string{tc.resourceType}))
		})
	})
}
