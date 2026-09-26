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
	"time"
)

// Round 16 asks what no earlier golden reached once the operand kinds were
// covered: the value types each operator meets, a PIP holding the value an
// attribute would, rules the goldens pin with a single case, forms that tell
// apart implementations of number parsing, MATCH, and JSON Path, condition
// syntax, and trees of sets that no golden combined the same way. Its
// cases are data under testdata/cases/round16, and each file's about field
// says what it asks. Each function runs one file, so that a recording run can
// be filtered to it and record it on a stand of its own. The files are listed
// in the order that asks the most per golden first.

// TestRound16HypothesesCases runs round16/hypotheses.json.
func (s *ParitySuite) TestRound16HypothesesCases() { s.runCaseFile("round16/hypotheses.json") }

// TestRound16SetsCases runs round16/sets.json.
func (s *ParitySuite) TestRound16SetsCases() { s.runCaseFile("round16/sets.json") }

// TestRound16OrderCases runs round16/order.json. Each request is filed under
// the order class the stand evaluated it in, by the call log of the failing
// PIP's route.
func (s *ParitySuite) TestRound16OrderCases() { s.runCaseFile("round16/order.json") }

// TestRound16SyntaxCases runs round16/syntax.json.
func (s *ParitySuite) TestRound16SyntaxCases() { s.runCaseFile("round16/syntax.json") }

// TestRound16SecondCarrierCases runs round16/second-carrier.json.
func (s *ParitySuite) TestRound16SecondCarrierCases() { s.runCaseFile("round16/second-carrier.json") }

// TestRound16ResidualCases runs round16/residual.json.
func (s *ParitySuite) TestRound16ResidualCases() { s.runCaseFile("round16/residual.json") }

// TestRound16ValuesCases runs round16/values.json.
func (s *ParitySuite) TestRound16ValuesCases() { s.runCaseFile("round16/values.json") }

// TestRound16PipOperandsCases runs round16/pip-operands.json.
func (s *ParitySuite) TestRound16PipOperandsCases() { s.runCaseFile("round16/pip-operands.json") }

// customizationUnderIterateCaseID prefixes the goldens of
// TestRound16CustomizationUnderIterateCases.
const customizationUnderIterateCaseID = "customization-under-iterate"

// customizationUnderIterateCase builds customizationCase's set and
// customization with the set iterating over subject.permissionScope, under the
// id customizationUnderIterateCaseID.
func customizationUnderIterateCase() (tc regularCase, customization []any, setID string) {
	b := regularBuilder{caseID: customizationUnderIterateCaseID}
	rt := regularResourceType(customizationUnderIterateCaseID)
	resource := map[string]any{"id": "r16-customization"}
	tc = regularCase{
		id:           customizationUnderIterateCaseID,
		resourceType: rt,
		pips:         []any{permissionScopeWirePIP},
		uploads: []regularUpload{{externalID: "parity-" + customizationUnderIterateCaseID, sets: []any{
			b.iteratingSet("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", "subject.permissionScope", []any{
				b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
					b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil),
					b.rule("update-allow", "operation == 'UPDATE'", round9FalseSubjectCondition, "ALLOW", nil),
					b.rule("probe-allow", "operation == 'PROBE'", "true", "ALLOW", nil)),
			}),
		}}},
		requests: []isolatedRequest{
			{name: "read-of-the-disabled-rule", operation: "READ", resource: resource},
			{name: "update-of-the-replaced-rule", operation: "UPDATE", resource: resource},
			{name: "probe-of-the-untouched-rule", operation: "PROBE", resource: resource},
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
					"name":      customizationUnderIterateCaseID + " update-allow replaced",
					"target":    "operation == 'UPDATE'",
					"condition": "true",
					"effect":    "ALLOW",
				},
			},
		}},
	}}
	return tc, customization, setID
}

// customizationUnderIterateRegularCases is the regular case of
// customizationUnderIterateCase, for TestRegularCaseIDsAreUnique.
func customizationUnderIterateRegularCases() []regularCase {
	tc, _, _ := customizationUnderIterateCase()
	return []regularCase{tc}
}

// TestRound16CustomizationUnderIterateCases asks whether a customization
// applies to the rules of a set that iterates over subject.permissionScope. It
// is TestRound10CustomizationCases with the set iterating over one grant,
// region r1: the READ rule is disabled, the UPDATE rule is replaced by one that
// holds, and PROBE is the control that the set is loaded and the pass applies.
//
// The case lives in its own test function so that a recording run can be
// filtered to it. Legacy profile only: customizations are the PAP's.
func (s *ParitySuite) TestRound16CustomizationUnderIterateCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("customizations are applied by the access-control PAP; authz-policy-admin has none")
	}
	ctx := context.Background()
	route := permissionScopeWirePath(parityReaderSubjectID)
	s.Require().NoError(s.pipMock.PinRoute(ctx, route, PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       permissionScopeWireBody(parityReaderSubjectID, []permissionScopeGrant{{"region": {"r1"}}}),
	}))
	// Wait out the cachePeriod of permissionScopeWirePIP, as pinTwoScopeGrants does.
	time.Sleep(2 * time.Second)
	s.Require().NoError(s.pipMock.ResetCalls(ctx))
	tc, customization, setID := customizationUnderIterateCase()
	s.runCustomizationCase(tc, customization, setID)
	// A scope service that no request called leaves PROBE false for a reason the
	// case does not ask about.
	s.Assert().Positive(s.pipCalls(route), "pip-mock calls to %s over %s", route, tc.id)
}
