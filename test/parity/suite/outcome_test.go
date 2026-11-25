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

package paritysuite

import (
	"encoding/json"
	"net/http"
	"testing"

	"authz-agent/test/parity/suite/model"
)

// outcomeOf reads every answer of a decision row through decodeAnswer, for the
// case runners and the export-fed judges alike. A 200 body of the wrong shape
// is an error on every row, an empty or null body of a v1 row reads as the
// legacy client's null, and a null list stays apart from an empty one.
func TestOutcomeOf_ReadsEachShapeOfAnAnswer(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		id     ParityEndpointID
		status int
		body   string
		want   string // the golden the answer records; empty where outcomeOf returns an error
	}{
		{"check v1, true", PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, http.StatusOK, `true`, `{"status":200,"decision":true}`},
		{"check v1, false", PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, http.StatusOK, `false`, `{"status":200,"decision":false}`},
		{"check v1, empty", PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, http.StatusOK, ``, `{"status":200,"decision":false}`},
		{"check v1, null", PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, http.StatusOK, ` null `, `{"status":200,"decision":false}`},
		{"check v1, a v2 object", PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, http.StatusOK, `{"decision":true}`, ``},
		{"check v1, a quoted true", PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, http.StatusOK, `"true"`, ``},
		{"check v1, not JSON", PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, http.StatusOK, `yes`, ``},
		{"check v1, an error body", PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, http.StatusBadRequest, `true`, `{"status":400,"decision":false}`},
		{"bulk v1, null", PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1_OUTCOME, http.StatusOK, `null`, `{"status":200,"allowed":null}`},
		{"bulk v1, empty", PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1_OUTCOME, http.StatusOK, ``, `{"status":200,"allowed":null}`},
		{"bulk v1, empty array", PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1_OUTCOME, http.StatusOK, `[]`, `{"status":200,"allowed":[]}`},
		{"bulk v1, ids out of order", PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1_OUTCOME, http.StatusOK, `["b","a"]`, `{"status":200,"allowed":["a","b"]}`},
		{"bulk v1, an object", PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1_OUTCOME, http.StatusOK, `{}`, ``},
		{"bulk v1, numbers", PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1_OUTCOME, http.StatusOK, `[1]`, ``},
		{"bulk v1, an error body", PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1_OUTCOME, http.StatusBadRequest, `{"error":"bad"}`, `{"status":400}`},
		{"bulk operations v1, an object", PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1_OUTCOME, http.StatusOK, `{}`, `{"status":200,"decision":{}}`},
		{"bulk operations v1, ids out of order", PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1_OUTCOME, http.StatusOK, `{"READ":["b","a"]}`, `{"status":200,"decision":{"READ":["a","b"]}}`},
		{"bulk operations v1, null", PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1_OUTCOME, http.StatusOK, `null`, `{"status":200,"decision":null}`},
		{"bulk operations v1, an array", PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1_OUTCOME, http.StatusOK, `[]`, ``},
		{"bulk operations v1, an error body", PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1_OUTCOME, http.StatusConflict, `{"error":"bad"}`, `{"status":409}`},
		{"filter v1, allow", PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, http.StatusOK, `{"calculationResult":"ALLOW"}`, `{"status":200,"result":{"calculationResult":"ALLOW"}}`},
		{"filter v1, empty", PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, http.StatusOK, ``, `{"status":200,"result":{"calculationResult":""}}`},
		{"filter v1, without calculationResult", PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, http.StatusOK, `{}`, ``},
		{"filter v1, not an object", PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, http.StatusOK, `[]`, ``},
		{"filter v1, an error body", PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, http.StatusBadRequest, `{"error":"bad"}`, `{"status":400,"result":{"calculationResult":""}}`},
		{"filter v1, an error body that is no JSON", PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, http.StatusInternalServerError, `boom`, `{"status":500,"result":{"calculationResult":""}}`},
		{"check v2, true", PSUITE_ROW_7_CHECK_RESOURCE_V2_OUTCOME, http.StatusOK, `{"decision":true}`, `{"status":200,"decision":true}`},
		{"check v2, without decision", PSUITE_ROW_7_CHECK_RESOURCE_V2_OUTCOME, http.StatusOK, `{}`, ``},
		{"check v2, a null decision", PSUITE_ROW_7_CHECK_RESOURCE_V2_OUTCOME, http.StatusOK, `{"decision":null}`, ``},
		{"check v2, a string decision", PSUITE_ROW_7_CHECK_RESOURCE_V2_OUTCOME, http.StatusOK, `{"decision":"true"}`, ``},
		{"check v2, empty", PSUITE_ROW_7_CHECK_RESOURCE_V2_OUTCOME, http.StatusOK, ``, ``},
		{"check v2, a v1 boolean", PSUITE_ROW_7_CHECK_RESOURCE_V2_OUTCOME, http.StatusOK, `true`, ``},
		{"check v2, an error body", PSUITE_ROW_7_CHECK_RESOURCE_V2_OUTCOME, http.StatusBadRequest, `{"error":"bad"}`, `{"status":400,"decision":false}`},
		{"bulk operations v2, ids out of order", PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2_OUTCOME, http.StatusOK, `{"decision":{"READ":["b","a"]}}`, `{"status":200,"decision":{"READ":["a","b"]}}`},
		{"bulk operations v2, an empty decision", PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2_OUTCOME, http.StatusOK, `{"decision":{}}`, `{"status":200,"decision":{}}`},
		{"bulk operations v2, without decision", PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2_OUTCOME, http.StatusOK, `{}`, ``},
		{"bulk operations v2, a null decision", PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2_OUTCOME, http.StatusOK, `{"decision":null}`, ``},
		{"bulk operations v2, obligations alone", PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2_OUTCOME, http.StatusOK, `{"obligations":[]}`, ``},
		{"bulk operations v2, an error body", PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2_OUTCOME, http.StatusBadRequest, `{"error":"bad"}`, `{"status":400}`},
		{"filter v2, allow", PSUITE_ROW_10_CHECK_FILTER_V2_OUTCOME, http.StatusOK, `{"calculationResult":"ALLOW"}`, `{"status":200,"result":{"calculationResult":"ALLOW"}}`},
		{"filter v2, without calculationResult", PSUITE_ROW_10_CHECK_FILTER_V2_OUTCOME, http.StatusOK, `{}`, ``},
		{"filter v2, empty", PSUITE_ROW_10_CHECK_FILTER_V2_OUTCOME, http.StatusOK, ``, ``},
		{"filter v2, an error body", PSUITE_ROW_10_CHECK_FILTER_V2_OUTCOME, http.StatusConflict, `{"error":"bad"}`, `{"status":409,"result":{"calculationResult":""}}`},
		{"check v1 row, false", PSUITE_ROW_2_CHECK_RESOURCE_V1, http.StatusOK, `false`, `false`},
		{"check v1 row, empty", PSUITE_ROW_2_CHECK_RESOURCE_V1, http.StatusOK, ``, `false`},
		{"check v1 row, a quoted true", PSUITE_ROW_2_CHECK_RESOURCE_V1, http.StatusOK, `"true"`, ``},
		{"check v1 row, a v2 object", PSUITE_ROW_2_CHECK_RESOURCE_V1, http.StatusOK, `{"decision":true}`, ``},
		{"check v1 row, an error status", PSUITE_ROW_2_CHECK_RESOURCE_V1, http.StatusBadRequest, `{"error":"bad"}`, ``},
		{"check v1 row, a 500 with a boolean body", PSUITE_ROW_2_CHECK_RESOURCE_V1, http.StatusInternalServerError, `false`, ``},
		{"bulk v1 row, ids keep their order", PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1, http.StatusOK, `["b","a"]`, `["b","a"]`},
		{"bulk v1 row, an object", PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1, http.StatusOK, `{}`, ``},
		{"bulk operations v1 row, ids keep their order", PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1, http.StatusOK, `{"READ":["b","a"]}`, `{"READ":["b","a"]}`},
		{"preview bulk operations v1 row, an array", PSUITE_ROW_5_PREVIEW_BULK_OPERATIONS_V1, http.StatusOK, `[]`, ``},
		{"filter v1 row, a 500", PSUITE_ROW_6_CHECK_FILTER_V1, http.StatusInternalServerError, `false`, ``},
		{"check v2 row, true", PSUITE_ROW_7_CHECK_RESOURCE_V2, http.StatusOK, `{"decision":true}`, `{"decision":true}`},
		{"check v2 row, without decision", PSUITE_ROW_7_CHECK_RESOURCE_V2, http.StatusOK, `{}`, ``},
		{"check v2 row, a string decision", PSUITE_ROW_7_CHECK_RESOURCE_V2, http.StatusOK, `{"decision":"true"}`, ``},
		{"bulk operations v2 row, without decision", PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2, http.StatusOK, `{}`, ``},
		{"preview bulk operations v2 row, without decision", PSUITE_ROW_9_PREVIEW_BULK_OPERATIONS_V2, http.StatusOK, `{}`, ``},
		{"filter v2 row, without calculationResult", PSUITE_ROW_10_CHECK_FILTER_V2, http.StatusOK, `{"obligations":[]}`, ``},
		{"api version, empty", PSUITE_ROW_1_API_VERSION, http.StatusOK, ``, `{"specs":null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := outcomeOf(tc.id, tc.status, []byte(tc.body), nil)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("outcomeOf(%d, %s) = %#v, want an error", tc.status, tc.body, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("outcomeOf(%d, %s): %v", tc.status, tc.body, err)
			}
			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != tc.want {
				t.Errorf("outcomeOf(%d, %s) records %s, want %s", tc.status, tc.body, encoded, tc.want)
			}
		})
	}
}

// Every row of the catalog either is a decision row, whose target allowanceOf
// reads, or is one of the rows listed here, which record no decision. A row
// added to the catalog fails this test until it is placed on one side, so
// allowsMoreThan never meets a decision it cannot read.
func TestAllowanceOf_ReadsTheTargetOfEveryDecisionRow(t *testing.T) {
	t.Parallel()
	noDecision := map[ParityEndpointID]bool{
		PSUITE_ROW_1_API_VERSION:        true,
		PSUITE_LOAD_SIMPLIFIED_POLICIES: true,
		PSUITE_LOAD_POLICY_SETS:         true,
		PSUITE_IMPORT_CUSTOMIZATION:     true,
		PSUITE_IMPORT_PIP_CUSTOMIZATION: true,
		PSUITE_DELETE_CUSTOMIZATION:     true,
		PSUITE_DELETE_PIP_CUSTOMIZATION: true,
		PSUITE_PAP_STATUS:               true,
		PSUITE_CONFIG_POLICY_SETS_V3:    true,
		PSUITE_CONFIG_PIPS_V3:           true,
		PSUITE_PIP_CALL:                 true,
		PSUITE_USER_MANAGEMENT_CALL:     true,
		PSUITE_PAP_READ:                 true,
		PSUITE_PAP_ERROR:                true,
		PSUITE_PAP_READ_RAW:             true,
	}
	for id := range rowMetas {
		_, ok := allowanceOf(NewGoldenTarget(id))
		if ok == noDecision[id] {
			t.Errorf("allowanceOf(%T) of row %s reads it: %t, want %t", NewGoldenTarget(id), Meta(id).GoldenDir, ok, !noDecision[id])
		}
	}
}

// allowsMoreThan compares what two targets of one row allow: an answer allows more
// only by a grant the golden lacks, and a refusal allows nothing. A filter
// that allows every row covers any condition, and a condition covers only the
// same condition, its unordered lists in any order.
func TestAllowsMoreThan_ComparesWhatTwoAnswersAllow(t *testing.T) {
	t.Parallel()
	ids := func(v ...string) *[]string { return &v }
	ops := func(m map[string][]string) *map[string][]string { return &m }
	filter := func(status int, result string) *model.FilterOutcome {
		return &model.FilterOutcome{Status: status, Result: model.OldFilterEvaluationResult{CalculationResult: result}}
	}
	condition := func(sql string) *model.FilterOutcome {
		return &model.FilterOutcome{Status: 200, Result: model.OldFilterEvaluationResult{
			CalculationResult: "USE_FILTER_CONDITION", SqlFilterCondition: model.FilterTextOf(sql)}}
	}
	cases := []struct {
		name         string
		actual, want any
		allowsMore   bool
	}{
		{"check allows where the golden denies", &model.CheckResourceOutcome{Status: 200, Decision: true}, &model.CheckResourceOutcome{Status: 200}, true},
		{"check denies where the golden allows", &model.CheckResourceOutcome{Status: 200}, &model.CheckResourceOutcome{Status: 200, Decision: true}, false},
		{"check allows where the golden refuses", &model.CheckResourceOutcome{Status: 200, Decision: true}, &model.CheckResourceOutcome{Status: 400}, true},
		{"a refusal against an allow", &model.CheckResourceV2Outcome{Status: 400}, &model.CheckResourceV2Outcome{Status: 200, Decision: true}, false},
		{"bulk adds an id", &model.CheckResourceBulkOutcome{Status: 200, Allowed: ids("a", "b")}, &model.CheckResourceBulkOutcome{Status: 200, Allowed: ids("a")}, true},
		{"bulk drops an id", &model.CheckResourceBulkOutcome{Status: 200, Allowed: ids()}, &model.CheckResourceBulkOutcome{Status: 200, Allowed: ids("a")}, false},
		{"bulk null against an empty list", &model.CheckResourceBulkOutcome{Status: 200}, &model.CheckResourceBulkOutcome{Status: 200, Allowed: ids()}, false},
		{"bulk operations move an id to another operation", &model.CheckResourceBulkOperationsOutcome{Status: 200, Decision: ops(map[string][]string{"READ": {"a"}})},
			&model.CheckResourceBulkOperationsOutcome{Status: 200, Decision: ops(map[string][]string{"WRITE": {"a"}})}, true},
		{"filter condition against deny", filter(200, "USE_FILTER_CONDITION"), filter(200, "DENY"), true},
		{"filter condition against allow", filter(200, "USE_FILTER_CONDITION"), filter(200, "ALLOW"), false},
		{"filter allow against a refusal", filter(200, "ALLOW"), filter(400, ""), true},
		{"filter allow against a condition", filter(200, "ALLOW"), condition("a=1"), true},
		{"filter condition against another condition", condition("a=1 OR b=2"), condition("a=1"), true},
		{"filter condition against the same with its operands swapped", condition("b=2 OR a=1"), condition("a=1 OR b=2"), false},
		{"filter deny against a condition", filter(200, "DENY"), condition("a=1"), false},
		{"bulk operations split an operation and an id differently",
			&model.CheckResourceBulkOperationsOutcome{Status: 200, Decision: ops(map[string][]string{"a id b": {"c"}})},
			&model.CheckResourceBulkOperationsOutcome{Status: 200, Decision: ops(map[string][]string{"a": {"b id c"}})}, true},
		{"targets of no decision row", &model.PapReadOutcome{}, &model.PapReadOutcome{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := allowsMoreThan(tc.actual, tc.want); got != tc.allowsMore {
				t.Errorf("allowsMoreThan(%+v, %+v) = %t, want %t", tc.actual, tc.want, got, tc.allowsMore)
			}
		})
	}
}
