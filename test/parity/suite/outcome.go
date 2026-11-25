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
	"fmt"
	"net/http"
	"sort"
	"strings"

	"authz-agent/test/parity/suite/model"
)

// outcomeOf returns the golden target of row id for an answer with status and
// body raw; message is the recorded body of a refusal, or nil where the caller
// records none. The case runners read the answers to the requests of a case
// file through it (recordedOutcome), and the export-fed profiles read the
// agent's answers through it (decisionOutcome), so both build a golden target
// of an outcome row the same way.
//
// An outcome row records every status: a refused answer keeps its status and
// carries no decision, ids, or filter result. Any other row records only a 200
// answer, and outcomeOf returns an error for another status. A 200 body that
// does not have the row's shape is an error too, as is a 200 v2 check answer
// without a boolean decision.
func outcomeOf(id ParityEndpointID, status int, raw []byte, message any) (any, error) {
	switch id {
	case PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME:
		return checkV1Outcome(status, raw, message), nil
	case PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1_OUTCOME:
		return bulkV1Outcome(status, raw, message)
	case PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1_OUTCOME:
		return bulkOperationsV1Outcome(status, raw, message)
	case PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME:
		return filterV1Outcome(status, raw, message)
	case PSUITE_ROW_7_CHECK_RESOURCE_V2_OUTCOME:
		return checkV2Outcome(status, raw, message)
	case PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2_OUTCOME:
		return bulkOperationsV2Outcome(status, raw, message)
	case PSUITE_ROW_10_CHECK_FILTER_V2_OUTCOME:
		return filterV2Outcome(status, raw, message)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", status, strings.TrimSpace(string(raw)))
	}
	if id == PSUITE_ROW_7_CHECK_RESOURCE_V2 {
		if _, err := v2Decision(raw); err != nil {
			return nil, err
		}
	}
	target := NewGoldenTarget(id)
	if decision, ok := target.(*bool); ok {
		*decision = decodeBoolean(raw)
		return decision, nil
	}
	if err := decodeJSON(raw, target); err != nil {
		return nil, err
	}
	return target, nil
}

// checkV1Outcome returns the golden shape of a check/resource answer: its
// status, and on 200 the decision the body holds, read as the legacy client
// reads it (see decodeBoolean).
func checkV1Outcome(status int, raw []byte, message any) *model.CheckResourceOutcome {
	return &model.CheckResourceOutcome{Status: status, Decision: status == http.StatusOK && decodeBoolean(raw), Message: message}
}

// bulkV1Outcome returns the golden shape of a check/resource/bulk answer: its
// status, and on 200 the allowed ids, sorted. A body of null records the ids as
// null, apart from an empty list.
func bulkV1Outcome(status int, raw []byte, message any) (*model.CheckResourceBulkOutcome, error) {
	out := &model.CheckResourceBulkOutcome{Status: status, Message: message}
	if status != http.StatusOK {
		return out, nil
	}
	var allowed []string
	if err := decodeJSON(raw, &allowed); err != nil {
		return nil, fmt.Errorf("decode the allowed ids of %s: %w", raw, err)
	}
	sort.Strings(allowed)
	out.Allowed = &allowed
	return out, nil
}

// bulkOperationsV1Outcome returns the golden shape of a bulk operations
// answer: its status, and on 200 the allowed ids of each operation, sorted.
func bulkOperationsV1Outcome(status int, raw []byte, message any) (*model.CheckResourceBulkOperationsOutcome, error) {
	out := &model.CheckResourceBulkOperationsOutcome{Status: status, Message: message}
	if status != http.StatusOK {
		return out, nil
	}
	decision, err := allowedByOperation(raw)
	if err != nil {
		return nil, err
	}
	out.Decision = decision
	return out, nil
}

// allowedByOperation decodes member, a map from an operation to the ids it
// allows, and sorts the ids of each operation.
func allowedByOperation(member []byte) (*map[string][]string, error) {
	decision := map[string][]string{}
	if err := decodeJSON(member, &decision); err != nil {
		return nil, fmt.Errorf("decode the allowed ids by operation of %s: %w", member, err)
	}
	for _, ids := range decision {
		sort.Strings(ids)
	}
	return &decision, nil
}

// filterV1Outcome returns the golden shape of a check/filter answer: its
// status, and on 200 the filter result the body holds.
func filterV1Outcome(status int, raw []byte, message any) (*model.FilterOutcome, error) {
	out := &model.FilterOutcome{Status: status, Message: message}
	if status != http.StatusOK {
		return out, nil
	}
	if err := decodeJSON(raw, &out.Result); err != nil {
		return nil, fmt.Errorf("decode the filter result of %s: %w", raw, err)
	}
	return out, nil
}

// A grant is one thing a decision allows: a check (kind grantCheck), an id of
// a bulk check, a pair of an operation and an id, a filter condition, or every
// row of a filter (grantFilterAll).
type grant struct {
	kind      grantKind
	operation string
	id        string
	// condition is the JSON of the filter conditions of a
	// USE_FILTER_CONDITION result, with their unordered lists sorted.
	condition string
}

type grantKind int

const (
	grantCheck grantKind = iota
	grantID
	grantOperation
	grantFilterCondition
	grantFilterAll
)

// allowanceOf returns what target allows, where target is the golden target of
// a decision row: a row whose golden records what a check, a bulk check, or a
// filter allowed. It reads it as a set of grants that two targets of one row can be compared by: a check
// grant for an allowed check, each allowed id of a bulk check, each pair of an
// operation and an id it allows, the filter conditions of every dialect of a
// USE_FILTER_CONDITION result, as one grant, and every row for ALLOW. A refused answer and
// DENY allow nothing. ok is false for a target that is not of a decision row.
func allowanceOf(target any) (grants map[grant]bool, ok bool) {
	grants = map[grant]bool{}
	allowCheck := func(allowed bool) {
		if allowed {
			grants[grant{kind: grantCheck}] = true
		}
	}
	allowIDs := func(ids []string) {
		for _, id := range ids {
			grants[grant{kind: grantID, id: id}] = true
		}
	}
	allowOperations := func(byOperation map[string][]string) {
		for operation, ids := range byOperation {
			for _, id := range ids {
				grants[grant{kind: grantOperation, operation: operation, id: id}] = true
			}
		}
	}
	allowFilter := func(result model.OldFilterEvaluationResult) {
		switch result.CalculationResult {
		case "ALLOW":
			grants[grant{kind: grantFilterAll}] = true
		case "USE_FILTER_CONDITION":
			result.CalculationResult = ""
			normalizeOldFilterResultOrder(&result)
			condition, err := json.Marshal(result)
			if err != nil {
				panic(fmt.Sprintf("paritysuite: marshal a filter condition: %v", err))
			}
			grants[grant{kind: grantFilterCondition, condition: string(condition)}] = true
		}
	}
	refused := func(status int) bool { return status != http.StatusOK }
	switch t := target.(type) {
	case *bool:
		allowCheck(*t)
	case *model.CheckResourceResponse:
		allowCheck(t.Decision)
	case *model.CheckResourceOutcome:
		allowCheck(!refused(t.Status) && t.Decision)
	case *model.CheckResourceV2Outcome:
		allowCheck(!refused(t.Status) && t.Decision)
	case *[]string:
		allowIDs(*t)
	case *model.CheckResourceBulkOutcome:
		if !refused(t.Status) && t.Allowed != nil {
			allowIDs(*t.Allowed)
		}
	case *map[string][]string:
		allowOperations(*t)
	case *model.CheckResourcesResponse:
		allowOperations(t.Decision)
	case *model.CheckResourceBulkOperationsOutcome:
		if !refused(t.Status) && t.Decision != nil {
			allowOperations(*t.Decision)
		}
	case *model.CheckResourceBulkOperationsV2Outcome:
		if !refused(t.Status) && t.Decision != nil {
			allowOperations(*t.Decision)
		}
	case *model.OldFilterEvaluationResult:
		allowFilter(*t)
	case *model.FilterResponse:
		allowFilter(model.OldFilterEvaluationResult{
			CalculationResult: t.CalculationResult, FilterCondition: t.FilterCondition,
			MongodbFilterCondition: t.MongodbFilterCondition, RsqlFilterCondition: t.RsqlFilterCondition,
			SqlFilterCondition: t.SqlFilterCondition, CustomFilterCondition: t.CustomFilterCondition,
		})
	case *model.FilterOutcome:
		if !refused(t.Status) {
			allowFilter(t.Result)
		}
	case *model.FilterV2Outcome:
		if !refused(t.Status) {
			allowFilter(t.Result)
		}
	default:
		return nil, false
	}
	return grants, true
}

// covers reports whether the grants of want include g: g itself, or, for a
// filter condition, every row.
func covers(want map[grant]bool, g grant) bool {
	return want[g] || g.kind == grantFilterCondition && want[grant{kind: grantFilterAll}]
}
