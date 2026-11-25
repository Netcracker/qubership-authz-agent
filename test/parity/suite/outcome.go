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
	"bytes"
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
// agent's answers through it, so both build a golden target the same way.
//
// An outcome row, one whose golden directory ends in -outcome, records every
// status: a refused answer keeps its status and carries no decision, ids, or
// filter result. Any other row records only a 200 answer, and outcomeOf
// returns an error for another status. A 200 body is read by [decodeAnswer],
// so a body that does not have the row's shape is an error on every row.
func outcomeOf(id ParityEndpointID, status int, raw []byte, message any) (any, error) {
	switch id {
	case PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME:
		return checkV1Outcome(status, raw, message)
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
	return decodeAnswer(id, raw)
}

// A jsonKind is the kind of a JSON value, told by its first byte.
type jsonKind int

const (
	jsonInvalid jsonKind = iota
	jsonNull
	jsonBoolean
	jsonNumber
	jsonString
	jsonArray
	jsonObject
)

func (k jsonKind) String() string {
	return [...]string{"invalid JSON", "null", "boolean", "number", "string", "array", "object"}[k]
}

// kindOf returns the kind of the JSON value raw, which has no surrounding
// space; jsonInvalid where raw is no JSON value.
func kindOf(raw []byte) jsonKind {
	if !json.Valid(raw) {
		return jsonInvalid
	}
	switch raw[0] {
	case 'n':
		return jsonNull
	case 't', 'f':
		return jsonBoolean
	case '"':
		return jsonString
	case '[':
		return jsonArray
	case '{':
		return jsonObject
	}
	return jsonNumber
}

// An answerShape is the form a 200 body of a decision row has: a row whose
// golden records what a check, a bulk check, or a filter allowed.
type answerShape struct {
	// kind is the kind of the body.
	kind jsonKind
	// legacyNull is set for a v1 row, whose body the legacy v1 client reads as
	// null where it is empty or null: no decision (false), no ids, and no
	// filter result.
	legacyNull bool
	// member names a member the body has to hold, with a value of kind
	// memberKind; empty for none.
	member     string
	memberKind jsonKind
}

// answerShapeOf returns the shape of a 200 body read into target, the golden
// target of a row that is not an outcome row, and false where that row records
// no decision. A v2 body has to hold the member that carries the decision,
// since every v2 answer legacy sends with 200 holds it.
func answerShapeOf(target any) (answerShape, bool) {
	switch target.(type) {
	case *bool:
		return answerShape{kind: jsonBoolean, legacyNull: true}, true
	case *[]string:
		return answerShape{kind: jsonArray, legacyNull: true}, true
	case *map[string][]string:
		return answerShape{kind: jsonObject, legacyNull: true}, true
	case *model.OldFilterEvaluationResult:
		return answerShape{kind: jsonObject, legacyNull: true, member: "calculationResult", memberKind: jsonString}, true
	case *model.CheckResourceResponse:
		return answerShape{kind: jsonObject, member: "decision", memberKind: jsonBoolean}, true
	case *model.CheckResourcesResponse:
		return answerShape{kind: jsonObject, member: "decision", memberKind: jsonObject}, true
	case *model.FilterResponse:
		return answerShape{kind: jsonObject, member: "calculationResult", memberKind: jsonString}, true
	}
	return answerShape{}, false
}

// check returns an error where raw, a 200 body, does not have the shape s.
func (s answerShape) check(raw []byte) error {
	body := bytes.TrimSpace(raw)
	kind := jsonNull
	if len(body) > 0 {
		kind = kindOf(body)
	}
	switch {
	case kind == jsonNull && s.legacyNull:
		return nil
	case kind != s.kind:
		return fmt.Errorf("the body is %s, not a JSON %s: %q", kind, s.kind, body)
	case s.member == "":
		return nil
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body, &members); err != nil {
		return fmt.Errorf("read the members of %q: %w", body, err)
	}
	member, ok := members[s.member]
	if !ok {
		return fmt.Errorf("the body has no %s member: %q", s.member, body)
	}
	if got := kindOf(bytes.TrimSpace(member)); got != s.memberKind {
		return fmt.Errorf("the %s member is %s, not a JSON %s: %q", s.member, got, s.memberKind, body)
	}
	return nil
}

// decodeAnswer decodes raw, the body of a 200 answer to row id, into a new
// golden target of the row (NewGoldenTarget). For a row that records a
// decision (answerShapeOf), a body without the row's shape is an error, and an
// empty body of a v1 row reads as null. Any other row reads an empty body as
// its zero target.
func decodeAnswer(id ParityEndpointID, raw []byte) (any, error) {
	target := NewGoldenTarget(id)
	shape, ok := answerShapeOf(target)
	if !ok {
		if err := decodeJSON(raw, target); err != nil {
			return nil, err
		}
		return target, nil
	}
	if err := shape.check(raw); err != nil {
		return nil, fmt.Errorf("a 200 answer of %s: %w", Meta(id).GoldenDir, err)
	}
	body := bytes.TrimSpace(raw)
	if len(body) == 0 {
		body = []byte("null")
	}
	if err := json.Unmarshal(body, target); err != nil {
		return nil, fmt.Errorf("a 200 answer of %s: decode %q: %w", Meta(id).GoldenDir, body, err)
	}
	return target, nil
}

// answerOf returns the 200 body raw of row id decoded by [decodeAnswer], where
// T is the type the row's golden target points to. For any other status it
// returns the zero T and reads nothing.
func answerOf[T any](id ParityEndpointID, status int, raw []byte) (T, error) {
	var answer T
	if status != http.StatusOK {
		return answer, nil
	}
	target, err := decodeAnswer(id, raw)
	if err != nil {
		return answer, err
	}
	return *target.(*T), nil
}

// checkV1Outcome returns the golden shape of a check/resource answer: its
// status, and on 200 the decision the body holds.
func checkV1Outcome(status int, raw []byte, message any) (*model.CheckResourceOutcome, error) {
	decision, err := answerOf[bool](PSUITE_ROW_2_CHECK_RESOURCE_V1, status, raw)
	if err != nil {
		return nil, err
	}
	return &model.CheckResourceOutcome{Status: status, Decision: decision, Message: message}, nil
}

// bulkV1Outcome returns the golden shape of a check/resource/bulk answer: its
// status, and on 200 the allowed ids, sorted. A body of null records the ids as
// null, apart from an empty list.
func bulkV1Outcome(status int, raw []byte, message any) (*model.CheckResourceBulkOutcome, error) {
	out := &model.CheckResourceBulkOutcome{Status: status, Message: message}
	if status != http.StatusOK {
		return out, nil
	}
	allowed, err := answerOf[[]string](PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1, status, raw)
	if err != nil {
		return nil, err
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
	decision, err := answerOf[map[string][]string](PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1, status, raw)
	if err != nil {
		return nil, err
	}
	sortIDs(decision)
	out.Decision = &decision
	return out, nil
}

// sortIDs sorts the ids of each operation of byOperation in place.
func sortIDs(byOperation map[string][]string) {
	for _, ids := range byOperation {
		sort.Strings(ids)
	}
}

// filterV1Outcome returns the golden shape of a check/filter answer: its
// status, and on 200 the filter result the body holds.
func filterV1Outcome(status int, raw []byte, message any) (*model.FilterOutcome, error) {
	result, err := answerOf[model.OldFilterEvaluationResult](PSUITE_ROW_6_CHECK_FILTER_V1, status, raw)
	if err != nil {
		return nil, err
	}
	return &model.FilterOutcome{Status: status, Result: result, Message: message}, nil
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
// filter allowed. The result is a set of grants, so two targets of one row can
// be compared grant by grant: a check grant for an allowed check, each allowed
// id of a bulk check, each pair of an operation and an id it allows, one grant
// for the filter conditions of every dialect of a USE_FILTER_CONDITION result,
// and the every-row grant for ALLOW. A refused answer and DENY allow nothing.
// ok is false for a target that is not of a decision row.
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
		allowFilter(t.EvaluationResult())
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
