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
	"net/http"

	"authz-agent/test/parity/suite/model"
)

// v2Body decodes the JSON object raw into its members, and returns nil for a
// body that is no JSON object, such as an empty one.
func v2Body(raw []byte) map[string]json.RawMessage {
	var members map[string]json.RawMessage
	if json.Unmarshal(bytes.TrimSpace(raw), &members) != nil {
		return nil
	}
	return members
}

// obligationsMember returns the obligations member of a v2 answer whose body
// is raw: absent when the body is no object or has no such member.
func obligationsMember(raw []byte) model.Member {
	var m model.Member
	if member, ok := v2Body(raw)["obligations"]; ok {
		_ = json.Unmarshal(member, &m)
	}
	return m
}

// checkV2Outcome returns the golden shape of a check/resource answer sent
// through v2: its status, its obligations member, and on 200 its decision.
func checkV2Outcome(status int, raw []byte, message any) (*model.CheckResourceV2Outcome, error) {
	answer, err := answerOf[model.CheckResourceResponse](PSUITE_ROW_7_CHECK_RESOURCE_V2, status, raw)
	if err != nil {
		return nil, err
	}
	return &model.CheckResourceV2Outcome{Status: status, Decision: answer.Decision, Obligations: obligationsMember(raw), Message: message}, nil
}

// bulkOperationsV2Outcome returns the golden shape of a bulk operations answer
// sent through v2: its status, its obligations member, and on 200 the allowed
// ids of each operation, sorted.
func bulkOperationsV2Outcome(status int, raw []byte, message any) (*model.CheckResourceBulkOperationsV2Outcome, error) {
	out := &model.CheckResourceBulkOperationsV2Outcome{Status: status, Obligations: obligationsMember(raw), Message: message}
	if status != http.StatusOK {
		return out, nil
	}
	answer, err := answerOf[model.CheckResourcesResponse](PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2, status, raw)
	if err != nil {
		return nil, err
	}
	sortIDs(answer.Decision)
	out.Decision = &answer.Decision
	return out, nil
}

// filterV2Outcome returns the golden shape of a check/filter answer sent
// through v2: its status, its obligations member, and on 200 its filter result
// members.
func filterV2Outcome(status int, raw []byte, message any) (*model.FilterV2Outcome, error) {
	answer, err := answerOf[model.FilterResponse](PSUITE_ROW_10_CHECK_FILTER_V2, status, raw)
	if err != nil {
		return nil, err
	}
	return &model.FilterV2Outcome{Status: status, Result: answer.EvaluationResult(), Obligations: obligationsMember(raw), Message: message}, nil
}
