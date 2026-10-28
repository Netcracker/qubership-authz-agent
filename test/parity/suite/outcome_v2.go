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
	"sort"

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
// through v2: its status, its decision, false when the body has none, and its
// obligations member.
func checkV2Outcome(status int, raw []byte, message any) *model.CheckResourceV2Outcome {
	out := &model.CheckResourceV2Outcome{Status: status, Obligations: obligationsMember(raw), Message: message}
	if decision, ok := v2Body(raw)["decision"]; ok {
		_ = json.Unmarshal(decision, &out.Decision)
	}
	return out
}

// bulkOperationsV2Outcome returns the golden shape of a bulk operations answer
// sent through v2: its status, on 200 the allowed ids of each operation,
// sorted, and its obligations member.
func bulkOperationsV2Outcome(status int, raw []byte, message any) (*model.CheckResourceBulkOperationsV2Outcome, error) {
	out := &model.CheckResourceBulkOperationsV2Outcome{Status: status, Obligations: obligationsMember(raw), Message: message}
	if status != 200 {
		return out, nil
	}
	decision := map[string][]string{}
	if member, ok := v2Body(raw)["decision"]; ok {
		if err := json.Unmarshal(member, &decision); err != nil {
			return nil, fmt.Errorf("decode the allowed ids by operation of %s: %w", raw, err)
		}
	}
	for _, ids := range decision {
		sort.Strings(ids)
	}
	out.Decision = &decision
	return out, nil
}

// filterV2Outcome returns the golden shape of a check/filter answer sent
// through v2: its status, its filter result members, and its obligations
// member.
func filterV2Outcome(status int, raw []byte, message any) *model.FilterV2Outcome {
	out := &model.FilterV2Outcome{Status: status, Obligations: obligationsMember(raw), Message: message}
	_ = decodeJSON(raw, &out.Result)
	return out
}
