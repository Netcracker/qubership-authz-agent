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

package model

import "encoding/json"

// OldFilterEvaluationResult is the v1 POST /access/v1/check/filter response
// body, mirroring
// com.netcracker.security.authorization.abac.impl.OldFilterEvaluationResult
// (OldFilterEvaluationResult.java:13-25). CalculationResult carries the
// @JsonProperty("calculationResult") annotation the legacy Effect enum uses;
// the Go field is a string because the parity assertion is on the wire form
// (ALLOW / DENY / NOT_APPLICABLE / USE_FILTER_CONDITION), not on a typed enum.
// CustomFilterCondition is json.RawMessage because the legacy type is a
// polymorphic CustomFilterConditionImpl that the parity suite does not need
// to inspect field-by-field — byte parity on the raw JSON is sufficient for
// every row that reaches this struct in Step 3.
type OldFilterEvaluationResult struct {
	CalculationResult      string          `json:"calculationResult"`
	FilterCondition        string          `json:"filterCondition"`
	MongodbFilterCondition string          `json:"mongodbFilterCondition"`
	RsqlFilterCondition    string          `json:"rsqlFilterCondition"`
	SqlFilterCondition     string          `json:"sqlFilterCondition"`
	CustomFilterCondition  json.RawMessage `json:"customFilterCondition,omitempty"`
}

// FilterResponse is the v2 POST /access/v2/check/filter response body,
// mirroring
// com.netcracker.security.authorization.abac.api.client.v2.model.response.FilterResponse
// (FilterResponse.java:18-66). Field set is identical to
// OldFilterEvaluationResult with an added Obligations block that the parity
// suite always filters out via cmpopts.IgnoreFields per D-E.
type FilterResponse struct {
	CalculationResult      string          `json:"calculationResult"`
	FilterCondition        string          `json:"filterCondition"`
	MongodbFilterCondition string          `json:"mongodbFilterCondition"`
	RsqlFilterCondition    string          `json:"rsqlFilterCondition"`
	SqlFilterCondition     string          `json:"sqlFilterCondition"`
	CustomFilterCondition  json.RawMessage `json:"customFilterCondition,omitempty"`
	Obligations            json.RawMessage `json:"obligations,omitempty"`
}
