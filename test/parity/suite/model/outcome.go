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

// CheckResourceOutcome is the golden shape of a check/resource case whose request
// may be refused. Status is the HTTP status; Decision is the decoded body, false
// for a refused request.
type CheckResourceOutcome struct {
	Status   int  `json:"status"`
	Decision bool `json:"decision"`
}

// FilterOutcome is the golden shape of a check/filter case whose request may be
// refused. Status is the HTTP status; Result is the decoded body, empty for a
// refused request.
type FilterOutcome struct {
	Status int                       `json:"status"`
	Result OldFilterEvaluationResult `json:"result"`
}

// CheckResourceBulkOutcome is the golden shape of a check/resource/bulk
// request that may be refused. Status is the HTTP status. Allowed holds the
// ids of the allowed items, sorted, and is present only when Status is 200.
type CheckResourceBulkOutcome struct {
	Status  int       `json:"status"`
	Allowed *[]string `json:"allowed,omitempty"`
}

// CheckResourceBulkOperationsOutcome is the golden shape of a
// check/resource/bulk/operations request that may be refused. Status is the
// HTTP status. Decision maps each operation to the ids of the items it is
// allowed on, each list sorted, and is present only when Status is 200.
type CheckResourceBulkOperationsOutcome struct {
	Status   int                  `json:"status"`
	Decision *map[string][]string `json:"decision,omitempty"`
}
