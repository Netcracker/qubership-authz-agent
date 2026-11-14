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

// CheckResourcesRequest is the v2 POST /access/v2/check/resource/bulk/operations
// request body.
type CheckResourcesRequest struct {
	Type    string                       `json:"type"`
	Entries []CheckResourcesRequestEntry `json:"entries"`
}

// CheckResourcesRequestEntry is one entry of CheckResourcesRequest. ID and
// Resource use omitempty because the legacy service leaves out null fields, per
// D-V item 8.
type CheckResourcesRequestEntry struct {
	ID         *string  `json:"id,omitempty"`
	Operations []string `json:"operations"`
	Resource   any      `json:"resource,omitempty"`
}

// CheckResourcesResponse is the v2 POST /access/v2/check/resource/bulk/operations
// response body. The Decision map holds a set of operations per id; Go
// represents it as
// map[string][]string and the GoldenComparator sorts the slice values
// order-insensitive via cmpopts.SortSlices per D-M.
type CheckResourcesResponse struct {
	Decision    map[string][]string `json:"decision"`
	Obligations json.RawMessage     `json:"obligations,omitempty"`
}
