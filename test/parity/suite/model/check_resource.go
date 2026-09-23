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

// CheckAccessRequest is the v1 POST /access/v1/check/resource request body.
// Resource is any because the legacy service accepts any JSON there and the
// actual shape depends on the policy under test.
type CheckAccessRequest struct {
	Operation string `json:"operation"`
	Type      string `json:"type"`
	Resource  any    `json:"resource,omitempty"`
}

// CheckAccessRequestWithID is the v1 POST /access/v1/check/resource/bulk
// entry type. ID is a pointer so omitempty drops it from the wire when unset,
// as the legacy service leaves out null fields, per D-V item 8.
type CheckAccessRequestWithID struct {
	ID        *string `json:"id,omitempty"`
	Operation string  `json:"operation"`
	Type      string  `json:"type"`
	Resource  any     `json:"resource,omitempty"`
}

// CheckAccessBulkOperationsRequest is the v1
// POST /access/v1/check/resource/bulk/operations entry type.
type CheckAccessBulkOperationsRequest struct {
	ID         *string  `json:"id,omitempty"`
	Operations []string `json:"operations"`
	Type       string   `json:"type"`
	Resource   any      `json:"resource,omitempty"`
}

// CheckResourceRequest is the v2 POST /access/v2/check/resource request body.
type CheckResourceRequest struct {
	Operation string `json:"operation"`
	Type      string `json:"type"`
	Resource  any    `json:"resource,omitempty"`
}

// CheckResourceResponse is the v2 POST /access/v2/check/resource response body.
// Obligations is json.RawMessage so it can
// be filtered out via cmpopts.IgnoreFields before cmp.Diff runs (D-E); it never
// participates in parity assertions in Step 3.
type CheckResourceResponse struct {
	Decision    bool            `json:"decision"`
	Obligations json.RawMessage `json:"obligations,omitempty"`
}
