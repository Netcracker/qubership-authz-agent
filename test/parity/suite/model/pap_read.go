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

// PapReadOutcome is the golden shape of a GET the suite sends to the PAP
// outside the v3 export, and of every read a case step observes. Status is the
// HTTP status. Body is the JSON body of a 2xx answer, narrowed and ordered by
// the case; an error body carries timestamps and is not recorded. Tenants, on
// a step's read, lists the distinct tenantId values anywhere in the whole 2xx
// body before it was narrowed, sorted.
type PapReadOutcome struct {
	Status  int      `json:"status"`
	Body    any      `json:"body,omitempty"`
	Tenants []string `json:"tenants,omitempty"`
}

// PapErrorOutcome is the golden shape of a case step's error-class
// observation. Status is the HTTP status of the step's call. Body is the
// response body of a non-2xx answer, decoded when it is JSON and kept as text
// otherwise, with every top-level timestamp member removed; it is null for a
// 2xx answer.
type PapErrorOutcome struct {
	Status int `json:"status"`
	Body   any `json:"body"`
}
