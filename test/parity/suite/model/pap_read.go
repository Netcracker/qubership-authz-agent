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
// the case; an error body carries timestamps and is not recorded.
// KeptTenants, on a step's read, lists the distinct tenantId values anywhere
// in Body, sorted: the tenants of the elements the case's markers keep.
// Tenants is the member a golden recorded before KeptTenants holds instead:
// the tenantId values of the whole body before it was narrowed, which include
// those of the elements the cases before it in the file wrote. The suite does
// not set it; it is read so that such a golden keeps the member through
// the canonicalizer and fails the comparison until it is recorded again.
type PapReadOutcome struct {
	Status      int      `json:"status"`
	Body        any      `json:"body,omitempty"`
	Tenants     []string `json:"tenants,omitempty"`
	KeptTenants []string `json:"keptTenants,omitempty"`
}

// PapReadRawOutcome is the golden shape of a case step's read-raw
// observation: the read whole, not narrowed. Status is the HTTP status. Body
// is the response body, decoded when it is JSON and kept as text otherwise,
// with the members that change on every write or read removed: hash,
// lastModificationTimestamp, and timestamp from a top-level object, the write
// stamps from every element, and the order of the lists nested in an element.
type PapReadRawOutcome struct {
	Status int `json:"status"`
	Body   any `json:"body"`
}

// PapErrorOutcome is the golden shape of a case step's error-class
// observation. Status is the HTTP status of the step's call. Body is the
// response body of a non-2xx answer, decoded when it is JSON and kept as text
// otherwise, with every top-level timestamp member removed; it is null for a
// 2xx answer. The suite compares Status alone: Body is recorded for the spec
// repository, which compares the class of the message, not its text.
type PapErrorOutcome struct {
	Status int `json:"status"`
	Body   any `json:"body"`
}
