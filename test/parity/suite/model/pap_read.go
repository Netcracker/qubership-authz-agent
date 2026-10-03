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
// outside the v3 export. Status is the HTTP status. Body is the JSON body of a
// 2xx answer, narrowed and ordered by the case; an error body carries
// timestamps and is not recorded.
type PapReadOutcome struct {
	Status int `json:"status"`
	Body   any `json:"body,omitempty"`
}
