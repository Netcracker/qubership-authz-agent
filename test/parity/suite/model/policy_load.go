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

// PolicyLoadOutcome is the golden shape of a simplified-policy upload, and of
// the other PAP writes a case runs. Status is the HTTP status.
//
// Message is the response body of a 400 or 409 answer, decoded when it is JSON
// and cut as an error-class observation cuts it, in the goldens of the case
// files that record it: those of round 44 and later. It is nil otherwise. The
// comparison ignores it, since the body is server-curated text that differs
// between access-control and any replacement PAP; the golden keeps it as the
// stand's reason for the refusal.
type PolicyLoadOutcome struct {
	Status  int `json:"status"`
	Message any `json:"message,omitempty"`
}
