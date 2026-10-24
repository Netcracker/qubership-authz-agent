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

// ConfigExportOutcome is the golden shape of a GET of the v3 configuration
// export. Status is the HTTP status. Export is the response body as a JSON
// object with the envelope fields that change on every write (hash,
// lastModificationTimestamp) removed and every array narrowed to the elements
// the case uploaded, in a fixed order; it is nil when the body is not a JSON
// object, and Body then carries the body as text.
type ConfigExportOutcome struct {
	Status int            `json:"status"`
	Export map[string]any `json:"export"`
	Body   string         `json:"body,omitempty"`
}
