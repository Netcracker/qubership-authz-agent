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

// PipCallOutcome is the golden shape of the calls a PIP received over one
// request. Calls is how many there were. RequestAttributes is the
// requestAttributes value of the first call's body, the part a declaration
// fills from placeholders; the rest of the body is the subject id and filters.
// Body carries the first body as text where it is not an object with a
// requestAttributes key, so a null value is told from an absent key.
type PipCallOutcome struct {
	Calls             int    `json:"calls"`
	RequestAttributes any    `json:"requestAttributes"`
	Body              string `json:"body,omitempty"`
}
