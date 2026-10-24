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

package legacyvalue

import "testing"

func TestText_ObjectKeepsDocumentOrder(t *testing.T) {
	doc := `{"z": [1.50, null, true], "a": {"y": "Q", "b": {}}}`
	want := "{z=[1.5, null, true], a={y=Q, b={}}}"
	if got := Text(mustDecode(t, doc)); got != want {
		t.Errorf("Text(%s) = %q, want %q", doc, got, want)
	}
}
