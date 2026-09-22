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

package paritysuite

import (
	"encoding/json"
	"sort"
	"strings"

	"authz-agent/test/parity/suite/model"
)

// configExportEnvelopeFields are the fields of the v3 export envelope that change
// with every write to the PAP and are removed before the body is recorded.
var configExportEnvelopeFields = []string{"hash", "lastModificationTimestamp"}

// narrowConfigExport turns a v3 export response into its golden shape: the fields
// in configExportEnvelopeFields are removed from the envelope, and every array of
// the envelope is reduced to the elements whose JSON text contains one of
// markers, sorted by that text. Nested arrays are left as they are. A body that
// is not a JSON object is kept as text in Body, with Export nil.
func narrowConfigExport(status int, body []byte, markers []string) *model.ConfigExportOutcome {
	var export map[string]any
	if err := json.Unmarshal(body, &export); err != nil || export == nil {
		return &model.ConfigExportOutcome{Status: status, Body: string(body)}
	}
	for _, field := range configExportEnvelopeFields {
		delete(export, field)
	}
	for key, value := range export {
		elements, isArray := value.([]any)
		if !isArray {
			continue
		}
		type keyed struct {
			text    string
			element any
		}
		kept := []keyed{}
		for _, element := range elements {
			text, err := json.Marshal(element)
			if err != nil {
				continue
			}
			for _, marker := range markers {
				if strings.Contains(string(text), marker) {
					kept = append(kept, keyed{text: string(text), element: element})
					break
				}
			}
		}
		sort.Slice(kept, func(i, j int) bool { return kept[i].text < kept[j].text })
		narrowed := make([]any, 0, len(kept))
		for _, k := range kept {
			narrowed = append(narrowed, k.element)
		}
		export[key] = narrowed
	}
	return &model.ConfigExportOutcome{Status: status, Export: export}
}
