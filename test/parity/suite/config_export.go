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

// configExportElementFields are the fields the PAP stamps on every exported set,
// policy, and rule at write time, and that differ between two stands or two
// uploads of one fixture: the wall-clock write times and the writing client.
// They are removed at every depth before the body is recorded.
var configExportElementFields = []string{"createdWhen", "lastModifiedWhen", "createdBy", "lastModifiedBy"}

// narrowConfigExport turns a v3 export response into its golden shape: the fields
// in configExportEnvelopeFields are removed from the envelope, every array of the
// envelope is reduced to the elements whose JSON text contains one of markers, and
// inside the kept elements the fields in configExportElementFields are removed
// and every array is sorted by the JSON text of its elements, at every depth. The
// PAP lists the policies of a set and the rules of a policy in an order that
// differs from one read to the next, so the golden holds them sorted. A body that
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
		kept := []any{}
		for _, element := range elements {
			text, err := json.Marshal(element)
			if err != nil {
				continue
			}
			for _, marker := range markers {
				if strings.Contains(string(text), marker) {
					kept = append(kept, element)
					break
				}
			}
		}
		export[key] = canonicalExportValue(kept)
	}
	return &model.ConfigExportOutcome{Status: status, Export: export}
}

// canonicalExportValue removes configExportElementFields from every object under
// v and sorts every array under v by the JSON text of its canonicalized elements.
func canonicalExportValue(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		for _, field := range configExportElementFields {
			delete(typed, field)
		}
		for key, value := range typed {
			typed[key] = canonicalExportValue(value)
		}
		return typed
	case []any:
		return sortByJSONText(typed, canonicalExportValue)
	default:
		return v
	}
}

// sortByJSONText applies canonicalize to every element of elements and returns
// them sorted by their JSON text. An element that does not marshal is left out.
func sortByJSONText(elements []any, canonicalize func(any) any) []any {
	type keyed struct {
		text    string
		element any
	}
	kept := make([]keyed, 0, len(elements))
	for _, element := range elements {
		element = canonicalize(element)
		text, err := json.Marshal(element)
		if err != nil {
			continue
		}
		kept = append(kept, keyed{text: string(text), element: element})
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].text < kept[j].text })
	sorted := make([]any, 0, len(kept))
	for _, k := range kept {
		sorted = append(sorted, k.element)
	}
	return sorted
}

// narrowPAPRead turns the answer to a GET of the PAP into its golden shape: the
// status, and for a 2xx JSON body the body narrowed as narrowConfigExport
// narrows the envelope. A body that is an array, and every array that is a value
// of a body that is an object, keep only the elements whose JSON text contains
// one of markers; what is kept is canonicalized by canonicalExportValue, so an
// array nested inside a kept element keeps every element, sorted. A 2xx body
// that is not JSON is kept as text, and an error body is dropped, since it
// carries a timestamp.
func narrowPAPRead(status int, body []byte, markers []string) *model.PapReadOutcome {
	outcome := &model.PapReadOutcome{Status: status}
	if status < 200 || status > 299 {
		return outcome
	}
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		outcome.Body = string(body)
		return outcome
	}
	switch typed := decoded.(type) {
	case []any:
		outcome.Body = keepMarked(typed, markers)
	case map[string]any:
		for key, value := range typed {
			if elements, isArray := value.([]any); isArray {
				typed[key] = keepMarked(elements, markers)
			}
		}
		outcome.Body = typed
	default:
		outcome.Body = decoded
	}
	return outcome
}

// keepMarked returns the elements whose JSON text contains one of markers,
// canonicalized and sorted by canonicalExportValue.
func keepMarked(elements []any, markers []string) any {
	kept := []any{}
	for _, element := range elements {
		text, err := json.Marshal(element)
		if err != nil {
			continue
		}
		for _, marker := range markers {
			if strings.Contains(string(text), marker) {
				kept = append(kept, element)
				break
			}
		}
	}
	return canonicalExportValue(kept)
}
