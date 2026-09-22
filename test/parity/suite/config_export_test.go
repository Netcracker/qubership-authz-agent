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
	"testing"

	"authz-agent/test/parity/suite/model"
	"github.com/google/go-cmp/cmp"
)

// The golden of an export read holds the elements the case uploaded and nothing
// that changes between two reads of one stand: the envelope's hash and timestamp
// go, an element without a marker goes, and the elements kept are ordered by
// their text rather than by the PAP's listing order.
func TestNarrowConfigExport_KeepsOnlyMarkedElementsInTextOrder(t *testing.T) {
	t.Parallel()
	body := []byte(`{
		"hash": "abc", "lastModificationTimestamp": "1740570563000", "other": 1,
		"pips": [
			{"name": "subject.zzzMarked", "tenantId": "t"},
			{"name": "subject.unrelated", "tenantId": "t"},
			{"name": "subject.aaaMarked", "tenantId": "t"}
		]
	}`)

	got := narrowConfigExport(200, body, []string{"Marked"})

	want := &model.ConfigExportOutcome{Status: 200, Export: map[string]any{
		"other": float64(1),
		"pips": []any{
			map[string]any{"name": "subject.aaaMarked", "tenantId": "t"},
			map[string]any{"name": "subject.zzzMarked", "tenantId": "t"},
		},
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("narrowConfigExport() mismatch (-want +got):\n%s", diff)
	}
}

// An array nested inside a kept element is recorded as it came, unmarked elements
// included: only the arrays of the envelope are narrowed.
func TestNarrowConfigExport_NestedArraysAreKeptWhole(t *testing.T) {
	t.Parallel()
	body := []byte(`{"policySets": [{"name": "Marked", "policies": [{"name": "unrelated"}, {"name": "alsoUnrelated"}]}]}`)

	got := narrowConfigExport(200, body, []string{"Marked"})

	want := &model.ConfigExportOutcome{Status: 200, Export: map[string]any{
		"policySets": []any{map[string]any{
			"name":     "Marked",
			"policies": []any{map[string]any{"name": "unrelated"}, map[string]any{"name": "alsoUnrelated"}},
		}},
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("narrowConfigExport() mismatch (-want +got):\n%s", diff)
	}
}

// An array with no marked element is recorded as empty rather than dropped, so the
// golden still says which arrays the envelope has.
func TestNarrowConfigExport_ArrayWithoutMarkedElementsIsEmpty(t *testing.T) {
	t.Parallel()
	body := []byte(`{"policySets": [{"name": "unrelated"}]}`)

	got := narrowConfigExport(200, body, []string{"Marked"})

	want := &model.ConfigExportOutcome{Status: 200, Export: map[string]any{"policySets": []any{}}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("narrowConfigExport() mismatch (-want +got):\n%s", diff)
	}
}

// A refused read comes back as text, not as a JSON object, and the golden keeps
// that text beside the status, so a 404 page and a 400 message are recorded as
// different goldens.
func TestNarrowConfigExport_NonObjectBodyIsKeptAsText(t *testing.T) {
	t.Parallel()
	got := narrowConfigExport(404, []byte("Not Found"), []string{"Marked"})

	want := &model.ConfigExportOutcome{Status: 404, Body: "Not Found"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("narrowConfigExport() mismatch (-want +got):\n%s", diff)
	}
}
