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

// An array nested inside a kept element keeps every element, unmarked ones
// included, and holds them sorted by their JSON text: the PAP lists the policies
// of a set in an order that differs between two reads of one stand.
func TestNarrowConfigExport_NestedArraysAreSortedAndKeptWhole(t *testing.T) {
	t.Parallel()
	body := []byte(`{"policySets": [{"name": "Marked", "policies": [
		{"name": "unrelated", "rules": [{"ruleId": "b"}, {"ruleId": "a"}]},
		{"name": "alsoUnrelated"}
	]}]}`)

	got := narrowConfigExport(200, body, []string{"Marked"})

	want := &model.ConfigExportOutcome{Status: 200, Export: map[string]any{
		"policySets": []any{map[string]any{
			"name": "Marked",
			"policies": []any{
				map[string]any{"name": "alsoUnrelated"},
				map[string]any{"name": "unrelated", "rules": []any{map[string]any{"ruleId": "a"}, map[string]any{"ruleId": "b"}}},
			},
		}},
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("narrowConfigExport() mismatch (-want +got):\n%s", diff)
	}
}

// The write stamps the PAP puts on a set, a policy, and a rule are removed at every
// depth, so two reads of one fixture on two stands record one golden; a field
// with another name beside them stays.
func TestNarrowConfigExport_WriteStampsAreRemovedAtEveryDepth(t *testing.T) {
	t.Parallel()
	body := []byte(`{"policySets": [{"name": "Marked", "createdWhen": 1, "lastModifiedWhen": 2,
		"createdBy": "svc", "lastModifiedBy": "svc", "policies": [
			{"name": "p", "createdWhen": 3, "rules": [{"ruleId": "r", "lastModifiedWhen": 4, "lastModifiedBy": "svc"}]}
		]}]}`)

	got := narrowConfigExport(200, body, []string{"Marked"})

	want := &model.ConfigExportOutcome{Status: 200, Export: map[string]any{
		"policySets": []any{map[string]any{
			"name":     "Marked",
			"policies": []any{map[string]any{"name": "p", "rules": []any{map[string]any{"ruleId": "r"}}}},
		}},
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("narrowConfigExport() mismatch (-want +got):\n%s", diff)
	}
}

// Two reads that list the nested policies in opposite orders narrow to one
// golden.
func TestNarrowConfigExport_NestedOrderDoesNotReachTheGolden(t *testing.T) {
	t.Parallel()
	first := []byte(`{"policySets": [{"name": "Marked", "policies": [{"name": "a"}, {"name": "b"}]}]}`)
	second := []byte(`{"policySets": [{"name": "Marked", "policies": [{"name": "b"}, {"name": "a"}]}]}`)

	if diff := cmp.Diff(narrowConfigExport(200, first, []string{"Marked"}), narrowConfigExport(200, second, []string{"Marked"})); diff != "" {
		t.Errorf("narrowConfigExport() of two policy orders differs (-first +second):\n%s", diff)
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

// A PAP read whose body is an object keeps its scalar fields and narrows each
// array value to the marked elements, in text order; an array nested inside a
// kept element is kept whole.
func TestNarrowPAPRead_ObjectBodyNarrowsItsArrays(t *testing.T) {
	t.Parallel()
	body := []byte(`{"level": "custom", "permissions": [
		{"permission": "zzz_marked", "pipNames": ["b", "a"]},
		{"permission": "unrelated"},
		{"permission": "aaa_marked"}
	]}`)

	got := narrowPAPRead(200, body, []string{"marked"})

	want := &model.PapReadOutcome{Status: 200, Body: map[string]any{
		"level": "custom",
		"permissions": []any{
			map[string]any{"permission": "aaa_marked"},
			map[string]any{"permission": "zzz_marked", "pipNames": []any{"a", "b"}},
		},
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("narrowPAPRead() mismatch (-want +got):\n%s", diff)
	}
}

// A PAP read whose body is an array keeps the marked elements.
func TestNarrowPAPRead_ArrayBodyKeepsTheMarkedElements(t *testing.T) {
	t.Parallel()
	got := narrowPAPRead(200, []byte(`[{"name": "b_marked"}, {"name": "other"}]`), []string{"marked"})

	want := &model.PapReadOutcome{Status: 200, Body: []any{map[string]any{"name": "b_marked"}}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("narrowPAPRead() mismatch (-want +got):\n%s", diff)
	}
}

// An error answer keeps its status and drops its body, which carries a
// timestamp.
func TestNarrowPAPRead_ErrorBodyIsDropped(t *testing.T) {
	t.Parallel()
	got := narrowPAPRead(404, []byte(`{"timestamp": "2026-09-23T10:00:00Z", "status": 404}`), []string{"marked"})

	if diff := cmp.Diff(&model.PapReadOutcome{Status: 404}, got); diff != "" {
		t.Errorf("narrowPAPRead() mismatch (-want +got):\n%s", diff)
	}
}
