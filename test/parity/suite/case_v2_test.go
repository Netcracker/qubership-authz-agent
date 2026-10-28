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
	"fmt"
	"maps"
	"net/url"
	"slices"
	"testing"

	"authz-agent/test/parity/suite/model"
	"github.com/google/go-cmp/cmp"
)

// v2Query returns the query parameters of a case's request sent through v2
// besides the tenant and the userId: those of filter for a filter request, and
// obligations when it is not nil.
func v2Query(filter url.Values, obligations *string) url.Values {
	extra := url.Values{}
	maps.Copy(extra, filter)
	if obligations != nil {
		extra.Set("obligations", *obligations)
	}
	return extra
}

// v2BulkOperationsBody returns the v2 body of the bulk operations items, each
// of which bulkItems has given a type, for a case whose resource type is rt:
// {"type", "entries"}, where type is the one type every item names, rt when
// there is no item, and each entry is its item without type. v2 takes one type
// for the whole request, so an item that is no object, a type that is no
// string, and items of two types are an error.
func v2BulkOperationsBody(items []any, rt string) (map[string]any, error) {
	entries := make([]any, 0, len(items))
	var types []string
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("the item %v is not an object", item)
		}
		t, ok := entry["type"].(string)
		if !ok {
			return nil, fmt.Errorf("the item %v names a type that is not a string", item)
		}
		if !slices.Contains(types, t) {
			types = append(types, t)
		}
		entry = maps.Clone(entry)
		delete(entry, "type")
		entries = append(entries, entry)
	}
	if len(types) > 1 {
		return nil, fmt.Errorf("its items name %d types, and v2 takes one type for the whole request", len(types))
	}
	if len(types) == 1 {
		rt = types[0]
	}
	return map[string]any{"type": rt, "entries": entries}, nil
}

// A v2 golden writes the obligations member only when the answer had one, and
// writes null for a member sent as null, so that a recorded absence and a
// recorded null stay apart when the golden is read back.
func TestCheckV2Outcome_ObligationsMember(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"absent", `{"decision":true}`, `{"status":200,"decision":true}`},
		{"null", `{"decision":true,"obligations":null}`, `{"status":200,"decision":true,"obligations":null}`},
		{"an object", `{"decision":false,"obligations":{"resourceType":"t"}}`,
			`{"status":200,"decision":false,"obligations":{"resourceType":"t"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			written, err := json.Marshal(checkV2Outcome(200, []byte(tc.body), nil))
			if err != nil {
				t.Fatal(err)
			}
			if string(written) != tc.want {
				t.Errorf("checkV2Outcome(200, %s) is written %s, want %s", tc.body, written, tc.want)
			}
			var back model.CheckResourceV2Outcome
			if err := json.Unmarshal(written, &back); err != nil {
				t.Fatal(err)
			}
			if again, _ := json.Marshal(back); string(again) != tc.want {
				t.Errorf("the golden %s reads back as %s", tc.want, again)
			}
		})
	}
}

// The v2 bulk operations body names the one type of its items, the case's
// own when it has no item, and lists the items without it; items of two
// types, or a type that is no string, have no v2 body.
func TestV2BulkOperationsBody(t *testing.T) {
	cases := []struct {
		name  string
		items []any
		want  map[string]any
	}{
		{"an omitted type beside the case's", []any{
			map[string]any{"id": "a", "operations": []any{"READ"}},
			map[string]any{"id": "b", "operations": []any{"WRITE"}, "type": "T"},
		}, map[string]any{"type": "T", "entries": []any{
			map[string]any{"id": "a", "operations": []any{"READ"}},
			map[string]any{"id": "b", "operations": []any{"WRITE"}},
		}}},
		{"no item", []any{}, map[string]any{"type": "T", "entries": []any{}}},
		{"two types", []any{map[string]any{"id": "a"}, map[string]any{"id": "b", "type": "U"}}, nil},
		{"a type that is an object", []any{
			map[string]any{"id": "a", "type": map[string]any{"x": 1}},
			map[string]any{"id": "b", "type": map[string]any{"x": 1}},
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := v2BulkOperationsBody(bulkItems(tc.items, "T"), "T")
			if tc.want == nil {
				if err == nil {
					t.Errorf("v2BulkOperationsBody(%v) = %v, want an error", tc.items, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("v2BulkOperationsBody(%v): %v", tc.items, err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("v2BulkOperationsBody(%v) mismatch (-want +got):\n%s", tc.items, diff)
			}
		})
	}
}

func TestV2Query_Obligations(t *testing.T) {
	yes := "true"
	cases := []struct {
		name        string
		obligations *string
		want        string
	}{
		{"none is sent when absent", nil, "resourceType=T"},
		{"the value is sent as written", &yes, "obligations=true&resourceType=T"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := v2Query(url.Values{"resourceType": {"T"}}, tc.obligations).Encode(); got != tc.want {
				t.Errorf("v2Query(resourceType=T, %v) = %q, want %q", tc.obligations, got, tc.want)
			}
		})
	}
}

// The comparison sorts the lists of strings inside the obligations member and
// leaves the decision as it is.
func TestNormalizeComparable_SortsObligationFields(t *testing.T) {
	got := normalizeComparable(PSUITE_ROW_7_CHECK_RESOURCE_V2_OUTCOME, "c",
		checkV2Outcome(200, []byte(`{"decision":true,"obligations":{"read":{"whitelist":{"fields":["b","a"]}}}}`), nil))
	want := &model.CheckResourceV2Outcome{Status: 200, Decision: true, Obligations: model.Member{Present: true,
		Value: map[string]any{"read": map[string]any{"whitelist": map[string]any{"fields": []any{"a", "b"}}}}}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("normalizeComparable mismatch (-want +got):\n%s", diff)
	}
}
