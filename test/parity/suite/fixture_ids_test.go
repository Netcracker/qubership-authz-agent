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
	"io/fs"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nestedIDKeys are the fields collected as ids at any depth of a fixture.
var nestedIDKeys = []string{"policySetId", "policyId", "ruleId"}

type fixtureID struct {
	key   string
	value string
}

// TestFixtureIDsAreUnique fails when two entries in the JSON files under
// testdata/fixtures carry the same id, in one file or in two, and reports each
// repeat against the first occurrence. The legacy PAP stores a simplified
// policy's id and a regular rule's ruleId under one primary key, and the legacy
// seeder uploads the simplified policies first, so a shared id fails the regular
// policy-set upload with HTTP 500. The check is deliberately stricter than that
// key: every id field is compared with every other, across tenants too.
func TestFixtureIDsAreUnique(t *testing.T) {
	t.Parallel()
	root := os.DirFS("testdata/fixtures")
	firstSeen := map[string]string{}
	err := fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		raw, err := fs.ReadFile(root, path)
		if err != nil {
			return err
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("decode %s: %w", path, err)
		}
		for _, id := range fixtureIDs(doc) {
			location := fmt.Sprintf("%s (%s)", path, id.key)
			if previous, ok := firstSeen[id.value]; ok {
				t.Errorf("id %s appears in %s and in %s", id.value, previous, location)
				continue
			}
			firstSeen[id.value] = location
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk testdata/fixtures: %v", err)
	}
	if len(firstSeen) == 0 {
		t.Fatal("found no ids under testdata/fixtures")
	}
}

func TestFixtureIDs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		json string
		want []fixtureID
	}{
		{
			name: "top-level array elements yield their id, repeats included",
			json: `[{"id": "p1"}, {"id": "p1"}]`,
			want: []fixtureID{{"id", "p1"}, {"id", "p1"}},
		},
		{
			name: "policy set ids are collected at every depth",
			json: `[{"policySetId": "s1", "policies": [{"policyId": "p1", "rules": [{"ruleId": "r1"}]}]}]`,
			want: []fixtureID{{"policySetId", "s1"}, {"policyId", "p1"}, {"ruleId", "r1"}},
		},
		{
			name: "an id nested under another key is not collected",
			json: `[{"name": "subject.x", "body": {"id": "seed"}}]`,
			want: nil,
		},
		{
			name: "an id on a top-level object is not collected",
			json: `{"id": "p1"}`,
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var doc any
			require.NoError(t, json.Unmarshal([]byte(tc.json), &doc))
			assert.Equal(t, tc.want, fixtureIDs(doc), "fixtureIDs(%s)", tc.json)
		})
	}
}

// fixtureIDs returns the ids a decoded fixture file declares: the id of each
// element of a top-level array, and every policySetId, policyId, and ruleId at
// any depth, in document order with object keys sorted. An id nested under any
// other key is data, such as a PIP request body, and is not returned.
func fixtureIDs(doc any) []fixtureID {
	var ids []fixtureID
	if items, ok := doc.([]any); ok {
		for _, item := range items {
			if object, ok := item.(map[string]any); ok {
				if value, ok := object["id"].(string); ok {
					ids = append(ids, fixtureID{key: "id", value: value})
				}
			}
		}
	}
	var walk func(node any)
	walk = func(node any) {
		switch typed := node.(type) {
		case map[string]any:
			for _, key := range nestedIDKeys {
				if value, ok := typed[key].(string); ok {
					ids = append(ids, fixtureID{key: key, value: value})
				}
			}
			for _, key := range slices.Sorted(maps.Keys(typed)) {
				walk(typed[key])
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(doc)
	return ids
}
