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
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// The goldens of one filter request recorded under several classes, such as
// -when-the-pip-was-read and -when-the-pip-was-skipped, record answers that
// differ, and normalizeComparable must keep them apart: if two of them
// compared alike, a run would pass against either class whatever the agent's
// answer depends on. No pair of the recorded goldens does.
func TestFilterGoldens_TheClassesOfARequestStayApartAfterNormalization(t *testing.T) {
	t.Parallel()
	collapsed, classified, err := filterClassesComparedAlike("testdata/golden")
	if err != nil {
		t.Fatal(err)
	}
	if classified == 0 {
		t.Fatal("no filter golden under testdata/golden has a class suffix; the test reads nothing")
	}
	for _, pair := range collapsed {
		t.Errorf("differ as recorded and compare alike after normalizeComparable: %s", pair)
	}
}

// The check reports two classes whose filter conditions differ only in the
// order of the operands of an OR, which the comparison ignores, and does not
// report two classes whose conditions differ in a value.
func TestFilterClassesComparedAlike_ReportsClassesThatDifferOnlyInOrder(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name          string
		read, skipped string
		reported      bool
	}{
		{"operands of an OR swapped", "p==1,q==1", "q==1,p==1", true},
		{"another operand value", "p==1,q==1", "p==1,q==2", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			dir := Meta(PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME).GoldenDir
			answer := `{"status":200,"result":{"calculationResult":"USE_FILTER_CONDITION","rsqlFilterCondition":%q}}`
			writeGolden(t, root, dir+"/regular/c/filter-when-the-pip-was-read", fmt.Sprintf(answer, tc.read))
			writeGolden(t, root, dir+"/regular/c/filter-when-the-pip-was-skipped", fmt.Sprintf(answer, tc.skipped))

			collapsed, classified, err := filterClassesComparedAlike(root)

			if err != nil {
				t.Fatal(err)
			}
			if classified != 2 {
				t.Fatalf("filterClassesComparedAlike read %d classified goldens, want 2", classified)
			}
			if got := len(collapsed) > 0; got != tc.reported {
				t.Errorf("filterClassesComparedAlike(%s against %s) = %v, want a report: %t", tc.read, tc.skipped, collapsed, tc.reported)
			}
		})
	}
}

// filterClassesComparedAlike returns every pair of filter goldens under root
// that belong to one request, differ only in their class suffix
// (-when-the-...), differ as recorded, and compare alike after
// normalizeComparable; classified counts the filter goldens with a suffix.
func filterClassesComparedAlike(root string) (collapsed []string, classified int, err error) {
	filterRows := map[string]ParityEndpointID{}
	for _, id := range []ParityEndpointID{PSUITE_ROW_6_CHECK_FILTER_V1, PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME,
		PSUITE_ROW_10_CHECK_FILTER_V2, PSUITE_ROW_10_CHECK_FILTER_V2_OUTCOME} {
		filterRows[Meta(id).GoldenDir] = id
	}
	class := regexp.MustCompile(`-when-the-[a-z0-9-]+$`)
	type golden struct {
		key string
		raw json.RawMessage
	}
	byRequest := map[string][]golden{}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") || strings.HasSuffix(path, ".observed.json") {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		entries, err := decodeGoldenFile(filepath.ToSlash(rel), raw)
		if err != nil {
			return err
		}
		for key, answer := range entries {
			if _, ok := filterRows[strings.SplitN(key, "/", 2)[0]]; !ok || !class.MatchString(key) {
				continue
			}
			classified++
			request := rel + " " + class.ReplaceAllString(key, "")
			byRequest[request] = append(byRequest[request], golden{key, answer})
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	for _, goldens := range byRequest {
		for i, a := range goldens {
			for _, b := range goldens[i+1:] {
				id := filterRows[strings.SplitN(a.key, "/", 2)[0]]
				ta, tb := NewGoldenTarget(id), NewGoldenTarget(id)
				if err := json.Unmarshal(a.raw, ta); err != nil {
					return nil, 0, fmt.Errorf("golden %s: %w", a.key, err)
				}
				if err := json.Unmarshal(b.raw, tb); err != nil {
					return nil, 0, fmt.Errorf("golden %s: %w", b.key, err)
				}
				opts := compareOptionsFor(id)
				if cmp.Equal(ta, tb, opts...) {
					continue
				}
				subA := strings.TrimPrefix(a.key, Meta(id).GoldenDir+"/")
				subB := strings.TrimPrefix(b.key, Meta(id).GoldenDir+"/")
				if cmp.Equal(normalizeComparable(id, subA, ta), normalizeComparable(id, subB, tb), opts...) {
					collapsed = append(collapsed, fmt.Sprintf("%s %s against %s %s", a.key, a.raw, b.key, b.raw))
				}
			}
		}
	}
	sort.Strings(collapsed)
	return collapsed, classified, nil
}
