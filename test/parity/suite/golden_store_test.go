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
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeGolden records answer as the golden of key under root.
func writeGolden(t *testing.T, root, key, answer string) {
	t.Helper()
	if err := goldensAt(root).Put(map[string]json.RawMessage{key: json.RawMessage(answer)}); err != nil {
		t.Fatal(err)
	}
}

func TestGoldenFileIn_PlacesAKeyInTheFileOfTheCaseItsThirdSegmentNames(t *testing.T) {
	t.Parallel()
	index := map[string]string{"c1": "round9/a.json"}
	cases := []struct {
		name, key, want string
	}{
		{"a request of a case", "check-resource-v1-outcome/regular/c1/allow", "round9/a.json"},
		{"a case with no request segment", "load-simplified-policies-v1/isolated/c1", "round9/a.json"},
		{"a nested request of a case", "pap-read/sequence/c1/step/read", "round9/a.json"},
		{"a case id in the second segment", "check-resource-v1/c1", "go/check-resource-v1.json"},
		{"an id no case file declares", "check-resource-v1-outcome/regular/c2/allow", "go/check-resource-v1-outcome.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := goldenFileIn(index, tc.key)
			if err != nil {
				t.Fatalf("goldenFileIn(%q): %v", tc.key, err)
			}
			if got != tc.want {
				t.Errorf("goldenFileIn(%q) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}

func TestEncodeGoldenFile_SortsKeysAndIndentsOnlyLongAnswers(t *testing.T) {
	t.Parallel()
	long := `{"status": 200, "body": {"policySets": ["` + strings.Repeat("x", 90) + `"]}}`
	entries := map[string]json.RawMessage{
		"load-policy-sets-v1/regular/c2/upload-1":    json.RawMessage(`{"status": 200}`),
		"pap-read-raw-v1/regular/c1/read":            json.RawMessage(long),
		"check-resource-v1-outcome/regular/c1/allow": json.RawMessage("{\n  \"status\": 200,\n  \"decision\": true\n}"),
		"load-simplified-policies-v1/isolated/c1":    json.RawMessage(`{"status": 400}`),
	}
	want := `{
  "c1": {
    "check-resource-v1-outcome/regular/allow": {"status":200,"decision":true},
    "load-simplified-policies-v1/isolated": {"status":400},
    "pap-read-raw-v1/regular/read": {
      "status": 200,
      "body": {
        "policySets": [
          "` + strings.Repeat("x", 90) + `"
        ]
      }
    }
  },
  "c2": {
    "load-policy-sets-v1/regular/upload-1": {"status":200}
  }
}
`
	got, err := encodeGoldenFile("round9/a.json", entries)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("encodeGoldenFile(round9/a.json) =\n%s\nwant\n%s", got, want)
	}
	back, err := decodeGoldenFile("round9/a.json", got)
	if err != nil {
		t.Fatal(err)
	}
	for key, answer := range entries {
		if !jsonEqual(t, back[key], answer) {
			t.Errorf("decodeGoldenFile(encodeGoldenFile(...))[%q] = %s, want %s", key, back[key], answer)
		}
	}
	if len(back) != len(entries) {
		t.Errorf("decodeGoldenFile(encodeGoldenFile(...)) holds %d keys, want %d", len(back), len(entries))
	}
}

func TestEncodeGoldenFile_KeysAGoFileByTheRestOfTheKey(t *testing.T) {
	t.Parallel()
	entries := map[string]json.RawMessage{
		"check-resource-v1/semantics/k1": json.RawMessage(`true`),
		"check-resource-v1/allow":        json.RawMessage(`false`),
	}
	want := `{
  "allow": false,
  "semantics/k1": true
}
`
	got, err := encodeGoldenFile("go/check-resource-v1.json", entries)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("encodeGoldenFile(go/check-resource-v1.json) =\n%s\nwant\n%s", got, want)
	}
}

// Recording one answer rewrites its file with the answers already there.
func TestGoldenStore_PutKeepsTheOtherAnswersOfTheFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeGolden(t, root, "check-resource-v1/first", "true")
	writeGolden(t, root, "check-resource-v1/second", "false")

	raw, err := os.ReadFile(filepath.Join(root, "go", "check-resource-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\n  \"first\": true,\n  \"second\": false\n}\n"; string(raw) != want {
		t.Errorf("go/check-resource-v1.json =\n%s\nwant\n%s", raw, want)
	}
}

// Every golden lives in the file its key belongs in, so that no golden is out of
// the suite's reach: a golden of a case that was deleted, renamed, or moved to
// another case file fails here. Every file is in the form encodeGoldenFile
// writes, so that recording an answer changes only the lines of that answer.
func TestGoldenFilesAreInTheirFilesAndCanonical(t *testing.T) {
	t.Parallel()
	root := "testdata/golden"
	if _, err := os.Stat(filepath.Join(casesDirOf(root), goldenGoDir)); err == nil {
		t.Fatalf("%s/%s is a directory of case files; its goldens would share %s/ with the goldens of Go tests",
			casesDirOf(root), goldenGoDir, goldenGoDir)
	}
	dirs := map[string]bool{}
	for _, meta := range rowMetas {
		dirs[meta.GoldenDir] = true
	}
	entries, where, err := (&goldenStore{root: root, suffix: ".json", cases: casesDirOf(root), files: map[string]map[string]json.RawMessage{}}).All()
	if err != nil {
		t.Fatalf("goldens under %s:\n%v", root, err)
	}
	if len(entries) == 0 {
		t.Fatalf("found no golden under %s", root)
	}
	byFile := map[string]map[string]json.RawMessage{}
	for key, answer := range entries {
		if dir, _, _ := strings.Cut(key, "/"); !dirs[dir] {
			t.Errorf("golden %s in %s: %s is the GoldenDir of no row", key, where[key], dir)
		}
		if byFile[where[key]] == nil {
			byFile[where[key]] = map[string]json.RawMessage{}
		}
		byFile[where[key]][key] = answer
	}
	for file, answers := range byFile {
		want, err := encodeGoldenFile(file, answers)
		if err != nil {
			t.Errorf("%s: %v", file, err)
			continue
		}
		got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s/%s is not in canonical form; rewrite it with go run ./tools/goldens split, then merge into an emptied %s", root, file, root)
		}
	}
}

func jsonEqual(t *testing.T, a, b json.RawMessage) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatalf("%s: %v", a, err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	xs, _ := json.Marshal(x)
	ys, _ := json.Marshal(y)
	return bytes.Equal(xs, ys)
}

// goldenTree makes a directory with a golden root beside one case file,
// round1/a.json, that declares the case c1, and returns the golden root.
func goldenTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cases := filepath.Join(dir, "cases", "round1")
	if err := os.MkdirAll(cases, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cases, "a.json"), []byte(`{"cases": [{"id": "c1"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "golden")
}

func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, text := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGoldenStoreAll_NamesAKeyStoredOutsideItsFile(t *testing.T) {
	t.Parallel()
	root := goldenTree(t)
	writeTree(t, root, map[string]string{
		"go/check-resource-v1-outcome.json": `{"regular/c1/allow": {"status": 200}, "regular/c2/allow": {"status": 200}}`,
	})

	_, _, err := goldensAt(root).All()

	want := filepath.Join(root, "go", "check-resource-v1-outcome.json") + " holds check-resource-v1-outcome/regular/c1/allow, which belongs in " +
		filepath.Join(root, "round1", "a.json")
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("All() = %v, want an error that contains %q", err, want)
	}
	if strings.Contains(err.Error(), "c2") {
		t.Errorf("All() = %v, want no word on regular/c2/allow, which no case file declares", err)
	}
}

// split of a merged tree gives back the tree, and a second merge replaces the
// answers it carries and keeps the rest.
func TestMergeGoldens_ThenSplitGivesBackEveryAnswer(t *testing.T) {
	t.Parallel()
	root := goldenTree(t)
	in := t.TempDir()
	writeTree(t, in, map[string]string{
		"check-resource-v1-outcome/regular/c1/allow.json": `{"status": 200, "decision": true}`,
		"load-policy-sets-v1/regular/c1/upload-1.json":    `{"status": 200}`,
		"check-resource-v1/semantics/k1.json":             `true`,
	})
	if _, err := MergeGoldens(root, in, false); err != nil {
		t.Fatal(err)
	}
	update := t.TempDir()
	writeTree(t, update, map[string]string{
		"check-resource-v1-outcome/regular/c1/allow.json": `{"status": 200, "decision": false}`,
	})
	if _, err := MergeGoldens(root, update, false); err != nil {
		t.Fatal(err)
	}

	out := t.TempDir()
	if _, err := SplitGoldens(root, out); err != nil {
		t.Fatal(err)
	}

	for name, want := range map[string]string{
		"check-resource-v1-outcome/regular/c1/allow.json": `{"status": 200, "decision": false}`,
		"load-policy-sets-v1/regular/c1/upload-1.json":    `{"status": 200}`,
		"check-resource-v1/semantics/k1.json":             `true`,
	} {
		got, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(name)))
		if err != nil {
			t.Errorf("split wrote no %s: %v", name, err)
			continue
		}
		if !jsonEqual(t, got, json.RawMessage(want)) {
			t.Errorf("split %s = %s, want %s", name, got, want)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "round1", "a.json")); err != nil {
		t.Errorf("merge left the answers of case c1 outside round1/a.json: %v", err)
	}
}

func TestMergeGoldens_TakesAnObservedAnswerOnlyWhenAsked(t *testing.T) {
	t.Parallel()
	in := t.TempDir()
	writeTree(t, in, map[string]string{"check-resource-v1/semantics/k1.observed.json": `false`})

	skipped := goldenTree(t)
	if keys, err := MergeGoldens(skipped, in, false); err != nil || len(keys) != 0 {
		t.Errorf("MergeGoldens(observed false) = %v, %v; want no key", keys, err)
	}
	taken := goldenTree(t)
	if keys, err := MergeGoldens(taken, in, true); err != nil || len(keys) != 1 || keys[0] != "check-resource-v1/semantics/k1" {
		t.Errorf("MergeGoldens(observed true) = %v, %v; want [check-resource-v1/semantics/k1]", keys, err)
	}
}

func TestMergeGoldens_RefusesAKeyAnsweredByAGoldenAndAnObservedFile(t *testing.T) {
	t.Parallel()
	in := t.TempDir()
	writeTree(t, in, map[string]string{
		"check-resource-v1/semantics/k1.json":          `true`,
		"check-resource-v1/semantics/k1.observed.json": `false`,
	})

	_, err := MergeGoldens(goldenTree(t), in, true)

	if err == nil || !strings.Contains(err.Error(), "both answer check-resource-v1/semantics/k1") {
		t.Fatalf("MergeGoldens = %v, want an error naming check-resource-v1/semantics/k1", err)
	}
}

func TestMergeGoldens_RefusesARootWithNoCaseFilesBesideIt(t *testing.T) {
	t.Parallel()
	_, err := MergeGoldens(filepath.Join(t.TempDir(), "golden"), t.TempDir(), false)

	if err == nil || !strings.Contains(err.Error(), "holds no case files") {
		t.Fatalf("MergeGoldens = %v, want an error that the root has no case files beside it", err)
	}
}
