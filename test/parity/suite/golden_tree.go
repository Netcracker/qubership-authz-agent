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
	"os"
	"path/filepath"
	"strings"
)

// SplitGoldens writes every golden under root to its own file in out, at
// <out>/<key>.json, the layout tools that read one answer per file expect. It
// returns the number of files written.
func SplitGoldens(root, out string) (int, error) {
	if err := requireCasesDir(root); err != nil {
		return 0, err
	}
	entries, _, err := goldensAt(root).All()
	if err != nil {
		return 0, err
	}
	for key, raw := range entries {
		p := filepath.Join(out, filepath.FromSlash(key)+".json")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return 0, err
		}
		if err := os.WriteFile(p, append(append([]byte{}, raw...), '\n'), 0o644); err != nil {
			return 0, err
		}
	}
	return len(entries), nil
}

// MergeGoldens records every <in>/<key>.json file as the golden of key under
// root, replacing an answer already recorded under that key and keeping the
// others. When observed is true, a <key>.observed.json file is recorded under
// key too, and a key with both files is an error; otherwise .observed.json
// files are skipped. It returns the keys it recorded.
func MergeGoldens(root, in string, observed bool) ([]string, error) {
	if err := requireCasesDir(root); err != nil {
		return nil, err
	}
	entries := map[string]json.RawMessage{}
	err := filepath.WalkDir(in, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".json" {
			return err
		}
		rel, _ := filepath.Rel(in, p)
		key := strings.TrimSuffix(filepath.ToSlash(rel), ".json")
		if strings.HasSuffix(key, ".observed") {
			if !observed {
				return nil
			}
			key = strings.TrimSuffix(key, ".observed")
			if _, err := os.Stat(filepath.Join(in, filepath.FromSlash(key)+".json")); err == nil {
				return fmt.Errorf("%s and %s.json both answer %s", p, key, key)
			}
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if !json.Valid(raw) {
			return fmt.Errorf("%s is not valid JSON", p)
		}
		entries[key] = raw
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := goldensAt(root).Put(entries); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	return keys, nil
}

// requireCasesDir reports an error when the case files beside root are
// missing: without them every golden of a case file would be taken for the
// golden of a Go test.
func requireCasesDir(root string) error {
	dir := casesDirOf(root)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return fmt.Errorf("%s holds no case files; the golden root must be the golden directory beside them", dir)
	}
	return nil
}
