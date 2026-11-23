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
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// A golden key names one recorded answer: "<GoldenDir>/<subCase>", such as
// "check-resource-v1-outcome/regular/some-case/allow". The answers are stored
// grouped, many to a file, under the golden root, whose sibling directory
// cases holds the case files:
//
//   - a key whose third segment is the id of a case in <cases>/<file> lives in
//     <golden root>/<file>, an object that maps the case id to an
//     object that maps the key without its case id segment to the answer;
//   - any other key lives in <golden root>/go/<GoldenDir>.json, an object that
//     maps the key without its GoldenDir segment to the answer.
//
// Keys are sorted and every answer of up to goldenInlineWidth bytes is written
// on one line, so recording one answer changes only its own lines.
const (
	goldenGoDir       = "go"
	goldenInlineWidth = 100
)

// GoldenKey returns the key of the golden of row id under subCase.
func GoldenKey(id ParityEndpointID, subCase string) string {
	return Meta(id).GoldenDir + "/" + subCase
}

// goldenStore reads and writes the grouped goldens under one root. It keeps
// every file it has read in memory, so a store must be the only writer of its
// root while it is in use; goldensAt hands out one store per root.
type goldenStore struct {
	root   string
	suffix string // ".json", or ".observed.json" for the sidecar of a mismatch
	cases  string // the directory of the case files, <root>/../cases

	mu    sync.Mutex
	files map[string]map[string]json.RawMessage // file under root -> key -> answer
}

var (
	goldenStoresMu sync.Mutex
	goldenStores   = map[string]*goldenStore{}
)

// goldensAt returns the store of the goldens under root.
func goldensAt(root string) *goldenStore {
	return storeAt(root, ".json")
}

// observedAt returns the store of the answers a run recorded beside the goldens
// under root when they did not match. Its files are named like the golden
// files with .observed.json in place of .json.
func observedAt(root string) *goldenStore {
	return storeAt(root, ".observed.json")
}

func storeAt(root, suffix string) *goldenStore {
	goldenStoresMu.Lock()
	defer goldenStoresMu.Unlock()
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = filepath.Clean(root)
	}
	id := suffix + "\x00" + abs
	s, ok := goldenStores[id]
	if !ok {
		s = &goldenStore{root: root, suffix: suffix, cases: casesDirOf(root), files: map[string]map[string]json.RawMessage{}}
		goldenStores[id] = s
	}
	return s
}

// casesDirOf returns the directory of the case files beside the golden root.
func casesDirOf(root string) string {
	return filepath.Join(filepath.Dir(filepath.Clean(root)), "cases")
}

var (
	caseIndexesMu sync.Mutex
	caseIndexes   = map[string]map[string]string{}
)

// caseIndexOf maps the id of every case under dir to the name of its file,
// relative to dir and with forward slashes. A dir that does not exist holds
// no case.
func caseIndexOf(dir string) (map[string]string, error) {
	caseIndexesMu.Lock()
	defer caseIndexesMu.Unlock()
	if index, ok := caseIndexes[dir]; ok {
		return index, nil
	}
	index, err := readCaseIndex(dir)
	if err != nil {
		return nil, err
	}
	caseIndexes[dir] = index
	return index, nil
}

func readCaseIndex(root string) (map[string]string, error) {
	index := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".json" {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var f struct {
			Cases []struct {
				ID string `json:"id"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			return fmt.Errorf("read the case ids of %s: %w", p, err)
		}
		name, _ := filepath.Rel(root, p)
		for _, c := range f.Cases {
			index[c.ID] = filepath.ToSlash(name)
		}
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return index, nil
	}
	return index, err
}

// fileOf returns the file, relative to the golden root and with .json as its
// extension, that holds the golden key, and whether that file is the one of a
// case file.
func (s *goldenStore) fileOf(key string) (string, bool, error) {
	index, err := caseIndexOf(s.cases)
	if err != nil {
		return "", false, err
	}
	return goldenFileIn(index, key)
}

// goldenFileIn is [goldenStore.fileOf] with index, from case id to case file,
// in place of the case files beside the golden root.
func goldenFileIn(index map[string]string, key string) (string, bool, error) {
	parts := strings.Split(key, "/")
	if len(parts) < 2 || slices.Contains(parts, "") {
		return "", false, fmt.Errorf("golden key %q is not <GoldenDir>/<subCase>", key)
	}
	if len(parts) >= 3 {
		if file, ok := index[parts[2]]; ok {
			return file, true, nil
		}
	}
	return path.Join(goldenGoDir, parts[0]+".json"), false, nil
}

// Where returns the key and the file that holds it, for a message.
func (s *goldenStore) Where(key string) string {
	file, _, err := s.fileOf(key)
	if err != nil {
		return key
	}
	return fmt.Sprintf("%s in %s", key, s.diskPath(file))
}

func (s *goldenStore) diskPath(file string) string {
	return filepath.Join(s.root, filepath.FromSlash(strings.TrimSuffix(file, ".json")+s.suffix))
}

// Lookup returns the answer recorded under key, and reports whether one is.
func (s *goldenStore) Lookup(key string) (json.RawMessage, bool, error) {
	file, _, err := s.fileOf(key)
	if err != nil {
		return nil, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.load(file)
	if err != nil {
		return nil, false, err
	}
	raw, ok := entries[key]
	return raw, ok, nil
}

// Put records the answers of entries, keyed by golden key, and rewrites every
// file one of them lives in. The other answers of those files are kept.
func (s *goldenStore) Put(entries map[string]json.RawMessage) error {
	files := map[string]string{}
	for _, key := range slices.Sorted(maps.Keys(entries)) {
		if !json.Valid(entries[key]) {
			return fmt.Errorf("the answer for golden %s is not JSON", key)
		}
		file, _, err := s.fileOf(key)
		if err != nil {
			return err
		}
		files[key] = file
	}
	byFile := map[string]bool{}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range slices.Sorted(maps.Keys(entries)) {
		stored, err := s.load(files[key])
		if err != nil {
			return err
		}
		stored[key] = slices.Clone(entries[key])
		byFile[files[key]] = true
	}
	for _, file := range slices.Sorted(maps.Keys(byFile)) {
		if err := s.write(file); err != nil {
			return err
		}
	}
	return nil
}

// All returns every answer under the root by key, and for each key the file,
// relative to the root, that holds it. It reports a key stored in a file other
// than the one [goldenStore.fileOf] names for it as an error, so that a golden
// is never silently out of reach.
func (s *goldenStore) All() (map[string]json.RawMessage, map[string]string, error) {
	out := map[string]json.RawMessage{}
	where := map[string]string{}
	var misplaced []string
	s.mu.Lock()
	defer s.mu.Unlock()
	err := filepath.WalkDir(s.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, s.suffix) {
			return err
		}
		if s.suffix == ".json" && strings.HasSuffix(p, ".observed.json") {
			return nil
		}
		rel, _ := filepath.Rel(s.root, p)
		file := strings.TrimSuffix(filepath.ToSlash(rel), s.suffix) + ".json"
		entries, err := s.load(file)
		if err != nil {
			return err
		}
		for key, raw := range entries {
			want, _, err := s.fileOf(key)
			if err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			if want != file {
				misplaced = append(misplaced, fmt.Sprintf("%s holds %s, which belongs in %s; move the entry there", p, key, s.diskPath(want)))
			}
			out[key] = raw
			where[key] = file
		}
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	if err == nil && len(misplaced) > 0 {
		slices.Sort(misplaced)
		err = errors.New(strings.Join(misplaced, "\n"))
	}
	return out, where, err
}

// load returns the answers of file by golden key, reading the file the first
// time. A file that does not exist holds no answer.
func (s *goldenStore) load(file string) (map[string]json.RawMessage, error) {
	if entries, ok := s.files[file]; ok {
		return entries, nil
	}
	entries := map[string]json.RawMessage{}
	raw, err := os.ReadFile(s.diskPath(file))
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		entries, err = decodeGoldenFile(file, raw)
		if err != nil {
			return nil, fmt.Errorf("read goldens %s: %w; a file holding one answer belongs in a tree that go run ./tools/goldens merge -in records here",
				s.diskPath(file), err)
		}
	}
	s.files[file] = entries
	return entries, nil
}

func (s *goldenStore) write(file string) error {
	encoded, err := encodeGoldenFile(file, s.files[file])
	if err != nil {
		return err
	}
	p := s.diskPath(file)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, encoded, 0o644)
}

// isGoFile reports whether file is one of the files of keys no case file owns.
func isGoFile(file string) bool {
	return strings.HasPrefix(file, goldenGoDir+"/")
}

// decodeGoldenFile returns the answers of a golden file by golden key.
func decodeGoldenFile(file string, raw []byte) (map[string]json.RawMessage, error) {
	out := map[string]json.RawMessage{}
	if isGoFile(file) {
		var flat map[string]json.RawMessage
		if err := json.Unmarshal(raw, &flat); err != nil {
			return nil, err
		}
		dir := strings.TrimSuffix(path.Base(file), ".json")
		for rest, answer := range flat {
			out[dir+"/"+rest] = answer
		}
		return out, nil
	}
	var nested map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &nested); err != nil {
		return nil, err
	}
	for id, answers := range nested {
		for rest, answer := range answers {
			parts := strings.SplitN(rest, "/", 3)
			if len(parts) < 2 {
				return nil, fmt.Errorf("case %s: %q is not <GoldenDir>/<group>[/<request>]", id, rest)
			}
			key := parts[0] + "/" + parts[1] + "/" + id
			if len(parts) == 3 {
				key += "/" + parts[2]
			}
			out[key] = answer
		}
	}
	return out, nil
}

// encodeGoldenFile renders the answers of a golden file, keyed by golden key,
// with sorted keys and a trailing newline.
func encodeGoldenFile(file string, entries map[string]json.RawMessage) ([]byte, error) {
	var b bytes.Buffer
	if isGoFile(file) {
		dir := strings.TrimSuffix(path.Base(file), ".json") + "/"
		flat := map[string]json.RawMessage{}
		for key, answer := range entries {
			flat[strings.TrimPrefix(key, dir)] = answer
		}
		if err := writeGoldenObject(&b, flat, "  ", func(answer json.RawMessage, indent string) error {
			return writeGoldenAnswer(&b, answer, indent)
		}); err != nil {
			return nil, err
		}
		b.WriteByte('\n')
		return b.Bytes(), nil
	}
	nested := map[string]map[string]json.RawMessage{}
	for key, answer := range entries {
		parts := strings.SplitN(key, "/", 4)
		if len(parts) < 3 {
			return nil, fmt.Errorf("golden key %q names no case", key)
		}
		rest := parts[0] + "/" + parts[1]
		if len(parts) == 4 {
			rest += "/" + parts[3]
		}
		if nested[parts[2]] == nil {
			nested[parts[2]] = map[string]json.RawMessage{}
		}
		nested[parts[2]][rest] = answer
	}
	err := writeGoldenObject(&b, nested, "  ", func(answers map[string]json.RawMessage, indent string) error {
		return writeGoldenObject(&b, answers, indent+"  ", func(answer json.RawMessage, indent string) error {
			return writeGoldenAnswer(&b, answer, indent)
		})
	})
	if err != nil {
		return nil, err
	}
	b.WriteByte('\n')
	return b.Bytes(), nil
}

// writeGoldenObject writes an object of members sorted by key, each on its own
// line at indent, closing the object one level out.
func writeGoldenObject[V any](b *bytes.Buffer, members map[string]V, indent string, value func(V, string) error) error {
	b.WriteString("{\n")
	for i, key := range slices.Sorted(maps.Keys(members)) {
		name, err := marshalNoEscape(key)
		if err != nil {
			return err
		}
		b.WriteString(indent)
		b.Write(name)
		b.WriteString(": ")
		if err := value(members[key], indent); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		if i < len(members)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString(strings.TrimSuffix(indent, "  "))
	b.WriteByte('}')
	return nil
}

// writeGoldenAnswer writes answer on one line when it fits goldenInlineWidth,
// and indented under indent otherwise.
func writeGoldenAnswer(b *bytes.Buffer, answer json.RawMessage, indent string) error {
	var compact bytes.Buffer
	if err := json.Compact(&compact, answer); err != nil {
		return err
	}
	if compact.Len() <= goldenInlineWidth {
		b.Write(compact.Bytes())
		return nil
	}
	return json.Indent(b, compact.Bytes(), indent, "  ")
}

func marshalNoEscape(s string) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}
