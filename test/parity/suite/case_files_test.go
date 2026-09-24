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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// caseFile is one file under testdata/cases: the cases one test function runs
// on one stand, as data rather than Go, so that a generator can write them and
// a reader outside the suite can read them without running it.
//
// A case with sets is a regular case: its sets form one upload under the
// external id parity-<id>. A case without sets is an isolated case: one
// simplified policy with condition, on operation (READ when empty), for the
// reader, unless operation names another. The text {{resourceType}} in a condition, a target, or a string of a
// request's resource stands for the case's resource type,
// resourceTypePrefix followed by the id in upper case with - turned into _;
// {{resourceTypeLowerCase}} stands for the same in lower case.
type caseFile struct {
	// About says what the file asks, for the reader of the file; nothing reads it.
	About              string `json:"about"`
	ResourceTypePrefix string `json:"resourceTypePrefix"`
	// Pins maps a pip-mock route to the answer it is pinned to before the first case.
	Pins map[string]PipStubResponse `json:"pins"`
	// PIPs holds the PIP declarations the cases name by key.
	PIPs  map[string]any `json:"pips"`
	Cases []caseSpec     `json:"cases"`
}

type caseSpec struct {
	ID string `json:"id"`
	// About says what the case asks where its id and condition do not; nothing
	// reads it.
	About     string        `json:"about"`
	Condition string        `json:"condition"`
	Operation string        `json:"operation"`
	PIPs      []string      `json:"pips"`
	Sets      []setSpec     `json:"sets"`
	Requests  []requestSpec `json:"requests"`
}

type setSpec struct {
	Key       string       `json:"key"`
	Target    string       `json:"target"`
	Algorithm string       `json:"algorithm"`
	Iterate   *iterateSpec `json:"iterate"`
	Policies  []policySpec `json:"policies"`
	Sets      []setSpec    `json:"sets"`
}

type iterateSpec struct {
	Foreach   string `json:"foreach"`
	Algorithm string `json:"algorithm"`
}

type policySpec struct {
	Key       string     `json:"key"`
	Target    string     `json:"target"`
	Algorithm string     `json:"algorithm"`
	Rules     []ruleSpec `json:"rules"`
}

type ruleSpec struct {
	Key        string            `json:"key"`
	Target     string            `json:"target"`
	Condition  string            `json:"condition"`
	Effect     string            `json:"effect"`
	Predicates map[string]string `json:"predicates"`
}

type requestSpec struct {
	Name      string            `json:"name"`
	Operation string            `json:"operation"`
	Type      string            `json:"type"`
	Resource  any               `json:"resource"`
	Headers   map[string]string `json:"headers"`
	Filter    bool              `json:"filter"`
	// Subject "m2m" sends the M2M token alone; empty sends parity-reader.
	Subject string `json:"subject"`
}

// readCaseFile reads testdata/cases/<name>. Numbers in a resource keep their
// JSON spelling, so 5.0 is sent as 5.0 and not as 5.
func readCaseFile(name string) (caseFile, error) {
	var f caseFile
	raw, err := os.ReadFile(filepath.Join("testdata", "cases", name))
	if err != nil {
		return f, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return f, fmt.Errorf("read %s: %w", name, err)
	}
	return f, nil
}

// resourceTypeReplacer replaces {{resourceType}} and {{resourceTypeLowerCase}}
// with rt.
func resourceTypeReplacer(rt string) *strings.Replacer {
	return strings.NewReplacer("{{resourceType}}", rt, "{{resourceTypeLowerCase}}", strings.ToLower(rt))
}

// withResourceType returns v with {{resourceType}} and
// {{resourceTypeLowerCase}} replaced in every string.
func withResourceType(v any, rt string) any {
	switch x := v.(type) {
	case string:
		return resourceTypeReplacer(rt).Replace(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = withResourceType(e, rt)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = withResourceType(e, rt)
		}
		return out
	default:
		return v
	}
}

// TestCaseFilesAreWellFormed reads every file under testdata/cases the way
// runCaseFile does, so that a misspelled field, a PIP a case names and its file
// does not declare, or an id two cases share fails here rather than on a stand
// spent recording it. Case ids are golden paths, so they are unique across
// files as well as within one.
func TestCaseFilesAreWellFormed(t *testing.T) {
	root := filepath.Join("testdata", "cases")
	seen := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".json" {
			return err
		}
		name, _ := filepath.Rel(root, path)
		f, err := readCaseFile(name)
		if err != nil {
			t.Error(err)
			return nil
		}
		for _, c := range f.Cases {
			if other, ok := seen[c.ID]; ok {
				t.Errorf("%s: case id %s is also used in %s", name, c.ID, other)
			}
			seen[c.ID] = name
			for _, key := range c.PIPs {
				if _, ok := f.PIPs[key]; !ok {
					t.Errorf("%s: case %s names the PIP %q, which the file does not declare", name, c.ID, key)
				}
			}
			if len(c.Requests) == 0 {
				t.Errorf("%s: case %s sends no request", name, c.ID)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) == 0 {
		t.Fatalf("no case under %s", root)
	}
}
