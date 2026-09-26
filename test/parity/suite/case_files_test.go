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
	// Roles replaces the roles of an isolated case's policy, which are
	// ROLE_PARITY_READER when the field is absent; an empty list uploads the
	// policy with no role.
	Roles []string `json:"roles"`
	// Domain names the domain an isolated case uploads its PIPs and policy
	// into, isolatedCaseDomain when empty. The function empties every domain its
	// cases named when it ends.
	Domain string `json:"domain"`
	// RuleIDsOf names an earlier case with sets in the same file. The rule ids
	// of this case are then derived from that case's id rather than its own, so
	// a rule whose key an earlier rule also has uploads with that rule's id.
	RuleIDsOf string `json:"ruleIdsOf"`
}

type setSpec struct {
	Key       string       `json:"key"`
	Target    string       `json:"target"`
	Algorithm string       `json:"algorithm"`
	Iterate   *iterateSpec `json:"iterate"`
	Policies  []policySpec `json:"policies"`
	Sets      []setSpec    `json:"sets"`
	// Status is the set's status, ACTIVE when empty.
	Status string `json:"status"`
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
	Key       string `json:"key"`
	Target    string `json:"target"`
	Condition string `json:"condition"`
	Effect    string `json:"effect"`
	// Predicates holds the rule's predicate fields by name: a string for each
	// dialect, and an object for customPredicate.
	Predicates map[string]any `json:"predicates"`
}

type requestSpec struct {
	Name      string            `json:"name"`
	Operation string            `json:"operation"`
	Type      string            `json:"type"`
	Resource  any               `json:"resource"`
	Headers   map[string]string `json:"headers"`
	Filter    bool              `json:"filter"`
	// Subject "m2m" sends the M2M token alone; "user:<username>" sends the
	// token of that user of the parity realm beside the M2M token; empty sends
	// parity-reader.
	Subject string `json:"subject"`
	// SubjectClaims holds claim values the token of a "user:" subject must
	// carry, such as sub and preferred_username. The suite decodes the token and
	// fails before sending the request when a claim is missing or differs, so a
	// stand whose realm lacks the user, or gives it other values, records
	// nothing.
	SubjectClaims map[string]string `json:"subjectClaims"`
	// ClassifyBy names a pip-mock route. The request's golden is then recorded
	// under <name>-when-the-pip-was-read when the route received a call while
	// the request ran, and under <name>-when-the-pip-was-skipped when it did
	// not, so that an answer that depends on the order access-control evaluates
	// the children of a node in is filed with that order. Regular cases only.
	ClassifyBy string `json:"classifyBy"`
	// TenantID replaces the stand's tenant in the tenant_id query parameter
	// when present; an empty string sends tenant_id with an empty value.
	TenantID *string `json:"tenantId"`
	// PIPCalls names a pip-mock route. The call log is cleared before the
	// request, and what the route received while the request ran is recorded
	// as a pip-call golden under the request's own name.
	PIPCalls string `json:"pipCalls"`
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
// does not declare, an id two cases share, a classifyBy on an isolated case or
// on a route the file does not pin, a pipCalls on a route the file does not pin
// or beside classifyBy, a subject other than m2m or user:<username>,
// subjectClaims without a user: subject, roles or domain on a case with sets, or a ruleIdsOf
// that names no earlier case with sets of the file fails here rather than on a
// stand spent recording it. Case ids are golden paths, so they are unique
// across files as well as within one.
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
		checkKeepsPIPNames(t, name, f)
		earlierRegular := map[string]bool{}
		for _, c := range f.Cases {
			if other, ok := seen[c.ID]; ok {
				t.Errorf("%s: case id %s is also used in %s", name, c.ID, other)
			}
			seen[c.ID] = name
			if len(c.Sets) > 0 {
				if c.Roles != nil || c.Domain != "" {
					t.Errorf("%s: case %s sets roles or domain, which only a case without sets reads", name, c.ID)
				}
				if c.RuleIDsOf != "" && !earlierRegular[c.RuleIDsOf] {
					t.Errorf("%s: case %s takes its rule ids from %q, which is no earlier case with sets of the file", name, c.ID, c.RuleIDsOf)
				}
				earlierRegular[c.ID] = true
			} else if c.RuleIDsOf != "" {
				t.Errorf("%s: case %s sets ruleIdsOf, which only a case with sets reads", name, c.ID)
			}
			for _, key := range c.PIPs {
				if _, ok := f.PIPs[key]; !ok {
					t.Errorf("%s: case %s names the PIP %q, which the file does not declare", name, c.ID, key)
				}
			}
			if len(c.Requests) == 0 {
				t.Errorf("%s: case %s sends no request", name, c.ID)
			}
			for _, r := range c.Requests {
				if r.Subject != "" && r.Subject != "m2m" && (!strings.HasPrefix(r.Subject, "user:") || r.Subject == "user:") {
					t.Errorf("%s: case %s request %s names the subject %q, which is neither m2m nor user:<username>", name, c.ID, r.Name, r.Subject)
				}
				if len(r.SubjectClaims) > 0 && !strings.HasPrefix(r.Subject, "user:") {
					t.Errorf("%s: case %s request %s sets subjectClaims without a user: subject", name, c.ID, r.Name)
				}
				if r.PIPCalls != "" {
					if _, ok := f.Pins[r.PIPCalls]; !ok {
						t.Errorf("%s: case %s request %s records the calls to %s, which the file does not pin", name, c.ID, r.Name, r.PIPCalls)
					}
					if r.ClassifyBy != "" {
						t.Errorf("%s: case %s request %s sets both pipCalls and classifyBy, which each clear the call log", name, c.ID, r.Name)
					}
				}
				if r.ClassifyBy == "" {
					continue
				}
				if len(c.Sets) == 0 {
					t.Errorf("%s: case %s request %s sets classifyBy, which only a regular case reads", name, c.ID, r.Name)
				}
				if _, ok := f.Pins[r.ClassifyBy]; !ok {
					t.Errorf("%s: case %s request %s is classified by %s, which the file does not pin", name, c.ID, r.Name, r.ClassifyBy)
				}
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

// dropsPIPNamesOnPurpose lists the case files that let a case declare fewer PIP
// names than the cases before it, because the file asks what that does.
var dropsPIPNamesOnPurpose = map[string]bool{"round19/stand-rule.json": true}

// checkKeepsPIPNames fails a file of round 19 or later in which a case with
// sets names PIPs without naming every PIP name that an earlier case with sets
// of the file named. A PIP upload replaces the whole declaration of the
// suite's domain, the sets of earlier cases stay loaded, and while a loaded set
// reads a PIP the declaration no longer names, access-control answers every
// check with 400. Cases without sets run before any set is loaded.
func checkKeepsPIPNames(t *testing.T, name string, f caseFile) {
	t.Helper()
	var round int
	if _, err := fmt.Sscanf(name, "round%d/", &round); err != nil || round < 19 || dropsPIPNamesOnPurpose[filepath.ToSlash(name)] {
		return
	}
	pipName := func(key string) string {
		if decl, ok := f.PIPs[key].(map[string]any); ok {
			if n, ok := decl["name"].(string); ok {
				return n
			}
		}
		return key
	}
	declared := map[string]bool{}
	for _, c := range f.Cases {
		if len(c.Sets) == 0 || len(c.PIPs) == 0 {
			continue
		}
		names := map[string]bool{}
		for _, key := range c.PIPs {
			names[pipName(key)] = true
		}
		for n := range declared {
			if !names[n] {
				t.Errorf("%s: case %s declares its PIPs without %s, which an earlier case declared", name, c.ID, n)
			}
		}
		for n := range names {
			declared[n] = true
		}
	}
}
